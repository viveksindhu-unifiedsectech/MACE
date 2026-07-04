"""User model — RBAC with 5 roles, SSO support, API key management."""
import uuid, hashlib, secrets
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, JSON, Enum as SAEnum, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import enum


class UserRole(str, enum.Enum):
    SUPER_ADMIN  = "super_admin"   # UnifiedSec staff — cross-tenant
    TENANT_ADMIN = "tenant_admin"  # Full access within tenant
    SOC_ANALYST  = "soc_analyst"   # SOC dashboard, incidents, correlation
    READ_ONLY    = "read_only"     # View only — auditors, executives
    API_USER     = "api_user"      # Machine-to-machine (connector accounts)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)

    # Identity
    email: Mapped[str] = mapped_column(String(255), nullable=False, index=True)
    full_name: Mapped[str] = mapped_column(String(255), nullable=True)
    avatar_url: Mapped[str] = mapped_column(String(512), nullable=True)

    # Auth — password OR SSO (not both required)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=True)
    sso_provider: Mapped[str] = mapped_column(String(50), nullable=True)  # google | microsoft | okta
    sso_subject: Mapped[str] = mapped_column(String(255), nullable=True)  # provider-issued sub

    # Authorization
    role: Mapped[UserRole] = mapped_column(SAEnum(UserRole), default=UserRole.SOC_ANALYST)
    permissions: Mapped[dict] = mapped_column(JSON, default=dict)   # fine-grained overrides
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    mfa_secret: Mapped[str] = mapped_column(String(255), nullable=True)

    # Session tracking
    last_login_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    last_login_ip: Mapped[str] = mapped_column(String(45), nullable=True)
    failed_login_count: Mapped[int] = mapped_column(default=0)
    locked_until: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Preferences
    timezone: Mapped[str] = mapped_column(String(50), default="UTC")
    jurisdiction_view: Mapped[str] = mapped_column(String(10), nullable=True)  # override tenant default
    password_reset_token: Mapped[str] = mapped_column(String(255), nullable=True)
    password_reset_expires: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    email_verify_token: Mapped[str] = mapped_column(String(255), nullable=True)
    mfa_backup_codes: Mapped[list] = mapped_column(JSON, nullable=True)
    notification_prefs: Mapped[dict] = mapped_column(JSON, default=dict)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="users")
    api_keys: Mapped[list["APIKey"]] = relationship("APIKey", back_populates="user", lazy="select")

    def __repr__(self):
        return f"<User {self.email} [{self.role}]>"


class APIKey(Base):
    """Long-lived API keys for machine-to-machine integration (connectors, CI/CD)."""
    __tablename__ = "api_keys"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    user_id: Mapped[str] = mapped_column(String(36), ForeignKey("users.id"), nullable=False)

    name: Mapped[str] = mapped_column(String(255), nullable=False)          # "CrowdStrike Connector"
    key_prefix: Mapped[str] = mapped_column(String(20), nullable=False)     # "mace_prod_"
    key_hash: Mapped[str] = mapped_column(String(255), nullable=False)      # SHA-256 of full key
    scopes: Mapped[list] = mapped_column(JSON, default=list)                # ["assets:write", "events:write"]
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)

    last_used_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    expires_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="api_keys")
    user: Mapped["User"] = relationship("User", back_populates="api_keys")

    @staticmethod
    def generate() -> tuple[str, str]:
        """Returns (full_key, key_hash). Store only the hash."""
        raw = f"mace_{secrets.token_urlsafe(32)}"
        hashed = hashlib.sha256(raw.encode()).hexdigest()
        return raw, hashed

    @staticmethod
    def hash_key(raw: str) -> str:
        return hashlib.sha256(raw.encode()).hexdigest()
