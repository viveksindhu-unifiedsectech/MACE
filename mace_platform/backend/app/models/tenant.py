"""
Multi-tenant model — every row in every table is scoped to a tenant_id.
Supports: US enterprise, UAE, EU, India. Each tenant has:
  - its own weight_profile (jurisdiction-specific CDCS weights)
  - its own data_residency (controls which cloud region stores data)
  - its own MACE engine instance in memory (isolated correlation)
"""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, JSON, Enum as SAEnum, Integer, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import enum


class TenantPlan(str, enum.Enum):
    MSME       = "msme"          # ₹500/asset/yr India, $12/asset/yr US
    STARTER    = "starter"       # Up to 500 assets
    PROFESSIONAL = "professional"# Up to 5,000 assets
    ENTERPRISE = "enterprise"    # Unlimited


class Tenant(Base):
    __tablename__ = "tenants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    slug: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    domain: Mapped[str] = mapped_column(String(255), nullable=True)

    # Plan & billing
    plan: Mapped[TenantPlan] = mapped_column(SAEnum(TenantPlan), default=TenantPlan.STARTER)
    asset_limit: Mapped[int] = mapped_column(Integer, default=500)
    stripe_customer_id: Mapped[str] = mapped_column(String(255), nullable=True)

    # Jurisdiction & data residency
    # US: 'usa_fedramp' | AE: 'uae_nesa' | EU: 'eu_gdpr' | IN: 'india_cii' | CA: 'canada_pipeda'
    jurisdiction: Mapped[str] = mapped_column(String(10), default="US")
    weight_profile: Mapped[str] = mapped_column(String(50), default="usa_fedramp")
    data_residency: Mapped[str] = mapped_column(String(50), default="us-east-1")
    sector: Mapped[str] = mapped_column(String(100), default="default")

    # MACE engine configuration
    cdcs_alert_threshold: Mapped[float] = mapped_column(default=7.0)
    rea_cdcs_threshold: Mapped[float] = mapped_column(default=6.5)
    mace_config: Mapped[dict] = mapped_column(JSON, default=dict)

    # Regulatory frameworks enabled
    enabled_frameworks: Mapped[list] = mapped_column(JSON, default=list)

    # Status
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    is_fedramp: Mapped[bool] = mapped_column(Boolean, default=False)    # GovCloud
    is_hipaa_baa: Mapped[bool] = mapped_column(Boolean, default=False)  # HIPAA BAA signed
    soc2_compliant: Mapped[bool] = mapped_column(Boolean, default=False)

    # Contact
    primary_contact_email: Mapped[str] = mapped_column(String(255), nullable=True)
    technical_contact_email: Mapped[str] = mapped_column(String(255), nullable=True)
    security_contact_email: Mapped[str] = mapped_column(String(255), nullable=True)

    # Timestamps
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)
    trial_ends_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)

    # Metadata
    settings: Mapped[dict] = mapped_column(JSON, default=dict)
    notes: Mapped[str] = mapped_column(Text, nullable=True)

    # Relationships
    users: Mapped[list["User"]] = relationship("User", back_populates="tenant", lazy="select")
    assets: Mapped[list["Asset"]] = relationship("Asset", back_populates="tenant", lazy="select")
    incidents: Mapped[list["Incident"]] = relationship("Incident", back_populates="tenant", lazy="select")
    subscriptions: Mapped[list["Subscription"]] = relationship("Subscription", back_populates="tenant", lazy="select")
    connectors: Mapped[list["ConnectorConfig"]] = relationship("ConnectorConfig", back_populates="tenant", lazy="select")
    api_keys: Mapped[list["APIKey"]] = relationship("APIKey", back_populates="tenant", lazy="select")

    def __repr__(self):
        return f"<Tenant {self.slug} ({self.plan})>"
