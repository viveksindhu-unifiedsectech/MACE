"""Audit log — immutable record of all actions (SOC 2, FedRAMP, GDPR requirement)."""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, JSON, ForeignKey, Text, Boolean
from sqlalchemy.orm import Mapped, mapped_column
from app.db.base import Base


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    user_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    user_email: Mapped[Optional[str]] = mapped_column(String(255), nullable=True)

    action: Mapped[str] = mapped_column(String(100), nullable=False, index=True)
    # e.g. "asset.create" | "incident.acknowledge" | "evidence.submit" | "user.login"

    resource_type: Mapped[Optional[str]] = mapped_column(String(100), nullable=True)
    resource_id: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)

    ip_address: Mapped[Optional[str]] = mapped_column(String(45), nullable=True)
    user_agent: Mapped[Optional[str]] = mapped_column(String(512), nullable=True)

    # Before/after state for mutations
    old_values: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    new_values: Mapped[Optional[dict]] = mapped_column(JSON, nullable=True)
    # 'metadata' is reserved by SQLAlchemy DeclarativeBase — use 'extra' instead
    extra: Mapped[dict] = mapped_column("metadata_json", JSON, default=dict)

    success: Mapped[bool] = mapped_column(Boolean, default=True)
    error_message: Mapped[Optional[str]] = mapped_column(Text, nullable=True)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    # Note: audit logs are NEVER updated or deleted
