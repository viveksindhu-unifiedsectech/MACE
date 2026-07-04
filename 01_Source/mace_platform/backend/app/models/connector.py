"""Data connector configurations — one row per (tenant, tool) integration."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, JSON, Enum as SAEnum, ForeignKey, Text, Integer
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import enum


class ConnectorType(str, enum.Enum):
    CROWDSTRIKE = "crowdstrike"
    TENABLE     = "tenable"
    AXONIUS     = "axonius"
    QUALYS      = "qualys"
    SPLUNK      = "splunk"
    SENTINEL    = "sentinel_one"
    MISP        = "misp"
    VIRUSTOTAL  = "virustotal"
    RECORDED_FUTURE = "recorded_future"
    CUSTOM_API  = "custom_api"


class ConnectorStatus(str, enum.Enum):
    ACTIVE      = "active"
    INACTIVE    = "inactive"
    ERROR       = "error"
    TESTING     = "testing"


class ConnectorConfig(Base):
    __tablename__ = "connector_configs"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)

    connector_type: Mapped[ConnectorType] = mapped_column(SAEnum(ConnectorType), nullable=False)
    name: Mapped[str] = mapped_column(String(255), nullable=False)    # "Production CrowdStrike"
    status: Mapped[ConnectorStatus] = mapped_column(SAEnum(ConnectorStatus), default=ConnectorStatus.TESTING)

    # Encrypted credentials (store encrypted, never plaintext)
    # In production: use AWS Secrets Manager / Azure Key Vault
    base_url: Mapped[str] = mapped_column(String(512), nullable=True)
    client_id: Mapped[str] = mapped_column(String(512), nullable=True)
    client_secret_encrypted: Mapped[str] = mapped_column(Text, nullable=True)   # AES-256 encrypted
    api_key_encrypted: Mapped[str] = mapped_column(Text, nullable=True)

    # Sync settings
    sync_enabled: Mapped[bool] = mapped_column(Boolean, default=True)
    sync_interval_minutes: Mapped[int] = mapped_column(Integer, default=60)
    last_sync_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    last_sync_status: Mapped[str] = mapped_column(String(50), nullable=True)
    last_sync_count: Mapped[int] = mapped_column(Integer, default=0)
    error_message: Mapped[str] = mapped_column(Text, nullable=True)

    # Data types this connector provides
    provides_assets: Mapped[bool] = mapped_column(Boolean, default=True)
    provides_vulns: Mapped[bool] = mapped_column(Boolean, default=False)
    provides_events: Mapped[bool] = mapped_column(Boolean, default=False)
    provides_threat_intel: Mapped[bool] = mapped_column(Boolean, default=False)

    # Field mapping config (source field -> MACE field)
    field_mapping: Mapped[dict] = mapped_column(JSON, default=dict)
    filters: Mapped[dict] = mapped_column(JSON, default=dict)

    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="connectors")
