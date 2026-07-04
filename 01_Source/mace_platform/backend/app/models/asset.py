"""Asset model — canonical device record after UTAG probabilistic merge."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, JSON, Float, Integer, Enum as SAEnum, ForeignKey, Text, Index
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import enum


class AssetClass(str, enum.Enum):
    CLOUD_VM        = "cloud_vm"
    CONTAINER       = "container"
    KUBERNETES_NODE = "kubernetes_node"
    SERVERLESS      = "serverless"
    ENDPOINT        = "endpoint"
    SERVER          = "server"
    MOBILE          = "mobile"
    NETWORK_DEVICE  = "network_device"
    OT_ICS          = "ot_ics"
    IOT_DEVICE      = "iot_device"
    DATABASE        = "database"
    UNKNOWN         = "unknown"


class AssetStatus(str, enum.Enum):
    ACTIVE          = "active"
    STALE           = "stale"
    SHADOW_IT       = "shadow_it"
    GEO_ANOMALY     = "geo_anomaly"
    DECOMMISSIONED  = "decommissioned"


class Asset(Base):
    __tablename__ = "assets"
    __table_args__ = (
        Index("ix_assets_tenant_status", "tenant_id", "status"),
        Index("ix_assets_tenant_class", "tenant_id", "asset_class"),
        Index("ix_assets_acs", "tenant_id", "acs_score"),
    )

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)

    # Identity (merged from all sources via UTAG)
    canonical_id: Mapped[str] = mapped_column(String(36), unique=True, nullable=False,
                                               default=lambda: str(uuid.uuid4()))
    hostname: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    mac_address: Mapped[str] = mapped_column(String(17), nullable=True, index=True)
    ip_address: Mapped[str] = mapped_column(String(45), nullable=True)
    cloud_instance_id: Mapped[str] = mapped_column(String(255), nullable=True, index=True)
    cloud_account_id: Mapped[str] = mapped_column(String(255), nullable=True)
    cert_fingerprint: Mapped[str] = mapped_column(String(512), nullable=True)
    serial_number: Mapped[str] = mapped_column(String(255), nullable=True)

    # Classification
    asset_class: Mapped[AssetClass] = mapped_column(SAEnum(AssetClass), default=AssetClass.UNKNOWN, index=True)
    status: Mapped[AssetStatus] = mapped_column(SAEnum(AssetStatus), default=AssetStatus.ACTIVE, index=True)
    os: Mapped[str] = mapped_column(String(255), nullable=True)
    open_ports: Mapped[list] = mapped_column(JSON, default=list)

    # Ownership
    owner: Mapped[str] = mapped_column(String(255), nullable=True)
    owner_email: Mapped[str] = mapped_column(String(255), nullable=True)
    sector: Mapped[str] = mapped_column(String(100), nullable=True)
    tags: Mapped[dict] = mapped_column(JSON, default=dict)

    # Jurisdiction & classification
    jurisdiction: Mapped[str] = mapped_column(String(10), default="US")
    data_classification: Mapped[str] = mapped_column(String(50), default="internal")
    is_internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    is_critical_infra: Mapped[bool] = mapped_column(Boolean, default=False)

    # MACE computed scores (refreshed every cycle)
    acs_score: Mapped[float] = mapped_column(Float, default=1.0)      # Asset Confidence Score
    entropy_score: Mapped[float] = mapped_column(Float, default=0.5)  # Graph entropy
    cdcs_score: Mapped[float] = mapped_column(Float, nullable=True)   # Latest CDCS
    risk_level: Mapped[str] = mapped_column(String(20), nullable=True) # CRITICAL/HIGH/MEDIUM/LOW

    # UTAG tracking
    source_set: Mapped[list] = mapped_column(JSON, default=list)      # ["crowdstrike", "tenable"]
    quorum_sources: Mapped[int] = mapped_column(Integer, default=1)
    shadow_it_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    geo_velocity_flag: Mapped[bool] = mapped_column(Boolean, default=False)
    max_geo_velocity_kmh: Mapped[float] = mapped_column(Float, default=0.0)

    # Geo
    last_geo_lat: Mapped[float] = mapped_column(Float, nullable=True)
    last_geo_lon: Mapped[float] = mapped_column(Float, nullable=True)
    last_geo_city: Mapped[str] = mapped_column(String(100), nullable=True)
    last_geo_country: Mapped[str] = mapped_column(String(10), nullable=True)

    # Vulnerability summary
    critical_vuln_count: Mapped[int] = mapped_column(Integer, default=0)
    high_vuln_count: Mapped[int] = mapped_column(Integer, default=0)
    open_cves: Mapped[list] = mapped_column(JSON, default=list)

    # Lineage
    parent_asset_id: Mapped[str] = mapped_column(String(36), nullable=True)  # clone parent
    lineage_events: Mapped[list] = mapped_column(JSON, default=list)

    # Timestamps
    first_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    last_scored_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Raw attributes from sources
    raw_attributes: Mapped[dict] = mapped_column(JSON, default=dict)

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="assets")
    vulnerabilities: Mapped[list["VulnerabilityFinding"]] = relationship(
        "VulnerabilityFinding", back_populates="asset", lazy="select"
    )
    sources: Mapped[list["AssetSource"]] = relationship(
        "AssetSource", back_populates="asset", lazy="select"
    )

    def __repr__(self):
        return f"<Asset {self.hostname or self.ip_address or self.canonical_id[:8]} [{self.asset_class}]>"


class AssetSource(Base):
    """One row per (asset, data_source) — tracks each tool's view of the asset."""
    __tablename__ = "asset_sources"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=False, index=True)
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)

    source_name: Mapped[str] = mapped_column(String(100), nullable=False)   # "crowdstrike" | "tenable"
    source_id: Mapped[str] = mapped_column(String(255), nullable=False)     # tool-native ID
    source_confidence: Mapped[float] = mapped_column(Float, default=1.0)
    raw_data: Mapped[dict] = mapped_column(JSON, default=dict)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    asset: Mapped["Asset"] = relationship("Asset", back_populates="sources")
