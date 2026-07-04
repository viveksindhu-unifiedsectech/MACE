"""Security incidents — created when CDCS >= alert threshold."""
import uuid
from datetime import datetime
from sqlalchemy import String, DateTime, Boolean, JSON, Float, Enum as SAEnum, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base
import enum


class IncidentSeverity(str, enum.Enum):
    CRITICAL = "critical"
    HIGH     = "high"
    MEDIUM   = "medium"
    LOW      = "low"


class IncidentStatus(str, enum.Enum):
    OPEN           = "open"
    INVESTIGATING  = "investigating"
    CONTAINED      = "contained"
    ERADICATED     = "eradicated"
    RECOVERED      = "recovered"
    CLOSED         = "closed"
    FALSE_POSITIVE = "false_positive"


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    asset_id: Mapped[str] = mapped_column(String(36), ForeignKey("assets.id"), nullable=True, index=True)

    # Core fields
    incident_ref: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)  # INC-A1B2C3D4
    title: Mapped[str] = mapped_column(String(512), nullable=False)
    description: Mapped[str] = mapped_column(Text, nullable=True)
    event_type: Mapped[str] = mapped_column(String(100), nullable=False)  # data_breach | ransomware | etc.

    # CDCS result
    cdcs_score: Mapped[float] = mapped_column(Float, nullable=False)
    severity: Mapped[IncidentSeverity] = mapped_column(SAEnum(IncidentSeverity), nullable=False, index=True)
    status: Mapped[IncidentStatus] = mapped_column(SAEnum(IncidentStatus), default=IncidentStatus.OPEN, index=True)

    # Domain sub-scores
    v_score: Mapped[float] = mapped_column(Float, default=0.0)
    e_score: Mapped[float] = mapped_column(Float, default=0.0)
    i_score: Mapped[float] = mapped_column(Float, default=0.0)
    n_score: Mapped[float] = mapped_column(Float, default=0.0)
    c_score: Mapped[float] = mapped_column(Float, default=0.0)
    t_score: Mapped[float] = mapped_column(Float, default=0.0)

    # Multipliers applied
    sector_multiplier: Mapped[float] = mapped_column(Float, default=1.0)
    blast_radius_multiplier: Mapped[float] = mapped_column(Float, default=1.0)
    kill_chain_multiplier: Mapped[float] = mapped_column(Float, default=1.0)
    kill_chain_stage: Mapped[str] = mapped_column(String(50), nullable=True)
    dominant_domain: Mapped[str] = mapped_column(String(50), nullable=True)
    lateral_hop_count: Mapped[int] = mapped_column(default=0)

    # Regulatory evidence
    regulatory_evidence_id: Mapped[str] = mapped_column(String(36), ForeignKey("regulatory_evidence.id"), nullable=True)
    jurisdictions: Mapped[list] = mapped_column(JSON, default=list)
    frameworks_triggered: Mapped[list] = mapped_column(JSON, default=list)

    # Assignment & response
    assigned_to: Mapped[str] = mapped_column(String(255), nullable=True)
    responders: Mapped[list] = mapped_column(JSON, default=list)
    response_notes: Mapped[str] = mapped_column(Text, nullable=True)
    timeline: Mapped[list] = mapped_column(JSON, default=list)     # list of {ts, action, user}

    # Feedback for adaptive learning
    confirmed_true_positive: Mapped[bool] = mapped_column(Boolean, nullable=True)
    feedback_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    feedback_by: Mapped[str] = mapped_column(String(255), nullable=True)

    # Timestamps
    detected_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, index=True)
    acknowledged_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    contained_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    resolved_at: Mapped[datetime] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    # Relationships
    tenant: Mapped["Tenant"] = relationship("Tenant", back_populates="incidents")
    asset: Mapped["Asset"] = relationship("Asset")
    regulatory_evidence: Mapped["RegulatoryEvidence"] = relationship("RegulatoryEvidence", back_populates="incident")
