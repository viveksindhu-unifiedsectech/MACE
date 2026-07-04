from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime


class IdentitySignalInput(BaseModel):
    impossible_travel: bool = False
    mfa_failures_1h: int = 0
    privilege_escalation: bool = False
    anomalous_login_time: bool = False
    new_device: bool = False
    credential_stuffing_indicator: bool = False
    service_account_anomaly: bool = False
    lateral_account_reuse: bool = False
    password_spray_detected: bool = False
    golden_ticket_indicator: bool = False
    pass_the_hash_indicator: bool = False
    oauth_abuse_indicator: bool = False

class NetworkContextInput(BaseModel):
    lateral_movement_score: float = Field(0.0, ge=0.0, le=1.0)
    c2_beacon_score: float = Field(0.0, ge=0.0, le=1.0)
    dns_entropy_score: float = Field(0.0, ge=0.0, le=1.0)
    port_scan_detected: bool = False
    data_exfil_indicator: float = Field(0.0, ge=0.0, le=1.0)
    lateral_hop_count: int = 0
    tor_exit_node: bool = False
    ransomware_c2_ioc: bool = False
    bytes_exfiltrated_mb: float = 0.0
    netflow_anomaly_score: float = Field(0.0, ge=0.0, le=1.0)

class CompliancePostureInput(BaseModel):
    stig_pass_count: int = 0
    stig_fail_count: int = 0
    last_scan_hours_ago: float = 0.0
    missing_patches: int = 0
    edr_coverage: bool = True
    mfa_enrolled: bool = True
    endpoint_encryption: bool = True
    dlp_enabled: bool = False
    privileged_access_managed: bool = False

class ThreatIntelInput(BaseModel):
    ioc_match_score: float = Field(0.0, ge=0.0, le=1.0)
    campaign_match: bool = False
    threat_actor_confidence: float = Field(0.0, ge=0.0, le=1.0)
    threat_actor_known: bool = False
    campaign_active: bool = False
    malware_family: Optional[str] = None
    feed_sources: List[str] = []

class SecurityEventInput(BaseModel):
    event_id: str
    event_type: str
    severity: str   # CRITICAL | HIGH | MEDIUM | LOW | INFO
    domain: str     # endpoint | network | identity | cloud
    description: str
    kill_chain_stage: Optional[str] = None
    source_tool: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    fidelity: float = Field(1.0, ge=0.0, le=1.0)

class CorrelationRequest(BaseModel):
    asset_id: str
    event: SecurityEventInput
    identity: Optional[IdentitySignalInput] = None
    network: Optional[NetworkContextInput] = None
    compliance: Optional[CompliancePostureInput] = None
    threat_intel: Optional[ThreatIntelInput] = None
    jurisdictions: Optional[List[str]] = None    # ["IN", "AE"] — override tenant default

class SubScores(BaseModel):
    vulnerability: float
    endpoint: float
    identity: float
    network: float
    compliance: float
    threat_intel: float

class Multipliers(BaseModel):
    sector: float
    blast_radius: float
    kill_chain: float
    acs: float

class CDCSResponse(BaseModel):
    cdcs: float
    severity: str
    alert_triggered: bool
    sub_scores: SubScores
    multipliers: Multipliers
    dominant_domain: str
    confidence_interval: List[float]
    weights: Dict[str, float]

class IncidentSummary(BaseModel):
    incident_id: str
    incident_ref: str
    cert_in_reference: Optional[str]
    aecert_reference: Optional[str]
    chain_of_custody_hash: Optional[str]
    frameworks: List[str]
    reporting_deadlines: Dict[str, str]
    sla_breached: bool
    has_dpdp_draft: bool = False
    has_gdpr_draft: bool = False
    has_fedramp_sir: bool = False
    has_nesa_draft: bool = False
    has_sec_8k: bool = False
    has_pipeda_draft: bool = False
    has_hipaa_draft: bool = False
    has_nis2_draft: bool = False

class CorrelationResponse(BaseModel):
    asset_id: str
    event_id: str
    event_type: str
    cdcs: CDCSResponse
    incident: Optional[IncidentSummary]
    alert: bool
    processed_at: datetime

class FeedbackRequest(BaseModel):
    incident_id: str
    confirmed_true_positive: bool
    notes: Optional[str] = None
