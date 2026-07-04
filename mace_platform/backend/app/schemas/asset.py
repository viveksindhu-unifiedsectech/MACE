from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime
from app.models.asset import AssetClass, AssetStatus


class AssetIngestRequest(BaseModel):
    source: str = Field(..., description="Data source name: crowdstrike | tenable | axonius | manual")
    source_id: str
    hostname: Optional[str] = None
    mac_address: Optional[str] = None
    ip_address: Optional[str] = None
    cert_fingerprint: Optional[str] = None
    cloud_instance_id: Optional[str] = None
    cloud_account_id: Optional[str] = None
    serial_number: Optional[str] = None
    os: Optional[str] = None
    owner: Optional[str] = None
    owner_email: Optional[str] = None
    sector: Optional[str] = None
    open_ports: List[int] = []
    asset_class: Optional[AssetClass] = None
    jurisdiction: str = "US"
    data_classification: str = "internal"
    is_internet_facing: bool = False
    is_critical_infra: bool = False
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    geo_city: Optional[str] = None
    geo_country: Optional[str] = None
    tags: Dict[str, str] = {}
    raw_attributes: Dict[str, Any] = {}
    source_confidence: float = Field(1.0, ge=0.0, le=1.0)

class AssetIngestResponse(BaseModel):
    canonical_id: str
    asset_id: str
    status: AssetStatus
    asset_class: AssetClass
    acs_score: float
    quorum_sources: int
    shadow_it_flag: bool
    geo_velocity_flag: bool
    merged: bool
    message: str

class AssetResponse(BaseModel):
    id: str
    canonical_id: str
    tenant_id: str
    hostname: Optional[str]
    ip_address: Optional[str]
    mac_address: Optional[str]
    cloud_instance_id: Optional[str]
    asset_class: AssetClass
    status: AssetStatus
    os: Optional[str]
    owner: Optional[str]
    sector: Optional[str]
    jurisdiction: str
    data_classification: str
    is_internet_facing: bool
    is_critical_infra: bool
    acs_score: float
    entropy_score: float
    cdcs_score: Optional[float]
    risk_level: Optional[str]
    source_set: List[str]
    quorum_sources: int
    shadow_it_flag: bool
    geo_velocity_flag: bool
    max_geo_velocity_kmh: float
    critical_vuln_count: int
    high_vuln_count: int
    open_cves: List[str]
    tags: Dict[str, str]
    first_seen_at: datetime
    last_seen_at: datetime
    created_at: datetime

    model_config = {"from_attributes": True}

class AssetListResponse(BaseModel):
    items: List[AssetResponse]
    total: int
    page: int
    page_size: int
    has_next: bool

class VulnAttachRequest(BaseModel):
    cve_id: str
    cvss_v3: float = Field(..., ge=0.0, le=10.0)
    exploit_status: str = "no_exploit_known"  # exploit_public | exploit_poc | no_exploit_known
    exposure: str = "internal"                 # internet_facing | internal | air_gapped
    sla_days: int = 30
    epss_score: float = Field(0.0, ge=0.0, le=1.0)
    affected_component: Optional[str] = None
    patch_available: bool = False
    discovered_by: Optional[str] = None
