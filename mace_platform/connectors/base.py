"""Base connector interface — all connectors implement this."""
from dataclasses import dataclass, field
from typing import Optional, List
from datetime import datetime
from abc import ABC, abstractmethod
import httpx
import logging

logger = logging.getLogger(__name__)


@dataclass
class NormalizedAsset:
    """Connector-agnostic asset record — maps into MACE AssetRecord."""
    source: str
    source_id: str
    hostname: Optional[str] = None
    ip_address: Optional[str] = None
    mac_address: Optional[str] = None
    os: Optional[str] = None
    asset_class: str = "endpoint"
    owner: Optional[str] = None
    owner_email: Optional[str] = None
    sector: Optional[str] = None
    cloud_instance_id: Optional[str] = None
    cloud_account_id: Optional[str] = None
    serial_number: Optional[str] = None
    cert_fingerprint: Optional[str] = None
    is_internet_facing: bool = False
    is_critical_infra: bool = False
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    geo_city: Optional[str] = None
    geo_country: Optional[str] = None
    open_ports: List[int] = field(default_factory=list)
    tags: dict = field(default_factory=dict)
    raw: dict = field(default_factory=dict)
    source_confidence: float = 0.90
    last_seen: Optional[datetime] = None


@dataclass
class NormalizedVuln:
    """Connector-agnostic vulnerability finding."""
    source: str
    source_asset_id: str
    cve_id: str
    cvss_v3: float
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    epss_score: float = 0.0
    exploit_status: str = "no_exploit_known"
    exposure: str = "internal"
    patch_available: bool = False
    affected_component: Optional[str] = None
    description: Optional[str] = None
    plugin_id: Optional[str] = None


@dataclass
class NormalizedEvent:
    """Connector-agnostic security event."""
    source: str
    event_id: str
    event_type: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW | INFO
    domain: str              # endpoint | network | identity | cloud
    description: str
    asset_id: Optional[str] = None
    kill_chain_stage: Optional[str] = None
    mitre_technique_id: Optional[str] = None
    source_tool: Optional[str] = None
    fidelity: float = 1.0
    occurred_at: Optional[datetime] = None
    raw: dict = field(default_factory=dict)


@dataclass
class ConnectorHealth:
    status: str              # ok | error | degraded
    message: str
    last_check: datetime = field(default_factory=datetime.utcnow)
    assets_available: bool = False
    vulns_available: bool = False
    events_available: bool = False
    latency_ms: float = 0.0


class BaseConnector(ABC):
    """All connectors inherit from this. Provides shared HTTP client + retry logic."""

    def __init__(self, base_url: str, timeout: int = 30, max_retries: int = 3):
        self.base_url = base_url.rstrip('/')
        self.timeout = timeout
        self.max_retries = max_retries
        self._client: Optional[httpx.AsyncClient] = None
        self.logger = logging.getLogger(self.__class__.__name__)

    async def __aenter__(self):
        self._client = httpx.AsyncClient(timeout=self.timeout, follow_redirects=True)
        return self

    async def __aexit__(self, *_):
        if self._client:
            await self._client.aclose()

    async def _get(self, path: str, **kwargs) -> dict:
        """GET with retry + error logging."""
        url = f"{self.base_url}{path}"
        for attempt in range(self.max_retries):
            try:
                resp = await self._client.get(url, **kwargs)
                resp.raise_for_status()
                return resp.json()
            except httpx.HTTPStatusError as e:
                self.logger.error(f"HTTP {e.response.status_code} on GET {path}: {e.response.text[:200]}")
                if e.response.status_code in (401, 403):
                    raise   # Don't retry auth errors
                if attempt == self.max_retries - 1:
                    raise
            except (httpx.ConnectError, httpx.TimeoutException) as e:
                self.logger.warning(f"Request attempt {attempt+1} failed: {e}")
                if attempt == self.max_retries - 1:
                    raise
        return {}

    async def _post(self, path: str, **kwargs) -> dict:
        url = f"{self.base_url}{path}"
        resp = await self._client.post(url, **kwargs)
        resp.raise_for_status()
        return resp.json()

    @abstractmethod
    async def authenticate(self) -> bool:
        """Authenticate and store credentials for subsequent calls."""
        ...

    @abstractmethod
    async def fetch_assets(self, limit: int = 500) -> List[NormalizedAsset]:
        ...

    async def fetch_vulns(self, limit: int = 1000) -> List[NormalizedVuln]:
        return []

    async def fetch_events(self, limit: int = 1000) -> List[NormalizedEvent]:
        return []

    async def health_check(self) -> ConnectorHealth:
        try:
            import time
            start = time.perf_counter()
            await self.authenticate()
            assets = await self.fetch_assets(limit=1)
            ms = (time.perf_counter() - start) * 1000
            return ConnectorHealth(
                status="ok", message="Connector healthy",
                assets_available=len(assets) > 0,
                latency_ms=round(ms, 1)
            )
        except Exception as e:
            return ConnectorHealth(status="error", message=str(e)[:200])
