"""
CrowdStrike Falcon Connector
============================
Provides: Assets (Devices API) + Vulns (Spotlight) + Events (Detections)
Auth: OAuth2 client credentials — US-1, EU-1, GovCloud supported.
"""
from typing import List, Optional
from datetime import datetime
from ..base import BaseConnector, NormalizedAsset, NormalizedVuln, NormalizedEvent

ASSET_CLASS_MAP = {
    "Workstation": "endpoint", "Server": "server", "Server (virtual)": "server",
    "Mobile": "mobile", "IoT": "iot_device", "Network device": "network_device",
    "Cloud VM": "cloud_vm", "Container": "container",
}
SEVERITY_MAP = {"critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM", "low": "LOW", "none": "INFO"}
KILL_CHAIN_MAP = {
    "Reconnaissance": "recon", "Exploit": "exploit", "Weaponization": "weaponize",
    "Delivery": "delivery", "Installation": "install",
    "Command & Control": "c2", "Actions on Objectives": "actions",
}


class CrowdStrikeConnector(BaseConnector):

    def __init__(self, client_id: str, client_secret: str,
                 base_url: str = "https://api.crowdstrike.com"):
        super().__init__(base_url)
        self.client_id = client_id
        self.client_secret = client_secret
        self._token: Optional[str] = None
        self._expires: float = 0.0

    async def authenticate(self) -> bool:
        import time
        if self._token and time.time() < self._expires - 60:
            return True
        resp = await self._client.post(
            f"{self.base_url}/oauth2/token",
            data={"client_id": self.client_id, "client_secret": self.client_secret,
                  "grant_type": "client_credentials"},
        )
        resp.raise_for_status()
        d = resp.json()
        self._token = d.get("access_token")
        self._expires = time.time() + d.get("expires_in", 1800)
        if self._client:
            self._client.headers["Authorization"] = f"Bearer {self._token}"
        return bool(self._token)

    async def fetch_assets(self, limit: int = 500) -> List[NormalizedAsset]:
        await self.authenticate()
        ids = (await self._get(
            "/devices/queries/devices/v1",
            params={"limit": min(limit, 500), "sort": "last_seen.desc"}
        )).get("resources", [])
        if not ids:
            return []
        assets = []
        for i in range(0, len(ids), 100):
            for d in (await self._post(
                "/devices/entities/devices/v2", json={"ids": ids[i:i+100]}
            )).get("resources", []):
                ac = ASSET_CLASS_MAP.get(d.get("product_type_desc", ""), "endpoint")
                cloud_id = None
                if d.get("service_provider", "") in ("AWS_EC2", "GCP_COMPUTE", "AZURE_VM"):
                    cloud_id = d.get("instance_id")
                    ac = "cloud_vm"
                assets.append(NormalizedAsset(
                    source="crowdstrike",
                    source_id=d.get("device_id", ""),
                    hostname=d.get("hostname") or d.get("computer_name"),
                    ip_address=d.get("local_ip"),
                    mac_address=d.get("mac_address"),
                    os=d.get("os_version"),
                    asset_class=ac,
                    cloud_instance_id=cloud_id,
                    cloud_account_id=d.get("service_provider_account_id"),
                    tags={
                        "cs_status": d.get("status", ""),
                        "cs_platform": d.get("platform_name", ""),
                        "cs_agent": d.get("agent_version", ""),
                    },
                    source_confidence=0.95,
                    last_seen=_pdt(d.get("last_seen")),
                    raw=d,
                ))
        self.logger.info(f"CrowdStrike: {len(assets)} devices fetched")
        return assets

    async def fetch_vulns(self, limit: int = 1000) -> List[NormalizedVuln]:
        await self.authenticate()
        try:
            ids = (await self._get(
                "/spotlight/queries/vulnerabilities/v1",
                params={"limit": min(limit, 400), "filter": "status:'open'+cve.base_score:>='7.0'"}
            )).get("resources", [])
            if not ids:
                return []
            vulns = []
            for v in (await self._post(
                "/spotlight/entities/vulnerabilities/GET/v2", json={"ids": ids}
            )).get("resources", []):
                cve = v.get("cve", {})
                cid = cve.get("id")
                if not cid:
                    continue
                vulns.append(NormalizedVuln(
                    source="crowdstrike",
                    source_asset_id=v.get("aid", ""),
                    cve_id=cid,
                    cvss_v3=float(cve.get("base_score", 0)),
                    severity=SEVERITY_MAP.get(cve.get("severity", "").lower(), "MEDIUM"),
                    epss_score=float(cve.get("epss_score", 0)),
                    exploit_status="exploit_public" if cve.get("exploit_status", 0) > 1 else "no_exploit_known",
                    patch_available=cve.get("remediation_level") not in ("unavailable", "workaround"),
                    affected_component=v.get("app", {}).get("product_name"),
                ))
            self.logger.info(f"CrowdStrike Spotlight: {len(vulns)} vulns fetched")
            return vulns
        except Exception as e:
            self.logger.error(f"Spotlight error: {e}")
            return []

    async def fetch_events(self, limit: int = 200) -> List[NormalizedEvent]:
        await self.authenticate()
        try:
            ids = (await self._get(
                "/detects/queries/detects/v1",
                params={"limit": min(limit, 100), "sort": "last_behavior.desc",
                        "filter": "status:!='false_positive'"}
            )).get("resources", [])
            if not ids:
                return []
            events = []
            for det in (await self._post(
                "/detects/entities/summaries/GET/v1", json={"ids": ids}
            )).get("resources", []):
                beh = (det.get("behaviors") or [{}])[0]
                sev_n = det.get("max_severity", 50)
                sev = ("CRITICAL" if sev_n >= 90 else "HIGH" if sev_n >= 70
                       else "MEDIUM" if sev_n >= 40 else "LOW")
                events.append(NormalizedEvent(
                    source="crowdstrike",
                    event_id=det.get("detection_id", ""),
                    event_type=beh.get("tactic", "malware_detection").replace(" ", "_").lower(),
                    severity=sev,
                    domain="endpoint",
                    description=beh.get("display_name", det.get("detection_id", "")),
                    asset_id=det.get("device", {}).get("device_id"),
                    kill_chain_stage=KILL_CHAIN_MAP.get(beh.get("tactic", ""), None),
                    mitre_technique_id=beh.get("technique_id"),
                    source_tool="crowdstrike",
                    fidelity=0.92,
                    occurred_at=_pdt(det.get("last_behavior")),
                    raw=det,
                ))
            self.logger.info(f"CrowdStrike: {len(events)} detections fetched")
            return events
        except Exception as e:
            self.logger.error(f"Detection error: {e}")
            return []


def _pdt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None
