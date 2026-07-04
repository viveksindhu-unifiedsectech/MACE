"""
Tenable.io Connector
====================
Provides: Assets (Assets API) + Vulns (Workbench Vulnerabilities API)
Auth: API access key + secret key in X-ApiKeys header.
"""
from typing import List, Optional
from datetime import datetime
from ..base import BaseConnector, NormalizedAsset, NormalizedVuln

SEVERITY_MAP = {4: "CRITICAL", 3: "HIGH", 2: "MEDIUM", 1: "LOW", 0: "INFO"}


class TenableConnector(BaseConnector):

    def __init__(self, access_key: str, secret_key: str,
                 base_url: str = "https://cloud.tenable.com"):
        super().__init__(base_url)
        self.access_key = access_key
        self.secret_key = secret_key

    async def authenticate(self) -> bool:
        if self._client:
            self._client.headers["X-ApiKeys"] = (
                f"accessKey={self.access_key};secretKey={self.secret_key}"
            )
        return True

    async def fetch_assets(self, limit: int = 500) -> List[NormalizedAsset]:
        await self.authenticate()
        data = await self._get("/assets", params={"limit": min(limit, 1000)})
        assets = []
        for a in data.get("assets", []):
            assets.append(NormalizedAsset(
                source="tenable",
                source_id=a.get("id", ""),
                hostname=_first(a.get("fqdn")),
                ip_address=_first(a.get("ipv4")) or _first(a.get("ipv6")),
                mac_address=_first(a.get("mac_address")),
                os=_first(a.get("operating_system")),
                asset_class=_tenable_asset_class(a),
                is_internet_facing=False,
                source_confidence=0.88,
                tags={
                    "tn_sources": ",".join(a.get("sources", [])),
                    "tn_network": a.get("network_id", ""),
                },
                last_seen=_pdt(_first(a.get("last_seen"))),
                raw=a,
            ))
        self.logger.info(f"Tenable: {len(assets)} assets fetched")
        return assets

    async def fetch_vulns(self, limit: int = 1000) -> List[NormalizedVuln]:
        await self.authenticate()
        try:
            data = await self._get(
                "/workbenches/vulnerabilities",
                params={"limit": min(limit, 5000), "severity": "critical,high,medium",
                        "filter.0.filter": "plugin.attributes.solution", "filter.0.quality": "set"}
            )
            vulns = []
            for v in data.get("vulnerabilities", []):
                pi = v.get("plugin_id", "")
                cve_ids = v.get("cve", [])
                if not cve_ids:
                    continue
                cvss = float(v.get("cvss3_base_score") or v.get("cvss_base_score") or 0)
                sev_num = v.get("severity", 2)
                sev = SEVERITY_MAP.get(sev_num, "MEDIUM")
                for cve_id in cve_ids[:3]:  # max 3 CVEs per finding
                    vulns.append(NormalizedVuln(
                        source="tenable",
                        source_asset_id=v.get("asset", {}).get("id", ""),
                        cve_id=cve_id,
                        cvss_v3=cvss,
                        severity=sev,
                        epss_score=float(v.get("epss_score", 0)),
                        exploit_status=(
                            "exploit_public" if v.get("exploit_available")
                            else "no_exploit_known"
                        ),
                        patch_available=bool(v.get("patch_available")),
                        affected_component=v.get("plugin_name"),
                        description=v.get("synopsis", "")[:400],
                        plugin_id=f"tn-{pi}",
                    ))
            self.logger.info(f"Tenable: {len(vulns)} vuln findings fetched")
            return vulns
        except Exception as e:
            self.logger.error(f"Tenable vuln error: {e}")
            return []


def _first(lst):
    if lst and isinstance(lst, list):
        return lst[0]
    return lst or None


def _tenable_asset_class(a: dict) -> str:
    os_str = (_first(a.get("operating_system")) or "").lower()
    if "windows server" in os_str or "linux" in os_str:
        return "server"
    if "windows" in os_str or "macos" in os_str:
        return "endpoint"
    if a.get("aws_ec2_instance_id") or a.get("azure_vm_id") or a.get("gcp_instance_id"):
        return "cloud_vm"
    return "endpoint"


def _pdt(s: Optional[str]) -> Optional[datetime]:
    if not s:
        return None
    try:
        return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception:
        return None
