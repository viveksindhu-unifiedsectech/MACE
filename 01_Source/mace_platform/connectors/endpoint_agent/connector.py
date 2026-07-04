"""
EndpointAgentConnector — translates a MACEAgentReport JSON bundle into
NormalizedAsset + NormalizedVuln + NormalizedEvent records and dispatches
them through the existing pipeline orchestrator.
"""
from __future__ import annotations
import json
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..base import (BaseConnector, NormalizedAsset, NormalizedEvent,
                     NormalizedVuln, ConnectorHealth)


def _iso(s: Optional[str]) -> Optional[datetime]:
    if not s: return None
    try: return datetime.fromisoformat(s.replace("Z", "+00:00"))
    except Exception: return None


class EndpointAgentConnector(BaseConnector):
    """
    Consumes a MACEAgentReport bundle directly (no HTTP fetch). Used by:
      • the ingest API: POST /agent/report → connector.from_bundle(...)
      • the demo: in-memory ingestion without HTTP
    """

    def __init__(self, base_url: str = "local://endpoint-agent"):
        super().__init__(base_url)
        self._bundles: List[Dict[str, Any]] = []
        self.logger.name = "EndpointAgentConnector"

    async def authenticate(self) -> bool:
        return True

    # ── ingestion ────────────────────────────────────────────────────

    def from_bundle(self, bundle: Dict[str, Any]) -> None:
        self._bundles.append(bundle)

    async def fetch_assets(self, limit: int = 500) -> List[NormalizedAsset]:
        out: List[NormalizedAsset] = []
        for b in self._bundles[:limit]:
            hw = b.get("hardware") or {}
            sw = b.get("software") or {}
            out.append(NormalizedAsset(
                source="endpoint_agent",
                source_id=b.get("host_id") or "",
                hostname=b.get("hostname"),
                ip_address=hw.get("primary_ip"),
                mac_address=hw.get("primary_mac"),
                os=f"{sw.get('os_name','')} {sw.get('os_version','')}".strip(),
                asset_class=_class_for(b),
                serial_number=hw.get("serial_number"),
                cert_fingerprint=None,
                open_ports=sw.get("open_ports") or [],
                tags={
                    "platform": b.get("platform", ""),
                    "real_collectors": str(b.get("real_collectors", False)),
                    "agent_version": b.get("agent_version", ""),
                    "secure_boot": str(hw.get("secure_boot")),
                    "disk_encryption": str(hw.get("disk_encryption")),
                },
                last_seen=_iso(b.get("captured_at")),
                source_confidence=0.98,
                raw=b,
            ))
        return out

    async def fetch_vulns(self, limit: int = 1000) -> List[NormalizedVuln]:
        out: List[NormalizedVuln] = []
        for b in self._bundles:
            host = b.get("host_id") or ""
            for h in (b.get("vulns", {}).get("hits") or [])[:limit]:
                out.append(NormalizedVuln(
                    source="endpoint_agent",
                    source_asset_id=host,
                    cve_id=h.get("cve_id"),
                    cvss_v3=h.get("cvss_v3", 0.0),
                    severity=h.get("severity", "MEDIUM"),
                    epss_score=h.get("epss_score", 0.0),
                    exploit_status=h.get("exploit_status", "no_exploit_known"),
                    exposure="internet_facing" if "primary_ip" in (b.get("hardware") or {}) else "internal",
                    patch_available=h.get("patch_available", False),
                    affected_component=h.get("affected_component"),
                    description=h.get("description"),
                ))
        return out

    async def fetch_events(self, limit: int = 200) -> List[NormalizedEvent]:
        """
        Map all detection signals (malware, EDR, intrusion, honeytoken)
        to NormalizedEvent so they flow through CDCS event scoring.
        """
        out: List[NormalizedEvent] = []
        for b in self._bundles:
            host = b.get("host_id") or ""
            captured = _iso(b.get("captured_at"))

            for m in (b.get("malware", {}).get("findings") or []):
                out.append(NormalizedEvent(
                    source="endpoint_agent",
                    event_id=f"mal-{host}-{m.get('detector')}",
                    event_type="malware_detection",
                    severity=m.get("severity", "HIGH"),
                    domain="endpoint",
                    description=m.get("description") or m.get("family") or "",
                    asset_id=host,
                    kill_chain_stage="install",
                    source_tool="umea-malware",
                    fidelity=0.9, occurred_at=captured, raw=m,
                ))
            for e in (b.get("edr", {}).get("hits") or []):
                out.append(NormalizedEvent(
                    source="endpoint_agent",
                    event_id=f"edr-{host}-{e.get('rule_id')}",
                    event_type="behaviour_alert",
                    severity=e.get("severity", "HIGH"),
                    domain="endpoint",
                    description=f"{e.get('technique')} · {e.get('title')}",
                    asset_id=host,
                    mitre_technique_id=e.get("technique"),
                    kill_chain_stage="exploit",
                    source_tool="umea-edr",
                    fidelity=0.85, occurred_at=captured, raw=e,
                ))
            for i in (b.get("intrusion", {}).get("events") or []):
                out.append(NormalizedEvent(
                    source="endpoint_agent",
                    event_id=f"int-{host}-{i.get('kind')}-{i.get('ts')}",
                    event_type=i.get("kind"),
                    severity=i.get("severity", "MEDIUM"),
                    domain="network" if i.get("scope") == "lan" else "identity",
                    description=i.get("description"),
                    asset_id=host,
                    source_tool="umea-intrusion",
                    fidelity=0.7,
                    occurred_at=datetime.utcfromtimestamp(i.get("ts", 0)) if i.get("ts") else captured,
                    raw=i,
                ))
            for a in (b.get("honeytokens", {}).get("alerts") or []):
                out.append(NormalizedEvent(
                    source="endpoint_agent",
                    event_id=f"honey-{host}-{a.get('token')}",
                    event_type="honeytoken_triggered",
                    severity=a.get("severity", "HIGH"),
                    domain="endpoint",
                    description=a.get("detail") or "",
                    asset_id=host,
                    kill_chain_stage="actions",
                    source_tool="umea-deception",
                    fidelity=0.95, occurred_at=captured, raw=a,
                ))
        return out[:limit]

    async def health_check(self) -> ConnectorHealth:
        return ConnectorHealth(
            status="ok", message=f"{len(self._bundles)} reports cached",
            assets_available=bool(self._bundles),
            vulns_available=any(b.get("vulns", {}).get("hits") for b in self._bundles),
            events_available=True,
            latency_ms=0.0,
        )


def _class_for(bundle: Dict[str, Any]) -> str:
    plat = (bundle.get("platform") or "").lower()
    if plat == "android" or plat == "ios": return "mobile"
    if plat == "linux":  return "server" if "Server" in (bundle.get("software") or {}).get("os_name", "") else "endpoint"
    if plat == "darwin": return "endpoint"
    if plat == "windows": return "endpoint"
    return "endpoint"
