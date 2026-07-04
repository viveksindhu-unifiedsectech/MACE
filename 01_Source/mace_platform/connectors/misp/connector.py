"""
MISP Threat Intelligence Connector
===================================
Fetches IOCs, campaigns, threat actors from MISP.
Provides: Threat intelligence events → NormalizedEvent with IOC context.
Auth: MISP API key in X-MISP-AUTH header.
"""
from typing import List
from datetime import datetime
from ..base import BaseConnector, NormalizedEvent

MISP_THREAT_LEVEL = {1: "CRITICAL", 2: "HIGH", 3: "MEDIUM", 4: "LOW"}
MISP_CATEGORY_DOMAIN = {
    "Network activity": "network", "Payload delivery": "endpoint",
    "Malware": "endpoint", "Attribution": "threat_intel",
    "External analysis": "threat_intel", "Payload installation": "endpoint",
}


class MISPConnector(BaseConnector):
    """MISP Open Source Threat Intelligence Platform."""

    def __init__(self, api_key: str, base_url: str):
        super().__init__(base_url)
        self.api_key = api_key

    async def authenticate(self) -> bool:
        if self._client:
            self._client.headers.update({
                "Authorization": self.api_key,
                "Accept": "application/json",
                "Content-Type": "application/json",
            })
        return True

    async def fetch_assets(self, limit: int = 500) -> List:
        return []  # MISP doesn't provide asset inventory

    async def fetch_events(self, limit: int = 200) -> List[NormalizedEvent]:
        await self.authenticate()
        try:
            data = await self._post(
                "/events/restSearch",
                json={
                    "limit": min(limit, 100),
                    "published": True,
                    "threat_level_id": [1, 2],  # HIGH + CRITICAL only
                    "returnFormat": "json",
                    "includeEventTags": True,
                    "includeSightings": True,
                }
            )
            events = []
            for event in data.get("response", []):
                ev = event.get("Event", event)
                tags = [t.get("Tag", {}).get("name", "") for t in ev.get("Tag", [])]
                mitre_tags = [t for t in tags if t.startswith("misp-galaxy:mitre-attack-pattern")]

                # Extract IOC count
                attr_count = len(ev.get("Attribute", []))
                ioc_summary = f"{attr_count} IOCs"

                threat_level = int(ev.get("threat_level_id", 3))
                severity = MISP_THREAT_LEVEL.get(threat_level, "MEDIUM")

                # Build NormalizedEvent — maps into threat_intel domain
                events.append(NormalizedEvent(
                    source="misp",
                    event_id=f"misp-{ev.get('uuid', ev.get('id', ''))}",
                    event_type=_clean_event_type(ev.get("info", "threat_intel")),
                    severity=severity,
                    domain="threat_intel",
                    description=f"{ev.get('info', 'MISP Event')} ({ioc_summary})",
                    kill_chain_stage=_misp_kill_chain(tags),
                    mitre_technique_id=mitre_tags[0].split("=")[-1] if mitre_tags else None,
                    source_tool="misp",
                    fidelity=0.75,  # MISP is community intel — slightly lower fidelity
                    occurred_at=_pdt(ev.get("date")),
                    raw={
                        "event_id": ev.get("id"),
                        "uuid": ev.get("uuid"),
                        "organisation": ev.get("Org", {}).get("name"),
                        "tags": tags,
                        "attribute_count": attr_count,
                        "ioc_types": list({a.get("type") for a in ev.get("Attribute", [])}),
                        "sightings": ev.get("sighting_timestamp", 0),
                    }
                ))
            self.logger.info(f"MISP: {len(events)} threat events fetched")
            return events
        except Exception as e:
            self.logger.error(f"MISP fetch error: {e}")
            return []

    async def get_ioc_match(self, value: str, ioc_type: str = "ip-dst") -> dict:
        """Check if a specific IOC value matches MISP database."""
        await self.authenticate()
        try:
            data = await self._post("/attributes/restSearch", json={
                "value": value, "type": ioc_type,
                "returnFormat": "json", "includeContext": True,
            })
            attrs = data.get("response", {}).get("Attribute", [])
            if not attrs:
                return {"match": False, "score": 0.0}
            # Score based on threat level and sightings
            best = attrs[0]
            threat_level = int(best.get("Event", {}).get("threat_level_id", 4))
            sightings = int(best.get("Sighting", [{}])[0].get("count", 0) if best.get("Sighting") else 0)
            score = min(1.0, (5 - threat_level) * 0.2 + min(sightings * 0.05, 0.3))
            return {
                "match": True,
                "score": round(score, 3),
                "event_info": best.get("Event", {}).get("info"),
                "threat_level": MISP_THREAT_LEVEL.get(threat_level, "MEDIUM"),
                "sightings": sightings,
            }
        except Exception:
            return {"match": False, "score": 0.0}


def _clean_event_type(info: str) -> str:
    return info.lower().replace(" ", "_").replace("-", "_")[:50]


def _misp_kill_chain(tags: list) -> str:
    for t in tags:
        t_lower = t.lower()
        if "recon" in t_lower: return "recon"
        if "delivery" in t_lower: return "delivery"
        if "exploit" in t_lower: return "exploit"
        if "install" in t_lower: return "install"
        if "c2" in t_lower or "command" in t_lower: return "c2"
        if "exfil" in t_lower: return "exfiltration"
        if "impact" in t_lower: return "impact"
    return "actions"


def _pdt(s):
    if not s: return None
    try:
        return datetime.fromisoformat(str(s))
    except Exception:
        return None
