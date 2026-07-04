"""
Splunk SIEM Connector
======================
Fetches security events via Splunk Search API (REST) + HEC for ingestion.
Provides: Security events (alerts, notable events, ES correlation searches).
Auth: Bearer token or username/password via /services/auth/login.
"""
from typing import List, Optional
from datetime import datetime, timedelta
from ..base import BaseConnector, NormalizedEvent

# Map Splunk ES urgency to MACE severity
URGENCY_MAP = {
    "critical": "CRITICAL", "high": "HIGH", "medium": "MEDIUM",
    "low": "LOW", "info": "INFO",
}

# Map Splunk source types to MACE domains
SOURCETYPE_DOMAIN = {
    "crowdstrike": "endpoint", "tenable": "endpoint", "aws": "cloud",
    "azure": "cloud", "gcp": "cloud", "cisco": "network", "palo": "network",
    "fortinet": "network", "okta": "identity", "azure:ad": "identity",
    "windows:security": "identity", "linux": "endpoint",
}


class SplunkConnector(BaseConnector):
    """
    Splunk Enterprise / Splunk Cloud REST API connector.
    Runs saved searches and fetches ES notable events.
    """

    def __init__(self, token: str, base_url: str, username: str = "", password: str = ""):
        super().__init__(base_url)
        self.token = token
        self.username = username
        self.password = password

    async def authenticate(self) -> bool:
        if self._client:
            if self.token:
                self._client.headers["Authorization"] = f"Bearer {self.token}"
                self._client.headers["Content-Type"] = "application/json"
            elif self.username and self.password:
                resp = await self._client.post(
                    f"{self.base_url}/services/auth/login",
                    data={"username": self.username, "password": self.password, "output_mode": "json"}
                )
                resp.raise_for_status()
                session_key = resp.json().get("sessionKey", "")
                self._client.headers["Authorization"] = f"Splunk {session_key}"
        return True

    async def fetch_assets(self, limit: int = 500) -> List:
        return []  # Splunk is a SIEM — not authoritative for asset inventory

    async def fetch_events(self, limit: int = 200) -> List[NormalizedEvent]:
        """Fetch ES notable events from the last 24h."""
        await self.authenticate()
        try:
            # Use Splunk search to pull ES notable events
            search_query = (
                'search index=notable earliest=-24h '
                '| eval severity=urgency '
                '| fields event_id,urgency,rule_name,dest,src,src_user,mitre_technique_id,'
                'kill_chain_phase,sourcetype,_time,risk_score'
            )
            # Start search job
            resp = await self._client.post(
                f"{self.base_url}/services/search/jobs",
                data={"search": search_query, "output_mode": "json", "count": min(limit, 100)},
                headers={"Content-Type": "application/x-www-form-urlencoded"},
            )
            resp.raise_for_status()
            sid = resp.json().get("sid")
            if not sid:
                return []

            # Poll until done (max 30s)
            import asyncio
            for _ in range(15):
                await asyncio.sleep(2)
                status = await self._get(
                    f"/services/search/jobs/{sid}",
                    params={"output_mode": "json"}
                )
                if status.get("entry", [{}])[0].get("content", {}).get("isDone"):
                    break

            # Fetch results
            results_resp = await self._get(
                f"/services/search/jobs/{sid}/results",
                params={"output_mode": "json", "count": min(limit, 100)}
            )
            events = []
            for r in results_resp.get("results", []):
                urgency = r.get("urgency", r.get("severity", "medium")).lower()
                severity = URGENCY_MAP.get(urgency, "MEDIUM")
                sourcetype = r.get("sourcetype", "")
                domain = next((v for k, v in SOURCETYPE_DOMAIN.items() if k in sourcetype.lower()), "endpoint")

                events.append(NormalizedEvent(
                    source="splunk",
                    event_id=r.get("event_id", f"splunk-{r.get('_time','')}"),
                    event_type=_clean(r.get("rule_name", "splunk_alert")),
                    severity=severity,
                    domain=domain,
                    description=r.get("rule_name", "Splunk ES Notable Event"),
                    asset_id=r.get("dest") or r.get("src"),
                    kill_chain_stage=_map_kill_chain(r.get("kill_chain_phase", "")),
                    mitre_technique_id=r.get("mitre_technique_id"),
                    source_tool="splunk",
                    fidelity=0.80,
                    occurred_at=_pdt(r.get("_time")),
                    raw=r,
                ))

            self.logger.info(f"Splunk: {len(events)} notable events fetched")
            return events
        except Exception as e:
            self.logger.error(f"Splunk fetch error: {e}")
            return []


def _clean(s: str) -> str:
    return s.lower().replace(" ", "_").replace("-", "_")[:60]


def _map_kill_chain(phase: str) -> Optional[str]:
    m = {"reconnaissance": "recon", "weaponization": "weaponize", "delivery": "delivery",
         "exploitation": "exploit", "installation": "install",
         "command and control": "c2", "actions on objectives": "actions",
         "exfiltration": "exfiltration", "impact": "impact"}
    return m.get(phase.lower().strip())


def _pdt(s) -> Optional[datetime]:
    if not s: return None
    try:
        return datetime.fromisoformat(str(s).replace("Z", "+00:00"))
    except Exception:
        return None
