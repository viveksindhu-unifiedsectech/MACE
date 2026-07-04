"""
MACE Pipeline Orchestrator
============================
Ties all stages together into one callable per-tenant pipeline.

Usage:
    pipeline = MACEPipeline(tenant_config)
    await pipeline.run_connector_sync("crowdstrike")
    await pipeline.process_event(asset_id, event, context)
"""
import logging
import asyncio
from typing import List, Optional, Dict, Any

from connectors.crowdstrike import CrowdStrikeConnector
from connectors.tenable import TenableConnector
from connectors.axonius import AxoniusConnector
from connectors.misp import MISPConnector
from connectors.splunk import SplunkConnector
from connectors.linkedin import LinkedInConnector
from connectors.generic import GenericAPIConnector
from connectors.base import NormalizedAsset, NormalizedEvent

from pipeline.processors.asset_processor import AssetProcessor, ProcessedAsset
from pipeline.processors.event_processor import EventCorrelationProcessor, CorrelationResult
from pipeline.enrichers.epss_enricher import get_epss_score, is_cisa_kev, enrich_vuln_with_epss
from pipeline.dispatchers.alert_dispatcher import AlertDispatcher

logger = logging.getLogger(__name__)


class MACEPipeline:
    """
    Per-tenant end-to-end MACE pipeline.

    Stages:
        1. Connector sync  → raw data
        2. Normalize       → NormalizedAsset / NormalizedVuln / NormalizedEvent
        3. EPSS enrich     → boost exploit scores
        4. UTAG process    → canonical merge, ACS scoring
        5. CDCS correlate  → 6-domain scoring per event
        6. UREA evidence   → regulatory evidence + drafts
        7. Dispatch        → WebSocket, Slack, PD, Teams, webhook
    """

    def __init__(self, tenant_config: Dict[str, Any]):
        self.config = tenant_config
        self.tenant_id = tenant_config["tenant_id"]
        jurisdiction = tenant_config.get("jurisdiction", "US")
        weight_profile = tenant_config.get("weight_profile", "usa_fedramp")

        # Initialize processors
        self.asset_processor = AssetProcessor(
            tenant_id=self.tenant_id,
            jurisdiction=jurisdiction,
            weight_profile=weight_profile,
        )
        self.event_processor = EventCorrelationProcessor(
            engine=self.asset_processor.engine
        )

        # Initialize dispatcher
        self.dispatcher = AlertDispatcher(
            config=tenant_config.get("dispatch_config", {})
        )

        logger.info(f"MACEPipeline ready for tenant {self.tenant_id}")

    def _build_connector(self, connector_config: Dict[str, Any]):
        """Instantiate the right connector from config."""
        ct = connector_config.get("type", "")
        base_url = connector_config.get("base_url", "")
        cid = connector_config.get("client_id", "")
        secret = connector_config.get("client_secret", "")
        api_key = connector_config.get("api_key", "")

        if ct == "crowdstrike":
            return CrowdStrikeConnector(cid, secret, base_url or "https://api.crowdstrike.com")
        elif ct == "tenable":
            return TenableConnector(cid, secret, base_url or "https://cloud.tenable.com")
        elif ct == "axonius":
            return AxoniusConnector(cid, secret, base_url)
        elif ct == "misp":
            return MISPConnector(api_key, base_url)
        elif ct == "splunk":
            return SplunkConnector(api_key, base_url)
        elif ct == "linkedin":
            return LinkedInConnector(
                client_id=cid, client_secret=secret,
                redirect_uri=connector_config.get("redirect_uri",
                    "https://app.unifiedsec.io/oauth/linkedin"),
                access_token=connector_config.get("access_token"),
                refresh_token=connector_config.get("refresh_token"),
                org_urn=connector_config.get("org_urn"))
        else:
            fm = connector_config.get("field_mapping", {})
            return GenericAPIConnector(base_url, token=api_key, field_mapping=fm)

    async def run_connector_sync(self, connector_config: Dict[str, Any]) -> Dict[str, int]:
        """
        Full connector sync cycle:
          fetch → enrich vulns → process assets → attach vulns → return counts.
        """
        connector = self._build_connector(connector_config)
        ct = connector_config.get("type", "custom")
        counts = {"assets": 0, "vulns": 0, "events": 0, "alerts": 0}

        async with connector:
            # Fetch assets
            try:
                raw_assets = await connector.fetch_assets(limit=500)
                counts["assets"] = len(raw_assets)
                processed = self.asset_processor.process_batch(raw_assets)
                logger.info(f"[{ct}] {len(processed)} assets processed")
            except Exception as e:
                logger.error(f"[{ct}] Asset fetch failed: {e}")
                processed = []

            # Fetch + enrich vulns
            try:
                raw_vulns = await connector.fetch_vulns(limit=1000)
                counts["vulns"] = len(raw_vulns)
                enriched_vulns = await self._enrich_vulns(raw_vulns)

                # Build source_id → canonical_id map for vuln attachment
                id_map = {p.source_id: p.canonical_id for p in processed}
                for vuln in enriched_vulns:
                    canonical_id = id_map.get(vuln.source_asset_id)
                    if canonical_id:
                        try:
                            from core.cdcs import VulnFinding
                            self.asset_processor.engine.ingest_vuln(
                                canonical_id,
                                VulnFinding(
                                    cve_id=vuln.cve_id, cvss_v3=vuln.cvss_v3,
                                    exploit_status=vuln.exploit_status,
                                    exposure=vuln.exposure,
                                    sla_days=1 if vuln.severity == "CRITICAL" else 7,
                                    epss_score=vuln.epss_score,
                                    patch_available=vuln.patch_available,
                                )
                            )
                        except Exception as e:
                            logger.debug(f"Vuln attach error: {e}")
            except Exception as e:
                logger.error(f"[{ct}] Vuln fetch failed: {e}")

            # Fetch + correlate events
            try:
                events = await connector.fetch_events(limit=200)
                counts["events"] = len(events)
                id_map = {p.source_id: p.canonical_id for p in processed}
                for event in events:
                    canonical_id = id_map.get(event.asset_id)
                    if not canonical_id:
                        continue
                    result = self.event_processor.correlate(canonical_id, event)
                    if result.alert:
                        counts["alerts"] += 1
                        await self._dispatch_alert(result, event)
            except Exception as e:
                logger.error(f"[{ct}] Event correlation failed: {e}")

        return counts

    async def _enrich_vulns(self, vulns):
        """Add EPSS scores + CISA KEV flags to vuln findings."""
        enriched = []
        for v in vulns:
            try:
                epss_score, epss_pct = await get_epss_score(v.cve_id)
                kev = await is_cisa_kev(v.cve_id)
                enriched.append(enrich_vuln_with_epss(v, epss_score, epss_pct, kev))
            except Exception:
                enriched.append(v)
        return enriched

    async def _dispatch_alert(self, result: CorrelationResult, event):
        """Send alert to all configured dispatch channels."""
        alert = {
            "type": "incident.new",
            "incident_ref": result.incident.get("incident_id", "INC-UNKNOWN") if result.incident else "INC-UNKNOWN",
            "cdcs": result.cdcs_score,
            "severity": result.severity,
            "asset": getattr(event, 'asset_id', ''),
            "event_type": result.event_type,
            "kill_chain_stage": getattr(event, 'kill_chain_stage', None),
            "cert_in_reference": result.cert_in_reference,
            "aecert_reference": result.aecert_reference,
            "frameworks": result.frameworks_triggered,
            "tenant_id": self.tenant_id,
            "ts": __import__('datetime').datetime.utcnow().isoformat(),
        }
        try:
            await self.dispatcher.dispatch(alert)
        except Exception as e:
            logger.error(f"Dispatch failed: {e}")

    async def process_event(self, asset_canonical_id: str, event: NormalizedEvent,
                            context: Optional[Dict] = None) -> CorrelationResult:
        """Run a single event through CDCS + UREA. Used by API endpoint."""
        ctx = context or {}
        result = self.event_processor.correlate(
            asset_canonical_id, event,
            identity=ctx.get("identity"),
            network=ctx.get("network"),
            compliance=ctx.get("compliance"),
            threat_intel=ctx.get("threat_intel"),
            jurisdictions=ctx.get("jurisdictions"),
        )
        if result.alert:
            await self._dispatch_alert(result, event)
        return result
