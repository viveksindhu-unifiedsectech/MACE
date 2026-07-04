"""
Event Correlation Processor — Pipeline Stage 4
================================================
Takes ProcessedAsset + NormalizedEvent and runs full CDCS + UREA pipeline.
Returns CorrelationResult with CDCS score, severity, frameworks, evidence.
"""
import logging
import sys
from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any

sys.path.insert(0, "/home/claude/UnifiedSec_MACE_v2")
logger = logging.getLogger(__name__)


@dataclass
class CorrelationResult:
    asset_canonical_id: str
    event_id: str
    event_type: str
    cdcs_score: float
    severity: str
    alert: bool
    sub_scores: Dict[str, float]
    multipliers: Dict[str, float]
    dominant_domain: str
    confidence_interval: List[float]
    incident: Optional[Dict[str, Any]] = None
    frameworks_triggered: List[str] = field(default_factory=list)
    cert_in_reference: Optional[str] = None
    aecert_reference: Optional[str] = None
    chain_of_custody_hash: Optional[str] = None
    reporting_deadlines: Dict[str, str] = field(default_factory=dict)


class EventCorrelationProcessor:
    """Runs CDCS + UREA on a (asset, event) pair. One instance per tenant."""

    def __init__(self, engine):
        self.engine = engine
        logger.info("EventCorrelationProcessor initialized")

    def correlate(self, asset_canonical_id: str, event,
                  identity=None, network=None, compliance=None,
                  threat_intel=None, jurisdictions=None) -> CorrelationResult:
        from core.cdcs import (SecurityEvent, Severity, KillChainStage,
                               IdentitySignal, NetworkContext, CompliancePosture,
                               ThreatIntelSignal)

        sev_map = {s: Severity(s) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
        kc_map = {k: KillChainStage(k) for k in [
            "recon","weaponize","delivery","exploit","install","c2",
            "actions","exfiltration","impact"
        ]}

        ev = SecurityEvent(
            event_id=event.event_id,
            event_type=event.event_type,
            severity=sev_map.get(event.severity.upper(), Severity.MEDIUM),
            domain=event.domain,
            description=event.description,
            kill_chain_stage=kc_map.get(event.kill_chain_stage or "", None),
            source_tool=event.source_tool or event.source,
            mitre_technique_id=event.mitre_technique_id or "",
            fidelity=event.fidelity,
        )

        # Build optional context objects
        id_sig, net_ctx, comp_pos, ti_sig = None, None, None, None

        if identity:
            id_sig = IdentitySignal(**{k: identity.get(k, v)
                for k, v in IdentitySignal().__dict__.items() if not k.startswith("_")})
        if network:
            net_ctx = NetworkContext(**{k: network.get(k, v)
                for k, v in NetworkContext().__dict__.items() if not k.startswith("_")})
        if compliance:
            comp_pos = CompliancePosture(**{k: compliance.get(k, v)
                for k, v in CompliancePosture().__dict__.items() if not k.startswith("_")})
        if threat_intel:
            ti_sig = ThreatIntelSignal(
                ioc_match_score=threat_intel.get("ioc_match_score", 0.0),
                campaign_match=threat_intel.get("campaign_match", False),
                threat_actor_confidence=threat_intel.get("threat_actor_confidence", 0.0),
                threat_actor_known=threat_intel.get("threat_actor_known", False),
                campaign_active=threat_intel.get("campaign_active", False),
                malware_family=threat_intel.get("malware_family", ""),
                feed_sources=threat_intel.get("feed_sources", []),
            )

        result = self.engine.ingest_event(
            asset_id=asset_canonical_id,
            event=ev,
            identity=id_sig,
            network=net_ctx,
            compliance=comp_pos,
            threat_intel=ti_sig,
            jurisdictions=jurisdictions,
        )

        cdcs_data = result["cdcs"]
        inc = result.get("incident")

        return CorrelationResult(
            asset_canonical_id=asset_canonical_id,
            event_id=event.event_id,
            event_type=event.event_type,
            cdcs_score=cdcs_data["cdcs"],
            severity=cdcs_data["severity"],
            alert=result["alert"],
            sub_scores=cdcs_data["sub_scores"],
            multipliers=cdcs_data["multipliers"],
            dominant_domain=cdcs_data["dominant_domain"],
            confidence_interval=cdcs_data["confidence_interval"],
            incident=inc,
            frameworks_triggered=inc.get("frameworks", []) if inc else [],
            cert_in_reference=inc.get("cert_in_reference") if inc else None,
            aecert_reference=inc.get("aecert_reference") if inc else None,
            chain_of_custody_hash=inc.get("chain_of_custody_hash") if inc else None,
            reporting_deadlines=inc.get("reporting_deadlines", {}) if inc else {},
        )
