"""
UnifiedSec MACE v2 — Unified Orchestrator
==========================================
Patent: IN/2026/UNISEC/MACE-001 + PCT → US / CA / EU / UAE
Inventor: Vivek Sindhu — UnifiedSec Technologies Pvt. Ltd.

The MACEEngine is the single entry point for the full three-component pipeline:
  ingest_asset()       → UTAG: probabilistic identity reconciliation
  ingest_vuln()        → UTAG: CVE attachment with lineage inheritance
  ingest_threat_intel()→ CDCS: threat intel domain pre-loading
  ingest_event()       → CDCS: 6-domain correlation → UREA: evidence generation

UNIFIED PIPELINE (no US prior art for this three-component combination):
  [CrowdStrike telemetry] → UTAG → ACS decay → CDCS 6-domain → UREA evidence
  [Tenable scan] ────────→ UTAG → asset graph ↗
  [Axonius export] ───────→ UTAG → merge ↗
  [NDR/Darktrace] ────────→ UTAG → network ↗
"""

import time
from typing import Dict, List, Optional, Any

from .tag  import (TemporalAssetGraph, AssetRecord, AssetVertex,
                   AssetClass, Jurisdiction, DataClassification, GeoPoint)
from .cdcs import (CDCSEngine, CDCSResult, VulnFinding, SecurityEvent,
                   IdentitySignal, NetworkContext, CompliancePosture,
                   ThreatIntelSignal, EndpointPosture,
                   Severity, KillChainStage, WEIGHT_PROFILES)
from .rea  import (RegulatoryEvidenceAutomaton, EvidenceRecord,
                   RegulatoryFramework, REPORTING_SLA_HOURS, JURISDICTION_FRAMEWORKS)


class MACEEngine:
    """
    Unified MACE v2 pipeline orchestrator.
    5 jurisdiction engines, each with its own CDCSEngine weight profile.
    """

    def __init__(
        self,
        cdcs_threshold: float = 7.0,
        rea_threshold:  float = 6.5,
        match_threshold: float = 0.38,
        jurisdiction: str = "IN",
        weight_profile: str = "india_cii",
    ):
        self.jurisdiction    = jurisdiction
        self.tag             = TemporalAssetGraph(match_threshold=match_threshold)
        self.cdcs            = CDCSEngine(weight_profile=weight_profile)
        self.cdcs.ALERT_THRESHOLD = cdcs_threshold
        self.rea             = RegulatoryEvidenceAutomaton(cdcs_threshold=rea_threshold)

        # Per-asset context stores
        self._asset_vulns:        Dict[str, List[VulnFinding]]   = {}
        self._asset_events:       Dict[str, List[SecurityEvent]] = {}
        self._asset_identity:     Dict[str, IdentitySignal]      = {}
        self._asset_network:      Dict[str, NetworkContext]      = {}
        self._asset_compliance:   Dict[str, CompliancePosture]   = {}
        self._asset_threat_intel: Dict[str, ThreatIntelSignal]   = {}

        self._cdcs_results:  List[CDCSResult]   = []
        self._pipeline_log:  List[Dict]         = []

    # ── Ingest layer ─────────────────────────────────────────────────

    def ingest_asset(self, record: AssetRecord) -> AssetVertex:
        v = self.tag.ingest(record)
        self._pipeline_log.append({
            "stage": "UTAG", "action": "asset_ingested",
            "canonical_id": v.id_canonical, "source": record.source,
            "acs": round(v.acs(), 4), "quorum": v.quorum_sources,
            "shadow_it": v.shadow_it_flag, "ts": time.time(),
        })
        return v

    def ingest_vuln(self, asset_id: str, vuln: VulnFinding):
        self._asset_vulns.setdefault(asset_id, []).append(vuln)
        v = self.tag.vertices.get(asset_id)
        if v and vuln.cve_id not in v.related_vulns:
            v.related_vulns.append(vuln.cve_id)
        self._pipeline_log.append({
            "stage": "UTAG", "action": "vuln_attached",
            "asset_id": asset_id, "cve_id": vuln.cve_id,
            "cvss": vuln.cvss_v3, "ts": time.time(),
        })

    def ingest_threat_intel(self, asset_id: str, ti: ThreatIntelSignal):
        self._asset_threat_intel[asset_id] = ti
        self._pipeline_log.append({
            "stage": "UTAG", "action": "threat_intel_attached",
            "asset_id": asset_id, "ioc_score": ti.ioc_match_score,
            "campaign_match": ti.campaign_match, "ts": time.time(),
        })

    def ingest_event(
        self,
        asset_id: str,
        event: SecurityEvent,
        identity:    Optional[IdentitySignal]   = None,
        network:     Optional[NetworkContext]   = None,
        compliance:  Optional[CompliancePosture] = None,
        threat_intel: Optional[ThreatIntelSignal] = None,
        jurisdictions: Optional[List[str]] = None,
        jurisdiction: Optional[str] = None,
    ) -> Dict[str, Any]:

        self._asset_events.setdefault(asset_id, []).append(event)
        if identity:    self._asset_identity[asset_id]     = identity
        if network:     self._asset_network[asset_id]      = network
        if compliance:  self._asset_compliance[asset_id]   = compliance
        if threat_intel: self._asset_threat_intel[asset_id] = threat_intel

        # Resolve jurisdiction list
        jlist = jurisdictions
        if not jlist and jurisdiction:
            jlist = [jurisdiction]
        if not jlist:
            v = self.tag.vertices.get(asset_id)
            if v and v.jurisdiction != Jurisdiction.GLOBAL:
                jlist = [v.jurisdiction.value]
        jlist = jlist or [self.jurisdiction]

        # Asset context for CDCS + REA
        v = self.tag.vertices.get(asset_id)
        sector = "default"
        attrs  = {}
        acs_val = 1.0
        if v:
            sector = v.attributes.get("sector", "default")
            attrs  = {**v.attributes, "jurisdiction": jlist[0]}
            acs_val = v.acs()

        # ── CDCS computation (6-domain) ──────────────────────────────
        cdcs_result = self.cdcs.compute(
            asset_id=asset_id,
            sector=sector,
            acs=acs_val,
            vulns=self._asset_vulns.get(asset_id, []),
            events=self._asset_events[asset_id],
            identity=self._asset_identity.get(asset_id),
            network=self._asset_network.get(asset_id),
            compliance=self._asset_compliance.get(asset_id),
            threat_intel=self._asset_threat_intel.get(asset_id),
        )
        self._cdcs_results.append(cdcs_result)

        # ── UREA evidence generation ─────────────────────────────────
        evidence = self.rea.process_cdcs_result(
            result=cdcs_result,
            event_type=event.event_type,
            asset_attributes=attrs,
            jurisdictions=jlist,
        )

        # Build evidence dict for response
        ev_dict = None
        if evidence:
            ev_dict = {
                "incident_id":           evidence.incident_id,
                "cert_in_reference":     evidence.cert_in_reference,
                "aecert_reference":      evidence.aecert_reference,
                "chain_of_custody_hash": evidence.chain_of_custody_hash,
                "frameworks":            [f.value for f in evidence.frameworks_triggered],
                "reporting_deadlines":   evidence.reporting_deadlines,
                "sla_breached":          evidence.sla_breached,
                "has_dpdp_draft":        evidence.dpdp_notification_draft is not None,
                "has_gdpr_draft":        evidence.gdpr_notification_draft is not None,
                "has_fedramp_sir":       evidence.fedramp_sir_draft is not None,
                "has_nesa_draft":        evidence.nesa_notification_draft is not None,
                "has_sec_8k":            evidence.sec_8k_draft is not None,
                "has_pipeda_draft":      evidence.pipeda_notification_draft is not None,
            }

        result = {
            "asset_id":   asset_id,
            "event_id":   event.event_id,
            "event_type": event.event_type,
            "cdcs":       cdcs_result.to_dict(),
            "incident":   ev_dict,
            "alert":      cdcs_result.alert_triggered,
            "timestamp":  time.time(),
        }

        self._pipeline_log.append({
            "stage": "MACE", "action": "event_processed",
            "asset_id": asset_id, "cdcs": round(cdcs_result.cdcs, 4),
            "alert": cdcs_result.alert_triggered,
            "incident": evidence.incident_id if evidence else None,
            "ts": time.time(),
        })
        return result

    # ── Query layer ──────────────────────────────────────────────────

    def get_shadow_it(self):
        return self.tag.get_shadow_it()

    def get_asset(self, cid: str) -> Optional[AssetVertex]:
        return self.tag.vertices.get(cid)

    def record_lineage(self, child_id: str, event_type: str,
                        parent_id: str, meta: Optional[Dict] = None):
        self.tag.record_lineage(child_id, event_type, parent_id, meta)

    def feedback(self, asset_id: str, cdcs_result: CDCSResult,
                  confirmed_true_positive: bool):
        self.cdcs.feedback(cdcs_result, confirmed_true_positive)

    def export_cert_in_reports(self) -> str:
        reports = []
        for r in self.rea.get_open_incidents():
            if RegulatoryFramework.CERT_IN in r.frameworks_triggered:
                reports.append(r.cert_in_report_text())
        sep = "\n\n" + "="*70 + "\n\n"
        return sep.join(reports) if reports else "No open CERT-In incidents."

    def full_stats(self) -> Dict[str, Any]:
        return {
            "tag":  self.tag.summary(),
            "cdcs": self.cdcs.stats(),
            "rea":  self.rea.stats(),
            "pipeline_events": len(self._pipeline_log),
        }
