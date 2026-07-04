"""Tests for the UREA (Universal Regulatory Evidence Automaton)."""
import time

import pytest

from core.cdcs import (
    CDCSEngine,
    IdentitySignal,
    KillChainStage,
    NetworkContext,
    SecurityEvent,
    Severity,
    VulnFinding,
)
from core.rea import (
    EvidenceRecord,
    JURISDICTION_FRAMEWORKS,
    REPORTING_SLA_HOURS,
    RegulatoryEvidenceAutomaton,
    RegulatoryFramework,
)


# ────────────────────────────────────────────────────────────────────────────
# Helpers — build a CDCS result that always crosses the UREA threshold
# ────────────────────────────────────────────────────────────────────────────

def _critical_result(jurisdiction_profile: str = "india_cii"):
    engine = CDCSEngine(weight_profile=jurisdiction_profile)
    vuln = VulnFinding(
        cve_id="CVE-2024-3400", cvss_v3=10.0,
        exploit_status="exploit_public", exposure="internet_facing",
        sla_days=-1, epss_score=0.97,
    )
    ev = SecurityEvent(
        event_id="E1", event_type="data_breach", severity=Severity.CRITICAL,
        domain="endpoint", description="exfil",
        kill_chain_stage=KillChainStage.EXFILTRATION, fidelity=0.95,
    )
    ident = IdentitySignal(
        impossible_travel=True, privilege_escalation=True,
        credential_stuffing_indicator=True, golden_ticket_indicator=True,
    )
    net = NetworkContext(
        lateral_movement_score=0.92, c2_beacon_score=0.88,
        data_exfil_indicator=0.95, lateral_hop_count=4,
        ransomware_c2_ioc=True, bytes_exfiltrated_mb=250.0,
    )
    return engine.compute(
        asset_id="srv-001", sector="Banking", acs=1.0,
        vulns=[vuln], events=[ev], identity=ident, network=net,
    )


# ────────────────────────────────────────────────────────────────────────────
# Thresholding
# ────────────────────────────────────────────────────────────────────────────

def test_below_threshold_returns_none():
    rea = RegulatoryEvidenceAutomaton(cdcs_threshold=6.5)
    engine = CDCSEngine(weight_profile="usa_fedramp")
    quiet = engine.compute(asset_id="x", sector="default", acs=1.0)
    evidence = rea.process_cdcs_result(quiet, event_type="login_success",
                                         jurisdictions=["US"])
    assert evidence is None


# ────────────────────────────────────────────────────────────────────────────
# Jurisdiction → framework selection
# ────────────────────────────────────────────────────────────────────────────

def test_india_data_breach_triggers_cert_in():
    rea = RegulatoryEvidenceAutomaton()
    result = _critical_result("india_cii")
    evidence = rea.process_cdcs_result(
        result, event_type="data_breach", jurisdictions=["IN"],
        asset_attributes={"hostname": "h1", "sector": "Banking", "owner": "HDFC"},
    )
    assert evidence is not None
    assert RegulatoryFramework.CERT_IN in evidence.frameworks_triggered
    assert evidence.cert_in_reference is not None
    assert evidence.cert_in_reference.startswith("CERTIN/")


def test_uae_data_breach_triggers_aecert():
    rea = RegulatoryEvidenceAutomaton()
    result = _critical_result("uae_nesa")
    evidence = rea.process_cdcs_result(
        result, event_type="data_breach", jurisdictions=["AE"],
        asset_attributes={"hostname": "h1"},
    )
    assert evidence is not None
    assert evidence.aecert_reference is not None
    assert evidence.aecert_reference.startswith("AECERT/")


def test_eu_data_breach_generates_gdpr_draft():
    rea = RegulatoryEvidenceAutomaton()
    result = _critical_result("eu_gdpr")
    evidence = rea.process_cdcs_result(
        result, event_type="data_breach", jurisdictions=["EU"],
    )
    assert evidence is not None
    assert RegulatoryFramework.GDPR in evidence.frameworks_triggered
    assert evidence.gdpr_notification_draft is not None
    assert "GDPR" in evidence.gdpr_notification_draft


def test_us_data_breach_generates_fedramp_sir():
    rea = RegulatoryEvidenceAutomaton()
    result = _critical_result("usa_fedramp")
    evidence = rea.process_cdcs_result(
        result, event_type="data_breach", jurisdictions=["US"],
        asset_attributes={"hostname": "vpc-1", "owner": "Federal CSP"},
    )
    assert evidence is not None
    assert RegulatoryFramework.FEDRAMP in evidence.frameworks_triggered
    assert evidence.fedramp_sir_draft is not None
    assert "FEDRAMP" in evidence.fedramp_sir_draft.upper()


# ────────────────────────────────────────────────────────────────────────────
# Chain of custody and deadlines
# ────────────────────────────────────────────────────────────────────────────

def test_chain_of_custody_hash_is_sha256_hex():
    rea = RegulatoryEvidenceAutomaton()
    result = _critical_result("india_cii")
    evidence = rea.process_cdcs_result(
        result, event_type="data_breach", jurisdictions=["IN"],
    )
    assert evidence.chain_of_custody_hash is not None
    assert len(evidence.chain_of_custody_hash) == 64
    int(evidence.chain_of_custody_hash, 16)  # must be valid hex


def test_two_incidents_have_different_hashes():
    rea = RegulatoryEvidenceAutomaton()
    a = rea.process_cdcs_result(_critical_result(), event_type="data_breach",
                                  jurisdictions=["IN"])
    b = rea.process_cdcs_result(_critical_result(), event_type="ransomware",
                                  jurisdictions=["IN"])
    assert a.chain_of_custody_hash != b.chain_of_custody_hash


def test_reporting_deadlines_are_iso8601():
    rea = RegulatoryEvidenceAutomaton()
    result = _critical_result()
    evidence = rea.process_cdcs_result(
        result, event_type="data_breach", jurisdictions=["IN"],
    )
    assert evidence.reporting_deadlines  # non-empty
    sample = next(iter(evidence.reporting_deadlines.values()))
    # ISO 8601 trailing Z format
    assert sample.endswith("Z")
    assert "T" in sample


def test_cert_in_sla_is_six_hours():
    assert REPORTING_SLA_HOURS[RegulatoryFramework.CERT_IN] == 6.0


def test_open_incidents_tracked():
    rea = RegulatoryEvidenceAutomaton()
    assert rea.get_open_incidents() == []
    rea.process_cdcs_result(_critical_result(), event_type="data_breach",
                              jurisdictions=["IN"])
    assert len(rea.get_open_incidents()) == 1


# ────────────────────────────────────────────────────────────────────────────
# Coverage matrix
# ────────────────────────────────────────────────────────────────────────────

def test_jurisdiction_coverage_includes_five_regions():
    expected = {"IN", "US", "EU", "CA", "AE"}
    assert expected.issubset(JURISDICTION_FRAMEWORKS.keys())


def test_multi_jurisdiction_triggers_frameworks_from_both():
    rea = RegulatoryEvidenceAutomaton()
    result = _critical_result()
    evidence = rea.process_cdcs_result(
        result, event_type="data_breach", jurisdictions=["IN", "EU"],
    )
    frameworks = set(evidence.frameworks_triggered)
    # CERT-In (IN) and GDPR (EU) should both be in there
    assert RegulatoryFramework.CERT_IN in frameworks
    assert RegulatoryFramework.GDPR in frameworks
