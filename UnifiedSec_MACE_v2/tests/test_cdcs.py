"""Tests for the CDCS (Cross-Domain Correlation Score) engine."""
import time

import pytest

from core.cdcs import (
    ALERT_THRESHOLD,
    CDCSEngine,
    CompliancePosture,
    IdentitySignal,
    KillChainStage,
    NetworkContext,
    SECTOR_MULTIPLIERS,
    SecurityEvent,
    Severity,
    ThreatIntelSignal,
    VulnFinding,
    WEIGHT_PROFILES,
    compute_compliance_score,
    compute_endpoint_score,
    compute_identity_score,
    compute_network_score,
    compute_threat_intel_score,
    compute_vulnerability_score,
)


# ────────────────────────────────────────────────────────────────────────────
# Sub-score functions
# ────────────────────────────────────────────────────────────────────────────

def test_vulnerability_score_zero_when_no_vulns():
    score, details = compute_vulnerability_score([])
    assert score == 0.0
    assert details == {}


def test_vulnerability_score_high_for_critical_internet_facing_kev():
    v = VulnFinding(
        cve_id="CVE-2024-3400",
        cvss_v3=10.0,
        exploit_status="exploit_public",
        exposure="internet_facing",
        sla_days=-1,  # breached
        epss_score=0.97,
    )
    score, details = compute_vulnerability_score([v])
    assert 0.8 <= score <= 1.0
    assert details["count"] == 1
    assert details["vulns"][0]["cve_id"] == "CVE-2024-3400"


def test_vulnerability_score_low_for_air_gapped_low_severity():
    v = VulnFinding(
        cve_id="CVE-2024-0001",
        cvss_v3=3.5,
        exploit_status="no_exploit_known",
        exposure="air_gapped",
        sla_days=30,
    )
    score, _ = compute_vulnerability_score([v])
    assert score < 0.20


def test_identity_score_zero_when_signal_missing():
    assert compute_identity_score(None) == 0.0


def test_identity_score_capped_at_one():
    sig = IdentitySignal(
        impossible_travel=True,
        privilege_escalation=True,
        credential_stuffing_indicator=True,
        golden_ticket_indicator=True,
        pass_the_hash_indicator=True,
    )
    assert compute_identity_score(sig) == 1.0


def test_network_score_lateral_hops_increase_score():
    low = NetworkContext(lateral_movement_score=0.2, lateral_hop_count=0)
    high = NetworkContext(lateral_movement_score=0.2, lateral_hop_count=4)
    assert compute_network_score(high) > compute_network_score(low)


def test_compliance_score_zero_for_well_postured_host():
    ok = CompliancePosture(stig_pass_count=100, stig_fail_count=0, edr_coverage=True,
                            mfa_enrolled=True, endpoint_encryption=True,
                            privileged_access_managed=True, last_scan_hours_ago=2,
                            missing_patches=0)
    assert compute_compliance_score(ok) < 0.05


def test_compliance_score_high_for_broken_host():
    bad = CompliancePosture(stig_pass_count=10, stig_fail_count=90,
                              edr_coverage=False, mfa_enrolled=False,
                              endpoint_encryption=False, last_scan_hours_ago=200,
                              missing_patches=20)
    assert compute_compliance_score(bad) > 0.9


def test_threat_intel_score_zero_when_no_match():
    assert compute_threat_intel_score(None) == 0.0
    assert compute_threat_intel_score(ThreatIntelSignal()) == 0.0


def test_threat_intel_score_capped_at_one():
    ti = ThreatIntelSignal(
        ioc_match_score=1.0, campaign_match=True, threat_actor_known=True,
        campaign_active=True, threat_actor_confidence=1.0, malware_family="X",
        feed_sources=["a", "b", "c"],
    )
    assert compute_threat_intel_score(ti) == 1.0


# ────────────────────────────────────────────────────────────────────────────
# Engine wiring
# ────────────────────────────────────────────────────────────────────────────

def test_engine_default_weights_sum_to_one():
    engine = CDCSEngine(weight_profile="usa_fedramp")
    w = engine.weights
    total = w.alpha + w.beta + w.gamma + w.delta + w.epsilon + w.zeta
    assert abs(total - 1.0) < 1e-6


def test_all_weight_profiles_sum_to_one():
    for profile_name in WEIGHT_PROFILES:
        engine = CDCSEngine(weight_profile=profile_name)
        w = engine.weights
        total = w.alpha + w.beta + w.gamma + w.delta + w.epsilon + w.zeta
        assert abs(total - 1.0) < 1e-6, f"{profile_name} weights don't sum to 1.0"


def test_quiet_asset_does_not_fire_alert():
    engine = CDCSEngine(weight_profile="usa_fedramp")
    result = engine.compute(asset_id="quiet-1", sector="default", acs=1.0)
    assert result.cdcs < ALERT_THRESHOLD
    assert not result.alert_triggered


def test_critical_event_fires_alert():
    engine = CDCSEngine(weight_profile="india_cii")
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
    comp = CompliancePosture(
        stig_pass_count=10, stig_fail_count=90,
        missing_patches=15, edr_coverage=False, mfa_enrolled=False,
    )
    ti = ThreatIntelSignal(
        ioc_match_score=0.92, campaign_match=True,
        threat_actor_confidence=0.95, campaign_active=True,
        malware_family="APT41",
    )
    result = engine.compute(
        asset_id="srv-bom-1", sector="Banking", acs=1.0,
        vulns=[vuln], events=[ev],
        identity=ident, network=net, compliance=comp, threat_intel=ti,
    )
    assert result.cdcs >= ALERT_THRESHOLD
    assert result.alert_triggered
    assert result.severity_label() in ("HIGH", "CRITICAL")


def test_kill_chain_multiplier_is_higher_for_later_stages():
    engine = CDCSEngine(weight_profile="usa_fedramp")
    base_kwargs = dict(
        asset_id="x", sector="default", acs=1.0,
        identity=IdentitySignal(privilege_escalation=True,
                                credential_stuffing_indicator=True),
    )
    recon = engine.compute(events=[SecurityEvent(
        event_id="r", event_type="probe", severity=Severity.MEDIUM,
        domain="network", description="", kill_chain_stage=KillChainStage.RECON,
    )], **base_kwargs)
    exfil = engine.compute(events=[SecurityEvent(
        event_id="e", event_type="exfil", severity=Severity.MEDIUM,
        domain="network", description="",
        kill_chain_stage=KillChainStage.EXFILTRATION,
    )], **base_kwargs)
    assert exfil.kill_chain_multiplier > recon.kill_chain_multiplier
    assert exfil.cdcs >= recon.cdcs


def test_banking_sector_boosts_score():
    engine = CDCSEngine(weight_profile="india_cii")
    ident = IdentitySignal(credential_stuffing_indicator=True,
                           privilege_escalation=True)
    default_run = engine.compute(asset_id="x", sector="default",
                                  acs=1.0, identity=ident)
    bank_run = engine.compute(asset_id="x", sector="Banking",
                               acs=1.0, identity=ident)
    assert bank_run.sector_multiplier > default_run.sector_multiplier
    assert bank_run.cdcs > default_run.cdcs


def test_feedback_increases_dominant_weight_on_true_positive():
    engine = CDCSEngine(weight_profile="usa_fedramp")
    ti = ThreatIntelSignal(ioc_match_score=0.95, campaign_match=True,
                            threat_actor_known=True)
    result = engine.compute(asset_id="x", sector="default", acs=1.0,
                              threat_intel=ti)
    before = engine.weights.zeta
    if result.dominant_domain == "threat_intel":
        engine.feedback(result, confirmed_true_positive=True)
        assert engine.weights.zeta > before


def test_engine_stats_track_alerts_and_feedback():
    engine = CDCSEngine(weight_profile="usa_fedramp")
    engine.compute(asset_id="a", sector="default", acs=1.0)
    stats = engine.stats()
    assert stats["total_computed"] == 1
    assert "weights" in stats
    assert stats["threshold"] == ALERT_THRESHOLD
