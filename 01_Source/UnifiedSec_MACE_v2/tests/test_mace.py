"""End-to-end pipeline tests — UTAG → CDCS → UREA wired through MACEEngine."""
import pytest

from core.cdcs import (
    IdentitySignal, KillChainStage, NetworkContext, SecurityEvent, Severity, VulnFinding,
    CompliancePosture, ThreatIntelSignal,
)
from core.mace import MACEEngine
from core.tag import AssetClass, AssetRecord, Jurisdiction


def _india_engine():
    return MACEEngine(
        cdcs_threshold=7.0, rea_threshold=6.5, match_threshold=0.38,
        jurisdiction="IN", weight_profile="india_cii",
    )


def test_engine_ingests_asset_and_returns_canonical_id():
    engine = _india_engine()
    rec = AssetRecord(
        source="crowdstrike", source_id="cs-1",
        hostname="web-01", mac_address="00:11:22:33:44:55",
        ip_address="10.0.0.10",
        asset_class=AssetClass.SERVER,
        jurisdiction=Jurisdiction.INDIA,
    )
    v = engine.ingest_asset(rec)
    assert v.id_canonical
    assert v.acs() > 0


def test_engine_merges_records_from_two_sources():
    engine = _india_engine()
    engine.ingest_asset(AssetRecord(
        source="crowdstrike", source_id="cs-1",
        mac_address="00:11:22:33:44:55", cloud_instance_id="i-abc",
    ))
    engine.ingest_asset(AssetRecord(
        source="tenable", source_id="tn-1",
        mac_address="00:11:22:33:44:55", cloud_instance_id="i-abc",
    ))
    stats = engine.full_stats()
    assert stats["tag"]["total_assets"] == 1


def test_full_pipeline_fires_alert_and_generates_evidence():
    engine = _india_engine()
    record = AssetRecord(
        source="crowdstrike", source_id="cs-bank-1",
        hostname="hdfc-backend-01",
        mac_address="aa:bb:cc:dd:ee:ff",
        ip_address="10.1.1.100",
        os="Red Hat Enterprise Linux 8.9",
        sector="Banking",
        asset_class=AssetClass.SERVER,
        jurisdiction=Jurisdiction.INDIA,
        is_internet_facing=True,
        is_critical_infra=True,
    )
    vertex = engine.ingest_asset(record)
    canonical = vertex.id_canonical

    engine.ingest_vuln(canonical, VulnFinding(
        cve_id="CVE-2024-3400", cvss_v3=10.0,
        exploit_status="exploit_public", exposure="internet_facing",
        sla_days=-1, epss_score=0.97,
    ))

    result = engine.ingest_event(
        asset_id=canonical,
        event=SecurityEvent(
            event_id="EVT-1", event_type="data_breach",
            severity=Severity.CRITICAL, domain="endpoint",
            description="active exfil",
            kill_chain_stage=KillChainStage.EXFILTRATION, fidelity=0.95,
        ),
        identity=IdentitySignal(
            impossible_travel=True, privilege_escalation=True,
            credential_stuffing_indicator=True, mfa_failures_1h=9,
            golden_ticket_indicator=True,
        ),
        network=NetworkContext(
            lateral_movement_score=0.92, c2_beacon_score=0.88,
            data_exfil_indicator=0.95, lateral_hop_count=4,
            ransomware_c2_ioc=True, bytes_exfiltrated_mb=250.0,
        ),
        compliance=CompliancePosture(
            stig_pass_count=10, stig_fail_count=90,
            missing_patches=15, edr_coverage=False, mfa_enrolled=False,
        ),
        threat_intel=ThreatIntelSignal(
            ioc_match_score=0.92, campaign_match=True,
            threat_actor_confidence=0.95, campaign_active=True,
            malware_family="APT41-CobaltStrike",
        ),
        jurisdictions=["IN"],
    )
    assert result["alert"] is True
    cdcs = result["cdcs"]["cdcs"]
    assert cdcs >= 7.0, f"Expected CDCS >= 7.0, got {cdcs}"
    incident = result["incident"]
    assert incident is not None
    assert incident["cert_in_reference"].startswith("CERTIN/")
    assert incident["chain_of_custody_hash"] is not None
    assert len(incident["chain_of_custody_hash"]) == 64


def test_low_severity_event_does_not_fire_alert():
    engine = _india_engine()
    record = AssetRecord(source="cs", source_id="benign-1",
                         hostname="dev-laptop")
    vertex = engine.ingest_asset(record)
    result = engine.ingest_event(
        asset_id=vertex.id_canonical,
        event=SecurityEvent(
            event_id="benign", event_type="login_success",
            severity=Severity.INFO, domain="identity", description="ok",
        ),
        jurisdictions=["IN"],
    )
    assert result["alert"] is False
    assert result["incident"] is None


def test_per_tenant_engines_are_isolated():
    a = _india_engine()
    b = _india_engine()
    a.ingest_asset(AssetRecord(source="cs", source_id="A1",
                                hostname="hostA",
                                mac_address="11:11:11:11:11:11"))
    # B knows nothing about A's assets
    assert len(a.tag.vertices) == 1
    assert len(b.tag.vertices) == 0
