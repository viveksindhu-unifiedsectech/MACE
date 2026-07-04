"""
Session 4 Integration Tests
=============================
Tests connector normalization, pipeline processing, and dispatcher logic.
No live API calls — uses mock data throughout.
"""
import sys
sys.path.insert(0, "/home/claude/UnifiedSec_MACE_v2")
sys.path.insert(0, "/home/claude/mace_platform")


def test_normalized_asset_structure():
    from connectors.base import NormalizedAsset
    asset = NormalizedAsset(
        source="crowdstrike",
        source_id="cs-test-001",
        hostname="prod-server-01",
        ip_address="10.1.1.100",
        mac_address="AA:BB:CC:DD:EE:FF",
        os="Windows Server 2022",
        asset_class="server",
        is_internet_facing=True,
        source_confidence=0.95,
    )
    assert asset.source == "crowdstrike"
    assert asset.source_confidence == 0.95
    assert asset.asset_class == "server"
    print("  ✓ NormalizedAsset structure correct")


def test_normalized_vuln_structure():
    from connectors.base import NormalizedVuln
    vuln = NormalizedVuln(
        source="tenable",
        source_asset_id="asset-001",
        cve_id="CVE-2024-3400",
        cvss_v3=10.0,
        severity="CRITICAL",
        epss_score=0.97,
        exploit_status="exploit_public",
        exposure="internet_facing",
    )
    assert vuln.cve_id == "CVE-2024-3400"
    assert vuln.cvss_v3 == 10.0
    assert vuln.epss_score == 0.97
    print("  ✓ NormalizedVuln structure correct")


def test_normalized_event_structure():
    from connectors.base import NormalizedEvent
    event = NormalizedEvent(
        source="crowdstrike",
        event_id="det-001",
        event_type="ransomware_detection",
        severity="CRITICAL",
        domain="endpoint",
        description="Ransomware activity detected on server",
        kill_chain_stage="install",
        mitre_technique_id="T1486",
        fidelity=0.95,
    )
    assert event.severity == "CRITICAL"
    assert event.domain == "endpoint"
    assert event.kill_chain_stage == "install"
    print("  ✓ NormalizedEvent structure correct")


def test_asset_processor_pipeline():
    """Full UTAG pipeline through AssetProcessor."""
    from connectors.base import NormalizedAsset
    from pipeline.processors.asset_processor import AssetProcessor

    proc = AssetProcessor(tenant_id="test-tenant", jurisdiction="US", weight_profile="usa_fedramp")

    # Ingest first observation
    a1 = NormalizedAsset(
        source="crowdstrike", source_id="cs-001",
        hostname="prod-db-01", mac_address="00:11:22:33:44:55",
        ip_address="192.168.1.10", os="RHEL 8.9",
        asset_class="server", is_critical_infra=True, source_confidence=0.95
    )
    r1 = proc.process(a1)
    assert r1.canonical_id
    assert r1.acs_score > 0
    assert not r1.merged
    canonical = r1.canonical_id

    # Second observation — same MAC → should merge
    a2 = NormalizedAsset(
        source="tenable", source_id="tn-001",
        mac_address="00:11:22:33:44:55",  # same MAC → UTAG merge
        ip_address="192.168.1.10",
        asset_class="server", source_confidence=0.88
    )
    r2 = proc.process(a2)
    assert r2.merged, "Second observation with same MAC should merge"
    assert r2.canonical_id == canonical
    assert r2.quorum_sources >= 2
    print(f"  ✓ AssetProcessor: UTAG merge works — quorum={r2.quorum_sources}, ACS={r2.acs_score}")


def test_event_correlation_processor():
    """CDCS correlation through EventCorrelationProcessor."""
    from connectors.base import NormalizedAsset, NormalizedEvent
    from pipeline.processors.asset_processor import AssetProcessor
    from pipeline.processors.event_processor import EventCorrelationProcessor

    proc = AssetProcessor(tenant_id="test-corr", jurisdiction="IN", weight_profile="india_cii")
    ev_proc = EventCorrelationProcessor(engine=proc.engine)

    asset = NormalizedAsset(
        source="crowdstrike", source_id="cs-corr-001",
        hostname="hdfc-trading-01", mac_address="AA:BB:CC:11:22:33",
        ip_address="10.0.1.50", asset_class="server",
        sector="Banking", is_internet_facing=True, is_critical_infra=True,
        source_confidence=0.95
    )
    processed = proc.process(asset)
    canonical_id = processed.canonical_id

    # Attach a critical CVE first
    from core.cdcs import VulnFinding
    proc.engine.ingest_vuln(canonical_id, VulnFinding(
        cve_id="CVE-2024-3400", cvss_v3=10.0, exploit_status="exploit_public",
        exposure="internet_facing", sla_days=-1, epss_score=0.97
    ))

    event = NormalizedEvent(
        source="crowdstrike", event_id="evt-corr-001",
        event_type="data_exfiltration", severity="CRITICAL",
        domain="endpoint", description="Large data exfil detected",
        kill_chain_stage="exfiltration", fidelity=0.95
    )
    result = ev_proc.correlate(
        canonical_id, event,
        identity={"impossible_travel": True, "privilege_escalation": True, "mfa_failures_1h": 8},
        network={"lateral_movement_score": 0.85, "data_exfil_indicator": 0.92, "lateral_hop_count": 3},
    )

    assert result.cdcs_score > 0
    assert result.severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]
    print(f"  ✓ EventCorrelationProcessor: CDCS={result.cdcs_score:.2f}, Alert={result.alert}, Severity={result.severity}")


def test_alert_dispatcher_config():
    """AlertDispatcher initializes correctly."""
    from pipeline.dispatchers.alert_dispatcher import AlertDispatcher, _severity_gte
    disp = AlertDispatcher({
        "slack_webhook": "https://hooks.slack.com/test",
        "min_severity_pagerduty": "CRITICAL",
    })
    assert disp.config["slack_webhook"]
    assert _severity_gte("CRITICAL", "HIGH")
    assert _severity_gte("HIGH", "HIGH")
    assert not _severity_gte("MEDIUM", "HIGH")
    print("  ✓ AlertDispatcher config + severity ordering correct")


def test_pipeline_orchestrator_init():
    """MACEPipeline initializes without errors."""
    from pipeline.orchestrator import MACEPipeline
    pipeline = MACEPipeline({
        "tenant_id": "orch-test-001",
        "jurisdiction": "AE",
        "weight_profile": "uae_nesa",
        "dispatch_config": {},
    })
    assert pipeline.tenant_id == "orch-test-001"
    assert pipeline.asset_processor is not None
    assert pipeline.event_processor is not None
    print("  ✓ MACEPipeline orchestrator initializes correctly")


def test_connector_base():
    """BaseConnector health check returns correct structure."""
    from connectors.base import ConnectorHealth
    h = ConnectorHealth(status="ok", message="healthy", assets_available=True, latency_ms=45.2)
    assert h.status == "ok"
    assert h.assets_available
    assert h.latency_ms == 45.2
    print("  ✓ ConnectorHealth structure correct")


def test_misp_connector_importable():
    from connectors.misp import MISPConnector
    c = MISPConnector(api_key="test-key", base_url="https://misp.example.com")
    assert c.api_key == "test-key"
    print("  ✓ MISPConnector importable and configurable")


def test_splunk_connector_importable():
    from connectors.splunk import SplunkConnector
    c = SplunkConnector(token="test-token", base_url="https://splunk.example.com")
    assert c.token == "test-token"
    print("  ✓ SplunkConnector importable and configurable")


def test_generic_connector_field_mapping():
    from connectors.generic import GenericAPIConnector
    c = GenericAPIConnector(
        base_url="https://api.example.com",
        token="test",
        field_mapping={"id": "device_id", "hostname": "name", "ip_address": "ip"},
        data_path="data.devices",
        list_endpoint="/devices",
    )
    assert c.field_mapping["hostname"] == "name"
    assert c.data_path == "data.devices"
    print("  ✓ GenericAPIConnector field mapping configurable")


if __name__ == "__main__":
    tests = [
        test_normalized_asset_structure,
        test_normalized_vuln_structure,
        test_normalized_event_structure,
        test_asset_processor_pipeline,
        test_event_correlation_processor,
        test_alert_dispatcher_config,
        test_pipeline_orchestrator_init,
        test_connector_base,
        test_misp_connector_importable,
        test_splunk_connector_importable,
        test_generic_connector_field_mapping,
    ]
    W = "=" * 60
    print(f"\n{W}")
    print("  UnifiedSec MACE — Session 4: Connectors + Pipeline Tests")
    print(W)
    passed = failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1
    print(f"\n{W}")
    print(f"  {passed}/{len(tests)} PASSED  {failed} FAILED")
    print(W + "\n")
    exit(0 if failed == 0 else 1)
