"""
Backend integration tests — validates full API pipeline.
Requires: running PostgreSQL + Redis OR uses TestClient with SQLite.
"""
import pytest
import sys, os
from pathlib import Path

# Backend root on sys.path so `app.*` imports resolve
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# MACE algorithm core — resolved by env var or by walking up to repo root
_here = Path(__file__).resolve()
_candidate_core = _here.parents[3] / "UnifiedSec_MACE_v2"
if os.environ.get("MACE_CORE_PATH"):
    sys.path.insert(0, os.environ["MACE_CORE_PATH"])
elif (_candidate_core / "core" / "mace.py").exists():
    sys.path.insert(0, str(_candidate_core))

from fastapi.testclient import TestClient

# ── UNIT TESTS (no DB required) ─────────────────────────────────────
def test_config_loads():
    from app.core.config import settings
    assert settings.APP_VERSION == "2.0.0"
    assert settings.API_V1_PREFIX == "/api/v1"
    assert settings.JWT_ALGORITHM == "HS256"
    assert settings.MACE_CDCS_ALERT_THRESHOLD == 7.0
    assert settings.MACE_MATCH_THRESHOLD == 0.38
    print("  ✓ Config loads correctly")

def test_jwt_create_decode():
    from app.auth.jwt import create_access_token, decode_token
    token = create_access_token({"sub": "user-123", "tenant_id": "tenant-456", "role": "soc_analyst"})
    assert isinstance(token, str)
    payload = decode_token(token)
    assert payload["sub"] == "user-123"
    assert payload["tenant_id"] == "tenant-456"
    print("  ✓ JWT create/decode works")

def test_jwt_invalid_returns_none():
    from app.auth.jwt import decode_token
    assert decode_token("invalid.token.here") is None
    assert decode_token("") is None
    print("  ✓ Invalid JWT returns None")

def test_password_hash_verify():
    from app.auth.jwt import hash_password, verify_password
    hashed = hash_password("SecurePass123!")
    assert hashed != "SecurePass123!"
    assert verify_password("SecurePass123!", hashed)
    assert not verify_password("wrong", hashed)
    print("  ✓ Password hash/verify works")

def test_api_key_generate():
    from app.models.user import APIKey
    raw, hashed = APIKey.generate()
    assert raw.startswith("mace_")
    assert len(raw) > 30
    assert len(hashed) == 64
    assert APIKey.hash_key(raw) == hashed
    print("  ✓ API key generation works")

def test_mace_engine_service_loads():
    """Test that MACEService can initialize and run the algorithm."""
    from app.services.mace_engine_service import MACEService

    class MockTenant:
        id = "tenant-test-001"
        slug = "test"
        jurisdiction = "US"
        weight_profile = "usa_fedramp"
        cdcs_alert_threshold = 7.0
        rea_cdcs_threshold = 6.5

    svc = MACEService(MockTenant())
    assert svc.engine is not None
    print("  ✓ MACEService initializes MACE engine")

def test_mace_engine_full_pipeline():
    """Run full UTAG → CDCS → UREA pipeline through MACEService."""
    from app.services.mace_engine_service import MACEService

    class MockTenant:
        id = "tenant-pipeline-test"
        slug = "pipeline-test"
        jurisdiction = "IN"
        weight_profile = "india_cii"
        cdcs_alert_threshold = 7.0
        rea_cdcs_threshold = 6.5

    svc = MACEService(MockTenant())

    # Step 1: Ingest asset
    record = {
        "source": "crowdstrike", "source_id": "cs-backend-test-001",
        "hostname": "hdfc-backend-server-01",
        "mac_address": "00:1B:44:11:3A:B7",
        "ip_address": "10.1.1.100",
        "os": "Red Hat Enterprise Linux 8.9",
        "owner": "HDFC Security Team",
        "sector": "Banking",
        "asset_class": "server",
        "jurisdiction": "IN",
        "is_internet_facing": True,
        "is_critical_infra": True,
    }
    vertex = svc.ingest_asset(record)
    assert "canonical_id" in vertex
    assert vertex["acs_score"] > 0
    canonical_id = vertex["canonical_id"]
    print(f"  ✓ Asset ingested: {canonical_id[:8]}... ACS={vertex['acs_score']}")

    # Step 2: Attach CVE
    svc.attach_vuln(canonical_id, {
        "cve_id": "CVE-2024-3400", "cvss_v3": 10.0,
        "exploit_status": "exploit_public",
        "exposure": "internet_facing", "sla_days": -1,
        "epss_score": 0.97,
    })
    print(f"  ✓ CVE-2024-3400 (EPSS=0.97) attached")

    # Step 3: Run correlation
    result = svc.correlate(
        asset_id=canonical_id,
        event_data={
            "event_id": "EVT-BACKEND-TEST-001",
            "event_type": "data_breach",
            "severity": "CRITICAL",
            "domain": "endpoint",
            "description": "Unauthorized database access with data exfiltration detected",
            "kill_chain_stage": "exfiltration",
            "fidelity": 0.95,
        },
        context={
            "identity": {
                "impossible_travel": True, "privilege_escalation": True,
                "credential_stuffing_indicator": True, "mfa_failures_1h": 9,
                "golden_ticket_indicator": True,
            },
            "network": {
                "lateral_movement_score": 0.92, "c2_beacon_score": 0.88,
                "data_exfil_indicator": 0.95, "lateral_hop_count": 4,
                "ransomware_c2_ioc": True, "bytes_exfiltrated_mb": 250.0,
            },
            "compliance": {
                "stig_pass_count": 10, "stig_fail_count": 90,
                "missing_patches": 15, "edr_coverage": False, "mfa_enrolled": False,
            },
            "threat_intel": {
                "ioc_match_score": 0.92, "campaign_match": True,
                "threat_actor_confidence": 0.95, "campaign_active": True,
                "malware_family": "APT41-CobaltStrike",
            },
            "jurisdictions": ["IN"],
        }
    )
    cdcs = result["cdcs"]["cdcs"]
    alert = result["alert"]
    incident = result.get("incident")
    print(f"  ✓ CDCS score: {cdcs:.2f}/10 | Alert: {alert}")
    assert cdcs > 7.0, f"Expected CDCS > 7.0, got {cdcs}"
    assert alert, "Expected alert to fire"
    if incident:
        print(f"  ✓ CERT-In ref: {incident.get('cert_in_reference', 'N/A')}")
        print(f"  ✓ SHA-256 chain: {incident.get('chain_of_custody_hash', 'N/A')[:20]}...")
    print(f"  ✓ Full pipeline complete: CDCS={cdcs:.2f}")

def test_schemas_validate():
    from app.schemas.asset import AssetIngestRequest
    req = AssetIngestRequest(
        source="crowdstrike", source_id="test-001",
        hostname="test-server", jurisdiction="US",
        is_internet_facing=False,
    )
    assert req.source == "crowdstrike"
    assert req.jurisdiction == "US"
    print("  ✓ AssetIngestRequest schema validates")

def test_tenant_plan_enum():
    from app.models.tenant import TenantPlan
    assert TenantPlan.MSME.value == "msme"
    assert TenantPlan.ENTERPRISE.value == "enterprise"
    print("  ✓ TenantPlan enum correct")

def test_user_role_enum():
    from app.models.user import UserRole
    assert UserRole.SUPER_ADMIN.value == "super_admin"
    assert UserRole.SOC_ANALYST.value == "soc_analyst"
    print("  ✓ UserRole enum correct")

def test_correlation_schema():
    from app.schemas.correlation import CorrelationRequest, SecurityEventInput
    req = CorrelationRequest(
        asset_id="asset-123",
        event=SecurityEventInput(
            event_id="EVT-001", event_type="data_breach",
            severity="CRITICAL", domain="endpoint",
            description="Test breach",
        )
    )
    assert req.asset_id == "asset-123"
    assert req.event.severity == "CRITICAL"
    print("  ✓ CorrelationRequest schema validates")

def test_connector_types():
    from app.models.connector import ConnectorType
    assert ConnectorType.CROWDSTRIKE.value == "crowdstrike"
    assert ConnectorType.TENABLE.value == "tenable"
    assert ConnectorType.MISP.value == "misp"
    print("  ✓ ConnectorType enum correct")


if __name__ == "__main__":
    tests = [
        test_config_loads,
        test_jwt_create_decode,
        test_jwt_invalid_returns_none,
        test_password_hash_verify,
        test_api_key_generate,
        test_mace_engine_service_loads,
        test_mace_engine_full_pipeline,
        test_schemas_validate,
        test_tenant_plan_enum,
        test_user_role_enum,
        test_correlation_schema,
        test_connector_types,
    ]
    W = "=" * 60
    print(f"\n{W}")
    print("  UnifiedSec MACE Platform — Backend Tests")
    print(W)
    passed = 0
    failed = 0
    for test in tests:
        try:
            test()
            passed += 1
        except Exception as e:
            print(f"  ✗ {test.__name__}: {e}")
            failed += 1
    print(f"\n{W}")
    print(f"  Backend Tests: {passed}/{len(tests)} PASSED, {failed} FAILED")
    print(W + "\n")
    exit(0 if failed == 0 else 1)
