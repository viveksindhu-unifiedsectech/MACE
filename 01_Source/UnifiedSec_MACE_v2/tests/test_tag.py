"""Tests for the UTAG (Universal Temporal Asset Graph) layer."""
import math
import time

import pytest

from core.tag import (
    AssetClass,
    AssetRecord,
    AssetStatus,
    DataClassification,
    GeoPoint,
    Jurisdiction,
    TemporalAssetGraph,
    HARDWARE_BOOST,
    IDENTITY_WEIGHTS,
    MATCH_THRESHOLD,
    _identity_vector,
    levenshtein_normalized,
    match_score,
)


# ────────────────────────────────────────────────────────────────────────────
# String similarity primitives
# ────────────────────────────────────────────────────────────────────────────

def test_levenshtein_identical_returns_one():
    assert levenshtein_normalized("server-01", "server-01") == 1.0


def test_levenshtein_completely_different_is_low():
    assert levenshtein_normalized("aaa", "zzz") < 0.5


def test_levenshtein_empty_inputs_return_zero():
    assert levenshtein_normalized("", "abc") == 0.0
    assert levenshtein_normalized("abc", None) == 0.0
    assert levenshtein_normalized(None, None) == 0.0


def test_levenshtein_is_case_insensitive():
    assert levenshtein_normalized("Host-01", "host-01") == 1.0


# ────────────────────────────────────────────────────────────────────────────
# Identity-vector matching with hardware boost
# ────────────────────────────────────────────────────────────────────────────

def _rec(**kw):
    base = dict(source="test", source_id="t1")
    base.update(kw)
    return AssetRecord(**base)


def test_match_score_exact_mac_gets_hardware_boost():
    iv1 = _identity_vector(_rec(mac_address="aa:bb:cc:dd:ee:ff"))
    iv2 = _identity_vector(_rec(mac_address="aa:bb:cc:dd:ee:ff"))
    score = match_score(iv1, iv2)
    expected = IDENTITY_WEIGHTS["mac"] * HARDWARE_BOOST
    assert math.isclose(score, expected, rel_tol=1e-6)


def test_match_score_no_overlap_is_zero():
    iv1 = _identity_vector(_rec(mac_address="aa:bb:cc:dd:ee:ff"))
    iv2 = _identity_vector(_rec(hostname="other"))
    assert match_score(iv1, iv2) == 0.0


def test_match_score_combined_hardware_clears_threshold():
    # MAC + cloud_id boosted should easily exceed 0.38
    iv1 = _identity_vector(_rec(
        mac_address="00:11:22:33:44:55",
        cloud_instance_id="i-0123456789abcdef",
    ))
    iv2 = _identity_vector(_rec(
        mac_address="00:11:22:33:44:55",
        cloud_instance_id="i-0123456789abcdef",
    ))
    assert match_score(iv1, iv2) >= MATCH_THRESHOLD


def test_match_score_score_is_clamped_to_one():
    # Even with all attributes matching, score must not exceed 1.0.
    rec = _rec(
        mac_address="aa:bb:cc:dd:ee:ff",
        cert_fingerprint="SHA256:abc",
        cloud_instance_id="i-x",
        serial_number="SN-1",
        cloud_account_id="acct-1",
        hostname="h1",
        ip_address="10.0.0.1",
    )
    iv = _identity_vector(rec)
    assert match_score(iv, iv) <= 1.0


# ────────────────────────────────────────────────────────────────────────────
# Geo / Haversine
# ────────────────────────────────────────────────────────────────────────────

def test_geo_distance_zero_for_same_point():
    p1 = GeoPoint(lat=12.97, lon=77.59, observed_at=time.time())
    p2 = GeoPoint(lat=12.97, lon=77.59, observed_at=time.time())
    assert p1.distance_km(p2) < 1e-6


def test_geo_distance_bangalore_to_mumbai_is_approximately_correct():
    # Bangalore → Mumbai is ~840 km
    blr = GeoPoint(lat=12.97, lon=77.59)
    bom = GeoPoint(lat=19.07, lon=72.87)
    d = blr.distance_km(bom)
    assert 800 < d < 900


def test_geo_velocity_impossible_travel_exceeds_threshold():
    now = time.time()
    p1 = GeoPoint(lat=12.97, lon=77.59, observed_at=now)
    p2 = GeoPoint(lat=40.71, lon=-74.0, observed_at=now + 600)  # 10 min later
    v = p1.velocity_kmh(p2)
    assert v > 500  # impossible travel threshold


# ────────────────────────────────────────────────────────────────────────────
# Asset graph: ingest, merge, decay, status
# ────────────────────────────────────────────────────────────────────────────

def test_first_ingest_creates_a_new_vertex():
    g = TemporalAssetGraph()
    v = g.ingest(_rec(
        source="crowdstrike",
        source_id="cs-1",
        hostname="web-01",
        mac_address="00:11:22:33:44:55",
        ip_address="10.0.0.10",
    ))
    assert v.quorum_sources == 1
    assert "crowdstrike" in v.source_set
    assert len(g.vertices) == 1


def test_second_source_for_same_host_merges_and_bumps_quorum():
    g = TemporalAssetGraph()
    g.ingest(_rec(
        source="crowdstrike",
        source_id="cs-1",
        mac_address="00:11:22:33:44:55",
        cloud_instance_id="i-1",
    ))
    g.ingest(_rec(
        source="tenable",
        source_id="tn-1",
        mac_address="00:11:22:33:44:55",
        cloud_instance_id="i-1",
    ))
    assert len(g.vertices) == 1
    v = list(g.vertices.values())[0]
    assert v.quorum_sources == 2
    assert v.source_set >= {"crowdstrike", "tenable"}


def test_unrelated_records_create_separate_vertices():
    g = TemporalAssetGraph()
    g.ingest(_rec(source="s1", source_id="a", mac_address="aa:aa:aa:aa:aa:aa"))
    g.ingest(_rec(source="s2", source_id="b", mac_address="bb:bb:bb:bb:bb:bb"))
    assert len(g.vertices) == 2


def test_acs_decays_with_time():
    g = TemporalAssetGraph()
    v = g.ingest(_rec(
        source="cs", source_id="x",
        asset_class=AssetClass.CONTAINER,  # short half-life
    ))
    acs_now = v.acs()
    acs_in_10_days = v.acs(at=time.time() + 86400 * 10)
    assert acs_in_10_days < acs_now


def test_status_returns_decommissioned_when_acs_below_threshold():
    g = TemporalAssetGraph()
    v = g.ingest(_rec(
        source="cs", source_id="x",
        asset_class=AssetClass.SERVERLESS,  # 3h half-life
    ))
    # Force decommissioned by checking far in the future
    far_future = time.time() + 86400 * 365
    acs = v.acs(at=far_future)
    assert acs < 0.10


def test_asset_class_inferred_from_database_ports():
    g = TemporalAssetGraph()
    v = g.ingest(_rec(
        source="s", source_id="db-1",
        open_ports=[5432, 22],
    ))
    assert v.asset_class == AssetClass.DATABASE


def test_asset_class_inferred_from_kubernetes_ports():
    g = TemporalAssetGraph()
    v = g.ingest(_rec(
        source="s", source_id="k8s-1",
        open_ports=[6443, 10250],
    ))
    assert v.asset_class == AssetClass.KUBERNETES_NODE


def test_jurisdiction_propagates_to_vertex():
    g = TemporalAssetGraph()
    v = g.ingest(_rec(
        source="s", source_id="i", jurisdiction=Jurisdiction.INDIA,
        mac_address="aa:bb:cc:dd:ee:ff",
    ))
    assert v.jurisdiction == Jurisdiction.INDIA
