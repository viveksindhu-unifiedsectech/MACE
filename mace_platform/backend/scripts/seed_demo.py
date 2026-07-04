#!/usr/bin/env python3
"""
seed_demo.py — Populate a freshly-started MACE backend with investor-demo data.

What it does:
  1. Register a demo tenant (ACME Security, jurisdiction US by default).
  2. Log in and obtain an access token.
  3. Ingest a curated set of assets (cloud VMs, servers, containers, OT, shadow IT).
  4. Attach realistic CVEs (a CISA KEV with EPSS=0.97 for the headline asset).
  5. Trigger several /correlate calls — at least one CRITICAL incident that
     generates regulatory evidence with a chain-of-custody hash.

Usage:
  # First make sure the stack is up:
  #   docker compose -f mace_platform/infra/docker-compose.local.yml up -d
  # Then:
  python scripts/seed_demo.py

Env vars (all optional):
  MACE_API_URL          default http://localhost:8080
  DEMO_TENANT_SLUG      default acme-security
  DEMO_ADMIN_EMAIL      default admin@acmesec.test
  DEMO_ADMIN_PASSWORD   default DemoPass123!Strong
  DEMO_JURISDICTION     default US (US | IN | EU | CA | AE)
"""
from __future__ import annotations

import json
import os
import sys
import time
from typing import Any, Dict, Optional

import httpx

API = os.environ.get("MACE_API_URL", "http://localhost:8080").rstrip("/")
SLUG = os.environ.get("DEMO_TENANT_SLUG", "acme-security")
EMAIL = os.environ.get("DEMO_ADMIN_EMAIL", "admin@acmesec.example.com")
PASSWORD = os.environ.get("DEMO_ADMIN_PASSWORD", "DemoPass123!Strong")
JURISDICTION = os.environ.get("DEMO_JURISDICTION", "US").upper()

ASSETS = [
    {
        "source": "crowdstrike", "source_id": "cs-001",
        "hostname": "prod-api-01", "mac_address": "00:1B:44:11:3A:01",
        "ip_address": "10.0.1.10", "os": "Ubuntu 22.04",
        "owner": "Platform Engineering", "sector": "Banking",
        "asset_class": "server", "is_internet_facing": True,
        "is_critical_infra": True, "tags": {"env": "prod"},
    },
    {
        "source": "tenable", "source_id": "tn-001",
        "hostname": "prod-api-01", "mac_address": "00:1B:44:11:3A:01",
        "ip_address": "10.0.1.10",
        "source_confidence": 0.90, "sector": "Banking",
    },
    {
        "source": "axonius", "source_id": "ax-001",
        "hostname": "prod-db-master", "ip_address": "10.0.2.20",
        "os": "PostgreSQL on Amazon Linux 2",
        "asset_class": "database", "open_ports": [5432, 22],
        "owner": "Data Platform", "sector": "Banking",
        "is_critical_infra": True,
    },
    {
        "source": "crowdstrike", "source_id": "cs-002",
        "hostname": "k8s-worker-04", "ip_address": "10.0.3.40",
        "asset_class": "kubernetes_node", "open_ports": [6443, 10250],
        "owner": "Platform Engineering", "sector": "Banking",
    },
    {
        "source": "manual", "source_id": "shadow-001",
        # No hostname, owner, or mac → flagged as shadow IT
        "ip_address": "10.99.0.99",
        "sector": "Banking",
    },
    {
        "source": "tenable", "source_id": "ot-001",
        "hostname": "scada-pumphouse-01", "ip_address": "10.10.5.50",
        "asset_class": "ot_ics", "open_ports": [502, 102],
        "owner": "Operations", "sector": "Critical Infrastructure",
        "is_critical_infra": True,
    },
]

CVES = [
    {
        "asset_hostname": "prod-api-01",
        "cve_id": "CVE-2024-3400", "cvss_v3": 10.0,
        "exploit_status": "exploit_public", "exposure": "internet_facing",
        "sla_days": -1, "epss_score": 0.97, "patch_available": True,
        "affected_component": "GlobalProtect VPN",
    },
    {
        "asset_hostname": "prod-db-master",
        "cve_id": "CVE-2024-1597", "cvss_v3": 9.1,
        "exploit_status": "exploit_poc", "exposure": "internal",
        "sla_days": 3, "epss_score": 0.45, "patch_available": False,
        "affected_component": "pgjdbc",
    },
]

EVENTS = [
    {
        "asset_hostname": "prod-api-01",
        "event_id": "EVT-EXFIL-001", "event_type": "data_breach",
        "severity": "CRITICAL", "domain": "endpoint",
        "description": "Database export to suspicious external IP detected",
        "kill_chain_stage": "exfiltration", "fidelity": 0.95,
        "source_tool": "crowdstrike",
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
    },
    {
        "asset_hostname": "prod-db-master",
        "event_id": "EVT-RECON-001", "event_type": "unauthorized_access",
        "severity": "MEDIUM", "domain": "identity",
        "description": "Failed auth burst from unusual ASN",
        "kill_chain_stage": "recon", "fidelity": 0.7,
        "source_tool": "splunk",
        "identity": {"mfa_failures_1h": 3, "anomalous_login_time": True},
    },
]


def _post(client: httpx.Client, path: str, json_body: Dict | None = None,
          params: Dict | None = None, headers: Dict | None = None) -> httpx.Response:
    return client.post(f"{API}{path}", json=json_body, params=params, headers=headers)


def _wait_for_api(client: httpx.Client, timeout_s: int = 60) -> None:
    deadline = time.time() + timeout_s
    while time.time() < deadline:
        try:
            r = client.get(f"{API}/health", timeout=5.0)
            if r.status_code == 200:
                return
        except httpx.HTTPError:
            pass
        time.sleep(1.0)
    raise RuntimeError(f"MACE API at {API} did not become healthy within {timeout_s}s")


def main() -> int:
    print(f"→ Seeding MACE demo data at {API}")
    with httpx.Client(timeout=30.0) as client:
        _wait_for_api(client)

        # 1. Register (idempotent — ignore duplicate slug)
        reg = _post(client, "/api/v1/auth/register", json_body={
            "email": EMAIL, "password": PASSWORD,
            "full_name": "Demo Admin",
            "tenant_name": "ACME Security", "tenant_slug": SLUG,
            "jurisdiction": JURISDICTION,
        })
        if reg.status_code in (200, 201):
            print(f"  ✓ Registered tenant '{SLUG}'")
        elif reg.status_code == 400 and "slug already taken" in reg.text.lower():
            print(f"  · Tenant '{SLUG}' already exists, continuing")
        else:
            print(f"  ✗ Registration failed: {reg.status_code} {reg.text[:200]}")
            return 2

        # 2. Login
        login = _post(client, "/api/v1/auth/login", json_body={
            "email": EMAIL, "password": PASSWORD, "tenant_slug": SLUG,
        })
        if login.status_code != 200:
            print(f"  ✗ Login failed: {login.status_code} {login.text[:200]}")
            return 2
        tokens = login.json()
        bearer = {"Authorization": f"Bearer {tokens['access_token']}"}
        print(f"  ✓ Logged in as {EMAIL}")

        # 3. Ingest assets
        hostname_to_id: Dict[str, str] = {}
        for asset in ASSETS:
            r = _post(client, "/api/v1/assets/ingest", json_body=asset, headers=bearer)
            if r.status_code in (200, 201):
                body = r.json()
                cid = body["canonical_id"]
                if asset.get("hostname"):
                    hostname_to_id[asset["hostname"]] = cid
                print(f"  ✓ Ingested {asset['source']:11s} → {asset.get('hostname','(unnamed)'):24s} → {cid[:8]}…  merged={body['merged']}")
            else:
                print(f"  ✗ Failed to ingest {asset['source_id']}: {r.status_code} {r.text[:200]}")

        # Re-discover assets DB IDs (we need them for vuln attach)
        list_r = client.get(f"{API}/api/v1/assets?page_size=200", headers=bearer)
        list_r.raise_for_status()
        db_assets = {a["hostname"]: a["id"] for a in list_r.json()["items"]
                     if a.get("hostname")}

        # 4. Attach vulnerabilities
        for cve in CVES:
            host = cve.pop("asset_hostname")
            db_id = db_assets.get(host)
            if not db_id:
                print(f"  ! No DB record found for {host}, skipping CVE")
                continue
            r = _post(client, f"/api/v1/assets/{db_id}/vulns", json_body=cve,
                      headers=bearer)
            if r.status_code in (200, 201):
                print(f"  ✓ Attached {cve['cve_id']} (CVSS {cve['cvss_v3']}, EPSS {cve['epss_score']}) → {host}")
            else:
                print(f"  ✗ Vuln attach failed: {r.status_code} {r.text[:200]}")

        # 5. Trigger correlations
        for event in EVENTS:
            host = event.pop("asset_hostname")
            db_id = db_assets.get(host)
            if not db_id:
                continue
            payload = {
                "asset_id": db_id,
                "event": {k: event[k] for k in (
                    "event_id", "event_type", "severity", "domain", "description",
                    "kill_chain_stage", "fidelity", "source_tool",
                ) if k in event},
                "jurisdictions": [JURISDICTION],
            }
            for ctx in ("identity", "network", "compliance", "threat_intel"):
                if ctx in event:
                    payload[ctx] = event[ctx]
            r = _post(client, "/api/v1/correlate", json_body=payload, headers=bearer)
            if r.status_code == 200:
                body = r.json()
                cdcs = body["cdcs"]["cdcs"]
                alert = body["alert"]
                marker = "🚨" if alert else "·"
                print(f"  {marker} Correlated {event['event_id']:18s} → CDCS={cdcs:.2f}  alert={alert}")
                if alert and body.get("incident"):
                    inc = body["incident"]
                    if inc.get("cert_in_reference"):
                        print(f"      CERT-In ref:   {inc['cert_in_reference']}")
                    if inc.get("chain_of_custody_hash"):
                        print(f"      Chain hash:    {inc['chain_of_custody_hash'][:32]}…")
                    print(f"      Frameworks:    {', '.join(inc.get('frameworks', []))}")
            else:
                print(f"  ✗ Correlate failed: {r.status_code} {r.text[:200]}")

        # 6. Summary
        stats = client.get(f"{API}/api/v1/admin/stats", headers=bearer).json()
        print("\nDemo seeded. Platform stats:")
        print(json.dumps({
            "assets":        stats.get("assets", {}),
            "incidents":     stats.get("incidents", {}),
            "vulns":         stats.get("vulnerabilities", {}),
        }, indent=2))
        print("\nOpen the SOC dashboard at http://localhost:3000")
        print(f"Login:  workspace={SLUG}  email={EMAIL}  password={PASSWORD}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
