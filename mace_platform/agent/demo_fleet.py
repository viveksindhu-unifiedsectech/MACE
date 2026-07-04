"""
Demo fleet synthesizer — generates a realistic 1,000-device enterprise fleet
plus a 30-day timeline of risk-score history per device. Used by
demo_launch.py for investor demos. Never bundled into the production .exe.

Distribution:
  • 65% macOS (engineering, exec, design)
  • 22% Windows (finance, legal, sales)
  •  8% Linux (servers, K8s nodes)
  •  3% Android (mobile fleet)
  •  2% iOS

Realism:
  • Department + role + hostname follow enterprise patterns
    (eng-mbp-1287, fin-dell-bos-4412, prod-k8s-aws-us-east-1a-12 …)
  • Vulns + STIG fails scale with department risk profile
    (engineering tolerates more bleeding-edge software; finance is locked down)
  • Timeline shows the average device improving 0-30 days as patches are
    applied; some devices regress when new CVEs land.
"""
from __future__ import annotations
import hashlib
import random
import time
from copy import deepcopy
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List

from .runner import scan_simulated


# ── enterprise distribution ────────────────────────────────────────

DEPARTMENTS = [
    # Workstations — ~52% of fleet
    ("eng",   "Engineering",         "macOS",   0.15, ["mbp","mba","studio"]),
    ("design","Design",               "macOS",   0.03, ["imac","mbp"]),
    ("exec",  "Executive",            "macOS",   0.02, ["mbp"]),
    ("fin",   "Finance",              "Windows", 0.06, ["dell","lenovo"]),
    ("legal", "Legal",                "Windows", 0.02, ["dell"]),
    ("sales", "Sales",                "Windows", 0.06, ["dell","hp"]),
    ("hr",    "HR",                   "Windows", 0.02, ["dell"]),
    ("ops",   "Ops",                  "macOS",   0.06, ["mbp"]),
    ("sec",   "Security",             "macOS",   0.04, ["mbp"]),
    ("mkt",   "Marketing",            "macOS",   0.04, ["mbp"]),
    ("data",  "Data Science",         "macOS",   0.03, ["mbp","mba"]),

    # Servers + cloud — ~28% of fleet
    ("server",       "Production server",       "Linux",   0.08, ["aws","gcp","azure","onprem"]),
    ("db_server",    "Database server",         "Linux",   0.04, ["aws","gcp"]),
    ("web_server",   "Web / API server",        "Linux",   0.04, ["aws","gcp","azure"]),
    ("k8s",          "Kubernetes node",         "Linux",   0.05, ["aws","gcp","azure"]),
    ("container",    "Container host",          "Linux",   0.03, ["aws"]),
    ("vpn_concentrator","VPN / gateway",        "Linux",   0.02, ["aws","onprem"]),
    ("domain_controller","Active Directory DC", "Windows", 0.02, ["onprem"]),

    # Mobile — ~10% of fleet
    ("mobile",       "Field / mobile",          "Android", 0.06, ["pixel","galaxy","oneplus","xiaomi"]),
    ("exec_mobile",  "Exec mobile",             "iOS",     0.03, ["iphone"]),
    ("tablet",       "Field tablet",            "iOS",     0.01, ["ipad"]),
]

CITIES = [("nyc","New York"),("sfo","San Francisco"),("bos","Boston"),
          ("chi","Chicago"),("aus","Austin"),("lon","London"),
          ("ber","Berlin"),("ban","Bangalore"),("dub","Dubai"),
          ("sin","Singapore"),("syd","Sydney"),("tok","Tokyo")]

# Each tenant gets a slice of the fleet; assignment is weighted random.
TENANTS = [
    ("acme",       "Acme Corporation",       "SaaS",        0.18),
    ("globex",     "Globex Capital",         "Banking",     0.14),
    ("initech",    "Initech Software",       "SaaS",        0.10),
    ("umbrella",   "Umbrella Pharma",        "Healthcare",  0.09),
    ("stark",      "Stark Industries",       "Manufacturing", 0.09),
    ("pied-piper", "Pied Piper Networks",    "SaaS",        0.07),
    ("hooli",      "Hooli Inc.",             "Consumer Internet", 0.07),
    ("tyrell",     "Tyrell Corporation",     "Energy/Utilities", 0.06),
    ("massive",    "Massive Dynamic",        "Defense",     0.06),
    ("nakatomi",   "Nakatomi Trading",       "Retail",      0.05),
    ("wonka",      "Wonka Logistics",        "Logistics",   0.04),
    ("waystar",    "Waystar Royco",          "Media",       0.03),
    ("vandelay",   "Vandelay Industries",    "Import/Export", 0.02),
]


def _pick_tenant():
    total = sum(t[3] for t in TENANTS)
    r = random.random() * total
    cum = 0
    for t in TENANTS:
        cum += t[3]
        if r < cum: return t
    return TENANTS[-1]

# Risk profile per department (how much vuln/STIG drift to add)
DEPT_RISK = {
    "eng": 0.55, "data": 0.50, "ops": 0.40, "design": 0.30,
    "fin": 0.20, "legal": 0.15, "hr": 0.18,
    "sales": 0.32, "exec": 0.10, "mkt": 0.30,
    "sec": 0.08, "server": 0.60, "k8s": 0.50,
    "mobile": 0.25, "exec_mobile": 0.05,
}


def _weighted_pick(dept_specs):
    total = sum(s[3] for s in dept_specs)
    r = random.random() * total
    cum = 0
    for s in dept_specs:
        cum += s[3]
        if r < cum: return s
    return dept_specs[-1]


def _hostname(idx, dept, model, city):
    return f"{dept}-{model}-{city}-{idx:05d}"


def _user_email(dept, idx):
    first = random.choice(["alex","sam","priya","raj","jamie","chris","drew","jordan",
                            "taylor","morgan","casey","jess","robin","lee","quinn",
                            "yuki","kavya","sarah","mike","amir","fatima","mei"])
    last = random.choice(["smith","patel","khan","liu","garcia","silva","jones","brown",
                           "kim","singh","ahmed","tanaka","cohen","wright"])
    return f"{first}.{last}@unifiedsec.io"


def synthesize_fleet(n: int = 1000, seed: int = 42) -> List[Dict[str, Any]]:
    """
    Build a fleet of N device reports. Each report has the full canonical
    bundle shape (hwam/swam/stig/vulns/etc.) — built by calling
    scan_simulated() and then mutating the result with department-specific
    drift so the demo looks like a real enterprise.
    """
    random.seed(seed)
    base_reports = {plat: scan_simulated(plat, hostname=f"_base_{plat}")
                     for plat in ("darwin","linux","windows","android","ios")}
    fleet: List[Dict[str, Any]] = []
    for idx in range(n):
        dept_id, dept_name, os_label, _, model_prefixes = _weighted_pick(DEPARTMENTS)
        city_id, city = random.choice(CITIES)
        model = random.choice(model_prefixes)
        host = _hostname(idx, dept_id, model, city_id)
        owner = _user_email(dept_id, idx)

        plat = {"macOS":"darwin","Windows":"windows","Linux":"linux",
                 "Android":"android","iOS":"ios"}[os_label]
        # Tablets use iOS base reports
        if dept_id == "tablet": plat = "ios"
        rep = deepcopy(base_reports[plat]).to_dict()
        rep["hostname"] = host
        rep["host_id"] = hashlib.sha256(host.encode()).hexdigest()[:32]
        rep["hardware"]["primary_ip"] = f"10.{random.randint(0,254)}.{random.randint(0,254)}.{random.randint(2,254)}"
        rep["hardware"]["primary_mac"] = ":".join(f"{random.randint(0,255):02x}" for _ in range(6))
        rep["hardware"]["serial_number"] = f"SN{random.randint(10**6, 10**7-1)}"
        # Manufacturer / origin — varies by platform + device type
        if plat == "darwin":
            rep["hardware"]["manufacturer"] = "Apple Inc."
            rep["hardware"]["country_of_origin"] = "USA (designed in Cupertino)"
        elif plat == "windows":
            manuf = random.choice([
                ("Dell Inc.", "USA / Vietnam (assembly)"),
                ("Lenovo", "China (assembly)"),
                ("HP Inc.", "USA / Vietnam"),
                ("Microsoft", "USA / China"),
                ("ASUS", "Taiwan"),
                ("Acer", "Taiwan"),
            ])
            rep["hardware"]["manufacturer"] = manuf[0]
            rep["hardware"]["country_of_origin"] = manuf[1]
        elif plat == "linux":
            manuf = random.choice([
                ("Amazon Web Services", "USA"),
                ("Google Cloud", "USA"),
                ("Microsoft Azure", "USA"),
                ("Supermicro", "USA / Taiwan"),
                ("Dell EMC", "USA"),
                ("HPE", "USA"),
            ])
            rep["hardware"]["manufacturer"] = manuf[0]
            rep["hardware"]["country_of_origin"] = manuf[1]
        elif plat == "android":
            manuf = random.choice([
                ("Samsung Electronics", "South Korea"),
                ("Google", "USA / China"),
                ("OnePlus", "China"),
                ("Xiaomi", "China"),
            ])
            rep["hardware"]["manufacturer"] = manuf[0]
            rep["hardware"]["country_of_origin"] = manuf[1]
        elif plat == "ios":
            rep["hardware"]["manufacturer"] = "Apple Inc."
            rep["hardware"]["country_of_origin"] = "USA / China (assembly)"
        tenant_id, tenant_name, tenant_sector, _ = _pick_tenant()
        # Department + tenant tag — used by dashboard multi-tenant filter
        rep["tags"] = {
            "department": dept_name, "city": city, "owner": owner,
            "tenant_id": tenant_id, "tenant": tenant_name, "sector": tenant_sector,
        }
        # Vary scan date so dashboard "Last scanned" shows realistic spread
        minutes_ago = random.choice([
            random.randint(1, 5),     # 30% scanned within last 5 min (real-time)
            random.randint(5, 60),    # 30% within last hour
            random.randint(60, 24*60),# 25% within last day
            random.randint(24*60, 7*24*60),  # 15% within last week
        ] * [3,3,2,2][random.randint(0,3)])  # weighting trick
        rep["captured_at"] = (datetime.now(timezone.utc) - timedelta(minutes=minutes_ago)).isoformat()
        # Scan type — most are scheduled, some on_demand, some real_time daemon
        rep["scan_type"] = random.choices(
            ["scheduled","on_demand","real_time","initial"],
            weights=[60, 15, 20, 5])[0]
        # Device type aligned with DHS CDM / NIST 800-60 asset classification.
        special = random.random()
        # Cloud provider tag for server-class devices
        if "aws" in (model or ""):   rep["cloud_provider"] = "AWS"
        elif "gcp" in (model or ""): rep["cloud_provider"] = "GCP"
        elif "azure" in (model or ""): rep["cloud_provider"] = "Azure"
        else: rep["cloud_provider"] = "on-prem" if dept_id in ("server","db_server","web_server","k8s","container","vpn_concentrator","domain_controller") else ""

        if dept_id == "server":               rep["device_type"] = "server"
        elif dept_id == "db_server":          rep["device_type"] = "database_server"
        elif dept_id == "web_server":         rep["device_type"] = "web_server"
        elif dept_id == "k8s":                rep["device_type"] = "kubernetes_node"
        elif dept_id == "container":          rep["device_type"] = "container_host"
        elif dept_id == "vpn_concentrator":   rep["device_type"] = "vpn_concentrator"
        elif dept_id == "domain_controller":  rep["device_type"] = "domain_controller"
        elif dept_id == "exec_mobile":        rep["device_type"] = "smartphone"
        elif dept_id == "mobile":             rep["device_type"] = "smartphone"
        elif dept_id == "tablet":             rep["device_type"] = "tablet"
        elif special < 0.012:                  rep["device_type"] = "printer"
        elif special < 0.022:                  rep["device_type"] = "ip_camera"
        elif special < 0.027:                  rep["device_type"] = "smart_tv"
        elif special < 0.030:                  rep["device_type"] = "ot_ics_plc"
        elif special < 0.032:                  rep["device_type"] = "medical_device"
        elif special < 0.035:                  rep["device_type"] = "network_router"
        elif special < 0.038:                  rep["device_type"] = "network_switch"
        elif special < 0.042:                  rep["device_type"] = "firewall_appliance"
        elif model in ("imac", "studio"):     rep["device_type"] = "desktop"
        elif model in ("mbp", "mba"):          rep["device_type"] = "laptop"
        elif plat == "windows":                rep["device_type"] = "laptop"
        else:                                  rep["device_type"] = "laptop"

        # Apply department drift to vulns + stig
        drift = DEPT_RISK.get(dept_id, 0.3) * random.uniform(0.5, 1.5)
        # Trim vulns proportionally — high-risk depts keep more
        vulns = rep.get("vulns", {}).get("hits", []) or []
        keep = max(0, int(len(vulns) * drift))
        rep["vulns"]["hits"] = vulns[:keep]
        # STIG: more failures in higher-drift departments
        checks = rep.get("stig", {}).get("checks", [])
        for c in checks:
            if c["result"] == "PASS" and random.random() < drift * 0.4 and c["category"] != "CAT_I":
                c["result"] = "FAIL"
        pass_n = sum(1 for c in checks if c["result"] == "PASS")
        fail_n = sum(1 for c in checks if c["result"] == "FAIL")
        rep["stig"]["pass_count"] = pass_n
        rep["stig"]["fail_count"] = fail_n
        # Threats: scale down for low-drift depts
        if drift < 0.2:
            rep["malware"]["findings"] = []
            rep["edr"]["hits"] = []
            rep["dlp"]["hits"] = []
            rep["intrusion"]["events"] = []
            rep["honeytokens"]["alerts"] = []
        # Recompute summary
        s = rep["summary"]
        s["hwam_assets"] = 1 + len(rep["hardware"]["disks"]) + len(rep["hardware"]["interfaces"])
        s["swam_apps"] = len(rep["software"]["applications"])
        s["stig_pass"] = pass_n
        s["stig_fail"] = fail_n
        s["stig_compliance_ratio"] = pass_n / max(1, pass_n + fail_n)
        s["vuln_count"] = len(rep["vulns"]["hits"])
        s["vuln_critical"] = sum(1 for v in rep["vulns"]["hits"] if v["severity"] == "CRITICAL")
        s["vuln_high"]     = sum(1 for v in rep["vulns"]["hits"] if v["severity"] == "HIGH")

        # Risk score = drift × CVE depth × STIG miss rate, capped 0-10
        cve_boost = min(1.0, len(rep["vulns"]["hits"]) / 10.0) * 4
        stig_boost = (1 - s["stig_compliance_ratio"]) * 3
        device_risk = round(min(9.7, drift * 2.5 + cve_boost + stig_boost + random.uniform(-0.5, 0.5)), 2)
        s["device_risk_score"] = max(0.1, device_risk)
        s["severity"] = ("CRITICAL" if device_risk >= 9 else
                          "HIGH" if device_risk >= 7 else
                          "MEDIUM" if device_risk >= 5 else
                          "LOW" if device_risk >= 3 else "INFO")
        fleet.append(rep)
    return fleet


def synthesize_timeline(fleet: List[Dict[str, Any]], days: int = 30) -> Dict[str, List[Dict[str, Any]]]:
    """
    Build a `host_id -> [{ts, risk, severity, vuln_count}]` timeline showing
    each device's risk over the last N days. The series trends mostly
    downward (remediation wins) with occasional spikes (new CVE landings,
    failed audits). Used by the dashboard timeline chart.
    """
    random.seed(43)
    out: Dict[str, List[Dict[str, Any]]] = {}
    now = datetime.now(timezone.utc)
    for d in fleet:
        host_id = d["host_id"]
        current = d["summary"]["device_risk_score"]
        # Reverse-engineer history: start higher 30 days ago, walk down
        start_risk = min(9.8, current + random.uniform(0.5, 2.5))
        series = []
        for i in range(days * 4, 0, -1):    # 4 samples per day
            ts = (now - timedelta(days=i/4)).isoformat()
            # Linear improvement with noise
            frac = 1 - i / (days * 4)
            risk = start_risk + (current - start_risk) * frac + random.uniform(-0.3, 0.4)
            risk = max(0.0, min(10.0, risk))
            sev = ("CRITICAL" if risk >= 9 else "HIGH" if risk >= 7 else
                    "MEDIUM" if risk >= 5 else "LOW" if risk >= 3 else "INFO")
            # Occasional remediation events (drops)
            if random.random() < 0.04:
                risk = max(0.5, risk - random.uniform(1.0, 3.0))
            series.append({"t": ts, "r": round(risk, 2), "s": sev,
                            "v": int(d["summary"]["vuln_count"] * (1 - frac + 0.3))})
        out[host_id] = series
    return out


def synthesize_fleet_events(fleet: List[Dict[str, Any]], n: int = 50) -> List[Dict[str, Any]]:
    """Generate recent fleet-events for the dashboard event ticker."""
    random.seed(44)
    kinds = ["report_received","remediation_approved","scan_requested",
              "malware_detected","stig_drift","honey_token_tripped","cve_landed"]
    events = []
    now = time.time()
    for _ in range(n):
        d = random.choice(fleet)
        kind = random.choice(kinds)
        events.append({
            "ts": now - random.uniform(0, 86400),
            "kind": kind,
            "host_id": d["host_id"],
            "hostname": d["hostname"],
            "summary": d["summary"],
        })
    events.sort(key=lambda e: -e["ts"])
    return events
