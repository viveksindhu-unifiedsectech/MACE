"""
DISA STIG library / CIS Benchmark feed.

Public DISA STIG zips are published at
  https://public.cyber.mil/stigs/downloads/
and CIS Benchmarks are linked from
  https://www.cisecurity.org/cis-benchmarks/

The DISA STIG Viewer ships XCCDF (XML) profiles inside the per-product ZIPs.
We download the ZIP for each profile we care about, parse Rule/check-content
out of XCCDF, and merge new check definitions into the agent's STIG runner.

A failure to fetch is non-fatal: the agent already ships with a
hand-curated baseline (see stig.py) so checks still run offline.

This module focuses on metadata refresh — keeping titles, severities and
remediation text current with DISA's latest releases. Probe code is shipped
with the agent (we can't safely execute downloaded probes).
"""
from __future__ import annotations
import io
import os
import re
import urllib.request
import zipfile
import xml.etree.ElementTree as ET
from pathlib import Path
from typing import Dict, List

# Catalog of STIG ZIPs we sync. These URLs follow DISA's public pattern and
# are kept here so updates can be made without touching agent code.
STIG_CATALOG: Dict[str, str] = {
    "macOS_14":         "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apple_macOS_14_V1R1_STIG.zip",
    "macOS_13":         "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apple_macOS_13_V1R3_STIG.zip",
    "Windows_11":       "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_MS_Windows_11_V1R6_STIG.zip",
    "RHEL_9":           "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_RHEL_9_V1R5_STIG.zip",
    "Ubuntu_22":        "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_CAN_Ubuntu_22-04_LTS_V1R3_STIG.zip",
    "Apple_iOS_17":     "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Apple_iOS_iPadOS_17_V1R2_STIG.zip",
    "Android_14":       "https://dl.dod.cyber.mil/wp-content/uploads/stigs/zip/U_Samsung_Android_14_with_Knox_V1R1_STIG.zip",
}

CACHE_DIR = Path(os.environ.get("MACE_CACHE_DIR", str(Path.home() / ".mace-agent" / "cache")))


def _ensure_cache():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _fetch_zip(url: str, timeout: int = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "UnifiedSec-MACE-Agent/1.0"})
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return resp.read()


def _parse_xccdf(xml_bytes: bytes) -> List[Dict]:
    ns = {"x": "http://checklists.nist.gov/xccdf/1.1"}
    rules: List[Dict] = []
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return rules
    for rule in root.iter("{http://checklists.nist.gov/xccdf/1.1}Rule"):
        rid    = rule.get("id", "")
        sev    = rule.get("severity", "low")
        title  = (rule.findtext("x:title", default="", namespaces=ns) or "").strip()
        descr  = (rule.findtext("x:description", default="", namespaces=ns) or "").strip()
        fix    = (rule.findtext("x:fixtext", default="", namespaces=ns) or "").strip()
        rules.append({
            "rule_id": rid,
            "severity": _normalise_severity(sev),
            "title": title[:240],
            "description": re.sub(r"<[^>]+>", "", descr)[:600],
            "fix": re.sub(r"<[^>]+>", "", fix)[:600],
        })
    return rules


def _normalise_severity(s: str) -> str:
    s = (s or "").lower()
    if s == "high":   return "CAT_I"
    if s == "medium": return "CAT_II"
    if s == "low":    return "CAT_III"
    return "CAT_III"


def refresh_catalog(only: list[str] | None = None) -> Dict[str, int]:
    """Download and parse every catalogued STIG. Returns {profile: rule_count}."""
    _ensure_cache()
    result: Dict[str, int] = {}
    for profile, url in STIG_CATALOG.items():
        if only and profile not in only: continue
        try:
            blob = _fetch_zip(url)
        except Exception:
            cached = CACHE_DIR / f"stig_{profile}.zip"
            if not cached.exists():
                result[profile] = 0
                continue
            blob = cached.read_bytes()
        else:
            (CACHE_DIR / f"stig_{profile}.zip").write_bytes(blob)
        # Find XCCDF inside the zip
        rules: List[Dict] = []
        try:
            with zipfile.ZipFile(io.BytesIO(blob)) as zf:
                for name in zf.namelist():
                    if name.endswith(".xml") and "xccdf" in name.lower():
                        rules = _parse_xccdf(zf.read(name))
                        break
        except Exception:
            pass
        # Cache parsed
        if rules:
            (CACHE_DIR / f"stig_{profile}.json").write_text(__import__("json").dumps(rules))
        result[profile] = len(rules)
    return result


def load_cached_rules(profile: str) -> List[Dict]:
    p = CACHE_DIR / f"stig_{profile}.json"
    if not p.exists():
        return []
    try:
        return __import__("json").loads(p.read_text())
    except Exception:
        return []
