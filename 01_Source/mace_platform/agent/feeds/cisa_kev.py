"""
CISA Known Exploited Vulnerabilities (KEV) catalog.

Source: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json

When a CVE is in KEV, its exploit_status is upgraded to "exploit_public" and
its EPSS-derived priority boost is uncapped: KEV-listed vulns always rank at
or above CVSS 8.0 in the remediation plan regardless of their CVSS, because
they have confirmed in-the-wild exploitation.
"""
from __future__ import annotations
import json
import urllib.request
from typing import Set

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev_ids(timeout: int = 30) -> Set[str]:
    try:
        with urllib.request.urlopen(KEV_URL, timeout=timeout) as resp:
            payload = json.loads(resp.read())
        return {v.get("cveID", "") for v in payload.get("vulnerabilities", []) if v.get("cveID")}
    except Exception:
        return set()


def annotate_known_exploited(kev_ids: Set[str]) -> int:
    """Mark records present in KEV as exploit_public. Returns count annotated."""
    from .. import cve_db
    n = 0
    new_records = []
    for rec in cve_db.CVE_DATABASE:
        if rec.cve_id in kev_ids and rec.exploit_status != "exploit_public":
            # CVERecord is frozen — rebuild
            from dataclasses import replace
            new_records.append(replace(rec, exploit_status="exploit_public"))
            n += 1
        else:
            new_records.append(rec)
    cve_db.CVE_DATABASE[:] = new_records
    # Rebuild index
    cve_db._INDEX = {}
    for rec in cve_db.CVE_DATABASE:
        cve_db._INDEX.setdefault(cve_db._normalise_pkg(rec.affected_pkg), []).append(rec)
    return n
