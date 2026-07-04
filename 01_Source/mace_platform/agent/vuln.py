"""
Vuln — CVE matcher.

Cross-references the SWAM inventory against the bundled CVE database
(cve_db.py) to produce VulnHit entries. The agent does this *locally*, so
unlike a network-based Tenable scan it does not need to send your inventory
to a cloud service.
"""
from __future__ import annotations
from typing import List

from .cve_db import cve_db_version, find_cves
from .report import SoftwareInventory, VulnHit, VulnReport


def collect_vulns(software: SoftwareInventory) -> VulnReport:
    rep = VulnReport(cve_db_version=cve_db_version())
    seen = set()

    # Match by OS as well — e.g. Windows kernel CVEs that key on the OS name.
    pseudo_apps = []
    if software.os_name:
        pseudo_apps.append(("Windows" if "Windows" in software.os_name else software.os_name,
                            software.os_version))
        pseudo_apps.append(("Python", _strip_first_python(software)))

    for entry in software.applications:
        pseudo_apps.append((entry.name, entry.version))
    rep.scanned_packages = len(pseudo_apps)

    for name, version in pseudo_apps:
        if not name: continue
        for rec in find_cves(name, version or ""):
            key = (rec.cve_id, name)
            if key in seen: continue
            seen.add(key)
            rep.hits.append(VulnHit(
                cve_id=rec.cve_id,
                cvss_v3=rec.cvss_v3,
                severity=rec.severity,
                affected_component=name,
                installed_version=version or "",
                fixed_version=rec.fixed_version,
                epss_score=rec.epss_score,
                exploit_status=rec.exploit_status,
                patch_available=bool(rec.fixed_version),
                description=rec.description,
                remediation=rec.remediation,
                remediation_cmd=rec.remediation_cmd,
            ))

    rep.hits.sort(key=lambda h: (-h.cvss_v3, h.cve_id))
    return rep


def _strip_first_python(s: SoftwareInventory) -> str:
    for a in s.applications:
        if a.name.lower() == "python":
            return a.version
    return ""
