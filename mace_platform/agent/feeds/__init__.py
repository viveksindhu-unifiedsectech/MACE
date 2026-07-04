"""
External-feed integrations for the MACE Endpoint Agent.

These modules keep the agent's CVE database, STIG baselines and threat
intelligence current. They run on a daily schedule (or on demand via
`mace-agent update`) and merge the upstream data into the local store.

  nvd        — NIST National Vulnerability Database (NVD 2.0 API).
  cisa_kev   — CISA Known Exploited Vulnerabilities catalog.
  epss       — FIRST.org EPSS daily score feed.
  stig       — DISA STIG library / CIS Benchmarks (XCCDF zip downloads).

All feeds degrade gracefully when offline: failure to fetch keeps the
last-known good snapshot bundled with the agent (cve_db.py).
"""
from .scheduler import update_all, FeedUpdate, last_update_status

__all__ = ["update_all", "FeedUpdate", "last_update_status"]
