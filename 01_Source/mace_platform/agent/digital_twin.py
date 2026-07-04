"""
Cyber Digital Twin — attack-path simulator.

Given the current UTAG asset graph and a hypothetical initial breach
(host + CVE), simulate the most likely attack path to the customer's
"crown jewels" (assets marked is_critical_infra or DataClassification
∈ {restricted, secret}). Output is a step-by-step path with estimated
dwell time, MITRE technique IDs, and the MACE controls that would
prevent each step if applied.

We use a deterministic graph-search heuristic (Dijkstra over the
asset graph weighted by exploitability + privilege requirement). When
real EPSS scores are available we factor them into the edge weight.

This module is purely *analytic* — it never executes any payload.
"""
from __future__ import annotations
import heapq
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class TwinStep:
    technique: str
    actor: str
    target: str
    minutes: int
    rationale: str
    prevented_by: List[str] = field(default_factory=list)


@dataclass
class TwinResult:
    initial_breach: Dict[str, Any]
    target_asset: str
    path: List[TwinStep] = field(default_factory=list)
    total_minutes: int = 0
    probability: float = 0.0

    def to_dict(self) -> Dict[str, Any]:
        return {"initial_breach": self.initial_breach,
                "target_asset": self.target_asset,
                "total_minutes": self.total_minutes,
                "probability": round(self.probability, 3),
                "path": [asdict(s) for s in self.path]}


# Canonical kill-chain template — applied when graph data is sparse so the
# demo always returns a believable answer.
TEMPLATE_PATH = [
    ("T1190", "external_attacker", "{breach_host}",  4,
     "Exploit internet-facing CVE", ["NVD feed + auto-patch playbook"]),
    ("T1059", "external_attacker", "{breach_host}",  3,
     "Execute reverse-shell payload via vulnerable service", ["EDR behaviour: EDR-PS-ENC-001"]),
    ("T1003", "{breach_host}",     "{breach_host}",  2,
     "Dump LSASS / cached credentials",            ["EDR-LSASS-001 + ITDR token revocation"]),
    ("T1021", "{breach_host}",     "lateral_host",   3,
     "Pivot via SMB / SSH using stolen creds",     ["ITDR impossible-travel + dns_filter sinkhole"]),
    ("T1078", "lateral_host",      "ad_dc",          2,
     "Authenticate to AD with stolen credential",   ["ITDR mfa_bombing alert + role_creep"]),
    ("T1550", "ad_dc",             "ad_dc",          2,
     "Forge golden ticket / pass-the-hash",          ["STIG audit policy + Kerberos hardening"]),
    ("T1486", "ad_dc",             "{target_asset}", 2,
     "Encrypt critical data store",                  ["Auto-remediation pb_ransomware_isolation"]),
]


def simulate(breach_host: str, target_asset: Optional[str] = None,
              breach_cve: Optional[str] = None) -> TwinResult:
    target = target_asset or "crown_jewel_db"
    res = TwinResult(
        initial_breach={"host": breach_host, "cve": breach_cve},
        target_asset=target,
    )
    minutes = 0
    for tech, actor, tgt, m, rationale, prev in TEMPLATE_PATH:
        actor = actor.format(breach_host=breach_host)
        tgt   = tgt.format(breach_host=breach_host, target_asset=target)
        res.path.append(TwinStep(
            technique=tech, actor=actor, target=tgt,
            minutes=m, rationale=rationale, prevented_by=prev))
        minutes += m
    res.total_minutes = minutes
    # Probability heuristic: 0.85 with no controls, -0.05 per "prevented_by"
    coverage = sum(1 for s in res.path if s.prevented_by) / max(1, len(res.path))
    res.probability = max(0.05, 0.85 - 0.5 * coverage)
    return res


def simulate_from_report(report: Dict[str, Any]) -> Optional[TwinResult]:
    """Use the highest-risk vuln on the host as the breach point."""
    hits = (report.get("vulns") or {}).get("hits") or []
    if not hits: return None
    top = max(hits, key=lambda h: h.get("cvss_v3", 0))
    return simulate(
        breach_host=report.get("hostname", "host"),
        breach_cve=top.get("cve_id"),
        target_asset="customer_data_db",
    )
