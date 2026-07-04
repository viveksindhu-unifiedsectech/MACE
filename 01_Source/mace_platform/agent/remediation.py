"""
Algorithm-driven, real-time remediation planner.

Given a freshly produced MACEAgentReport this module:

  1. Scores every vulnerability and STIG failure with the same CDCS-style
     weighting used by the main MACE algorithm — so a "what to fix first"
     answer is consistent with what the SOC will see in the dashboard.

  2. Bundles fixes that share a remediation (e.g. upgrading OpenSSL once
     resolves three CVEs) so the analyst sees N actions, not N CVE rows.

  3. Emits machine-readable RemediationAction objects:
       - priority_score (0–10)
       - severity        (CRITICAL/HIGH/MEDIUM/LOW)
       - affected_count
       - one-line shell command (when available)
       - human description + rationale

The same prioritisation is used in the real-time daemon loop: whenever the
event stream triggers a rescan, the new RemediationPlan is diff'd against
the previous one and only the *deltas* are pushed to the UI / ingest so the
analyst sees newly-introduced exposure immediately.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional

from .report import MACEAgentReport, STIGCheck, VulnHit


# Algorithm weights — kept consistent with CDCS sub-scores.
W_CVSS    = 0.55
W_EPSS    = 0.20
W_EXPLOIT = 0.15
W_SLA     = 0.10

EXPLOIT_FACTOR = {
    "exploit_public":   1.50,
    "exploit_poc":      1.20,
    "no_exploit_known": 1.00,
}

STIG_CAT_WEIGHT = {"CAT_I": 1.00, "CAT_II": 0.66, "CAT_III": 0.33}


@dataclass
class RemediationAction:
    action_id: str
    title: str
    severity: str
    priority_score: float
    affected_count: int
    component: str
    fixed_version: str = ""
    cve_ids: List[str] = field(default_factory=list)
    stig_ids: List[str] = field(default_factory=list)
    description: str = ""
    remediation: str = ""
    remediation_cmd: str = ""
    rationale: str = ""
    introduced_at: float = 0.0


@dataclass
class RemediationPlan:
    generated_at: str
    host_id: str
    actions: List[RemediationAction] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "generated_at": self.generated_at,
            "host_id": self.host_id,
            "actions": [asdict(a) for a in self.actions],
        }


# ── scoring ──────────────────────────────────────────────────────────

def _score_vuln(v: VulnHit) -> float:
    cvss_norm = max(0.0, min(1.0, v.cvss_v3 / 10.0))
    epss      = max(0.0, min(1.0, v.epss_score))
    expl      = (EXPLOIT_FACTOR.get(v.exploit_status, 1.0) - 1.0) / 0.5  # 0..1
    expl      = max(0.0, min(1.0, expl))
    sla       = 1.0 if v.patch_available else 0.5
    raw = (W_CVSS * cvss_norm) + (W_EPSS * epss) + (W_EXPLOIT * expl) + (W_SLA * sla)
    return round(10.0 * raw, 2)


def _score_stig(c: STIGCheck) -> float:
    if c.result != "FAIL":
        return 0.0
    w = STIG_CAT_WEIGHT.get(c.category, 0.33)
    return round(10.0 * w * 0.55, 2)        # cap STIG-only findings under "HIGH"


def _severity_for(score: float) -> str:
    if score >= 9: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 5: return "MEDIUM"
    if score >= 3: return "LOW"
    return "INFO"


# ── bundling ─────────────────────────────────────────────────────────

def _bundle_key_for_vuln(v: VulnHit) -> str:
    fv = v.fixed_version or "any"
    return f"vuln::{v.affected_component.lower()}::{fv}"


def _bundle_key_for_stig(c: STIGCheck) -> str:
    # Bundle STIG fixes by remediation command so e.g. all FileVault checks
    # collapse into one action.
    return f"stig::{c.check_id}"


def build_plan(report: MACEAgentReport) -> RemediationPlan:
    bundles: Dict[str, RemediationAction] = {}

    # — Vulnerabilities —
    for v in report.vulns.hits:
        score = _score_vuln(v)
        v.priority_score = score
        key = _bundle_key_for_vuln(v)
        if key not in bundles:
            bundles[key] = RemediationAction(
                action_id=f"act-{len(bundles)+1:03d}",
                title=f"Update {v.affected_component} to {v.fixed_version or 'a fixed version'}",
                severity=_severity_for(score),
                priority_score=score,
                affected_count=0,
                component=v.affected_component,
                fixed_version=v.fixed_version,
                remediation=v.remediation or "Apply vendor patch.",
                remediation_cmd=v.remediation_cmd,
                description=v.description,
                rationale=(f"CVSS {v.cvss_v3} · EPSS {v.epss_score:.2f} · "
                            f"exploit:{v.exploit_status}"),
            )
        b = bundles[key]
        b.affected_count += 1
        b.cve_ids.append(v.cve_id)
        if score > b.priority_score:
            b.priority_score = score
            b.severity = _severity_for(score)

    # — STIG failures —
    for c in report.stig.checks:
        if c.result != "FAIL":
            continue
        score = _score_stig(c)
        key = _bundle_key_for_stig(c)
        bundles[key] = RemediationAction(
            action_id=f"act-{len(bundles)+1:03d}",
            title=c.title,
            severity=_severity_for(score),
            priority_score=score,
            affected_count=1,
            component="OS hardening",
            stig_ids=[c.check_id],
            remediation=c.remediation,
            description=f"Observed: {c.observed}. Expected: {c.expected}.",
            rationale=f"STIG {c.category}",
        )

    # — Malware findings (always top priority) —
    for f in (report.malware or {}).get("findings", []) or []:
        sev = f.get("severity", "HIGH")
        score = 10.0 if sev == "CRITICAL" else 9.2 if sev == "HIGH" else 7.0
        bundles[f"malware::{f.get('path','')}::{f.get('sha256','')}"] = RemediationAction(
            action_id=f"act-{len(bundles)+1:03d}",
            title=f"Quarantine {f.get('family','unknown malware')}",
            severity=sev, priority_score=score, affected_count=1,
            component=f.get("path","") or f.get("family",""),
            remediation=f.get("remediation",""),
            remediation_cmd=f.get("remediation_cmd",""),
            description=f.get("description",""),
            rationale=f"detector:{f.get('detector')}",
        )

    # — Hackable-software / risky-config findings —
    for h in (report.hackable or {}).get("findings", []) or []:
        sev = h.get("severity", "MEDIUM")
        score = {"CRITICAL": 9.2, "HIGH": 7.5, "MEDIUM": 5.5, "LOW": 3.5}.get(sev, 4.0)
        bundles[f"hackable::{h.get('rule_id')}::{h.get('component')}"] = RemediationAction(
            action_id=f"act-{len(bundles)+1:03d}",
            title=h.get("title",""), severity=sev, priority_score=score,
            affected_count=1, component=h.get("component",""),
            remediation=h.get("remediation",""),
            remediation_cmd=h.get("remediation_cmd",""),
            description=h.get("observed",""),
            rationale="risky configuration",
        )

    # Sort highest priority first
    actions = sorted(bundles.values(),
                     key=lambda a: (-a.priority_score, -a.affected_count, a.component))
    return RemediationPlan(
        generated_at=report.captured_at,
        host_id=report.host_id,
        actions=actions,
    )


def diff_plans(prev: Optional[RemediationPlan], curr: RemediationPlan) -> List[RemediationAction]:
    """Return only the actions in `curr` that are new or escalated since `prev`."""
    if not prev:
        return list(curr.actions)
    prev_index = {(a.component, frozenset(a.cve_ids), frozenset(a.stig_ids)): a
                  for a in prev.actions}
    deltas: List[RemediationAction] = []
    for a in curr.actions:
        key = (a.component, frozenset(a.cve_ids), frozenset(a.stig_ids))
        p = prev_index.get(key)
        if p is None or a.priority_score > p.priority_score + 0.5:
            deltas.append(a)
    return deltas
