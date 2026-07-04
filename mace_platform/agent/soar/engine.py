"""
Playbook engine — runs a multi-step incident response in order, capturing
the outcome of each step into a PlaybookRun record that flows back into
the audit log.
"""
from __future__ import annotations
import json
import time
import urllib.request
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class PlaybookStep:
    name: str
    kind: str                # shell | http | wait | signal
    target: str = ""         # shell cmd / URL / event-kind
    body: Optional[Dict[str, Any]] = None
    timeout_s: int = 60
    require_priority: float = 0.0   # min CDCS / priority_score to allow
    continue_on_failure: bool = False


@dataclass
class Playbook:
    name: str
    description: str
    trigger: str             # cdcs.alert | malware.detected | itdr.mfa_bombing | …
    steps: List[PlaybookStep] = field(default_factory=list)


@dataclass
class StepResult:
    name: str
    kind: str
    started_at: float
    finished_at: float
    success: bool
    output: str = ""
    error: str = ""


@dataclass
class PlaybookRun:
    playbook: str
    trigger_payload: Dict[str, Any]
    started_at: float
    finished_at: float = 0.0
    success: bool = False
    steps: List[StepResult] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        return d


# ── built-in catalogue ───────────────────────────────────────────────

BUILTINS: Dict[str, Playbook] = {
    "pb_ransomware_isolation": Playbook(
        name="pb_ransomware_isolation",
        description="Quarantine the file, kill the process, drop network, alert SOC.",
        trigger="malware.detected",
        steps=[
            PlaybookStep("quarantine_file",     "shell", "{remediation_cmd}",
                         require_priority=9.0),
            PlaybookStep("notify_soc",          "http",
                         "{SLACK_WEBHOOK}",
                         body={"text": "🚨 Ransomware indicator on {hostname}"}),
            PlaybookStep("drop_network",        "signal", "network_isolate",
                         body={"reason": "ransomware indicator"}),
            PlaybookStep("snapshot_evidence",   "shell",
                         "tar -czf /var/log/mace-evidence-{ts}.tgz /var/log /etc",
                         require_priority=9.0, continue_on_failure=True),
        ],
    ),
    "pb_mfa_bombing_block": Playbook(
        name="pb_mfa_bombing_block",
        description="Block user temporarily, revoke MFA push, page on-call.",
        trigger="itdr.mfa_bombing",
        steps=[
            PlaybookStep("revoke_sessions",     "http",
                         "{OKTA_REVOKE_URL}",
                         body={"user": "{user}", "reason": "mfa_bombing"}),
            PlaybookStep("page_oncall",         "http",
                         "{PD_WEBHOOK}",
                         body={"incident_key": "{user}", "severity": "high"}),
        ],
    ),
    "pb_critical_cve_patch": Playbook(
        name="pb_critical_cve_patch",
        description="Auto-patch a CRITICAL CVE if the remediation_cmd is allowlisted.",
        trigger="cdcs.alert",
        steps=[
            PlaybookStep("patch", "shell", "{remediation_cmd}", require_priority=9.0),
            PlaybookStep("rescan", "signal", "scan_now"),
        ],
    ),
    "pb_unauthorized_lan_access": Playbook(
        name="pb_unauthorized_lan_access",
        description="Add LAN attacker to host firewall blocklist.",
        trigger="intrusion.lan_attempt",
        steps=[
            PlaybookStep("block_ip", "shell",
                         "pfctl -t mace_block -T add {source_ip}",
                         require_priority=7.0),
            PlaybookStep("alert", "http", "{SLACK_WEBHOOK}",
                         body={"text": "Blocked LAN IP {source_ip} on {hostname}"}),
        ],
    ),
    "pb_lost_device_lock": Playbook(
        name="pb_lost_device_lock",
        description="Lock screen + erase cached secrets when device reported lost.",
        trigger="manual",
        steps=[
            PlaybookStep("lock_screen", "shell", "pmset displaysleepnow",
                         require_priority=0.0),
            PlaybookStep("evict_creds", "signal", "evict_credentials"),
        ],
    ),
}


def list_builtin_playbooks() -> List[Dict[str, Any]]:
    return [{"name": p.name, "trigger": p.trigger, "description": p.description,
             "steps": len(p.steps)} for p in BUILTINS.values()]


# ── runner ───────────────────────────────────────────────────────────

def _interpolate(s: str, ctx: Dict[str, Any]) -> str:
    out = s
    for k, v in ctx.items():
        out = out.replace("{" + k + "}", str(v))
    return out


def run_playbook(playbook: Playbook, trigger_payload: Dict[str, Any],
                  *, dry_run: bool = False) -> PlaybookRun:
    from ..auto_remediate import execute as exec_safe
    run = PlaybookRun(playbook=playbook.name,
                       trigger_payload=trigger_payload,
                       started_at=time.time())
    ctx = {**trigger_payload, "ts": int(time.time())}

    for step in playbook.steps:
        t0 = time.time()
        sr = StepResult(name=step.name, kind=step.kind,
                         started_at=t0, finished_at=t0, success=False)
        try:
            target = _interpolate(step.target, ctx)
            if step.kind == "shell":
                if dry_run:
                    sr.output = f"DRY: {target}"; sr.success = True
                else:
                    action = {
                        "action_id": step.name,
                        "title": step.name,
                        "remediation_cmd": target,
                        "priority_score": step.require_priority,
                    }
                    res = exec_safe(action, mode="auto",
                                     host_id=ctx.get("host_id"))
                    sr.success = res["decision"] in ("executed_ok", "plan")
                    sr.output  = res.get("stdout", "")[:1024]
                    sr.error   = res.get("stderr", "")[:1024]
            elif step.kind == "http":
                body = {k: _interpolate(str(v), ctx) for k, v in (step.body or {}).items()}
                if dry_run or not target.startswith("http"):
                    sr.output = f"DRY POST {target} {body}"; sr.success = True
                else:
                    req = urllib.request.Request(
                        target, data=json.dumps(body).encode("utf-8"),
                        headers={"Content-Type": "application/json"}, method="POST")
                    with urllib.request.urlopen(req, timeout=step.timeout_s) as resp:
                        sr.success = 200 <= resp.status < 300
                        sr.output  = f"HTTP {resp.status}"
            elif step.kind == "wait":
                if not dry_run: time.sleep(int(target or "5"))
                sr.success = True
            elif step.kind == "signal":
                # Signals are emitted back to the daemon — recorded in audit only.
                sr.output  = f"signal:{target} body={step.body}"
                sr.success = True
            else:
                sr.error = f"unknown step kind: {step.kind}"
        except Exception as e:
            sr.error = str(e)[:1024]
        sr.finished_at = time.time()
        run.steps.append(sr)
        if not sr.success and not step.continue_on_failure:
            break
    run.finished_at = time.time()
    run.success = all(s.success or any(st.continue_on_failure
                                         for st in playbook.steps
                                         if st.name == s.name)
                       for s in run.steps)
    return run
