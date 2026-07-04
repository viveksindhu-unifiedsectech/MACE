"""
Self-remediation executor.

This module turns a RemediationAction into actual change on disk by running
its remediation_cmd. Because that is necessarily a privileged, lossy
operation we wrap it in two safety layers:

  • Allowlist     — only specific verbs may be auto-executed
                      (brew/apt/dnf upgrade, defaults write, launchctl unload,
                      softwareupdate -i, pip install --upgrade …).
                      Anything outside the allowlist is downgraded to
                      "needs human approval" and returned untouched.

  • Audit log     — every executed command is appended to
                      ~/.mace-agent/audit.log with timestamp, host id, the
                      RemediationAction snapshot, the exit code and the
                      first 4 KB of stdout/stderr. This produces the
                      chain-of-custody trail UREA requires.

The GUI / dashboard calls `execute(action, mode='ask')` which raises a
confirmation prompt before running. The daemon calls
`execute(action, mode='auto')` only when the action's priority_score is in
the auto-approved band (configured per tenant; default ≥ 9.0 + KEV-listed).
"""
from __future__ import annotations
import json
import os
import re
import shlex
import subprocess
import time
from dataclasses import asdict
from pathlib import Path
from typing import Any, Dict, Optional


AUDIT_LOG = Path(os.environ.get("MACE_AUDIT_LOG",
                                 str(Path.home() / ".mace-agent" / "audit.log")))


SAFE_VERBS = re.compile(
    r"^("
    r"brew\s+(upgrade|reinstall|install)|"
    r"apt-get\s+install\s+-y\s+--only-upgrade|"
    r"apt-get\s+upgrade\s+-y\s+--with-new-pkgs|"
    r"dnf\s+upgrade\s+-y|"
    r"yum\s+upgrade\s+-y|"
    r"pip(3)?\s+install\s+--upgrade\s+'?[a-zA-Z0-9_.\-=<>!]+'?$|"
    r"npm\s+install\s+-g\s+[a-zA-Z0-9_@./\-]+@latest|"
    r"softwareupdate\s+-i\s+-a|"
    r"defaults\s+(write|delete)\s+|"
    r"launchctl\s+(unload|disable)\s+|"
    r"powershell\s+-Command\s+\"Install-WindowsUpdate"
    r")"
)


def is_safe(cmd: str) -> bool:
    if not cmd: return False
    if "|" in cmd or "&&" in cmd or ";" in cmd or "$(" in cmd or "`" in cmd:
        return False
    return bool(SAFE_VERBS.match(cmd.strip()))


def execute(action: Dict[str, Any],
             mode: str = "ask",
             host_id: Optional[str] = None,
             confirm_fn=None,
             dry_run: bool = False,
             approved_by: Optional[str] = None) -> Dict[str, Any]:
    """
    Execute (or refuse) one RemediationAction.

    mode = 'ask'   → call confirm_fn(action) for human y/n. If None, refuse.
    mode = 'auto'  → require is_safe(cmd) AND priority_score ≥ 9.0.
    mode = 'plan'  → never execute; just return what would happen.
    """
    import getpass
    try: who = approved_by or getpass.getuser()
    except Exception: who = approved_by or "system"
    cmd = action.get("remediation_cmd") or ""
    title = action.get("title", "")
    pri   = float(action.get("priority_score", 0))
    result = {
        "action_id": action.get("action_id"),
        "title":     title,
        "host_id":   host_id,
        "mode":      mode,
        "cmd":       cmd,
        "executed":  False,
        "exit_code": None,
        "stdout":    "",
        "stderr":    "",
        "decision":  "skipped",
        "started_at": None, "finished_at": None,
        "approved_by": who,
        "approver_role": "macey-auto" if mode == "auto" else "analyst",
    }

    if mode == "plan" or dry_run:
        result["decision"] = "plan"
        _audit(result, action); return result

    if not is_safe(cmd):
        result["decision"] = "refused_unsafe_cmd"
        result["stderr"]   = "Command is not in the auto-remediation allowlist."
        _audit(result, action); return result

    if mode == "auto" and pri < 9.0:
        result["decision"] = "refused_low_priority"
        result["stderr"]   = "Auto-mode requires priority_score ≥ 9.0."
        _audit(result, action); return result

    if mode == "ask":
        ok = confirm_fn(action) if callable(confirm_fn) else False
        if not ok:
            result["decision"] = "user_declined"
            _audit(result, action); return result

    # Execute
    result["started_at"] = time.time()
    try:
        proc = subprocess.run(shlex.split(cmd), capture_output=True, text=True,
                               timeout=600, check=False)
        result["executed"]   = True
        result["exit_code"]  = proc.returncode
        result["stdout"]     = (proc.stdout or "")[:4096]
        result["stderr"]     = (proc.stderr or "")[:4096]
        result["decision"]   = "executed_ok" if proc.returncode == 0 else "executed_fail"
    except Exception as e:
        result["decision"] = "exception"
        result["stderr"]   = str(e)[:4096]
    result["finished_at"] = time.time()
    _audit(result, action)
    return result


def _audit(result: dict, action: dict) -> None:
    try:
        AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
        line = json.dumps({"audit_ts": time.time(),
                            "action": action,
                            "result": result}, default=str)
        with AUDIT_LOG.open("a") as f:
            f.write(line + "\n")
    except Exception:
        pass
