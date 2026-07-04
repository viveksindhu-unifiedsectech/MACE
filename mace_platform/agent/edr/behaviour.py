"""
Behaviour-based EDR detection — finds malware patterns at runtime that
signature scanners miss.
"""
from __future__ import annotations
import os
import platform
import re
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass
class BehaviourHit:
    rule_id: str
    technique: str               # MITRE ATT&CK ID, e.g. T1003.001
    title: str
    severity: str
    pid: int = 0
    process: str = ""
    parent: str = ""
    cmdline: str = ""
    evidence: str = ""
    remediation: str = ""


@dataclass
class BehaviourReport:
    hits: List[BehaviourHit] = field(default_factory=list)
    processes_examined: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"hits": [asdict(h) for h in self.hits],
                "processes_examined": self.processes_examined}


# ── rule set ─────────────────────────────────────────────────────────

RULES = [
    # (technique, rule_id, title, severity, predicate on (proc, parent, cmd))
    ("T1003.001", "EDR-LSASS-001", "LSASS access by non-system process",
     "CRITICAL",
     lambda p, par, cmd: ("lsass" in cmd.lower() and "rundll32" not in p.lower()
                            and "system" not in par.lower())),
    ("T1059.001", "EDR-PS-ENC-001", "PowerShell encoded command",
     "HIGH",
     lambda p, par, cmd: ("powershell" in p.lower() and re.search(r"-e(nc)?(odedcommand)?\s+[A-Za-z0-9+/=]{30,}", cmd))),
    ("T1218.005", "EDR-MSHTA-001", "mshta launching remote content",
     "HIGH",
     lambda p, par, cmd: ("mshta" in p.lower() and ("http://" in cmd or "https://" in cmd))),
    ("T1218.011", "EDR-RUNDLL-001", "rundll32 with javascript: protocol",
     "HIGH",
     lambda p, par, cmd: ("rundll32" in p.lower() and "javascript:" in cmd.lower())),
    ("T1059.003", "EDR-CHILD-OFFICE", "Office spawning shell",
     "HIGH",
     lambda p, par, cmd: (("winword" in par.lower() or "excel" in par.lower()
                            or "powerpnt" in par.lower())
                           and any(s in p.lower() for s in ("cmd", "powershell", "wscript", "cscript")))),
    ("T1546.003", "EDR-WMI-PERSIST", "WMI event subscription created",
     "HIGH",
     lambda p, par, cmd: ("wmic" in p.lower() and "create" in cmd.lower()
                           and "eventsubscription" in cmd.lower())),
    ("T1620",     "EDR-CS-BEACON", "Cobalt Strike beacon mutex / pattern",
     "CRITICAL",
     lambda p, par, cmd: any(m in cmd.lower() for m in
        ("status_666", "mscoree.dll", "/0x", "metsrv.dll", "beacon.dll"))),
    ("T1574.011", "EDR-DLL-PROXY", "DLL search-order hijack candidate (rundll32 + tmp)",
     "MEDIUM",
     lambda p, par, cmd: ("rundll32" in p.lower() and (re.search(r"\\Temp\\|/tmp/", cmd)))),
    ("T1110",     "EDR-BRUTE-LOC", "Local brute-force tool detected",
     "MEDIUM",
     lambda p, par, cmd: any(t in p.lower() for t in ("hydra", "medusa", "hashcat"))),
]


# ── process enumeration ──────────────────────────────────────────────

def _ps_unix() -> List[tuple]:
    """Return list of (pid, ppid, comm, args)."""
    out: List[tuple] = []
    try:
        proc = subprocess.run(["ps", "-eo", "pid,ppid,comm,args"],
                                 capture_output=True, text=True, timeout=8)
    except Exception:
        return out
    for line in (proc.stdout or "").splitlines()[1:]:
        parts = line.split(None, 3)
        if len(parts) < 4: continue
        try:
            pid = int(parts[0]); ppid = int(parts[1])
            out.append((pid, ppid, parts[2], parts[3]))
        except Exception:
            continue
    return out


def _ps_windows() -> List[tuple]:
    if not shutil.which("powershell"): return []
    out: List[tuple] = []
    try:
        ps = subprocess.run(["powershell", "-NoProfile", "-Command",
            "Get-CimInstance Win32_Process | "
            "Select-Object ProcessId,ParentProcessId,Name,CommandLine | "
            "ConvertTo-Json -Compress"],
            capture_output=True, text=True, timeout=20)
        import json as _j
        data = _j.loads(ps.stdout or "[]")
        if isinstance(data, dict): data = [data]
        for d in data:
            out.append((d.get("ProcessId", 0) or 0, d.get("ParentProcessId", 0) or 0,
                         d.get("Name", "") or "", d.get("CommandLine", "") or ""))
    except Exception:
        pass
    return out


def scan_memory_behaviour() -> BehaviourReport:
    rep = BehaviourReport()
    plat = platform.system().lower()
    procs = _ps_windows() if plat == "windows" else _ps_unix()
    by_pid = {p[0]: p for p in procs}
    rep.processes_examined = len(procs)

    for (pid, ppid, comm, args) in procs:
        parent = (by_pid.get(ppid) or (0, 0, "", ""))[2]
        for tech, rid, title, sev, predicate in RULES:
            try:
                if predicate(comm, parent, args):
                    rep.hits.append(BehaviourHit(
                        rule_id=rid, technique=tech, title=title, severity=sev,
                        pid=pid, process=comm, parent=parent,
                        cmdline=args[:300], evidence=args[:300],
                        remediation="Kill the process tree and quarantine related files; "
                                     "investigate parent process."))
            except Exception:
                continue
    return rep
