"""
Agent runner — orchestrates HWAM + SWAM + STIG + Vuln in one pass.
"""
from __future__ import annotations
import platform
import socket
from datetime import datetime, timezone
from typing import Optional

from .hwam import collect_hwam
from .swam import collect_swam
from .stig import collect_stig
from .vuln import collect_vulns
from .remediation import build_plan
from .report import MACEAgentReport, stable_host_id
from . import hackable as hackable_mod
from . import intrusion as intrusion_mod
from . import malware as malware_mod
from . import sbom as sbom_mod
from . import dlp as dlp_mod
from .edr import scan_memory_behaviour
from .deception import check_tokens

AGENT_VERSION = "1.0.0-umea"


# ── Dummy-data helpers for simulated runs (so investor demos show every module) ──
import time as _t

def _demo_malware(plat):
    base = {"scanner_version": "umea-malware-1.0", "files_scanned": 247,
            "elapsed_s": 1.8, "clamav_used": False}
    if plat == "linux":
        base["findings"] = [
            {"detector": "ioc_path", "family": "XMRig-Cryptominer",
             "severity": "HIGH", "path": "/var/tmp/.X11-unix/.kthrotlds",
             "sha256": "0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b6c7d8e9f0a1b",
             "description": "Cryptojacking persistence in /var/tmp.",
             "remediation": "Quarantine and analyse; rotate creds.",
             "remediation_cmd": "mv /var/tmp/.X11-unix/.kthrotlds /var/quarantine/"},
        ]
    elif plat == "windows":
        base["findings"] = [
            {"detector": "heuristic", "family": "suspicious persistence",
             "severity": "MEDIUM",
             "path": "C:\\Users\\Public\\Roaming\\loader\\updater.exe",
             "description": "Run-key invokes binary from non-system path.",
             "remediation": "Inspect HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run."},
        ]
    else:
        base["findings"] = []
    return base


def _demo_intrusion(plat):
    base = {"failed_login_burst": False, "scan_origins": [],
            "suspicious_installs": [], "unauth_lan_attempts": 0, "events": []}
    if plat == "linux":
        base["failed_login_burst"] = True
        base["scan_origins"] = ["45.142.121.91"]
        base["events"] = [
            {"ts": _t.time() - 600, "kind": "failed_login", "scope": "lan",
             "source_ip": "45.142.121.91", "source_user": "root", "target_service": "ssh",
             "severity": "HIGH", "description": "Failed SSH for root from 45.142.121.91"},
            {"ts": _t.time() - 540, "kind": "failed_login", "scope": "lan",
             "source_ip": "45.142.121.91", "source_user": "admin", "target_service": "ssh",
             "severity": "HIGH", "description": "Failed SSH for admin from 45.142.121.91"},
            {"ts": _t.time() - 480, "kind": "failed_login", "scope": "lan",
             "source_ip": "45.142.121.91", "source_user": "ubuntu", "target_service": "ssh",
             "severity": "HIGH", "description": "Failed SSH for ubuntu from 45.142.121.91"},
            {"ts": _t.time() - 200, "kind": "unauthorized_access", "scope": "lan",
             "source_ip": "10.0.0.42", "target_service": "port 22",
             "severity": "MEDIUM", "description": "LAN host 10.0.0.42 connected to port 22"},
        ]
    elif plat == "windows":
        base["events"] = [
            {"ts": _t.time() - 1200, "kind": "install_attempt", "scope": "device",
             "target_service": "Notepad++ 8.6.2",
             "severity": "LOW", "description": "Package installed: Notepad++"},
            {"ts": _t.time() - 400, "kind": "failed_login", "scope": "device",
             "target_service": "windows-logon", "severity": "HIGH",
             "description": "Windows logon failure (4625)"},
        ]
    return base


def _demo_edr(plat):
    if plat == "linux":
        return {"processes_examined": 184, "hits": [
            {"rule_id": "EDR-PS-ENC-001", "technique": "T1059.001",
             "title": "PowerShell encoded command", "severity": "HIGH",
             "pid": 3221, "process": "powershell", "parent": "wmic", "cmdline": "-enc TVoAAAAA…",
             "remediation": "Kill process tree and review parent process."}]}
    if plat == "windows":
        return {"processes_examined": 312, "hits": [
            {"rule_id": "EDR-CHILD-OFFICE", "technique": "T1059.003",
             "title": "Office spawning shell", "severity": "HIGH",
             "pid": 6612, "process": "cmd.exe", "parent": "WINWORD.EXE",
             "cmdline": "cmd /c powershell -nop -w hidden -c iex(…)",
             "remediation": "Kill cmd.exe tree; isolate host from network."}]}
    return {"processes_examined": 0, "hits": []}


def _demo_dlp(plat):
    if plat == "linux":
        return {"files_scanned": 422, "hits": [
            {"rule_id": "DLP-AWS-001", "severity": "CRITICAL",
             "path": "/home/ubuntu/.aws/credentials", "classifier": "AWS access key",
             "target_channel": "", "remediation": "Rotate the AWS access key immediately via IAM."}]}
    if plat == "windows":
        return {"files_scanned": 318, "hits": [
            {"rule_id": "DLP-PCI-001", "severity": "HIGH",
             "path": "C:\\Users\\jdoe\\Documents\\quarter-end.xlsx",
             "classifier": "PAN (PCI-DSS)", "excerpt": "411111…",
             "remediation": "Remove or tokenise PANs before storing on disk."}]}
    return {"files_scanned": 0, "hits": []}


def _demo_honeytokens(plat):
    if plat == "linux":
        return {"alerts": [
            {"token": "ssh_key", "path": "/root/.ssh/id_rsa.bak",
             "kind": "read", "severity": "HIGH",
             "detail": "Honey-token SSH key accessed at " + _t.strftime("%H:%M:%S"),
             "observed_at": _t.time()}]}
    return {"alerts": []}


def _current_user() -> str:
    """Return the OS user running the scan, in a cross-platform way."""
    import getpass, os
    try: return getpass.getuser()
    except Exception:
        return os.environ.get("USER") or os.environ.get("USERNAME") or "unknown"


def scan_this_device() -> MACEAgentReport:
    """Run a real scan of the host the agent is installed on."""
    plat = platform.system().lower()
    hostname = socket.gethostname() or "unknown-host"
    scanned_by = _current_user()

    hwam = collect_hwam(simulate=False)
    swam = collect_swam(simulate=False)
    stig = collect_stig(simulate=False, disk_encryption=hwam.disk_encryption)
    vulns = collect_vulns(swam)
    mal_rep = malware_mod.scan(deep=False)
    hack_rep = hackable_mod.scan(swam)
    intr_rep = intrusion_mod.scan(window_seconds=24*3600)
    edr_rep  = scan_memory_behaviour()
    sbom_rep = sbom_mod.build(swam)
    dlp_rep  = dlp_mod.scan(max_files=200)   # cap for scan-time
    honey_alerts = []
    try:
        from dataclasses import asdict as _ad
        honey_alerts = [_ad(a) for a in check_tokens()]
    except Exception:
        pass

    import hashlib as _h
    now_iso = datetime.now(timezone.utc).isoformat()
    host_id_ = stable_host_id(hwam, hostname)
    sig = _h.sha256(f"{scanned_by}|{host_id_}|{now_iso}".encode()).hexdigest()[:24]
    report = MACEAgentReport(
        agent_version=AGENT_VERSION,
        host_id=host_id_,
        hostname=hostname,
        platform=plat,
        captured_at=now_iso,
        real_collectors=plat == "darwin",
        scanned_by=scanned_by,
        scan_signature=sig,
        hardware=hwam,
        software=swam,
        stig=stig,
        vulns=vulns,
        malware=mal_rep.to_dict(),
        hackable=hack_rep.to_dict(),
        intrusion=intr_rep.to_dict(),
        edr=edr_rep.to_dict(),
        sbom=sbom_rep.to_dict(),
        dlp=dlp_rep.to_dict(),
        honeytokens={"alerts": honey_alerts},
    )
    report.finalize()
    report.remediation_plan = build_plan(report).to_dict()
    return report


def scan_simulated(force_platform: str = "linux", hostname: Optional[str] = None) -> MACEAgentReport:
    """Run a simulated scan as if the agent were installed on a different OS."""
    plat = force_platform.lower()
    hostname = hostname or f"sim-{plat}-host"

    hwam = collect_hwam(simulate=True, force_platform=plat)
    swam = collect_swam(simulate=True, force_platform=plat)
    stig = collect_stig(simulate=True, force_platform=plat, disk_encryption=hwam.disk_encryption)
    vulns = collect_vulns(swam)
    hack_rep = hackable_mod.scan(swam)

    report = MACEAgentReport(
        agent_version=AGENT_VERSION,
        host_id=stable_host_id(hwam, hostname),
        hostname=hostname,
        platform=plat,
        captured_at=datetime.now(timezone.utc).isoformat(),
        real_collectors=False,
        hardware=hwam,
        software=swam,
        stig=stig,
        vulns=vulns,
        malware=_demo_malware(plat),
        hackable=hack_rep.to_dict(),
        intrusion=_demo_intrusion(plat),
        edr=_demo_edr(plat),
        sbom=sbom_mod.build(swam).to_dict(),
        dlp=_demo_dlp(plat),
        honeytokens=_demo_honeytokens(plat),
    )
    report.finalize()
    report.remediation_plan = build_plan(report).to_dict()
    return report
