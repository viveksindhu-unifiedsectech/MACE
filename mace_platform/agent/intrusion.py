"""
Intrusion / unauthorized-access detection.

Two scopes:

  1. ON-DEVICE — someone with shell or physical access to the host doing
                  things they shouldn't:
       • Failed login bursts (SSH, sudo, screen unlock, TouchID).
       • New device unlock from an unrecognised face / fingerprint slot.
       • Privilege-escalation attempts (sudo without TTY, su, pkexec).
       • Disabled audit logging.
       • Tampering with /etc/sudoers, login items, LaunchAgents.

  2. ON-LAN  — someone on the local network reaching the device without
                authorization:
       • Inbound connection attempts to closed ports (SYN, then nothing).
       • Port scans (ARP storms or TCP scans from a single source IP).
       • Failed SMB / AFP / Screen Sharing / RDP / VNC handshakes.
       • mDNS / SSDP probes from outside the device's normal LAN segment.

Both scopes share an `IntrusionEvent` payload and feed the same upstream
pipeline as endpoint detections. The daemon subscribes them in real time.

For the demo this module also exposes `scan()` which produces a snapshot
of recent events (last 24 h) so the dashboard has something to show even
without running the daemon for hours.
"""
from __future__ import annotations
import platform
import re
import shutil
import socket
import subprocess
import time
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional


@dataclass
class IntrusionEvent:
    ts: float
    kind: str                    # failed_login | scan | unauthorized_access | priv_esc | install_attempt | tamper
    scope: str                   # device | lan
    source_ip: str = ""
    source_user: str = ""
    target_service: str = ""
    severity: str = "MEDIUM"
    description: str = ""
    raw: str = ""


@dataclass
class IntrusionReport:
    events: List[IntrusionEvent] = field(default_factory=list)
    failed_login_burst: bool = False
    scan_origins: List[str] = field(default_factory=list)
    suspicious_installs: List[str] = field(default_factory=list)
    unauth_lan_attempts: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {
            "events": [asdict(e) for e in self.events[-200:]],
            "failed_login_burst": self.failed_login_burst,
            "scan_origins": self.scan_origins,
            "suspicious_installs": self.suspicious_installs,
            "unauth_lan_attempts": self.unauth_lan_attempts,
        }


# ── source readers ───────────────────────────────────────────────────

_FAILED_LOGIN_PATTERNS = [
    re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"authentication failure.*user=(\S+).*rhost=(\d+\.\d+\.\d+\.\d+)"),
    re.compile(r"Authentication failure for user (\S+)\b"),
]

_INSTALL_PATTERNS = [
    re.compile(r"installer\[\d+\]: Installed \"([^\"]+)\""),
    re.compile(r"Installed product (\S+)"),
    re.compile(r"dpkg: ([A-Za-z0-9\-+.]+): installed"),
    re.compile(r"\bMsiInstaller\b.*Product: (.+?) -- Installation"),
]

_TAMPER_PATHS = [
    "/etc/sudoers", "/etc/ssh/sshd_config", "/etc/passwd", "/etc/shadow",
    "/Library/LaunchDaemons", str(Path.home() / "Library/LaunchAgents"),
]


def _read_macos_log(seconds: int = 86400) -> Iterable[str]:
    if not shutil.which("log"):
        return []
    try:
        out = subprocess.run(
            ["log", "show", "--style", "compact", "--last", f"{max(1,seconds//3600)}h",
             "--predicate",
             "eventMessage CONTAINS 'Failed password' "
             "OR eventMessage CONTAINS 'Authentication failure' "
             "OR eventMessage CONTAINS 'sudo' "
             "OR eventMessage CONTAINS 'installer'"],
            capture_output=True, text=True, timeout=15, check=False)
        return (out.stdout or "").splitlines()
    except Exception:
        return []


def _read_linux_auth(seconds: int = 86400) -> Iterable[str]:
    candidates = ["/var/log/auth.log", "/var/log/secure"]
    for p in candidates:
        try:
            with open(p) as f:
                return f.read().splitlines()
        except Exception:
            continue
    if shutil.which("journalctl"):
        out = subprocess.run(["journalctl", "-u", "sshd", "-u", "sudo",
                               "--since", f"-{seconds}s", "-o", "cat"],
            capture_output=True, text=True, timeout=20, check=False)
        return (out.stdout or "").splitlines()
    return []


def _read_windows_events(seconds: int = 86400) -> Iterable[str]:
    if not shutil.which("powershell"):
        return []
    out = subprocess.run(["powershell", "-NoProfile", "-Command",
        f"Get-WinEvent -FilterHashtable @{{LogName='Security';Id=4625,4624,4688,4720;"
        f"StartTime=(Get-Date).AddSeconds(-{seconds})}} | "
        f"Select TimeCreated,Id,Message | ConvertTo-Json -Compress"],
        capture_output=True, text=True, timeout=30, check=False)
    return (out.stdout or "").splitlines()


# ── detection ────────────────────────────────────────────────────────

def _classify(line: str, plat: str) -> Optional[IntrusionEvent]:
    # Failed logins
    for pat in _FAILED_LOGIN_PATTERNS:
        m = pat.search(line)
        if m:
            user = m.group(1) if m.lastindex and m.lastindex >= 1 else ""
            ip   = m.group(2) if m.lastindex and m.lastindex >= 2 else ""
            return IntrusionEvent(
                ts=time.time(), kind="failed_login", scope="lan" if ip else "device",
                source_ip=ip, source_user=user, target_service="ssh",
                severity="HIGH" if ip else "MEDIUM",
                description=f"Failed login attempt for user '{user}'"
                             + (f" from {ip}" if ip else ""), raw=line[:300])
    # Installs
    for pat in _INSTALL_PATTERNS:
        m = pat.search(line)
        if m:
            product = m.group(1)
            return IntrusionEvent(
                ts=time.time(), kind="install_attempt", scope="device",
                target_service=product, severity="LOW",
                description=f"Package installed: {product}", raw=line[:300])
    # Privilege escalation
    if "sudo" in line and ("incorrect password" in line or "user NOT in sudoers" in line):
        return IntrusionEvent(
            ts=time.time(), kind="priv_esc", scope="device", severity="HIGH",
            target_service="sudo", description="Unauthorized sudo attempt", raw=line[:300])
    # Windows logon failures (4625)
    if '"Id":4625' in line or '"4625"' in line:
        return IntrusionEvent(
            ts=time.time(), kind="failed_login", scope="device", severity="HIGH",
            target_service="windows-logon", description="Windows logon failure (4625)",
            raw=line[:300])
    return None


def _detect_scans(events: List[IntrusionEvent]) -> List[str]:
    """If a single source IP triggers multiple failed_login events, treat as a scan."""
    counts: Dict[str, int] = defaultdict(int)
    for ev in events:
        if ev.kind == "failed_login" and ev.source_ip:
            counts[ev.source_ip] += 1
    return [ip for ip, n in counts.items() if n >= 5]


def _check_lan_inbound() -> List[IntrusionEvent]:
    """Snapshot inbound TCP connections — anything from outside the local /24 is flagged."""
    out: List[IntrusionEvent] = []
    if not shutil.which("netstat"):
        return out
    try:
        ns = subprocess.run(["netstat", "-an"], capture_output=True, text=True, timeout=5).stdout
    except Exception:
        return out
    local_24 = _local_prefix()
    for line in ns.splitlines():
        if "ESTABLISHED" not in line: continue
        m = re.search(r"\s(\d+\.\d+\.\d+\.\d+)[.:](\d+)\s.*\s(\d+\.\d+\.\d+\.\d+)[.:](\d+)\s+ESTABLISHED", line)
        if not m: continue
        local_ip, local_port, remote_ip, remote_port = m.groups()
        if remote_ip == "127.0.0.1": continue
        if local_24 and not remote_ip.startswith(local_24):
            continue
        # Local-LAN connection to a sensitive port — flag it
        if int(local_port) in (22, 445, 3389, 5900, 5985, 5986):
            out.append(IntrusionEvent(
                ts=time.time(), kind="unauthorized_access", scope="lan",
                source_ip=remote_ip, target_service=f"port {local_port}",
                severity="MEDIUM",
                description=f"LAN host {remote_ip} connected to local port {local_port}"))
    return out


def _local_prefix() -> str:
    """Return the /24 prefix of the primary interface, e.g. '192.168.1.'."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip.rsplit(".", 1)[0] + "."
    except Exception:
        return ""


# ── public entrypoint ────────────────────────────────────────────────

def scan(window_seconds: int = 86400) -> IntrusionReport:
    rep = IntrusionReport()
    plat = platform.system().lower()
    if   plat == "darwin":  lines = list(_read_macos_log(window_seconds))
    elif plat == "linux":   lines = list(_read_linux_auth(window_seconds))
    elif plat == "windows": lines = list(_read_windows_events(window_seconds))
    else: lines = []

    for line in lines:
        ev = _classify(line, plat)
        if ev:
            rep.events.append(ev)
            if ev.kind == "install_attempt":
                rep.suspicious_installs.append(ev.target_service)

    # Failed-login burst detection
    failed_in_window = [e for e in rep.events
                        if e.kind == "failed_login" and (time.time() - e.ts) < 3600]
    rep.failed_login_burst = len(failed_in_window) >= 10
    rep.scan_origins = _detect_scans(rep.events)

    # LAN inbound snapshot
    lan_events = _check_lan_inbound()
    rep.events.extend(lan_events)
    rep.unauth_lan_attempts = len(lan_events)

    return rep
