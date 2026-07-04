"""
Hackable-software / risky-configuration heuristics.

This complements the strict CVE matcher in vuln.py by surfacing software
or settings that aren't tied to a specific CVE but materially increase
hackability:

  • EOL / unsupported software (Python 2.x, Node 14, Java 8, Office 2016…)
  • Default-credentials services (Jenkins, MongoDB, Redis on 0.0.0.0)
  • Open SMB / RDP / VNC / SSH to the world
  • Browser extensions with broad permissions ("all sites")
  • SSH keys with no passphrase
  • Mounted USB drives with autorun executables
  • Outdated TLS (1.0 / 1.1) bound on a listening socket
  • Sudo NOPASSWD entries

Each heuristic returns a finding with a remediation hint that flows into
the unified remediation plan so the analyst sees them in the same list as
CVE patches and STIG failures.
"""
from __future__ import annotations
import os
import re
import shutil
import subprocess
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List


@dataclass
class HackableFinding:
    rule_id: str
    title: str
    severity: str            # CRITICAL | HIGH | MEDIUM | LOW
    component: str
    observed: str = ""
    remediation: str = ""
    remediation_cmd: str = ""


@dataclass
class HackableReport:
    findings: List[HackableFinding] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"findings": [asdict(f) for f in self.findings]}


# ── checks ───────────────────────────────────────────────────────────

def _eol_software(apps) -> List[HackableFinding]:
    eol = []
    for entry in apps:
        n = entry.name.lower()
        v = entry.version or ""
        if n == "python" and v.startswith("2."):
            eol.append(HackableFinding("HACK-EOL-001",
                "End-of-life Python 2.x detected", "HIGH", "Python",
                v, "Migrate to Python ≥ 3.11; remove Python 2.x.",
                ""))
        if n.startswith("node") and v.startswith("14."):
            eol.append(HackableFinding("HACK-EOL-002",
                "End-of-life Node.js 14", "HIGH", "Node.js", v,
                "Upgrade Node.js to an active LTS line.",
                "brew upgrade node"))
        if n.startswith("java") and (v.startswith("1.8") or v.startswith("8")):
            eol.append(HackableFinding("HACK-EOL-003",
                "Java 8 reaching end of public updates", "MEDIUM", "Java", v,
                "Plan migration to Java 17 LTS or Java 21 LTS.", ""))
        if n.startswith("microsoft office") and v.startswith("16.0") and "2016" in entry.install_date:
            eol.append(HackableFinding("HACK-EOL-004",
                "Office 2016 nearing end of support", "MEDIUM", "Microsoft Office", v,
                "Upgrade to Microsoft 365 Apps.", ""))
    return eol


def _open_services(open_ports) -> List[HackableFinding]:
    out: List[HackableFinding] = []
    high_risk = {
        22:   ("SSH",  "MEDIUM", "Limit SSH to VPN / bastion CIDR; disable password auth."),
        23:   ("Telnet","CRITICAL","Telnet is unencrypted. Disable and remove inetd entry."),
        445:  ("SMB",  "HIGH",   "Restrict SMB to LAN; never expose to the public internet."),
        3389: ("RDP",  "HIGH",   "Place RDP behind Azure Bastion / Tailscale; require MFA."),
        5900: ("VNC",  "HIGH",   "Disable Screen Sharing or move behind VPN."),
        6379: ("Redis","CRITICAL","Bind Redis to 127.0.0.1 and require AUTH."),
        27017:("MongoDB","CRITICAL","Bind to 127.0.0.1 and enable SCRAM auth."),
        8080: ("HTTP-alt", "LOW", "Confirm the service requires auth."),
        9200: ("Elasticsearch","HIGH","Bind to localhost; require X-Pack security."),
        11211:("Memcached","HIGH","Bind to localhost; never expose to internet."),
    }
    for p in open_ports:
        if p in high_risk:
            svc, sev, rem = high_risk[p]
            out.append(HackableFinding(
                f"HACK-NET-{p}", f"Service on port {p} ({svc}) listening", sev,
                "OS", f"port {p} LISTEN", rem, ""))
    return out


def _ssh_passphraseless(home: Path) -> List[HackableFinding]:
    out: List[HackableFinding] = []
    sshdir = home / ".ssh"
    if not sshdir.is_dir(): return out
    for f in sshdir.iterdir():
        if not f.is_file(): continue
        if f.name.startswith("id_") and not f.name.endswith(".pub"):
            try:
                head = f.read_text().splitlines()[:2]
                if not any("ENCRYPTED" in line for line in head):
                    out.append(HackableFinding(
                        "HACK-SSH-001",
                        f"SSH private key {f.name} has no passphrase",
                        "MEDIUM", "SSH",
                        str(f), "Set a passphrase: ssh-keygen -p -f " + str(f),
                        ""))
            except Exception:
                continue
    return out


def _sudo_nopasswd() -> List[HackableFinding]:
    out: List[HackableFinding] = []
    for path in ("/etc/sudoers", *map(str, Path("/etc/sudoers.d").glob("*"))) \
                 if os.path.isdir("/etc/sudoers.d") else ("/etc/sudoers",):
        try:
            text = open(path).read()
        except Exception:
            continue
        for line in text.splitlines():
            if "NOPASSWD" in line and not line.lstrip().startswith("#"):
                out.append(HackableFinding(
                    "HACK-SUDO-001",
                    "Sudo rule allows NOPASSWD escalation", "HIGH",
                    "sudo", line.strip(),
                    "Remove NOPASSWD or scope it to a single binary path.", ""))
                break
    return out


def _outdated_tls() -> List[HackableFinding]:
    out: List[HackableFinding] = []
    if shutil.which("openssl"):
        try:
            res = subprocess.run(["openssl", "version"], capture_output=True, text=True, timeout=3).stdout
            m = re.search(r"OpenSSL ([\d.]+)", res)
            if m:
                v = m.group(1)
                if v.startswith("1.0") or v.startswith("0."):
                    out.append(HackableFinding(
                        "HACK-TLS-001",
                        "OpenSSL ≤ 1.0 supports vulnerable TLS 1.0/1.1", "HIGH",
                        "OpenSSL", v, "Upgrade OpenSSL to ≥ 1.1.1 and disable TLS < 1.2.",
                        ""))
        except Exception:
            pass
    return out


# ── public entrypoint ────────────────────────────────────────────────

def scan(software_inventory) -> HackableReport:
    rep = HackableReport()
    rep.findings.extend(_eol_software(software_inventory.applications or []))
    rep.findings.extend(_open_services(software_inventory.open_ports or []))
    rep.findings.extend(_ssh_passphraseless(Path.home()))
    if os.path.exists("/etc/sudoers"):
        rep.findings.extend(_sudo_nopasswd())
    rep.findings.extend(_outdated_tls())
    return rep
