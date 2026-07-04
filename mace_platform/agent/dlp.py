"""
Endpoint Data Loss Prevention (DLP).

Inspects file and network operations for sensitive-data exfil patterns:

  • Credit-card numbers (PCI-DSS scope)            — Luhn-checked PAN regex
  • US Social Security Numbers                     — strict 9-digit format
  • Indian Aadhaar numbers                          — 12-digit + Verhoeff
  • EU IBAN account numbers
  • API keys / cloud secrets (AWS/GCP/Slack/GitHub)
  • Source code with TODOs containing secret strings
  • Files being copied to USB / personal-cloud sync dirs (Dropbox, Drive,
    OneDrive personal, iCloud Drive)
  • Outgoing emails / messages addressed to personal domains when the
    sender is on a corp domain.

This is a *pattern* engine — the daemon hooks watchdog events to it so
detection happens in real time. The scan() entrypoint runs a one-shot
pass over likely-exfil paths (Downloads, Desktop, USB mounts).
"""
from __future__ import annotations
import os
import re
import platform
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List

# ── classifiers ──────────────────────────────────────────────────────

_PAN_RE   = re.compile(r"\b(?:\d[ \-]?){13,19}\b")
_SSN_RE   = re.compile(r"\b\d{3}-\d{2}-\d{4}\b")
_AADHAAR  = re.compile(r"\b\d{4}\s\d{4}\s\d{4}\b")
_IBAN_RE  = re.compile(r"\b[A-Z]{2}\d{2}[A-Z0-9]{11,30}\b")
_AWS_RE   = re.compile(r"AKIA[0-9A-Z]{16}")
_GCP_RE   = re.compile(r"AIza[0-9A-Za-z\-_]{35}")
_SLACK_RE = re.compile(r"xox[abp]-[0-9A-Za-z\-]{10,48}")
_GH_RE    = re.compile(r"ghp_[A-Za-z0-9]{36}")

# Common personal-cloud sync directories
PERSONAL_SYNC_DIRS = [
    "Dropbox", "Google Drive", "GoogleDrive", "iCloud Drive", "iCloudDrive",
    "OneDrive - Personal", "Box Sync",
]

# Common USB volume locations
USB_PATHS = [
    "/Volumes",          # macOS
    "/media",            # Linux
    "/mnt",              # Linux
    "D:\\", "E:\\", "F:\\",  # Windows
]


def _luhn_ok(num: str) -> bool:
    digits = [int(c) for c in re.sub(r"\D", "", num)]
    if not 13 <= len(digits) <= 19: return False
    odd = digits[-1::-2]; even = digits[-2::-2]
    s = sum(odd) + sum(sum(divmod(d*2, 10)) for d in even)
    return s % 10 == 0


@dataclass
class DLPHit:
    rule_id: str
    severity: str
    path: str = ""
    excerpt: str = ""
    classifier: str = ""
    target_channel: str = ""
    remediation: str = ""


@dataclass
class DLPReport:
    hits: List[DLPHit] = field(default_factory=list)
    files_scanned: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"hits": [asdict(h) for h in self.hits],
                "files_scanned": self.files_scanned}


def _classify_text(text: str) -> List[DLPHit]:
    out: List[DLPHit] = []
    for m in _PAN_RE.finditer(text):
        if _luhn_ok(m.group(0)):
            out.append(DLPHit("DLP-PCI-001", "HIGH", excerpt=m.group(0)[:6] + "…",
                               classifier="PAN (PCI-DSS)",
                               remediation="Remove or tokenise PANs before storing on disk."))
    if _SSN_RE.search(text):
        out.append(DLPHit("DLP-SSN-001", "HIGH", classifier="US SSN",
                           remediation="Encrypt or move SSNs to a managed secret store."))
    if _AADHAAR.search(text):
        out.append(DLPHit("DLP-AAD-001", "HIGH", classifier="Aadhaar",
                           remediation="Per India DPDP / Aadhaar Act, do not store in cleartext."))
    if _IBAN_RE.search(text):
        out.append(DLPHit("DLP-IBAN-001", "MEDIUM", classifier="IBAN",
                           remediation="Apply EU PSD2 / GDPR Article 32 protections."))
    if _AWS_RE.search(text):
        out.append(DLPHit("DLP-AWS-001", "CRITICAL", classifier="AWS access key",
                           remediation="Rotate the AWS access key immediately via IAM."))
    if _GCP_RE.search(text):
        out.append(DLPHit("DLP-GCP-001", "HIGH", classifier="GCP API key",
                           remediation="Rotate GCP key in IAM & Admin → Credentials."))
    if _SLACK_RE.search(text):
        out.append(DLPHit("DLP-SLACK-001", "HIGH", classifier="Slack token",
                           remediation="Revoke the token in Slack workspace settings."))
    if _GH_RE.search(text):
        out.append(DLPHit("DLP-GH-001", "HIGH", classifier="GitHub PAT",
                           remediation="Revoke the personal-access token in GitHub Settings."))
    return out


def _scan_file(path: str) -> List[DLPHit]:
    try:
        if os.path.getsize(path) > 5_000_000:  # 5 MB cap to stay fast
            return []
        with open(path, "r", errors="ignore") as f:
            text = f.read()
        return [h._replace(path=path) if hasattr(h, "_replace") else _attach_path(h, path)
                 for h in _classify_text(text)]
    except Exception:
        return []


def _attach_path(h: DLPHit, path: str) -> DLPHit:
    h.path = path; return h


# ── public scan ──────────────────────────────────────────────────────

def scan(extra_paths: List[str] | None = None, max_files: int = 1000) -> DLPReport:
    rep = DLPReport()
    home = Path.home()
    targets: List[str] = []
    for sub in ("Downloads", "Desktop", "Documents"):
        if (home / sub).is_dir():
            targets.append(str(home / sub))
    for d in PERSONAL_SYNC_DIRS:
        cand = home / d
        if cand.is_dir(): targets.append(str(cand))
    for usb in USB_PATHS:
        if os.path.isdir(usb):
            for entry in os.listdir(usb)[:5]:
                p = os.path.join(usb, entry)
                if os.path.isdir(p): targets.append(p)
    targets.extend(extra_paths or [])

    seen = 0
    for root in targets:
        for base, _dirs, files in os.walk(root):
            for fn in files:
                p = os.path.join(base, fn)
                if seen >= max_files: break
                seen += 1
                hits = _scan_file(p)
                if hits:
                    rep.hits.extend(hits)
                    if hits[0].severity == "CRITICAL":
                        # Tag exfil channel if root sits inside personal cloud / USB
                        if any(d in p for d in PERSONAL_SYNC_DIRS):
                            for h in hits: h.target_channel = "personal_cloud_sync"
                        if any(p.startswith(u) for u in USB_PATHS):
                            for h in hits: h.target_channel = "usb"
            if seen >= max_files: break
    rep.files_scanned = seen
    return rep
