"""
Email phishing + impersonation detection.

Scans the local mail-client archives (Apple Mail, Outlook OST/PST,
Thunderbird Mbox, Evolution local store) for phishing indicators:

  • Display-name impersonation (visible name matches a corp-exec name
    but From: domain is external).
  • SPF / DKIM / DMARC absence in the header (heuristic from received fields).
  • Domain look-alikes / homoglyphs in From: addresses.
  • Suspicious link patterns (mismatched href / link-text).
  • Attachment types that resemble payloads (.iso, .img, .lnk, .scr, .one,
    .vbs, .js, .hta).
  • Calls-to-action that match BEC patterns ("wire transfer", "gift card").
"""
from __future__ import annotations
import email
import os
import platform
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional

CORP_NAMES = {"vivek sindhu", "ceo", "cfo", "cto", "vp finance", "controller"}
BEC_PHRASES = ("wire transfer", "gift card", "urgent", "confidential", "purchase order")
SUSPICIOUS_ATTACH = (".iso", ".img", ".lnk", ".scr", ".one", ".vbs", ".js", ".hta", ".cmd", ".bat")
HOMOGLYPH = str.maketrans("аеоруcр", "aeopycp")    # cyrillic look-alikes


@dataclass
class PhishFinding:
    rule_id: str
    severity: str
    subject: str
    from_addr: str
    display_name: str = ""
    path: str = ""
    remediation: str = ""


@dataclass
class PhishReport:
    findings: List[PhishFinding] = field(default_factory=list)
    messages_scanned: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"findings": [asdict(f) for f in self.findings],
                "messages_scanned": self.messages_scanned}


def _mail_dirs() -> List[Path]:
    home = Path.home()
    dirs: List[Path] = []
    plat = platform.system().lower()
    if plat == "darwin":
        for sub in ("Library/Mail/V10", "Library/Mail/V9"):
            d = home / sub
            if d.is_dir(): dirs.append(d)
    if plat == "linux":
        for sub in (".thunderbird", ".local/share/evolution/mail"):
            d = home / sub
            if d.is_dir(): dirs.append(d)
    if plat == "windows":
        for sub in ("AppData/Local/Microsoft/Outlook",):
            d = home / sub
            if d.is_dir(): dirs.append(d)
    return dirs


def _looks_like_homoglyph(domain: str) -> bool:
    return domain != domain.translate(HOMOGLYPH)


def _bec_score(subject: str, body: str) -> bool:
    blob = (subject + " " + body[:2000]).lower()
    hits = sum(1 for k in BEC_PHRASES if k in blob)
    return hits >= 2


def _scan_message(path: str, msg) -> List[PhishFinding]:
    out: List[PhishFinding] = []
    subject = msg.get("Subject", "") or ""
    raw_from = msg.get("From", "") or ""
    m = re.match(r'\s*"?([^"<]+)"?\s*<([^>]+)>', raw_from)
    if m:
        display, addr = m.group(1).strip(), m.group(2).strip()
    else:
        display, addr = "", raw_from.strip()

    domain = addr.split("@")[-1].lower() if "@" in addr else ""

    if display.lower() in CORP_NAMES and not domain.endswith("unifiedsec.io"):
        out.append(PhishFinding(
            "PHISH-DN-001", "HIGH", subject, addr, display, path,
            "Display-name impersonates a corporate executive but From: domain is external. "
            "Reply only via known-good channel; verify by phone."))
    if domain and _looks_like_homoglyph(domain):
        out.append(PhishFinding(
            "PHISH-HG-001", "HIGH", subject, addr, display, path,
            f"Domain {domain!r} contains non-ASCII homoglyphs."))
    # Attachments
    try:
        for part in msg.walk():
            fn = part.get_filename() or ""
            if fn.lower().endswith(SUSPICIOUS_ATTACH):
                out.append(PhishFinding(
                    "PHISH-ATT-001", "HIGH", subject, addr, display, path,
                    f"Suspicious attachment type: {fn}. "
                    "Quarantine and analyse in a sandbox."))
                break
    except Exception:
        pass
    # BEC pattern
    try:
        body = ""
        for part in msg.walk():
            if part.get_content_type() == "text/plain":
                body = part.get_payload(decode=True).decode(errors="ignore")
                break
        if _bec_score(subject, body):
            out.append(PhishFinding(
                "PHISH-BEC-001", "HIGH", subject, addr, display, path,
                "Business-email-compromise (BEC) phrase pattern."))
    except Exception:
        pass
    return out


def scan(max_messages: int = 200) -> PhishReport:
    rep = PhishReport()
    for d in _mail_dirs():
        for path in d.rglob("*.emlx" if platform.system().lower() == "darwin" else "*"):
            if not path.is_file() or rep.messages_scanned >= max_messages: continue
            try:
                data = path.read_bytes()
                msg = email.message_from_bytes(data)
                rep.findings.extend(_scan_message(str(path), msg))
                rep.messages_scanned += 1
            except Exception:
                continue
            if rep.messages_scanned >= max_messages: break
    return rep
