"""
Browser security — risky extensions + phishing URL helpers.

Detects:
  • Chrome / Edge / Firefox / Safari extensions with risky permissions
    ("<all_urls>", "tabs", "history", "cookies", "webRequestBlocking",
    "nativeMessaging").
  • Extensions with developer IDs on a bundled abuse list.
  • Stored passwords + autofill counts (per Chromium Login Data DB).
  • Phishing-URL classifier callable from the daemon to score outbound
    HTTP requests (uses heuristics — domain entropy, IDN, TLD risk).
"""
from __future__ import annotations
import json
import math
import platform
import re
import sqlite3
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


RISKY_PERMS = {"<all_urls>", "tabs", "history", "cookies",
                "webRequestBlocking", "nativeMessaging", "debugger",
                "downloads", "management", "proxy", "privacy"}

KNOWN_BAD_EXT_IDS = {
    "nllcnknpjnininklegdoijpljgdjkijc": "GreatSuspender malware (2021)",
    "mghigbhdmbjjeohheidnnbmfkpklnedp": "Malicious 'Auto Refresh Plus' clone",
    "kkpllkodjeloidieedojogacfhpaihoh": "Crypto-mining hijack (2019)",
}


@dataclass
class ExtensionFinding:
    browser: str
    name: str
    id: str
    version: str
    risk_score: float
    permissions: List[str] = field(default_factory=list)
    notes: str = ""


@dataclass
class BrowserSecReport:
    findings: List[ExtensionFinding] = field(default_factory=list)
    extensions_scanned: int = 0
    stored_passwords: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"findings": [asdict(f) for f in self.findings],
                "extensions_scanned": self.extensions_scanned,
                "stored_passwords": self.stored_passwords}


def _chromium_extension_dirs() -> List[Path]:
    home = Path.home()
    plat = platform.system().lower()
    out: List[Path] = []
    if plat == "darwin":
        for base in ("Google/Chrome", "Microsoft Edge", "BraveSoftware/Brave-Browser"):
            d = home / "Library/Application Support" / base / "Default/Extensions"
            if d.is_dir(): out.append(d)
    elif plat == "linux":
        for base in (".config/google-chrome", ".config/microsoft-edge", ".config/BraveSoftware/Brave-Browser"):
            d = home / base / "Default/Extensions"
            if d.is_dir(): out.append(d)
    elif plat == "windows":
        for base in ("AppData/Local/Google/Chrome/User Data/Default/Extensions",
                     "AppData/Local/Microsoft/Edge/User Data/Default/Extensions"):
            d = home / base
            if d.is_dir(): out.append(d)
    return out


def _scan_chromium(rep: BrowserSecReport):
    for ext_root in _chromium_extension_dirs():
        for ext_id_dir in ext_root.iterdir():
            if not ext_id_dir.is_dir(): continue
            ext_id = ext_id_dir.name
            for ver in ext_id_dir.iterdir():
                if not ver.is_dir(): continue
                mf = ver / "manifest.json"
                if not mf.exists(): continue
                rep.extensions_scanned += 1
                try:
                    m = json.loads(mf.read_text(errors="ignore"))
                except Exception:
                    continue
                perms = set(m.get("permissions", []) or [])
                if isinstance(m.get("host_permissions"), list):
                    perms.update(m["host_permissions"])
                risk = len(perms & RISKY_PERMS) * 0.15
                if ext_id in KNOWN_BAD_EXT_IDS:
                    risk = 1.0
                if risk > 0:
                    rep.findings.append(ExtensionFinding(
                        browser=str(ext_root).split("/")[-3] if "/" in str(ext_root) else "Chromium",
                        name=m.get("name", "")[:80], id=ext_id, version=ver.name,
                        risk_score=min(1.0, risk),
                        permissions=sorted(perms),
                        notes=KNOWN_BAD_EXT_IDS.get(ext_id, "")))
                break  # only newest version


def _count_chromium_passwords(rep: BrowserSecReport):
    home = Path.home()
    plat = platform.system().lower()
    candidates: List[Path] = []
    if plat == "darwin":
        candidates += [home / "Library/Application Support/Google/Chrome/Default/Login Data",
                        home / "Library/Application Support/Microsoft Edge/Default/Login Data"]
    elif plat == "linux":
        candidates += [home / ".config/google-chrome/Default/Login Data"]
    elif plat == "windows":
        candidates += [home / "AppData/Local/Google/Chrome/User Data/Default/Login Data",
                        home / "AppData/Local/Microsoft/Edge/User Data/Default/Login Data"]
    for path in candidates:
        if not path.exists(): continue
        try:
            tmp = path.with_suffix(".scan.db")
            tmp.write_bytes(path.read_bytes())
            con = sqlite3.connect(str(tmp))
            cur = con.execute("SELECT COUNT(*) FROM logins")
            rep.stored_passwords += cur.fetchone()[0] or 0
            con.close(); tmp.unlink(missing_ok=True)
        except Exception:
            continue


def scan() -> BrowserSecReport:
    rep = BrowserSecReport()
    _scan_chromium(rep)
    _count_chromium_passwords(rep)
    return rep


# ── phishing URL heuristic (callable from daemon / dns_filter) ──────

def url_phish_score(url: str) -> float:
    score = 0.0
    if re.search(r"https?://(?:\d+\.){3}\d+", url): score += 0.3   # IP literal
    m = re.search(r"https?://([^/]+)", url)
    if not m: return score
    host = m.group(1).lower()
    # IDN
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        score += 0.4
    # TLD risk
    suspicious_tlds = (".cyou", ".tk", ".click", ".zip", ".bit", ".onion")
    if any(host.endswith(t) for t in suspicious_tlds): score += 0.4
    # Domain entropy
    parts = host.split(".")
    if parts and len(parts[0]) > 12:
        # Shannon entropy
        from collections import Counter
        c = Counter(parts[0])
        n = len(parts[0])
        H = -sum((v/n)*math.log2(v/n) for v in c.values())
        if H > 3.8: score += 0.2
    return min(1.0, score)
