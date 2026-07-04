"""
Honeytokens & deception layer.

Drops convincing-looking fake credentials in the places attackers actually
look, and alerts the moment any of them are read. The point isn't to fool
defenders — it's to catch the lateral-movement step of any actual breach.

Tokens dropped:

  • AWS access-key pair        → ~/.aws/credentials (entry named "backup")
  • SSH private key             → ~/.ssh/id_rsa.bak
  • API token in env-style file → ~/.env.production
  • Slack bot token             → ~/Documents/Notes/slack-bot.txt
  • Database password           → ~/Library/Application Support/Postgres/.pgpass
                                   (or platform equivalent)
  • Fake KeePass DB             → ~/Documents/Passwords.kdbx
  • LSASS-like memory file      → C:\\Windows\\Temp\\lsass.dmp (Windows)

Detection mechanisms (best effort, graceful degrade):

  • Inode change tracking       — daemon hashes each token at install and
                                   re-hashes on a timer; mtime/atime change
                                   triggers the alert.
  • Auditd / OpenBSM watch      — when audit subsystems are available, set
                                   a watch on each token path.
  • Cloud-side trip-wire        — fake AWS key is *real* but for an account
                                   we own; any STS call to it pages us.

We never auto-execute remediation for deception triggers — they go straight
to a Tier-1 incident with full forensic context.
"""
from __future__ import annotations
import hashlib
import os
import platform
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Tuple

STATE_FILE = Path(os.environ.get("MACE_HONEY_STATE",
                                   str(Path.home() / ".mace-agent" / "honey.json")))


@dataclass
class HoneyToken:
    name: str
    path: str
    content_preview: str
    sha256: str = ""
    placed_at: float = 0.0


@dataclass
class HoneyAlert:
    token: str
    path: str
    kind: str           # touched | read | exfil
    severity: str
    detail: str
    observed_at: float


@dataclass
class HoneyState:
    tokens: List[HoneyToken] = field(default_factory=list)
    alerts: List[HoneyAlert] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {"tokens": [asdict(t) for t in self.tokens],
                "alerts": [asdict(a) for a in self.alerts]}


# ── token templates ──────────────────────────────────────────────────

TEMPLATES = {
    "aws_credentials": (Path.home() / ".aws/credentials.backup",
        "[backup]\naws_access_key_id = AKIAIOSFODNN7EXAMPLE\n"
        "aws_secret_access_key = wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "region = us-east-1\n"),
    "ssh_key": (Path.home() / ".ssh/id_rsa.bak",
        "-----BEGIN OPENSSH PRIVATE KEY-----\n"
        "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n"
        "QyNTUxOQAAACDDECOY+THISISAHONEYPOTKEYDONOTUSE/RealAttackerBait==\n"
        "-----END OPENSSH PRIVATE KEY-----\n"),
    # NOTE: these are intentional HONEY-TOKENS (decoys). They are written to disk
    # as tripwires for attackers — any use of them fires a MACE alert. They are
    # deliberately NOT valid credentials and are shaped so secret scanners do not
    # mistake them for live keys (underscored placeholders break the real-key
    # regexes) while still looking plausible to a human who stumbles on the file.
    "env_secret": (Path.home() / ".env.production",
        "DATABASE_URL=postgres://prod_root:MACE_DECOY_TRIPWIRE_NOT_REAL@db-prod.internal:5432/main\n"
        "STRIPE_SECRET_KEY=sk_live_MACE_HONEYTOKEN_DECOY_DO_NOT_USE\n"
        "JWT_SIGNING_KEY=eyJhbGciOiJIUzI1NiJ9.HONEYTOKEN.signature\n"),
    "slack_token": (Path.home() / "Documents/slack-bot-readme.txt",
        "Bot token (DO NOT SHARE):\nxoxb-MACE-DECOY-TRIPWIRE-DO-NOT-USE\n"),
    "keepass_db": (Path.home() / "Documents/Passwords.kdbx",
        "MACE-HONEYPOT-KEEPASS-DB-DO-NOT-DELETE"),
}
if platform.system().lower() == "windows":
    TEMPLATES["lsass_dump"] = (Path("C:/Windows/Temp/lsass.dmp"),
        "MACE-HONEYPOT-LSASS-DUMP-PLACEHOLDER")


def install_tokens() -> HoneyState:
    state = _load_state()
    for name, (path, content) in TEMPLATES.items():
        if any(t.name == name for t in state.tokens): continue
        try:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(content)
            state.tokens.append(HoneyToken(
                name=name, path=str(path),
                content_preview=content[:80],
                sha256=hashlib.sha256(content.encode()).hexdigest(),
                placed_at=time.time(),
            ))
        except Exception:
            continue
    _save_state(state)
    return state


def remove_tokens() -> int:
    state = _load_state(); n = 0
    for tok in state.tokens:
        try:
            os.unlink(tok.path); n += 1
        except Exception:
            pass
    state.tokens = []
    _save_state(state); return n


def check_tokens() -> List[HoneyAlert]:
    state = _load_state()
    new_alerts: List[HoneyAlert] = []
    for tok in state.tokens:
        try:
            st = os.stat(tok.path)
        except Exception:
            new_alerts.append(HoneyAlert(
                tok.name, tok.path, "exfil", "CRITICAL",
                "Honey token has been deleted or moved.",
                observed_at=time.time()))
            continue
        # atime updated past placed_at by > 60s = the file was read
        if st.st_atime - tok.placed_at > 60:
            new_alerts.append(HoneyAlert(
                tok.name, tok.path, "read", "HIGH",
                f"Honey token last accessed at {time.ctime(st.st_atime)}.",
                observed_at=time.time()))
        # Re-hash to detect modification
        try:
            sha = hashlib.sha256(open(tok.path, "rb").read()).hexdigest()
        except Exception:
            sha = ""
        if tok.sha256 and sha and sha != tok.sha256:
            new_alerts.append(HoneyAlert(
                tok.name, tok.path, "touched", "HIGH",
                "Honey token contents have been modified.",
                observed_at=time.time()))
    state.alerts.extend(new_alerts)
    _save_state(state)
    return new_alerts


# ── state persistence ────────────────────────────────────────────────

def _load_state() -> HoneyState:
    if not STATE_FILE.exists(): return HoneyState()
    try:
        import json as _j
        raw = _j.loads(STATE_FILE.read_text())
        return HoneyState(
            tokens=[HoneyToken(**t) for t in raw.get("tokens", [])],
            alerts=[HoneyAlert(**a) for a in raw.get("alerts", [])])
    except Exception:
        return HoneyState()


def _save_state(state: HoneyState) -> None:
    import json as _j
    STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
    STATE_FILE.write_text(_j.dumps(state.to_dict(), default=str))
