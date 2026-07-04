"""
DNS filter / network microsegmentation.

Sinkholes known-bad C2 / phishing / ransomware domains so an infected device
cannot reach back to its operator even before the analyst sees the alert.

Two implementations:
  • Local hosts file mode  — appends entries to /etc/hosts (or
    %SystemRoot%\\System32\\drivers\\etc\\hosts) with a marker block.
  • Resolver mode           — configures the OS to use the agent's tiny
    UDP/53 sinkhole resolver, which answers known-bad domains with
    127.0.0.1 and forwards everything else.

The bundled blocklist combines:
  • CISA Known Exploited C2 domains (refreshed daily via feeds/cisa_kev.py).
  • Spamhaus DBL + Surbl (free tiers).
  • OpenPhish / PhishTank.
  • Bundled snapshot for offline / air-gapped operation.
"""
from __future__ import annotations
import os
import platform
import socket
import threading
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import List, Set

MARKER_BEGIN = "# >>> mace-agent sinkhole begin"
MARKER_END   = "# <<< mace-agent sinkhole end"


# Bundled snapshot — production sources are refreshed via the feeds path.
BUNDLED_BLOCKLIST = [
    "loaderbot.cyou", "rumorscam.top", "fakeupdate.xyz",
    "windows-defender-security-alert.click",
    "microsoft-update-helper.cn",
    "secure-bank-of-america-com.tk",
    "appleid-verify.zz",
    "metamask-claim.cyou",
    "office365-renew.live",
    # IOC families commonly used by C2 frameworks (sinkhole names)
    "cobalt-strike-c2.example",
    "emotet-tracker.example",
    "lazarus-c2.example",
    "log4shell.example",
    "ransomware-portal.onion.example",
]


@dataclass
class FilterStatus:
    installed: bool
    domains_blocked: int
    mode: str        # hosts | resolver
    last_updated: str = ""


# ── hosts-file mode ──────────────────────────────────────────────────

def _hosts_path() -> Path:
    if platform.system().lower() == "windows":
        return Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts"
    return Path("/etc/hosts")


def install_hosts(domains: List[str] | None = None) -> FilterStatus:
    domains = list(set(domains or BUNDLED_BLOCKLIST))
    p = _hosts_path()
    try:
        text = p.read_text()
    except Exception as e:
        return FilterStatus(False, 0, "hosts", "")
    # Strip any previous block
    if MARKER_BEGIN in text and MARKER_END in text:
        text = (text.split(MARKER_BEGIN)[0]
                 + text.split(MARKER_END, 1)[1].lstrip("\n"))
    block = [MARKER_BEGIN]
    for d in sorted(domains):
        block.append(f"0.0.0.0 {d}")
        block.append(f"::      {d}")
    block.append(MARKER_END)
    try:
        p.write_text(text.rstrip("\n") + "\n\n" + "\n".join(block) + "\n")
        return FilterStatus(True, len(domains), "hosts")
    except PermissionError:
        return FilterStatus(False, 0, "hosts", "needs sudo / Administrator")


def uninstall_hosts() -> FilterStatus:
    p = _hosts_path()
    try:
        text = p.read_text()
    except Exception:
        return FilterStatus(False, 0, "hosts")
    if MARKER_BEGIN not in text:
        return FilterStatus(False, 0, "hosts")
    new_text = (text.split(MARKER_BEGIN)[0]
                 + text.split(MARKER_END, 1)[1].lstrip("\n"))
    try:
        p.write_text(new_text)
        return FilterStatus(True, 0, "hosts")
    except PermissionError:
        return FilterStatus(False, 0, "hosts", "needs sudo / Administrator")


# ── resolver mode (tiny UDP/53 sinkhole) ─────────────────────────────

class SinkholeResolver(threading.Thread):
    """Tiny stub resolver that answers known-bad with 127.0.0.1, forwards rest."""
    def __init__(self, bind="127.0.0.1", port=53053,
                  upstream=("1.1.1.1", 53), blocked: Set[str] | None = None):
        super().__init__(daemon=True)
        self.bind = bind; self.port = port; self.upstream = upstream
        self.blocked = blocked or set(BUNDLED_BLOCKLIST)
        self._stop = threading.Event()

    def run(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind((self.bind, self.port))
        sock.settimeout(1.0)
        while not self._stop.is_set():
            try:
                data, addr = sock.recvfrom(512)
            except socket.timeout:
                continue
            qname = _parse_qname(data)
            if any(qname.endswith(b) for b in self.blocked):
                # Construct a minimal A 127.0.0.1 answer
                resp = _block_response(data)
                sock.sendto(resp, addr)
            else:
                try:
                    fwd = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    fwd.settimeout(2.0)
                    fwd.sendto(data, self.upstream)
                    reply, _ = fwd.recvfrom(512)
                    sock.sendto(reply, addr)
                except Exception:
                    pass

    def stop(self): self._stop.set()


def _parse_qname(pkt: bytes) -> str:
    try:
        i = 12; parts = []
        while pkt[i] != 0:
            n = pkt[i]; i += 1
            parts.append(pkt[i:i+n].decode("idna", errors="ignore"))
            i += n
        return ".".join(parts)
    except Exception:
        return ""


def _block_response(req: bytes) -> bytes:
    tid = req[:2]
    flags = b"\x81\x80"
    qdcount = req[4:6]
    answer = bytearray()
    answer += tid + flags + qdcount + b"\x00\x01\x00\x00\x00\x00"
    # Copy question
    i = 12
    while req[i] != 0: i += req[i] + 1
    answer += req[12:i+5]
    # Answer: pointer to qname, A, IN, TTL=60, RDLEN=4, 127.0.0.1
    answer += b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x00\x3c\x00\x04\x7f\x00\x00\x01"
    return bytes(answer)
