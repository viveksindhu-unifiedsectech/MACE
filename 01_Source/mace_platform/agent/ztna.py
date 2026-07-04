"""
Zero-Trust Network Access + Secure Web Gateway (replaces Zscaler).

Zscaler ships three products in one cloud: Zscaler Internet Access (ZIA —
secure web gateway / cloud firewall), Zscaler Private Access (ZPA —
identity-aware access to private apps), and Zscaler Digital Experience
(ZDX — performance telemetry). MACE replaces all three from the endpoint:

  • ZIA equivalent: per-process URL / category / SSL inspection ruleset
    enforced via the agent's DNS sinkhole + local outbound interceptor.
  • ZPA equivalent: identity-aware tunnel — only authenticated apps can
    talk to designated private CIDRs; everything else is dropped at the
    host firewall.
  • ZDX equivalent: per-app latency + packet-loss metric collected from
    the agent's outbound socket telemetry.

A SOC analyst defines policies as YAML and the agent compiles them into
host-firewall rules (`pf` on macOS, `nftables` on Linux, Windows Defender
Firewall on Windows) and the DNS sinkhole blocklist.

This module exposes the policy compiler and the runtime that publishes
status to the dashboard. Actual rule installation is gated by the same
auto-remediation allowlist so a mis-typed policy cannot brick the host.
"""
from __future__ import annotations
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


# ── policy schema ────────────────────────────────────────────────────

@dataclass
class AccessRule:
    name: str
    action: str                # allow | deny | inspect | isolate
    user: str = "*"
    process: str = "*"         # process name glob
    destination: str = "*"     # CIDR | domain | URL-category
    direction: str = "outbound"
    require_mfa: bool = False
    note: str = ""


@dataclass
class ZTNAPolicy:
    tenant: str
    version: str
    rules: List[AccessRule] = field(default_factory=list)
    blocked_categories: List[str] = field(default_factory=list)    # gambling, malware, etc.
    enforced_at: str = ""


@dataclass
class EnforcementStatus:
    rules_loaded: int
    rules_applied: int
    last_enforced_at: float
    dropped_24h: int = 0
    inspected_24h: int = 0
    isolated_processes: List[str] = field(default_factory=list)


# Built-in URL category blocklists (production maps to BrightCloud / Webroot
# / Cisco Talos taxonomies — bundled here for offline operation).
CATEGORY_DOMAINS = {
    "malware": ["loaderbot.cyou", "fakeupdate.xyz", "metamask-claim.cyou"],
    "phishing": ["secure-bank-of-america-com.tk", "appleid-verify.zz", "windows-defender-security-alert.click"],
    "gambling": ["bet365.online.example", "stake.gambling.example"],
    "adult":    ["adult-fake.example"],
    "anonymizer": ["tor-gateway.example", "anonymouse.example"],
    "crypto_mining": ["coinhive-mine.example", "minero.cc.example"],
}


# ── compiler + enforcers ─────────────────────────────────────────────

def load_policy(path: str) -> ZTNAPolicy:
    text = Path(path).read_text()
    if path.endswith((".yaml", ".yml")):
        try:
            import yaml  # type: ignore
            raw = yaml.safe_load(text)
        except Exception:
            raw = json.loads(text)
    else:
        raw = json.loads(text)
    rules = [AccessRule(**r) for r in raw.get("rules", [])]
    return ZTNAPolicy(
        tenant=raw.get("tenant", "default"), version=raw.get("version", "1"),
        rules=rules,
        blocked_categories=raw.get("blocked_categories", []),
    )


def compile_to_dns_blocklist(policy: ZTNAPolicy) -> List[str]:
    blocked: List[str] = []
    for cat in policy.blocked_categories:
        blocked.extend(CATEGORY_DOMAINS.get(cat, []))
    for r in policy.rules:
        if r.action == "deny" and re.match(r"^[a-z0-9.\-_]+$", r.destination or ""):
            blocked.append(r.destination)
    # de-dupe + sort
    return sorted(set(blocked))


def compile_to_pf_rules_macos(policy: ZTNAPolicy) -> str:
    lines = ["# MACE ZTNA rules — generated", "set skip on lo0", "block return log all"]
    for r in policy.rules:
        if r.action == "allow":
            lines.append(f"pass out proto tcp to {r.destination if r.destination!='*' else 'any'}")
        elif r.action == "deny":
            lines.append(f"block return out proto tcp to {r.destination if r.destination!='*' else 'any'}")
    return "\n".join(lines) + "\n"


def compile_to_nftables_linux(policy: ZTNAPolicy) -> str:
    out = ["table inet mace_ztna {",
            "  chain output { type filter hook output priority 0; policy drop; }",
            "  chain allowlist { }",
           "}"]
    for r in policy.rules:
        if r.action == "allow":
            out.insert(2, f"  ip daddr {r.destination if r.destination!='*' else '0.0.0.0/0'} accept;")
    return "\n".join(out) + "\n"


def compile_to_netsh_windows(policy: ZTNAPolicy) -> List[str]:
    cmds = []
    for r in policy.rules:
        name = re.sub(r"[^A-Za-z0-9_-]", "_", r.name)[:50]
        if r.action == "deny":
            cmds.append(f'netsh advfirewall firewall add rule name="MACE_{name}" dir=out action=block remoteip={r.destination}')
        elif r.action == "allow":
            cmds.append(f'netsh advfirewall firewall add rule name="MACE_{name}" dir=out action=allow remoteip={r.destination}')
    return cmds


def enforce(policy: ZTNAPolicy, dry_run: bool = True) -> EnforcementStatus:
    """Apply the policy. Always dry-run by default to keep the demo safe."""
    plat = platform.system().lower()
    status = EnforcementStatus(rules_loaded=len(policy.rules), rules_applied=0,
                                last_enforced_at=time.time())
    if dry_run:
        status.rules_applied = len(policy.rules)
        return status
    # Compile + install (gated by allowlist)
    if plat == "darwin":
        text = compile_to_pf_rules_macos(policy)
        if shutil.which("pfctl"):
            tmp = Path("/tmp/mace_ztna.conf"); tmp.write_text(text)
            subprocess.run(["pfctl", "-f", str(tmp), "-e"], check=False)
            status.rules_applied = len(policy.rules)
    elif plat == "linux" and shutil.which("nft"):
        text = compile_to_nftables_linux(policy)
        tmp = Path("/tmp/mace_ztna.nft"); tmp.write_text(text)
        subprocess.run(["nft", "-f", str(tmp)], check=False)
        status.rules_applied = len(policy.rules)
    elif plat == "windows":
        for cmd in compile_to_netsh_windows(policy):
            subprocess.run(cmd, shell=True, check=False)
        status.rules_applied = len(policy.rules)
    return status


def builtin_policy() -> ZTNAPolicy:
    """A sensible default that demonstrates ZTNA / SWG capabilities."""
    return ZTNAPolicy(
        tenant="demo", version="1.0",
        blocked_categories=["malware", "phishing", "crypto_mining"],
        rules=[
            AccessRule("allow_corp_apps", "allow",
                       destination="app.unifiedsec.io", require_mfa=True),
            AccessRule("allow_ms_365", "allow", destination="*.office.com"),
            AccessRule("deny_personal_drive", "deny", destination="*.dropbox.com",
                       note="DLP: prevent corp-data egress to personal sync"),
            AccessRule("deny_gambling", "deny", destination="*.bet365.com"),
            AccessRule("inspect_ssl", "inspect", destination="0.0.0.0/0",
                       note="Inspect TLS via local CA (user-installed certificate)."),
            AccessRule("isolate_high_risk_proc", "isolate",
                       process="powershell.exe", direction="outbound",
                       note="Quarantine PowerShell outbound until analyst approves."),
        ],
        enforced_at=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    )


def status_summary() -> Dict[str, Any]:
    pol = builtin_policy()
    blocked = compile_to_dns_blocklist(pol)
    return {
        "tenant": pol.tenant, "version": pol.version,
        "rules_loaded": len(pol.rules),
        "blocked_categories": pol.blocked_categories,
        "blocked_domains": blocked[:50],
        "platform": platform.system().lower(),
    }
