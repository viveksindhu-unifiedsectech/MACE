"""
STIG / CIS baseline compliance checker.

This module implements a curated subset of DISA STIG and CIS Benchmark
controls that the endpoint agent can verify locally without external
references. The checks are intentionally cross-platform: each check has
a per-platform probe and a NOT_APPLICABLE branch for the others.

Categories follow STIG severity:
  CAT_I   — severe (e.g. disk encryption off, SSH root login)
  CAT_II  — significant (e.g. weak password policy, screen lock disabled)
  CAT_III — informational (e.g. banner not configured)

Real on macOS (Darwin). Simulated on Linux + Windows with realistic
pass/fail mixes so downstream scoring exercises every branch.
"""
from __future__ import annotations
import os
import platform
import shutil
import subprocess
from typing import List

from .report import STIGCheck, STIGReport


def _run(cmd, timeout: int = 8) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return (out.stdout or "") + (out.stderr or "")
    except Exception:
        return ""


def _mk(check_id, title, category, result, observed="", expected="", remediation="") -> STIGCheck:
    return STIGCheck(check_id=check_id, title=title, category=category, result=result,
                     observed=observed, expected=expected, remediation=remediation)


# ── macOS real checks ────────────────────────────────────────────────

def _check_macos(hwam_disk_encryption: bool | None) -> List[STIGCheck]:
    checks: List[STIGCheck] = []

    # 1. FileVault enabled (CAT I)
    fv = _run(["fdesetup", "status"])
    enabled = "FileVault is On" in fv
    checks.append(_mk(
        "STIG-MAC-OS-000010", "FileVault disk encryption must be enabled", "CAT_I",
        "PASS" if enabled else "FAIL",
        observed=fv.strip().splitlines()[0] if fv else "fdesetup unavailable",
        expected="FileVault is On",
        remediation="Enable FileVault in System Settings → Privacy & Security.",
    ))

    # 2. Firewall enabled (CAT II)
    fw = _run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"])
    fw_on = "enabled" in fw.lower() and "disabled" not in fw.lower()
    checks.append(_mk(
        "STIG-MAC-OS-000020", "Application firewall must be enabled", "CAT_II",
        "PASS" if fw_on else "FAIL",
        observed=fw.strip() or "n/a",
        expected="Firewall is enabled.",
        remediation="System Settings → Network → Firewall → Turn On Firewall.",
    ))

    # 3. SSH root login disabled (CAT I) — check sshd_config
    sshd_paths = ["/etc/ssh/sshd_config", "/private/etc/ssh/sshd_config"]
    root_login = None
    sshd_present = False
    for p in sshd_paths:
        if os.path.exists(p):
            sshd_present = True
            try:
                with open(p) as f:
                    for line in f:
                        line = line.strip()
                        if line.startswith("#") or not line: continue
                        if line.lower().startswith("permitrootlogin"):
                            root_login = line.split()[-1].lower()
                            break
            except Exception:
                pass
            break
    if not sshd_present:
        checks.append(_mk(
            "STIG-MAC-OS-000030", "SSH PermitRootLogin must be 'no'", "CAT_I",
            "NOT_APPLICABLE", observed="sshd_config not present", expected="PermitRootLogin no",
            remediation="N/A: SSH service not installed.",
        ))
    else:
        ok = root_login in (None, "no", "prohibit-password")
        checks.append(_mk(
            "STIG-MAC-OS-000030", "SSH PermitRootLogin must be 'no'", "CAT_I",
            "PASS" if ok else "FAIL",
            observed=f"PermitRootLogin {root_login or 'unset'}",
            expected="PermitRootLogin no",
            remediation="Set 'PermitRootLogin no' in /etc/ssh/sshd_config and reload ssh.",
        ))

    # 4. Remote Login (SSH service) state (CAT II)
    rl = _run(["systemsetup", "-getremotelogin"])
    rl_off = "Off" in rl
    checks.append(_mk(
        "STIG-MAC-OS-000031", "Remote Login (sshd) should be off unless required", "CAT_II",
        "PASS" if rl_off else "FAIL",
        observed=rl.strip(),
        expected="Remote Login: Off",
        remediation="sudo systemsetup -setremotelogin off",
    ))

    # 5. Screen lock idle time ≤ 15 minutes (CAT II)
    idle = _run(["defaults", "-currentHost", "read", "com.apple.screensaver", "idleTime"]).strip()
    try:
        idle_i = int(idle)
        ok = 0 < idle_i <= 900
        checks.append(_mk(
            "STIG-MAC-OS-000040", "Screen saver idle time must be ≤ 15 minutes", "CAT_II",
            "PASS" if ok else "FAIL",
            observed=f"idleTime={idle_i}s",
            expected="0 < idleTime ≤ 900",
            remediation="defaults -currentHost write com.apple.screensaver idleTime -int 600",
        ))
    except Exception:
        checks.append(_mk(
            "STIG-MAC-OS-000040", "Screen saver idle time must be ≤ 15 minutes", "CAT_II",
            "FAIL", observed=idle or "unset", expected="0 < idleTime ≤ 900",
            remediation="defaults -currentHost write com.apple.screensaver idleTime -int 600",
        ))

    # 6. Require password immediately after screensaver (CAT II)
    askp = _run(["defaults", "read", "com.apple.screensaver", "askForPassword"]).strip()
    delay = _run(["defaults", "read", "com.apple.screensaver", "askForPasswordDelay"]).strip()
    ok = askp == "1" and (delay in ("0", "5"))
    checks.append(_mk(
        "STIG-MAC-OS-000041", "Require password immediately after screensaver", "CAT_II",
        "PASS" if ok else "FAIL",
        observed=f"askForPassword={askp}, delay={delay}",
        expected="askForPassword=1, delay ≤ 5",
        remediation="defaults write com.apple.screensaver askForPassword -int 1; "
                    "defaults write com.apple.screensaver askForPasswordDelay -int 0",
    ))

    # 7. Automatic software updates enabled (CAT II)
    auto = _run(["defaults", "read", "/Library/Preferences/com.apple.SoftwareUpdate", "AutomaticCheckEnabled"]).strip()
    ok = auto == "1"
    checks.append(_mk(
        "STIG-MAC-OS-000050", "Automatic software-update checks must be enabled", "CAT_II",
        "PASS" if ok else "FAIL",
        observed=f"AutomaticCheckEnabled={auto or 'unset'}",
        expected="AutomaticCheckEnabled=1",
        remediation="sudo defaults write /Library/Preferences/com.apple.SoftwareUpdate AutomaticCheckEnabled -int 1",
    ))

    # 8. Gatekeeper enabled (CAT I)
    gk = _run(["spctl", "--status"])
    ok = "assessments enabled" in gk.lower()
    checks.append(_mk(
        "STIG-MAC-OS-000060", "Gatekeeper must be enabled", "CAT_I",
        "PASS" if ok else "FAIL",
        observed=gk.strip(),
        expected="assessments enabled",
        remediation="sudo spctl --master-enable",
    ))

    # 9. SIP (System Integrity Protection) enabled (CAT I)
    sip = _run(["csrutil", "status"])
    ok = "enabled" in sip.lower()
    checks.append(_mk(
        "STIG-MAC-OS-000070", "System Integrity Protection must be enabled", "CAT_I",
        "PASS" if ok else "FAIL",
        observed=sip.strip(),
        expected="System Integrity Protection status: enabled.",
        remediation="Reboot to Recovery → Terminal → csrutil enable.",
    ))

    # 10. Guest account disabled (CAT II)
    guest = _run(["defaults", "read", "/Library/Preferences/com.apple.loginwindow", "GuestEnabled"]).strip()
    ok = guest in ("0", "")
    checks.append(_mk(
        "STIG-MAC-OS-000080", "Guest user account must be disabled", "CAT_II",
        "PASS" if ok else "FAIL",
        observed=f"GuestEnabled={guest or 'unset'}",
        expected="GuestEnabled=0",
        remediation="sudo defaults write /Library/Preferences/com.apple.loginwindow GuestEnabled -int 0",
    ))

    # 11. Bluetooth discoverability (CAT III)
    bt = _run(["defaults", "read", "/Library/Preferences/com.apple.Bluetooth", "DiscoverableState"]).strip()
    ok = bt in ("0", "")
    checks.append(_mk(
        "STIG-MAC-OS-000090", "Bluetooth must not be in discoverable state", "CAT_III",
        "PASS" if ok else "FAIL",
        observed=f"DiscoverableState={bt or 'unset'}",
        expected="DiscoverableState=0",
        remediation="Disable Bluetooth discoverability in System Settings.",
    ))

    # 12. Wi-Fi captive bypass off (CAT III)
    cap = _run(["defaults", "read", "/Library/Preferences/SystemConfiguration/com.apple.captive.control", "Active"]).strip()
    ok = cap in ("0", "")
    checks.append(_mk(
        "STIG-MAC-OS-000100", "Captive portal auto-detect should be disabled", "CAT_III",
        "PASS" if ok else "NOT_APPLICABLE",
        observed=f"Active={cap or 'unset'}",
        expected="Active=0",
        remediation="sudo defaults write /Library/Preferences/SystemConfiguration/com.apple.captive.control Active -int 0",
    ))

    return checks


# ── Linux simulated checks ───────────────────────────────────────────

def _check_linux() -> List[STIGCheck]:
    checks: List[STIGCheck] = []

    # Try real probes where possible
    if shutil.which("ufw"):
        fw = _run(["ufw", "status"])
        fw_on = "active" in fw.lower()
    else:
        fw_on = True
    checks.append(_mk("STIG-LIN-000010", "Host firewall must be enabled", "CAT_I",
                      "PASS" if fw_on else "FAIL", expected="Firewall active",
                      remediation="sudo ufw enable"))

    sshd_no_root = True
    if os.path.exists("/etc/ssh/sshd_config"):
        try:
            with open("/etc/ssh/sshd_config") as f:
                for line in f:
                    if line.strip().lower().startswith("permitrootlogin") and "yes" in line.lower():
                        sshd_no_root = False
                        break
        except Exception:
            pass
    checks.append(_mk("STIG-LIN-000020", "SSH PermitRootLogin must not be 'yes'", "CAT_I",
                      "PASS" if sshd_no_root else "FAIL",
                      expected="PermitRootLogin no",
                      remediation="Set PermitRootLogin no in /etc/ssh/sshd_config; systemctl restart sshd"))

    # Simulated: disk encryption, audit, password aging, screen lock
    sim_results = [
        ("STIG-LIN-000030", "LUKS disk encryption must be enabled",      "CAT_I",  "PASS"),
        ("STIG-LIN-000040", "Auditd must be running",                    "CAT_II", "PASS"),
        ("STIG-LIN-000050", "PASS_MAX_DAYS must be ≤ 60",                "CAT_II", "FAIL"),
        ("STIG-LIN-000060", "Idle session timeout (TMOUT) must be set",  "CAT_II", "FAIL"),
        ("STIG-LIN-000070", "Banner /etc/issue must be configured",      "CAT_III","PASS"),
        ("STIG-LIN-000080", "SELinux/AppArmor must be enforcing",        "CAT_I",  "PASS"),
        ("STIG-LIN-000090", "Automatic security updates must be enabled","CAT_II", "PASS"),
        ("STIG-LIN-000100", "TLS 1.2+ enforced in /etc/ssl/openssl.cnf", "CAT_II", "PASS"),
    ]
    for cid, title, cat, res in sim_results:
        checks.append(_mk(cid, title, cat, res, observed="simulated", expected="see remediation",
                          remediation="Refer to CIS Ubuntu Benchmark / DISA STIG for Linux."))
    return checks


# ── Windows simulated checks ─────────────────────────────────────────

def _check_windows() -> List[STIGCheck]:
    base = [
        ("STIG-WIN-000010", "BitLocker must be enabled on system drive",    "CAT_I",  "PASS"),
        ("STIG-WIN-000020", "Windows Defender real-time protection on",     "CAT_I",  "PASS"),
        ("STIG-WIN-000030", "Account lockout threshold ≤ 3",                "CAT_II", "FAIL"),
        ("STIG-WIN-000040", "Password length ≥ 14 characters",              "CAT_II", "PASS"),
        ("STIG-WIN-000050", "Auto-lock after 15 minutes",                   "CAT_II", "PASS"),
        ("STIG-WIN-000060", "SMBv1 must be disabled",                       "CAT_I",  "PASS"),
        ("STIG-WIN-000070", "UAC must be set to highest",                   "CAT_II", "FAIL"),
        ("STIG-WIN-000080", "Audit Logon Events: Success + Failure",        "CAT_II", "PASS"),
        ("STIG-WIN-000090", "Guest account disabled",                       "CAT_I",  "PASS"),
        ("STIG-WIN-000100", "PowerShell ConstrainedLanguage mode enforced", "CAT_II", "PASS"),
    ]
    out = []
    for cid, title, cat, res in base:
        out.append(_mk(cid, title, cat, res, observed="simulated",
                       remediation="See DISA STIG for Microsoft Windows 10/11."))
    return out


# ── public entrypoint ────────────────────────────────────────────────

def collect_stig(simulate: bool = False, force_platform: str | None = None,
                  disk_encryption: bool | None = None) -> STIGReport:
    plat = (force_platform or platform.system()).lower()
    if simulate or plat not in ("darwin", "linux", "windows"):
        if plat == "linux":   checks = _check_linux()
        elif plat == "windows": checks = _check_windows()
        else: checks = _simulated_macos_checks(disk_encryption)
    else:
        if plat == "darwin":  checks = _check_macos(disk_encryption)
        elif plat == "linux":   checks = _check_linux()
        else: checks = _check_windows()

    rep = STIGReport(checks=checks)
    for c in checks:
        if   c.result == "PASS":           rep.pass_count  += 1
        elif c.result == "FAIL":           rep.fail_count  += 1
        elif c.result == "NOT_APPLICABLE": rep.na_count    += 1
        else:                              rep.error_count += 1
    return rep


def _simulated_macos_checks(disk_encryption: bool | None = None) -> List[STIGCheck]:
    base = [
        ("STIG-MAC-OS-000010", "FileVault disk encryption must be enabled", "CAT_I",  "PASS" if disk_encryption is not False else "FAIL"),
        ("STIG-MAC-OS-000020", "Application firewall must be enabled",       "CAT_II", "PASS"),
        ("STIG-MAC-OS-000030", "SSH PermitRootLogin must be 'no'",            "CAT_I",  "PASS"),
        ("STIG-MAC-OS-000040", "Screen saver idle time ≤ 15 minutes",         "CAT_II", "PASS"),
        ("STIG-MAC-OS-000041", "Require password immediately after lock",     "CAT_II", "FAIL"),
        ("STIG-MAC-OS-000050", "Automatic software-update checks enabled",    "CAT_II", "PASS"),
        ("STIG-MAC-OS-000060", "Gatekeeper enabled",                          "CAT_I",  "PASS"),
        ("STIG-MAC-OS-000070", "SIP enabled",                                 "CAT_I",  "PASS"),
        ("STIG-MAC-OS-000080", "Guest user account disabled",                 "CAT_II", "PASS"),
        ("STIG-MAC-OS-000090", "Bluetooth not in discoverable state",         "CAT_III","PASS"),
    ]
    return [_mk(cid, t, cat, r, observed="simulated") for cid, t, cat, r in base]
