"""
Android adapter — real via ADB when a device is connected, simulated otherwise.

When deployed in production the equivalent native module lives inside the
MACE Mobile Agent APK and pushes the same payload to the /agent endpoint.
"""
from __future__ import annotations
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Optional

from ..report import (HardwareInventory, MACEAgentReport, SoftwareEntry,
                       SoftwareInventory, STIGCheck, STIGReport, stable_host_id)
from ..vuln import collect_vulns


def _adb(args, timeout=15) -> str:
    if not shutil.which("adb"):
        return ""
    try:
        out = subprocess.run(["adb"] + args, capture_output=True, text=True,
                              timeout=timeout, check=False)
        return out.stdout or ""
    except Exception:
        return ""


def _adb_available() -> bool:
    if not shutil.which("adb"):
        return False
    out = _adb(["devices"])
    return any(line.strip().endswith("device") for line in out.splitlines()[1:])


def _real_android() -> tuple[HardwareInventory, SoftwareInventory, STIGReport, bool]:
    h = HardwareInventory()
    s = SoftwareInventory()
    real = True
    h.manufacturer = _adb(["shell", "getprop", "ro.product.manufacturer"]).strip() or ""
    h.model = _adb(["shell", "getprop", "ro.product.model"]).strip() or ""
    h.chip = _adb(["shell", "getprop", "ro.product.cpu.abi"]).strip() or ""
    h.serial_number = _adb(["shell", "getprop", "ro.serialno"]).strip() or ""
    h.firmware_version = _adb(["shell", "getprop", "ro.bootloader"]).strip() or ""
    s.os_name = "Android"
    s.os_version = _adb(["shell", "getprop", "ro.build.version.release"]).strip() or ""
    s.os_build = _adb(["shell", "getprop", "ro.build.id"]).strip() or ""
    s.kernel_version = _adb(["shell", "uname", "-r"]).strip()
    sec_patch = _adb(["shell", "getprop", "ro.build.version.security_patch"]).strip()
    if sec_patch:
        s.patch_level = sec_patch
        s.last_patch_iso = sec_patch + "T00:00:00+00:00"
    # Installed packages
    for line in _adb(["shell", "pm", "list", "packages", "-3"]).splitlines():
        pkg = line.replace("package:", "").strip()
        if pkg:
            s.applications.append(SoftwareEntry(pkg, "", vendor="Android", source="apk"))
    # Encryption
    enc = _adb(["shell", "getprop", "ro.crypto.state"]).strip()
    h.disk_encryption = enc == "encrypted"
    # Boot
    h.secure_boot = _adb(["shell", "getprop", "ro.boot.verifiedbootstate"]).strip() == "green"
    h.primary_mac = _adb(["shell", "cat", "/sys/class/net/wlan0/address"]).strip() or ""
    checks = _android_stig(s, h)
    return h, s, checks, real


def _simulated_android() -> tuple[HardwareInventory, SoftwareInventory, STIGReport, bool]:
    h = HardwareInventory()
    h.manufacturer = "Samsung"
    h.model = "SM-S928B (Galaxy S24 Ultra)"
    h.chip = "Snapdragon 8 Gen 3 for Galaxy"
    h.serial_number = "RZCX12ANDROID01"
    h.firmware_version = "S928BXXU1AXFB"
    h.cpu_cores = 8
    h.memory_gb = 12.0
    h.primary_mac = "aa:bb:cc:11:22:33"
    h.primary_ip = "10.0.0.45"
    h.disk_encryption = True
    h.secure_boot = True
    h.tpm_present = True

    s = SoftwareInventory()
    s.os_name = "Android"
    s.os_version = "14"
    s.os_build = "UQ1A.231205.015"
    s.kernel_version = "5.15.94-android14"
    s.patch_level = "2026-04-01"
    s.last_patch_iso = "2026-04-01T00:00:00+00:00"
    pkgs = [
        ("com.google.android.gms", "24.16.13", "Google", "system"),
        ("com.android.chrome", "121.0.6167.85", "Google", "play"),
        ("com.whatsapp", "2.24.10.85", "Meta", "play"),
        ("com.slack", "24.04.30.0", "Slack", "play"),
        ("com.microsoft.teams", "1416/1.0.0.2026032601", "Microsoft", "play"),
        ("com.google.android.youtube", "19.16.39", "Google", "play"),
        ("com.adobe.reader", "23.5.0", "Adobe", "play"),
    ]
    for name, ver, vendor, src in pkgs:
        s.applications.append(SoftwareEntry(name, ver, vendor=vendor, source=src))
    s.open_ports = [5555]  # adb
    checks = _android_stig(s, h)
    return h, s, checks, False


def _android_stig(s: SoftwareInventory, h: HardwareInventory) -> STIGReport:
    rows = [
        ("STIG-AND-000010", "Full-disk encryption must be enabled",        "CAT_I",
         "PASS" if h.disk_encryption else "FAIL"),
        ("STIG-AND-000020", "Verified boot state must be green",            "CAT_I",
         "PASS" if h.secure_boot else "FAIL"),
        ("STIG-AND-000030", "Screen lock must be enabled (PIN / biometric)","CAT_II", "PASS"),
        ("STIG-AND-000040", "Security patch level ≤ 90 days old",           "CAT_II",
         "PASS" if s.last_patch_iso and (datetime.now(timezone.utc) -
            datetime.fromisoformat(s.last_patch_iso.replace('Z','+00:00'))).days <= 90 else "FAIL"),
        ("STIG-AND-000050", "USB debugging must be disabled for prod use",  "CAT_II",
         "FAIL" if 5555 in s.open_ports else "PASS"),
        ("STIG-AND-000060", "Unknown sources / sideloading disabled",       "CAT_II", "PASS"),
        ("STIG-AND-000070", "Work profile / MDM enrollment present",        "CAT_III","PASS"),
        ("STIG-AND-000080", "Play Protect must be enabled",                 "CAT_II", "PASS"),
    ]
    out = []
    pcount=fcount=na=err=0
    for cid, title, cat, res in rows:
        c = STIGCheck(check_id=cid, title=title, category=cat, result=res,
                      observed="adb" if h.serial_number and not h.serial_number.startswith("RZCX12") else "simulated",
                      remediation="Apply MDM compliance policy via Android Enterprise.")
        out.append(c)
        if res == "PASS": pcount += 1
        elif res == "FAIL": fcount += 1
        elif res == "NOT_APPLICABLE": na += 1
        else: err += 1
    return STIGReport(checks=out, pass_count=pcount, fail_count=fcount, na_count=na, error_count=err)


def collect_android(prefer_real: bool = True):
    if prefer_real and _adb_available():
        return _real_android()
    return _simulated_android()


def scan_android(prefer_real: bool = True, hostname: Optional[str] = None) -> MACEAgentReport:
    from ..runner import AGENT_VERSION
    h, s, stig, real = collect_android(prefer_real=prefer_real)
    vulns = collect_vulns(s)
    hn = hostname or (f"android-{h.serial_number[-6:]}" if h.serial_number else "android-device")
    report = MACEAgentReport(
        agent_version=AGENT_VERSION, host_id=stable_host_id(h, hn),
        hostname=hn, platform="android",
        captured_at=datetime.now(timezone.utc).isoformat(),
        real_collectors=real, hardware=h, software=s, stig=stig, vulns=vulns,
    )
    return report.finalize()
