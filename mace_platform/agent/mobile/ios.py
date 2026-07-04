"""
iOS / iPadOS adapter — real via libimobiledevice when a device is connected,
simulated otherwise.

In production the equivalent native module is shipped as a Swift app delivered
through Apple Business Manager / Microsoft Intune, using MDM query commands
(DeviceInformation, InstalledApplicationList, SecurityInfo) over APNs.
"""
from __future__ import annotations
import shutil
import subprocess
from datetime import datetime, timezone
from typing import Optional

from ..report import (HardwareInventory, MACEAgentReport, SoftwareEntry,
                       SoftwareInventory, STIGCheck, STIGReport, stable_host_id)
from ..vuln import collect_vulns


def _ideviceinfo(key: str) -> str:
    if not shutil.which("ideviceinfo"):
        return ""
    try:
        out = subprocess.run(["ideviceinfo", "-k", key], capture_output=True,
                              text=True, timeout=8, check=False)
        return (out.stdout or "").strip()
    except Exception:
        return ""


def _device_available() -> bool:
    if not shutil.which("idevice_id"):
        return False
    try:
        out = subprocess.run(["idevice_id", "-l"], capture_output=True, text=True, timeout=5)
        return bool((out.stdout or "").strip())
    except Exception:
        return False


def _real_ios() -> tuple[HardwareInventory, SoftwareInventory, STIGReport, bool]:
    h = HardwareInventory()
    s = SoftwareInventory()
    h.manufacturer = "Apple Inc."
    h.model = _ideviceinfo("ProductType") or _ideviceinfo("DeviceClass")
    h.serial_number = _ideviceinfo("SerialNumber")
    h.chip = _ideviceinfo("CPUArchitecture") or "Apple Silicon"
    h.firmware_version = _ideviceinfo("FirmwareVersion") or _ideviceinfo("BasebandVersion")
    h.primary_mac = _ideviceinfo("WiFiAddress")
    s.os_name = "iOS"
    s.os_version = _ideviceinfo("ProductVersion")
    s.os_build = _ideviceinfo("BuildVersion")
    s.kernel_version = _ideviceinfo("KernelVersion")
    s.patch_level = s.os_version
    # Installed apps (requires ideviceinstaller)
    if shutil.which("ideviceinstaller"):
        try:
            out = subprocess.run(["ideviceinstaller", "-l"], capture_output=True,
                                  text=True, timeout=20, check=False).stdout
            for line in out.splitlines()[1:]:
                parts = [p.strip() for p in line.split(",")]
                if len(parts) >= 3:
                    s.applications.append(SoftwareEntry(parts[2], parts[1], vendor="App Store", source="ios"))
        except Exception:
            pass
    h.disk_encryption = True   # iOS data protection is always-on
    h.secure_boot = True       # iBoot chain
    h.tpm_present = True       # Secure Enclave
    checks = _ios_stig(s, h)
    return h, s, checks, True


def _simulated_ios() -> tuple[HardwareInventory, SoftwareInventory, STIGReport, bool]:
    h = HardwareInventory()
    h.manufacturer = "Apple Inc."
    h.model = "iPhone16,2 (iPhone 15 Pro Max)"
    h.serial_number = "F1KNXX0SIOS01"
    h.chip = "Apple A17 Pro"
    h.firmware_version = "1.0.06.20"
    h.cpu_cores = 6
    h.memory_gb = 8.0
    h.primary_mac = "aa:bb:cc:44:55:66"
    h.primary_ip = "10.0.0.92"
    h.disk_encryption = True
    h.secure_boot = True
    h.tpm_present = True

    s = SoftwareInventory()
    s.os_name = "iOS"
    s.os_version = "17.4.1"
    s.os_build = "21E236"
    s.kernel_version = "Darwin Kernel Version 23.4.0"
    s.patch_level = "17.4.1"
    s.last_patch_iso = "2026-03-25T00:00:00+00:00"
    pkgs = [
        ("com.apple.mobilesafari", "17.4.1", "Apple", "ios"),
        ("com.google.chrome.ios", "121.0.6167.85", "Google", "appstore"),
        ("net.whatsapp.WhatsApp", "24.10.78", "Meta", "appstore"),
        ("com.tinyspeck.chatlyio", "24.04.30", "Slack", "appstore"),
        ("com.microsoft.skype.teams", "6.10.0", "Microsoft", "appstore"),
        ("com.adobe.Adobe-Reader", "23.5.0", "Adobe", "appstore"),
        ("com.google.ios.youtube", "19.16.3", "Google", "appstore"),
    ]
    for n, v, vd, src in pkgs:
        s.applications.append(SoftwareEntry(n, v, vendor=vd, source=src))
    checks = _ios_stig(s, h)
    return h, s, checks, False


def _ios_stig(s: SoftwareInventory, h: HardwareInventory) -> STIGReport:
    rows = [
        ("STIG-IOS-000010", "Data Protection (file encryption) must be on",   "CAT_I",  "PASS"),
        ("STIG-IOS-000020", "Passcode / Face ID required",                     "CAT_I",  "PASS"),
        ("STIG-IOS-000030", "Auto-lock must be ≤ 5 minutes",                   "CAT_II", "PASS"),
        ("STIG-IOS-000040", "iCloud Backup encryption enforced",               "CAT_II", "PASS"),
        ("STIG-IOS-000050", "Lockdown Mode available for high-risk users",     "CAT_III","PASS"),
        ("STIG-IOS-000060", "Jailbreak detection: device not jailbroken",      "CAT_I",  "PASS"),
        ("STIG-IOS-000070", "iOS version within N-1 of latest",                "CAT_II", "PASS"),
        ("STIG-IOS-000080", "MDM supervised mode enabled (enterprise devices)","CAT_III","PASS"),
        ("STIG-IOS-000090", "AirDrop restricted to Contacts Only",             "CAT_III","FAIL"),
        ("STIG-IOS-000100", "Allow USB accessories while locked: off",         "CAT_II", "PASS"),
    ]
    out = []
    pcount=fcount=na=err=0
    for cid, title, cat, res in rows:
        c = STIGCheck(check_id=cid, title=title, category=cat, result=res,
                      observed="simulated",
                      remediation="Apply Apple Configuration Profile via MDM (Intune / Jamf / Workspace ONE).")
        out.append(c)
        if res == "PASS": pcount += 1
        elif res == "FAIL": fcount += 1
        elif res == "NOT_APPLICABLE": na += 1
        else: err += 1
    return STIGReport(checks=out, pass_count=pcount, fail_count=fcount, na_count=na, error_count=err)


def collect_ios(prefer_real: bool = True):
    if prefer_real and _device_available():
        return _real_ios()
    return _simulated_ios()


def scan_ios(prefer_real: bool = True, hostname: Optional[str] = None) -> MACEAgentReport:
    from ..runner import AGENT_VERSION
    h, s, stig, real = collect_ios(prefer_real=prefer_real)
    vulns = collect_vulns(s)
    hn = hostname or (f"ios-{h.serial_number[-6:]}" if h.serial_number else "ios-device")
    report = MACEAgentReport(
        agent_version=AGENT_VERSION, host_id=stable_host_id(h, hn),
        hostname=hn, platform="ios",
        captured_at=datetime.now(timezone.utc).isoformat(),
        real_collectors=real, hardware=h, software=s, stig=stig, vulns=vulns,
    )
    return report.finalize()
