"""
HWAM — Hardware Asset Management collector.

Real implementation for macOS (Darwin) via:
  - system_profiler SPHardwareDataType -json
  - system_profiler SPNetworkDataType -json
  - system_profiler SPStorageDataType -json
  - ioreg / sysctl fallbacks
  - fdesetup status (FileVault)
  - csrutil status (SIP / Secure Boot indicator)
  - ifconfig / netstat

For Linux + Windows we ship a hook layer that returns realistic simulated
data with the same shape; the structure matches the real macOS output so
downstream consumers don't branch on platform.
"""
from __future__ import annotations
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import uuid
from typing import Any, Dict, List, Optional

from .report import HardwareInventory


# ── shell helpers ────────────────────────────────────────────────────

def _run(cmd: List[str], timeout: int = 10) -> str:
    try:
        out = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout, check=False,
        )
        return out.stdout or ""
    except Exception:
        return ""


def _primary_ip() -> str:
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip
    except Exception:
        try:
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return ""


def _primary_mac() -> str:
    """48-bit MAC address of the active interface, lower-case, colon-separated."""
    try:
        mac_int = uuid.getnode()
        if (mac_int >> 40) % 2:
            # locally administered / random — fall through to platform-specific
            return ""
        mac = ":".join(f"{(mac_int >> (8 * i)) & 0xff:02x}" for i in reversed(range(6)))
        return mac
    except Exception:
        return ""


# ── macOS real collector ─────────────────────────────────────────────

def _collect_macos() -> HardwareInventory:
    h = HardwareInventory()

    # SPHardwareDataType
    raw = _run(["system_profiler", "SPHardwareDataType", "-json"], timeout=20)
    if raw:
        try:
            data = json.loads(raw).get("SPHardwareDataType", [{}])[0]
            h.manufacturer = "Apple Inc."
            h.model = data.get("machine_model") or data.get("machine_name") or ""
            h.serial_number = data.get("serial_number") or ""
            h.chip = data.get("chip_type") or data.get("cpu_type") or ""
            # Cores
            cores = data.get("number_processors") or ""
            m = re.search(r"(\d+)", str(cores))
            if m:
                h.cpu_cores = int(m.group(1))
            # Memory
            mem = data.get("physical_memory") or ""
            m = re.search(r"(\d+(?:\.\d+)?)", str(mem))
            if m:
                val = float(m.group(1))
                if "TB" in mem.upper():
                    val *= 1024
                h.memory_gb = round(val, 1)
            h.firmware_version = data.get("boot_rom_version") or ""
        except Exception:
            pass

    # Network interfaces
    raw = _run(["system_profiler", "SPNetworkDataType", "-json"], timeout=15)
    if raw:
        try:
            for iface in json.loads(raw).get("SPNetworkDataType", []):
                if iface.get("type", "").lower() in ("ethernet", "wi-fi", "wifi", "airport"):
                    h.interfaces.append({
                        "name": iface.get("interface") or iface.get("_name") or "",
                        "type": iface.get("type", ""),
                        "mac": iface.get("Ethernet", {}).get("MAC Address", ""),
                        "ip": (iface.get("IPv4", {}) or {}).get("Addresses", [""])[0] if isinstance((iface.get("IPv4") or {}).get("Addresses"), list) else "",
                        "active": iface.get("hardware", "") != "",
                    })
        except Exception:
            pass

    # Storage / disks
    raw = _run(["system_profiler", "SPStorageDataType", "-json"], timeout=15)
    if raw:
        try:
            for disk in json.loads(raw).get("SPStorageDataType", []):
                size_b = int(disk.get("size_in_bytes", 0) or 0)
                free_b = int(disk.get("free_space_in_bytes", 0) or 0)
                h.disks.append({
                    "name": disk.get("_name", ""),
                    "mount": disk.get("mount_point", ""),
                    "fs": disk.get("file_system", ""),
                    "size_gb": round(size_b / 1e9, 1) if size_b else 0,
                    "free_gb": round(free_b / 1e9, 1) if free_b else 0,
                    "encrypted": bool(disk.get("physical_drive", {}).get("is_encrypted")),
                })
        except Exception:
            pass

    # FileVault status
    fv = _run(["fdesetup", "status"], timeout=5)
    if fv:
        h.disk_encryption = "FileVault is On" in fv

    # SIP / Secure Boot
    sip = _run(["csrutil", "status"], timeout=5)
    if sip:
        h.secure_boot = "enabled" in sip.lower()

    # Primary MAC / IP
    h.primary_ip = _primary_ip()
    if not h.primary_mac and h.interfaces:
        for iface in h.interfaces:
            if iface.get("mac"):
                h.primary_mac = iface["mac"]
                break
    if not h.primary_mac:
        h.primary_mac = _primary_mac()

    # Peripherals (USB devices)
    raw = _run(["system_profiler", "SPUSBDataType", "-json"], timeout=10)
    if raw:
        try:
            def _walk(items):
                for it in items or []:
                    name = it.get("_name")
                    if name and name not in h.peripherals:
                        h.peripherals.append(name)
                    if it.get("_items"):
                        _walk(it["_items"])
            _walk(json.loads(raw).get("SPUSBDataType", []))
        except Exception:
            pass
        h.peripherals = h.peripherals[:25]  # cap

    return h


# ── Linux simulated collector with optional real hooks ───────────────

def _collect_linux() -> HardwareInventory:
    h = HardwareInventory()
    h.manufacturer = "Generic"
    h.model = "Linux Workstation"
    # Try a real hook if dmidecode is available
    if shutil.which("dmidecode"):
        out = _run(["dmidecode", "-s", "system-manufacturer"], timeout=5).strip()
        if out: h.manufacturer = out
        out = _run(["dmidecode", "-s", "system-product-name"], timeout=5).strip()
        if out: h.model = out
        out = _run(["dmidecode", "-s", "system-serial-number"], timeout=5).strip()
        if out: h.serial_number = out
    h.chip = _run(["uname", "-p"]).strip() or platform.machine()
    h.cpu_cores = os.cpu_count() or 0
    try:
        with open("/proc/meminfo") as f:
            for line in f:
                if line.startswith("MemTotal:"):
                    kb = int(line.split()[1])
                    h.memory_gb = round(kb / 1024 / 1024, 1)
                    break
    except Exception:
        h.memory_gb = 8.0  # simulated default
    # Disks
    if os.path.exists("/proc/mounts"):
        try:
            seen = set()
            with open("/proc/mounts") as f:
                for line in f:
                    parts = line.split()
                    if len(parts) >= 3 and parts[1].startswith("/") and parts[2] in ("ext4", "xfs", "btrfs", "zfs"):
                        if parts[0] in seen: continue
                        seen.add(parts[0])
                        h.disks.append({
                            "name": parts[0], "mount": parts[1], "fs": parts[2],
                            "size_gb": 0, "free_gb": 0, "encrypted": "/dev/mapper" in parts[0],
                        })
        except Exception:
            pass
    h.primary_ip = _primary_ip()
    h.primary_mac = _primary_mac()
    h.interfaces.append({
        "name": "eth0", "type": "Ethernet",
        "mac": h.primary_mac, "ip": h.primary_ip, "active": True,
    })
    h.disk_encryption = any(d.get("encrypted") for d in h.disks) or False
    h.secure_boot = os.path.exists("/sys/firmware/efi") or False
    h.tpm_present = os.path.exists("/dev/tpm0")
    return h


# ── Windows simulated collector with optional real hooks ─────────────

def _collect_windows() -> HardwareInventory:
    h = HardwareInventory()
    h.manufacturer = "Generic"
    h.model = "Windows PC"
    if shutil.which("wmic"):
        out = _run(["wmic", "computersystem", "get", "manufacturer,model,name", "/format:list"], timeout=10)
        for line in out.splitlines():
            if line.startswith("Manufacturer="): h.manufacturer = line.split("=", 1)[1].strip()
            if line.startswith("Model="):        h.model        = line.split("=", 1)[1].strip()
        out = _run(["wmic", "bios", "get", "serialnumber", "/format:list"], timeout=10)
        for line in out.splitlines():
            if line.startswith("SerialNumber="): h.serial_number = line.split("=", 1)[1].strip()
    h.chip = platform.processor() or platform.machine()
    h.cpu_cores = os.cpu_count() or 0
    h.memory_gb = 16.0  # simulated default
    h.disks.append({"name": "C:", "mount": "C:\\", "fs": "NTFS",
                    "size_gb": 512.0, "free_gb": 200.0, "encrypted": True})
    h.primary_ip = _primary_ip()
    h.primary_mac = _primary_mac()
    h.interfaces.append({
        "name": "Ethernet", "type": "Ethernet",
        "mac": h.primary_mac, "ip": h.primary_ip, "active": True,
    })
    h.disk_encryption = True   # BitLocker assumed
    h.secure_boot = True
    h.tpm_present = True
    return h


# ── public entrypoint ────────────────────────────────────────────────

def collect_hwam(simulate: bool = False, force_platform: Optional[str] = None) -> HardwareInventory:
    """
    Collect hardware inventory.

    `force_platform` lets the demo show what scans would look like on other
    operating systems (the simulated structure is identical in shape).
    """
    plat = (force_platform or platform.system()).lower()
    if simulate:
        if plat == "darwin":
            return _simulated_macos()
        if plat == "linux":
            return _collect_linux()
        if plat == "windows":
            return _collect_windows()
        return _simulated_macos()

    if plat == "darwin":
        return _collect_macos()
    if plat == "linux":
        return _collect_linux()
    if plat == "windows":
        return _collect_windows()
    return _simulated_macos()


def _simulated_macos() -> HardwareInventory:
    h = HardwareInventory()
    h.manufacturer = "Apple Inc."
    h.model = "MacBook Pro (14-inch, M2 Pro)"
    h.serial_number = "SIMU-XXXX-XXXX"
    h.chip = "Apple M2 Pro"
    h.cpu_cores = 12
    h.memory_gb = 32.0
    h.firmware_version = "10151.61.4"
    h.disks.append({"name": "Macintosh HD", "mount": "/", "fs": "APFS",
                    "size_gb": 1000.0, "free_gb": 320.0, "encrypted": True})
    h.interfaces.append({"name": "en0", "type": "Wi-Fi",
                          "mac": "aa:bb:cc:dd:ee:ff", "ip": "192.168.1.42", "active": True})
    h.primary_mac = "aa:bb:cc:dd:ee:ff"
    h.primary_ip = "192.168.1.42"
    h.disk_encryption = True
    h.secure_boot = True
    h.tpm_present = True
    return h
