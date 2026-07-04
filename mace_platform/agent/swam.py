"""
SWAM — Software Asset Management collector.

macOS real implementation:
  - sw_vers          → OS name + version + build
  - uname -r         → kernel version
  - ls /Applications → installed .app bundles, parsing Info.plist for version
  - mdls / defaults  → application bundle metadata
  - brew list        → Homebrew packages (if installed)
  - launchctl list   → running launchd services
  - kextstat         → kernel extensions
  - lsof / netstat   → listening ports

Linux + Windows: structured simulation with optional real hooks (dpkg / rpm /
systemctl on Linux; wmic / Get-WmiObject on Windows). Output shape is identical
across platforms.
"""
from __future__ import annotations
import json
import os
import platform
import plistlib
import re
import shutil
import subprocess
from datetime import datetime, timezone
from typing import List, Optional

from .report import SoftwareEntry, SoftwareInventory


def _run(cmd, timeout: int = 15) -> str:
    try:
        out = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
        return out.stdout or ""
    except Exception:
        return ""


def _app_version_from_bundle(app_path: str) -> str:
    plist = os.path.join(app_path, "Contents", "Info.plist")
    if not os.path.exists(plist):
        return ""
    try:
        with open(plist, "rb") as f:
            data = plistlib.load(f)
        return data.get("CFBundleShortVersionString") or data.get("CFBundleVersion") or ""
    except Exception:
        return ""


def _app_bundle_id(app_path: str) -> str:
    plist = os.path.join(app_path, "Contents", "Info.plist")
    if not os.path.exists(plist): return ""
    try:
        with open(plist, "rb") as f:
            return plistlib.load(f).get("CFBundleIdentifier", "") or ""
    except Exception:
        return ""


def _app_vendor_from_bundle(app_path: str) -> str:
    plist = os.path.join(app_path, "Contents", "Info.plist")
    if not os.path.exists(plist):
        return ""
    try:
        with open(plist, "rb") as f:
            data = plistlib.load(f)
        bid = data.get("CFBundleIdentifier", "") or ""
        # com.apple.Safari → Apple
        if bid.startswith("com.apple."): return "Apple"
        if bid.startswith("com.google."): return "Google"
        if bid.startswith("com.microsoft."): return "Microsoft"
        if bid.startswith("com.adobe."): return "Adobe"
        if bid.startswith("org.mozilla."): return "Mozilla"
        if bid.startswith("com.docker."): return "Docker"
        return data.get("CFBundleGetInfoString", "").split(",")[0] or bid.split(".")[1].capitalize() if "." in bid else bid
    except Exception:
        return ""


# ── macOS ────────────────────────────────────────────────────────────

def _collect_macos() -> SoftwareInventory:
    s = SoftwareInventory()

    # OS info
    s.os_name = "macOS"
    out = _run(["sw_vers"])
    for line in out.splitlines():
        if line.startswith("ProductVersion:"): s.os_version = line.split(":", 1)[1].strip()
        if line.startswith("BuildVersion:"):   s.os_build   = line.split(":", 1)[1].strip()
    s.kernel_version = _run(["uname", "-r"]).strip()
    s.patch_level = s.os_version

    # Last system update — softwareupdate history lives in /Library/Receipts/InstallHistory.plist
    plist_path = "/Library/Receipts/InstallHistory.plist"
    if os.path.exists(plist_path):
        try:
            with open(plist_path, "rb") as f:
                hist = plistlib.load(f)
            if isinstance(hist, list) and hist:
                last = hist[-1].get("date")
                if last:
                    if isinstance(last, datetime):
                        s.last_patch_iso = last.replace(tzinfo=timezone.utc).isoformat()
                    else:
                        s.last_patch_iso = str(last)
        except Exception:
            pass

    # Installed apps from /Applications + ~/Applications
    candidates = []
    for root in ("/Applications", os.path.expanduser("~/Applications"), "/System/Applications"):
        if os.path.isdir(root):
            for name in os.listdir(root):
                if name.endswith(".app"):
                    candidates.append(os.path.join(root, name))
    for app in candidates[:300]:
        name = os.path.basename(app).rsplit(".app", 1)[0]
        bundle_id = _app_bundle_id(app)
        s.applications.append(SoftwareEntry(
            name=name,
            version=_app_version_from_bundle(app),
            vendor=_app_vendor_from_bundle(app),
            source="app_store" if "/System/Applications" in app else "macos",
            install_path=app,
            bundle_id=bundle_id,
        ))

    # Homebrew packages
    if shutil.which("brew"):
        brew_prefix = _run(["brew", "--prefix"], timeout=5).strip() or "/opt/homebrew"
        out = _run(["brew", "list", "--versions"], timeout=20)
        for line in out.splitlines():
            parts = line.strip().split()
            if not parts: continue
            s.applications.append(SoftwareEntry(
                name=parts[0],
                version=parts[1] if len(parts) > 1 else "",
                vendor="Homebrew",
                source="brew",
                install_path=f"{brew_prefix}/Cellar/{parts[0]}/{parts[1] if len(parts) > 1 else ''}",
            ))

    # Running services (launchctl)
    out = _run(["launchctl", "list"], timeout=10)
    for line in out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 3 and parts[2].strip():
            s.services.append({"label": parts[2].strip(), "pid": parts[0].strip(), "status": parts[1].strip()})
    s.services = s.services[:60]

    # Kernel extensions
    out = _run(["kextstat", "-l"], timeout=10)
    for line in out.splitlines()[1:]:
        parts = re.split(r"\s+", line.strip(), maxsplit=6)
        if len(parts) >= 6:
            s.kernel_modules.append(parts[5])
    s.kernel_modules = list(dict.fromkeys(s.kernel_modules))[:80]

    # Listening ports
    out = _run(["lsof", "-iTCP", "-sTCP:LISTEN", "-Pn"], timeout=10)
    for line in out.splitlines()[1:]:
        m = re.search(r":(\d+)\s*\(LISTEN\)", line)
        if m:
            p = int(m.group(1))
            if p not in s.open_ports:
                s.open_ports.append(p)
    s.open_ports.sort()

    return s


# ── Linux ────────────────────────────────────────────────────────────

def _collect_linux() -> SoftwareInventory:
    s = SoftwareInventory()
    s.os_name = "Linux"
    try:
        with open("/etc/os-release") as f:
            for line in f:
                if line.startswith("PRETTY_NAME="):
                    s.os_name = line.split("=", 1)[1].strip().strip('"')
                elif line.startswith("VERSION_ID="):
                    s.os_version = line.split("=", 1)[1].strip().strip('"')
    except Exception:
        s.os_version = "unknown"
    s.kernel_version = _run(["uname", "-r"]).strip()
    s.patch_level = s.kernel_version

    if shutil.which("dpkg"):
        out = _run(["dpkg", "-l"], timeout=15)
        for line in out.splitlines():
            if not line.startswith("ii"): continue
            parts = line.split()
            if len(parts) >= 3:
                s.applications.append(SoftwareEntry(parts[1], parts[2], vendor="Debian/Ubuntu", source="apt"))
    elif shutil.which("rpm"):
        out = _run(["rpm", "-qa", "--queryformat", "%{NAME}|%{VERSION}\n"], timeout=15)
        for line in out.splitlines():
            if "|" in line:
                n, v = line.split("|", 1)
                s.applications.append(SoftwareEntry(n, v, vendor="RHEL/Fedora", source="dnf"))
    else:
        # simulated: richer Ubuntu 22.04 fleet image
        s.os_name = "Ubuntu 22.04.3 LTS"; s.os_version = "22.04"
        for n, v in [
            ("openssh-server", "8.9p1-3ubuntu0.4"), ("nginx", "1.22.1"),
            ("python3", "3.10.12"), ("python3-pip", "22.0.2"),
            ("openssl", "3.0.2"), ("curl", "7.81.0-1ubuntu1.15"),
            ("bash", "5.1.16-1ubuntu3"), ("systemd", "249.11-0ubuntu3.11"),
            ("apt", "2.4.11"), ("dpkg", "1.21.1ubuntu2.3"),
            ("libssl3", "3.0.2-0ubuntu1.14"), ("libc6", "2.35-0ubuntu3.6"),
            ("nodejs", "20.10.0"), ("npm", "10.2.4"), ("docker.io", "24.0.5-0ubuntu1"),
            ("postgresql-14", "14.10-0ubuntu0.22.04.1"),
            ("redis-server", "5:6.0.16-1ubuntu1"),
            ("nginx-common", "1.22.1"), ("xz-utils", "5.2.5-2ubuntu1"),
            ("ca-certificates", "20230311ubuntu0.22.04.1"),
            ("vim", "2:8.2.3995-1ubuntu2.16"),
            ("git", "1:2.34.1-1ubuntu1.10"),
            ("htop", "3.0.5-7build2"),
            ("aiohttp", "3.9.0"), ("Jinja2", "3.1.2"), ("requests", "2.30.0"),
        ]:
            path = f"/usr/bin/{n}" if "-" not in n else f"/var/lib/dpkg/info/{n}.list"
            if n in ("aiohttp", "Jinja2", "requests"):
                path = f"/usr/lib/python3/dist-packages/{n.lower()}"
            elif n == "docker.io":
                path = "/usr/bin/dockerd"
            elif n == "postgresql-14":
                path = "/usr/lib/postgresql/14/bin/postgres"
            elif n == "redis-server":
                path = "/usr/bin/redis-server"
            elif n == "nginx":
                path = "/usr/sbin/nginx"
            elif n == "nodejs":
                path = "/usr/bin/node"
            elif n == "openssh-server":
                path = "/usr/sbin/sshd"
            s.applications.append(SoftwareEntry(n, v, vendor="Ubuntu", source="apt",
                install_path=path))
        s.services = [
            {"label": "sshd.service", "pid": "1024", "status": "running"},
            {"label": "nginx.service", "pid": "2048", "status": "running"},
            {"label": "postgresql.service", "pid": "3072", "status": "running"},
            {"label": "docker.service", "pid": "4096", "status": "running"},
            {"label": "ufw.service", "pid": "512", "status": "active"},
        ]
        s.kernel_modules = ["nf_conntrack", "iptable_nat", "xt_conntrack",
                              "vfio", "kvm_intel", "ext4"]
        s.open_ports = [22, 80, 443, 5432, 6379, 8080, 8443, 9090]

    s.last_patch_iso = datetime.now(timezone.utc).isoformat()
    return s


# ── Windows ──────────────────────────────────────────────────────────

def _collect_windows() -> SoftwareInventory:
    s = SoftwareInventory()
    s.os_name = "Windows"
    s.os_version = platform.release()
    s.kernel_version = platform.version()
    s.patch_level = platform.version()
    if shutil.which("wmic"):
        out = _run(["wmic", "product", "get", "name,version", "/format:csv"], timeout=30)
        for line in out.splitlines()[2:]:
            parts = line.split(",")
            if len(parts) >= 3:
                name = parts[1].strip()
                ver  = parts[2].strip()
                if name:
                    s.applications.append(SoftwareEntry(name, ver, vendor="Windows", source="msi"))
    if not s.applications:
        win_paths = {
            "Microsoft Edge":          r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            "Google Chrome":           r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            "Microsoft Office":        r"C:\Program Files\Microsoft Office\root\Office16",
            "Adobe Acrobat Reader":    r"C:\Program Files\Adobe\Acrobat DC\Acrobat\Acrobat.exe",
            "Zoom":                    r"C:\Users\Public\AppData\Roaming\Zoom\bin\Zoom.exe",
            "Microsoft Teams":         r"C:\Users\jdoe\AppData\Local\Microsoft\Teams\current\Teams.exe",
            "VMware Horizon Client":   r"C:\Program Files (x86)\VMware\VMware Horizon View Client",
            "Cisco AnyConnect":        r"C:\Program Files (x86)\Cisco\Cisco AnyConnect Secure Mobility Client",
            "Notepad++":               r"C:\Program Files\Notepad++\notepad++.exe",
            "7-Zip":                   r"C:\Program Files\7-Zip\7zG.exe",
            "WinRAR":                  r"C:\Program Files\WinRAR\WinRAR.exe",
            "Mozilla Firefox":         r"C:\Program Files\Mozilla Firefox\firefox.exe",
            "Slack":                   r"C:\Users\jdoe\AppData\Local\slack\slack.exe",
            "Visual Studio Code":      r"C:\Users\jdoe\AppData\Local\Programs\Microsoft VS Code\Code.exe",
            "OpenSSL":                 r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe",
            "Python":                  r"C:\Users\jdoe\AppData\Local\Programs\Python\Python311\python.exe",
            "Node.js":                 r"C:\Program Files\nodejs\node.exe",
            "Docker Desktop":          r"C:\Program Files\Docker\Docker\Docker Desktop.exe",
            "nginx":                   r"C:\nginx\nginx.exe",
            "curl":                    r"C:\Windows\System32\curl.exe",
            "Windows":                 r"C:\Windows",
        }
        for n, v, vd in [
            ("Microsoft Edge", "120.0.2210.61", "Microsoft"),
            ("Google Chrome", "120.0.6099.71", "Google"),
            ("Microsoft Office", "16.0.16924.20106", "Microsoft"),
            ("Adobe Acrobat Reader", "23.006.20320", "Adobe"),
            ("Zoom", "5.16.10.27752", "Zoom Video Communications"),
            ("Microsoft Teams", "1.5.00.36367", "Microsoft"),
            ("VMware Horizon Client", "8.10.0", "VMware"),
            ("Cisco AnyConnect", "4.10.06090", "Cisco"),
            ("Notepad++", "8.6.2", "Don Ho"),
            ("7-Zip", "23.01", "Igor Pavlov"),
            ("WinRAR", "6.24.0", "RARLAB"),
            ("Mozilla Firefox", "121.0.1", "Mozilla"),
            ("Slack", "4.36.140", "Slack Technologies"),
            ("Visual Studio Code", "1.85.2", "Microsoft"),
            ("OpenSSL", "1.1.1u", "OpenSSL Project"),
            ("Python", "3.11.4", "Python Software Foundation"),
            ("Node.js", "20.10.0", "OpenJS Foundation"),
            ("Docker Desktop", "4.26.0", "Docker"),
            ("nginx", "1.22.1", "nginx"),
            ("curl", "7.81.0", "curl"),
            ("Windows", "10.0.22631.3007", "Microsoft"),
        ]:
            s.applications.append(SoftwareEntry(n, v, vendor=vd, source="msi",
                install_path=win_paths.get(n, "")))
        s.services = [
            {"label": "WinDefend", "pid": "1234", "status": "running"},
            {"label": "spoolsv", "pid": "5678", "status": "running"},
            {"label": "Dnscache", "pid": "910", "status": "running"},
            {"label": "BITS", "pid": "1500", "status": "running"},
        ]
        s.open_ports = [135, 139, 445, 3389, 5040, 49664]
    s.last_patch_iso = datetime.now(timezone.utc).isoformat()
    return s


# ── public entrypoint ────────────────────────────────────────────────

def collect_swam(simulate: bool = False, force_platform: Optional[str] = None) -> SoftwareInventory:
    plat = (force_platform or platform.system()).lower()
    if simulate or plat not in ("darwin", "linux", "windows"):
        if plat == "linux":   return _collect_linux()
        if plat == "windows": return _collect_windows()
        return _simulated_macos()
    if plat == "darwin":  return _collect_macos()
    if plat == "linux":   return _collect_linux()
    if plat == "windows": return _collect_windows()
    return _simulated_macos()


def _simulated_macos() -> SoftwareInventory:
    s = SoftwareInventory()
    s.os_name = "macOS"
    s.os_version = "14.4.1"
    s.os_build = "23E224"
    s.kernel_version = "23.4.0"
    s.patch_level = "14.4.1"
    s.last_patch_iso = "2026-04-15T18:22:00+00:00"
    macos_paths = {
        "Safari": "/Applications/Safari.app",
        "Google Chrome": "/Applications/Google Chrome.app",
        "Firefox": "/Applications/Firefox.app",
        "Slack": "/Applications/Slack.app",
        "Visual Studio Code": "/Applications/Visual Studio Code.app",
        "Docker Desktop": "/Applications/Docker.app",
        "Zoom": "/Applications/zoom.us.app",
        "OpenSSL": "/opt/homebrew/Cellar/openssl@1.1",
        "Python": "/opt/homebrew/Cellar/python@3.11",
        "Node.js": "/opt/homebrew/Cellar/node",
        "Microsoft Office": "/Applications/Microsoft Word.app",
        "Microsoft Teams": "/Applications/Microsoft Teams.app",
        "Adobe Acrobat Reader": "/Applications/Adobe Acrobat Reader.app",
        "1Password": "/Applications/1Password.app",
        "Postman": "/Applications/Postman.app",
        "Figma": "/Applications/Figma.app",
        "Notion": "/Applications/Notion.app",
        "Spotify": "/Applications/Spotify.app",
        "Discord": "/Applications/Discord.app",
        "Telegram": "/Applications/Telegram.app",
        "WhatsApp": "/Applications/WhatsApp.app",
        "curl": "/usr/bin/curl",
        "Microsoft Edge": "/Applications/Microsoft Edge.app",
        "nginx": "/opt/homebrew/Cellar/nginx",
        "jq": "/opt/homebrew/Cellar/jq",
        "git": "/opt/homebrew/Cellar/git",
        "vim": "/opt/homebrew/Cellar/vim",
        "openssh": "/opt/homebrew/Cellar/openssh",
    }
    for n, v, vd, src in [
        ("Safari", "17.2", "Apple", "macos"),
        ("Google Chrome", "120.0.6099.71", "Google", "macos"),
        ("Firefox", "123.0.1", "Mozilla", "macos"),
        ("Slack", "4.36.140", "Slack", "macos"),
        ("Visual Studio Code", "1.85.2", "Microsoft", "macos"),
        ("Docker Desktop", "4.26.0", "Docker", "macos"),
        ("Zoom", "5.16.10", "Zoom", "macos"),
        ("OpenSSL", "1.1.1u", "OpenSSL", "brew"),
        ("Python", "3.11.4", "Python", "brew"),
        ("Node.js", "20.10.0", "OpenJS", "brew"),
        ("Microsoft Office", "16.78", "Microsoft", "macos"),
        ("Microsoft Teams", "1.5.0", "Microsoft", "macos"),
        ("Adobe Acrobat Reader", "23.6.20320", "Adobe", "macos"),
        ("1Password", "8.10.20", "AgileBits", "macos"),
        ("Postman", "10.21.0", "Postman Inc.", "macos"),
        ("Figma", "116.16.4", "Figma", "macos"),
        ("Notion", "3.4.0", "Notion Labs", "macos"),
        ("Spotify", "1.2.31.1205", "Spotify", "macos"),
        ("Discord", "0.0.296", "Discord", "macos"),
        ("Telegram", "10.6", "Telegram", "macos"),
        ("WhatsApp", "23.21.79", "Meta", "macos"),
        ("curl", "7.81.0", "curl", "system"),
        ("Microsoft Edge", "120.0.2210.61", "Microsoft", "macos"),
        ("nginx", "1.22.1", "nginx", "brew"),
        ("jq", "1.6", "Stedolan", "brew"),
        ("git", "2.40.1", "git", "brew"),
        ("vim", "9.0.1500", "Vim", "brew"),
        ("openssh", "9.4", "OpenSSH", "brew"),
    ]:
        s.applications.append(SoftwareEntry(n, v, vendor=vd, source=src,
            install_path=macos_paths.get(n, ""),
            bundle_id=("com." + vd.lower().replace(" ", "") + "." + n.lower().replace(" ", "")
                       if src == "macos" else "")))
    s.services = [
        {"label": "com.apple.WindowServer", "pid": "150", "status": "0"},
        {"label": "com.apple.cfprefsd.xpc.daemon", "pid": "75", "status": "0"},
        {"label": "com.docker.helper", "pid": "1024", "status": "0"},
        {"label": "homebrew.mxcl.postgresql", "pid": "2048", "status": "0"},
        {"label": "io.unifiedsec.maceagent", "pid": "3071", "status": "0"},
    ]
    s.kernel_modules = ["com.apple.kext.AppleHWAccess", "com.apple.driver.AppleAPFS",
                         "com.apple.iokit.IONetworkingFamily", "com.apple.kext.CoreTrust"]
    s.open_ports = [22, 88, 445, 5000, 5432, 7000, 8765]
    return s
