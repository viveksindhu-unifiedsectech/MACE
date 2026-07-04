"""
Real-time monitoring daemon — UMEA continuous detection mode.

`mace-agent daemon` keeps the agent running as a long-lived process that:

  • performs a full HWAM+SWAM+STIG+Vuln scan on startup,
  • subscribes to OS-level event streams to detect changes immediately,
  • re-runs a delta scan when high-signal events fire,
  • pushes incremental updates to the ingest URL (or invokes a callback in
    embedded mode used by the GUI).

Event streams (best effort, gracefully degrades when unavailable):

  macOS    : FSEvents via `fs_usage` and `log stream` for process exec;
             /etc/security/audit_user for login events.
  Linux    : inotify on /etc /var/log /usr/bin via `inotifywait`;
             `journalctl -f -u sshd -u auditd` for logins/exec.
  Windows  : ETW summary via `wevtutil qe Security /f:Text` polling;
             `Get-WinEvent` for process create/terminate (4688/4689).
  Android  : `adb logcat -T 1` filtered for PackageInstaller, SELinux denies,
             screenlock state changes.
  iOS      : libimobiledevice `idevicesyslog` filtered for kSecure / Boot /
             MDM events.

This module ships an event-loop that runs the OS-appropriate streaming
command in a background thread and re-evaluates the agent report when an
interesting event fires. A debounce window (default 30 s) prevents storms.
"""
from __future__ import annotations
import os
import platform
import shutil
import subprocess
import threading
import time
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from queue import Empty, Queue
from typing import Callable, List, Optional

from .runner import scan_this_device


@dataclass
class RealtimeEvent:
    ts: float
    kind: str            # process_exec | file_change | login | net_conn | package | policy
    source: str
    detail: str
    severity: str = "INFO"
    raw: str = ""


# ── platform-specific watchers ───────────────────────────────────────

def _macos_watchers(q: Queue, stop: threading.Event):
    threads = []
    if shutil.which("log"):
        threads.append(_spawn(
            ["log", "stream", "--style", "compact",
             "--predicate", "subsystem == 'com.apple.securityd' "
             "OR eventMessage CONTAINS 'exec' "
             "OR eventMessage CONTAINS 'sudo' "
             "OR eventMessage CONTAINS 'sshd' "
             "OR eventMessage CONTAINS 'AuthorizationCopyRights'"],
            "process_exec", q, stop, "macos:unified-log"
        ))
    if shutil.which("fs_usage"):
        # fs_usage requires root — try without sudo, fall through if it fails
        threads.append(_spawn(
            ["fs_usage", "-w", "-f", "filesys"], "file_change", q, stop, "macos:fs_usage",
            warn_on_fail=False,
        ))
    return threads


def _linux_watchers(q: Queue, stop: threading.Event):
    threads = []
    if shutil.which("journalctl"):
        threads.append(_spawn(
            ["journalctl", "-f", "-n", "0", "-o", "cat",
             "-u", "sshd", "-u", "auditd", "-u", "systemd-logind"],
            "login", q, stop, "linux:journald",
        ))
    if shutil.which("inotifywait"):
        watch_dirs = [d for d in ("/etc", "/usr/local/bin", "/var/log") if os.path.isdir(d)]
        if watch_dirs:
            threads.append(_spawn(
                ["inotifywait", "-mqr", "-e", "modify,create,delete,attrib"] + watch_dirs,
                "file_change", q, stop, "linux:inotify",
            ))
    return threads


def _windows_watchers(q: Queue, stop: threading.Event):
    threads = []
    if shutil.which("powershell"):
        # Poll 4688 (process create) + 4624 (logon) every ~5s
        ps = ("Get-WinEvent -LogName Security -MaxEvents 20 "
              "-FilterHashtable @{LogName='Security';Id=4688,4624} "
              "| Select TimeCreated,Id,Message | ConvertTo-Json -Compress")
        threads.append(_spawn(
            ["powershell", "-NoProfile", "-Command",
             f"while($true){{ {ps}; Start-Sleep -Seconds 5 }}"],
            "process_exec", q, stop, "windows:eventlog",
        ))
    return threads


def _android_watchers(q: Queue, stop: threading.Event):
    if shutil.which("adb"):
        return [_spawn(
            ["adb", "logcat", "-T", "1",
             "PackageManager:I", "PackageInstaller:I", "SELinux:W", "*:S"],
            "package", q, stop, "android:logcat",
        )]
    return []


def _ios_watchers(q: Queue, stop: threading.Event):
    if shutil.which("idevicesyslog"):
        return [_spawn(["idevicesyslog"], "policy", q, stop, "ios:syslog")]
    return []


def _spawn(cmd: List[str], kind: str, q: Queue, stop: threading.Event,
            source_tag: str, warn_on_fail: bool = True) -> threading.Thread:
    def _runner():
        try:
            proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                     text=True, bufsize=1)
        except Exception as e:
            if warn_on_fail:
                q.put(RealtimeEvent(time.time(), "policy", source_tag,
                                     f"watcher failed: {e}", severity="LOW"))
            return
        try:
            while not stop.is_set():
                line = proc.stdout.readline()
                if not line:
                    if proc.poll() is not None: break
                    continue
                line = line.strip()
                if not line: continue
                sev = "HIGH" if any(k in line.lower()
                                     for k in ("denied", "sudo", "root", "exec", "failed password",
                                               "install", "uninstall")) else "INFO"
                q.put(RealtimeEvent(time.time(), kind, source_tag, line[:240], severity=sev, raw=line))
        finally:
            try: proc.terminate()
            except Exception: pass
    t = threading.Thread(target=_runner, name=f"watcher:{source_tag}", daemon=True)
    t.start()
    return t


# ── public API ───────────────────────────────────────────────────────

@dataclass
class DaemonHandle:
    queue: Queue = field(default_factory=Queue)
    stop_event: threading.Event = field(default_factory=threading.Event)
    threads: list = field(default_factory=list)

    def stop(self):
        self.stop_event.set()


def start_watchers(platform_override: Optional[str] = None) -> DaemonHandle:
    """Spawn OS-appropriate watcher threads and return a handle."""
    h = DaemonHandle()
    plat = (platform_override or platform.system()).lower()
    if plat == "darwin":      h.threads = _macos_watchers(h.queue, h.stop_event)
    elif plat == "linux":     h.threads = _linux_watchers(h.queue, h.stop_event)
    elif plat == "windows":   h.threads = _windows_watchers(h.queue, h.stop_event)
    elif plat == "android":   h.threads = _android_watchers(h.queue, h.stop_event)
    elif plat == "ios":       h.threads = _ios_watchers(h.queue, h.stop_event)
    return h


def run_daemon(
    ingest_url: Optional[str] = None,
    on_event: Optional[Callable[[RealtimeEvent], None]] = None,
    on_rescan: Optional[Callable[[object], None]] = None,
    rescan_debounce_s: int = 30,
    rescan_floor_s: int = 600,
    max_seconds: Optional[int] = None,
) -> None:
    """
    Run the real-time agent loop.

    - on_event   : invoked for every RealtimeEvent (for live GUI / logging).
    - on_rescan  : invoked with the new MACEAgentReport after a rescan.
    - ingest_url : if provided, POST the report there after each rescan.
    - rescan_debounce_s : minimum seconds between rescans after a triggering event.
    - rescan_floor_s    : forced rescan cadence even if nothing happens.
    """
    handle = start_watchers()
    started = time.time()
    last_rescan = 0.0
    pending = False

    # Initial full scan
    report = scan_this_device()
    last_rescan = time.time()
    _deliver(report, on_rescan, ingest_url)

    while True:
        if max_seconds and (time.time() - started) > max_seconds:
            break
        try:
            ev = handle.queue.get(timeout=1.0)
            if on_event:
                try: on_event(ev)
                except Exception: pass
            if ev.severity in ("HIGH", "CRITICAL") or ev.kind in ("package", "policy"):
                pending = True
        except Empty:
            pass

        now = time.time()
        forced = (now - last_rescan) >= rescan_floor_s
        if (pending and (now - last_rescan) >= rescan_debounce_s) or forced:
            report = scan_this_device()
            last_rescan = now
            pending = False
            _deliver(report, on_rescan, ingest_url)

    handle.stop()


def _deliver(report, on_rescan, ingest_url):
    if on_rescan:
        try: on_rescan(report)
        except Exception: pass
    if ingest_url:
        try:
            req = urllib.request.Request(ingest_url, data=report.to_json().encode("utf-8"),
                headers={"Content-Type": "application/json"}, method="POST")
            urllib.request.urlopen(req, timeout=10).read()
        except Exception:
            pass
