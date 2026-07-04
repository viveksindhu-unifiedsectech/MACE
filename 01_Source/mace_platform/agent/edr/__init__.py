"""
EDR — Endpoint Detection & Response: in-memory behaviour layer.

Detects malware patterns at runtime that signature scanners miss:

  • LSASS dumping                — process opening lsass.exe with PROCESS_VM_READ
  • Process hollowing             — section unmap + remote VirtualAllocEx + thread create
  • Cobalt Strike beacons         — known beacon mutex names + sleep/jitter heuristic
  • Suspicious living-off-the-land— PowerShell -enc, certutil -decode, mshta http
  • Suspicious child trees        — winword.exe → cmd.exe → powershell.exe
  • EBPF/seccomp escapes (Linux)  — ptrace + capabilities + namespace transitions

Platform hooks (best effort, gracefully degrades):
  • macOS    : EndpointSecurity framework via /System/Library/Frameworks/EndpointSecurity
               Real-time process / file / network notifications.
  • Windows  : ETW Microsoft-Windows-Sysmon / Threat-Intelligence providers via
               PowerShell Get-WinEvent or external Sysmon installation.
  • Linux    : eBPF via bcc / bpftrace when available, else perf events.

For platforms without root, the module degrades to a *poll-based* watchdog
that snapshots `ps`/`tasklist` and compares against a built-in ruleset.
"""
from .behaviour import scan_memory_behaviour, BehaviourReport, BehaviourHit

__all__ = ["scan_memory_behaviour", "BehaviourReport", "BehaviourHit"]
