"""
UnifiedSec MACE — Endpoint Agent (UMEA)
========================================
Patent: IN/2026/UNISEC/MACE-001 + PCT, addendum filed May 2026 covering the
Unified Endpoint Agent component (HWAM + SWAM + STIG + Vuln fused scan).

The agent replaces the data-collection role previously filled by:
  - CrowdStrike Falcon (endpoint telemetry, asset inventory)
  - Tenable.io / Tenable.sc (vulnerability scanning, patch posture)

It does so by performing four scans IN A SINGLE PASS on the host where it is
installed and reporting the results back into the MACE pipeline:

  1. HWAM — Hardware Asset Management
       CPU, memory, disks, network interfaces, peripherals, serial, MAC,
       firmware revisions, boot security (Secure Boot / FileVault / BitLocker)
  2. SWAM — Software Asset Management
       Operating system + patch level, installed applications, kernel modules,
       running services, package-manager inventories (brew, apt, dnf, msi)
  3. STIG — Security Technical Implementation Guide compliance
       A baseline of CIS / DISA STIG checks: sshd config, firewall state,
       disk encryption, password policy, audit logging, screen lock, etc.
  4. Vuln — CVE matching from SWAM inventory against a local CVE database
       Replaces the need for a Tenable network scan: the agent already knows
       every installed package + version, so CVE matching is exact.

Realism profile:
  - macOS (Darwin)   : real collectors (system_profiler, sw_vers, sysctl,
                        defaults read, launchctl, security)
  - Linux            : simulated structure with hooks for /etc/os-release,
                        dpkg, rpm, systemctl when present
  - Windows          : simulated structure with hooks for wmic, Get-CimInstance

The agent emits a single MACEAgentReport bundle which is consumed by the
EndpointAgentConnector (mace_platform/connectors/endpoint_agent) and ingested
into the standard UTAG → CDCS → UREA pipeline.
"""

from .report import MACEAgentReport, ReportSummary
from .runner import scan_this_device, scan_simulated

__all__ = [
    "MACEAgentReport",
    "ReportSummary",
    "scan_this_device",
    "scan_simulated",
]
