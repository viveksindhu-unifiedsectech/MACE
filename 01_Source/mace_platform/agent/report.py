"""
MACEAgentReport — unified bundle emitted by the endpoint agent.

A single report carries HWAM, SWAM, STIG and Vuln results together with the
device identity needed for UTAG ingestion. The CDCS engine consumes the
report directly via the EndpointAgentConnector.
"""
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import hashlib
import json
import platform as _platform


# ── HWAM ─────────────────────────────────────────────────────────────

@dataclass
class HardwareInventory:
    manufacturer: str = ""
    model: str = ""
    serial_number: str = ""
    chip: str = ""               # e.g. "Apple M2 Pro"
    cpu_cores: int = 0
    memory_gb: float = 0.0
    disks: List[Dict[str, Any]] = field(default_factory=list)
    interfaces: List[Dict[str, Any]] = field(default_factory=list)
    primary_mac: str = ""
    primary_ip: str = ""
    secure_boot: Optional[bool] = None
    disk_encryption: Optional[bool] = None     # FileVault / BitLocker / LUKS
    firmware_version: str = ""
    tpm_present: Optional[bool] = None
    peripherals: List[str] = field(default_factory=list)


# ── SWAM ─────────────────────────────────────────────────────────────

@dataclass
class SoftwareEntry:
    name: str
    version: str = ""
    vendor: str = ""
    install_date: str = ""
    source: str = ""             # brew | apt | dnf | msi | system | app_store
    install_path: str = ""       # where the app/bundle/package lives on disk
    bundle_id: str = ""          # macOS bundle id / Android package / iOS bundle id
    installed_by: str = ""       # the local user / SID that installed the package
    installer_signature: str = ""# code-signing identity if known (Apple Dev ID / SmbiosCS)


@dataclass
class SoftwareInventory:
    os_name: str = ""
    os_version: str = ""
    os_build: str = ""
    kernel_version: str = ""
    patch_level: str = ""
    last_patch_iso: str = ""
    applications: List[SoftwareEntry] = field(default_factory=list)
    services: List[Dict[str, Any]] = field(default_factory=list)
    kernel_modules: List[str] = field(default_factory=list)
    open_ports: List[int] = field(default_factory=list)


# ── STIG ─────────────────────────────────────────────────────────────

@dataclass
class STIGCheck:
    check_id: str                # e.g. "STIG-MAC-OS-000010"
    title: str
    category: str                # CAT_I (critical) | CAT_II | CAT_III
    result: str                  # PASS | FAIL | NOT_APPLICABLE | ERROR
    observed: str = ""
    expected: str = ""
    remediation: str = ""


@dataclass
class STIGReport:
    baseline: str = "CIS+DISA-STIG hybrid v1"
    pass_count: int = 0
    fail_count: int = 0
    na_count: int = 0
    error_count: int = 0
    checks: List[STIGCheck] = field(default_factory=list)

    @property
    def compliance_ratio(self) -> float:
        t = self.pass_count + self.fail_count
        return self.pass_count / t if t else 0.5


# ── Vuln ─────────────────────────────────────────────────────────────

@dataclass
class VulnHit:
    cve_id: str
    cvss_v3: float
    severity: str                # CRITICAL | HIGH | MEDIUM | LOW
    affected_component: str      # package or app name
    installed_version: str
    fixed_version: str = ""
    epss_score: float = 0.0
    exploit_status: str = "no_exploit_known"
    patch_available: bool = False
    description: str = ""
    remediation: str = ""        # human-readable concrete fix step
    remediation_cmd: str = ""    # one-liner shell command when available
    priority_score: float = 0.0  # 0..10 — populated by the algorithm
    source: str = "umea-cve-db"


@dataclass
class VulnReport:
    scanned_packages: int = 0
    cve_db_version: str = ""
    hits: List[VulnHit] = field(default_factory=list)

    def by_severity(self) -> Dict[str, int]:
        out = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
        for h in self.hits:
            out[h.severity] = out.get(h.severity, 0) + 1
        return out


# ── Full bundle ──────────────────────────────────────────────────────

@dataclass
class ReportSummary:
    hwam_assets: int
    swam_apps: int
    stig_pass: int
    stig_fail: int
    stig_compliance_ratio: float
    vuln_count: int
    vuln_critical: int
    vuln_high: int
    device_risk_score: float          # 0.0 – 10.0 (fused MACE-style device risk)
    severity: str                     # CRITICAL | HIGH | MEDIUM | LOW | INFO


@dataclass
class MACEAgentReport:
    """
    A single emission from the endpoint agent.

    The report_hash field is a SHA-256 chain-of-custody hash over the canonical
    JSON serialization, used by UREA for evidence integrity.
    """
    agent_version: str
    host_id: str                      # stable per-device id
    hostname: str
    platform: str                     # darwin | linux | windows
    captured_at: str                  # ISO-8601 UTC
    real_collectors: bool             # True when collectors actually probed the OS
    scanned_by: str = ""              # OS user that ran the scan
    scan_signature: str = ""          # SHA-256(scanned_by ‖ host_id ‖ captured_at)
    hardware: HardwareInventory = field(default_factory=HardwareInventory)
    software: SoftwareInventory = field(default_factory=SoftwareInventory)
    stig: STIGReport = field(default_factory=STIGReport)
    vulns: VulnReport = field(default_factory=VulnReport)
    malware: Optional[Dict[str, Any]] = None
    hackable: Optional[Dict[str, Any]] = None
    intrusion: Optional[Dict[str, Any]] = None
    edr: Optional[Dict[str, Any]] = None
    sbom: Optional[Dict[str, Any]] = None
    dlp: Optional[Dict[str, Any]] = None
    cspm: Optional[Dict[str, Any]] = None
    honeytokens: Optional[Dict[str, Any]] = None
    summary: Optional[ReportSummary] = None
    remediation_plan: Optional[Dict[str, Any]] = None    # populated by remediation.build_plan
    report_hash: str = ""

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        # asdict turns dataclasses into dicts recursively; keep enums as strings
        return d

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), default=str, indent=2, sort_keys=True)

    def finalize(self) -> "MACEAgentReport":
        """Compute summary + chain-of-custody hash."""
        self.summary = build_summary(self)
        canon = json.dumps(
            {k: v for k, v in self.to_dict().items() if k != "report_hash"},
            default=str, sort_keys=True,
        )
        self.report_hash = hashlib.sha256(canon.encode("utf-8")).hexdigest()
        return self


# ── Summary fusion (mini-MACE per device) ────────────────────────────

_SEV_W = {"CRITICAL": 1.0, "HIGH": 0.75, "MEDIUM": 0.50, "LOW": 0.25}


def _device_risk(report: "MACEAgentReport") -> float:
    """
    Per-device risk on a 0–10 scale. This is a deliberately compressed
    preview of the full CDCS computation so the agent UI can show something
    immediately. The real fused score is recomputed server-side by CDCS.

    Risk = 10 × (0.45·V + 0.20·H + 0.20·S + 0.15·C) where
      V = max CVSS·EPSS·sev hit, normalised
      H = HWAM exposure (no encryption / no secure boot / many open ports)
      S = STIG noncompliance ratio
      C = patch staleness factor
    """
    # V — vulnerability sub-score
    v = 0.0
    for hit in report.vulns.hits:
        sev_w = _SEV_W.get(hit.severity, 0.25)
        epss_boost = 1.0 + 0.30 * max(0.0, min(1.0, hit.epss_score))
        s = (hit.cvss_v3 / 10.0) * sev_w * epss_boost
        if s > v:
            v = s
    v = min(1.0, v)

    # H — HWAM exposure
    h = 0.0
    if report.hardware.disk_encryption is False:
        h += 0.4
    if report.hardware.secure_boot is False:
        h += 0.25
    h += min(0.35, 0.02 * len(report.software.open_ports))
    h = min(1.0, h)

    # S — STIG noncompliance
    s = 1.0 - report.stig.compliance_ratio
    s = max(0.0, min(1.0, s))

    # C — patch staleness (very rough)
    c = 0.5
    last = report.software.last_patch_iso
    if last:
        try:
            dt = datetime.fromisoformat(last.replace("Z", "+00:00"))
            age_days = (datetime.now(timezone.utc) - dt).days
            c = max(0.0, min(1.0, age_days / 180.0))
        except Exception:
            pass

    return round(10.0 * (0.45 * v + 0.20 * h + 0.20 * s + 0.15 * c), 2)


def _severity_label(score: float) -> str:
    if score >= 9: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 5: return "MEDIUM"
    if score >= 3: return "LOW"
    return "INFO"


def build_summary(report: "MACEAgentReport") -> ReportSummary:
    by_sev = report.vulns.by_severity()
    risk = _device_risk(report)
    return ReportSummary(
        hwam_assets=1 + len(report.hardware.disks) + len(report.hardware.interfaces),
        swam_apps=len(report.software.applications),
        stig_pass=report.stig.pass_count,
        stig_fail=report.stig.fail_count,
        stig_compliance_ratio=round(report.stig.compliance_ratio, 3),
        vuln_count=len(report.vulns.hits),
        vuln_critical=by_sev.get("CRITICAL", 0),
        vuln_high=by_sev.get("HIGH", 0),
        device_risk_score=risk,
        severity=_severity_label(risk),
    )


def stable_host_id(hwam: HardwareInventory, hostname: str) -> str:
    """SHA-256 of MAC + serial + hostname — stable across reboots."""
    seed = "|".join([hwam.primary_mac or "", hwam.serial_number or "", hostname or ""])
    if not seed.strip("|"):
        seed = _platform.node() or "unknown-host"
    return hashlib.sha256(seed.encode("utf-8")).hexdigest()[:32]
