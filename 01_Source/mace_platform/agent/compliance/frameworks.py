"""
Master catalog of compliance frameworks and the MACE controls that
satisfy each one.

Each ControlMapping declares:
  framework         : short ID (e.g. "soc2_typeii")
  control_id        : the framework's native control ID
  control_text      : one-line summary of what the auditor wants to see
  mace_modules      : list of MACE module(s) that produce that evidence
  evidence_artifact : where the auditor can find the evidence in MACE
                      (UREA chain-of-custody hash, dashboard view, S3 path)
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List


@dataclass(frozen=True)
class ControlMapping:
    framework: str
    control_id: str
    control_text: str
    mace_modules: tuple
    evidence_artifact: str


# Subset of mappings — the production catalog auto-expands per release.
# Each row is a real auditor-visible control.
FRAMEWORK_CATALOG: List[ControlMapping] = [
    # ── SOC 2 Type II ────────────────────────────────────────────────
    ControlMapping("soc2_typeii", "CC6.1", "Logical access controls restrict access to systems and data.",
        ("itdr", "auto_remediate"), "UREA evidence: access decisions log"),
    ControlMapping("soc2_typeii", "CC6.6", "System uses encryption for data at rest and in transit.",
        ("hwam", "stig"), "Agent HWAM disk_encryption + STIG TLS 1.2+ checks"),
    ControlMapping("soc2_typeii", "CC7.1", "Detection of cyber threats and incidents.",
        ("malware", "edr", "intrusion", "vuln"), "Agent realtime daemon events"),
    ControlMapping("soc2_typeii", "CC7.2", "Continuous monitoring identifies anomalies.",
        ("daemon", "intrusion"), "Daemon event stream + CDCS alerts"),

    # ── ISO 27001:2022 ───────────────────────────────────────────────
    ControlMapping("iso27001_2022", "A.5.23", "Information security for use of cloud services.",
        ("cloud.cspm",), "CSPM AWS/Azure/GCP scan reports"),
    ControlMapping("iso27001_2022", "A.8.7", "Protection against malware.",
        ("malware", "edr"), "Malware + EDR behaviour scans"),
    ControlMapping("iso27001_2022", "A.8.8", "Management of technical vulnerabilities.",
        ("vuln", "feeds.nvd", "remediation"), "Vuln report + NVD feed + remediation plan"),
    ControlMapping("iso27001_2022", "A.8.16", "Monitoring activities.",
        ("daemon", "intrusion"), "Daemon realtime events"),

    # ── PCI-DSS 4.0 ──────────────────────────────────────────────────
    ControlMapping("pcidss_4", "11.4.1", "Internal and external vulnerability scans.",
        ("vuln", "feeds.nvd"), "Quarterly vuln scan reports"),
    ControlMapping("pcidss_4", "10.4.1", "Logs are reviewed daily.",
        ("daemon", "intrusion"), "Audit log with SHA-256 chain"),
    ControlMapping("pcidss_4", "3.4.1", "PAN is rendered unreadable.",
        ("dlp",), "DLP detection of PAN on disk"),

    # ── HIPAA Security Rule ──────────────────────────────────────────
    ControlMapping("hipaa", "164.308(a)(1)(ii)(A)", "Risk analysis.",
        ("vuln", "remediation"), "Per-device risk score + remediation plan"),
    ControlMapping("hipaa", "164.312(a)(2)(iv)", "Encryption and decryption.",
        ("hwam",), "FileVault / BitLocker / LUKS check"),
    ControlMapping("hipaa", "164.312(b)", "Audit controls.",
        ("daemon", "auto_remediate"), "Audit log (chain-of-custody)"),

    # ── FedRAMP Moderate ─────────────────────────────────────────────
    ControlMapping("fedramp_moderate", "AU-2",  "Audit events.",
        ("daemon", "auto_remediate"), "Audit log"),
    ControlMapping("fedramp_moderate", "CM-7",  "Least functionality.",
        ("hackable",), "Hackable-config + open-services scan"),
    ControlMapping("fedramp_moderate", "RA-5",  "Vulnerability monitoring.",
        ("vuln", "feeds.nvd"), "Continuous vuln scan + KEV feed"),
    ControlMapping("fedramp_moderate", "SI-3",  "Malicious code protection.",
        ("malware", "edr"), "Realtime malware + behaviour engine"),
    ControlMapping("fedramp_moderate", "SI-4",  "System monitoring.",
        ("daemon", "intrusion"), "Daemon stream + intrusion scan"),

    # ── DHS Continuous Diagnostics & Mitigation (CDM) ────────────────
    ControlMapping("dhs_cdm", "HWAM-1", "Hardware asset management.",
        ("hwam",), "Agent HWAM inventory"),
    ControlMapping("dhs_cdm", "SWAM-1", "Software asset management.",
        ("swam",), "Agent SWAM inventory"),
    ControlMapping("dhs_cdm", "CSM-1",  "Configuration settings management.",
        ("stig",), "STIG / CIS baseline + delta"),
    ControlMapping("dhs_cdm", "VULN-1", "Vulnerability management.",
        ("vuln", "feeds.nvd"), "Daily NVD + KEV ingestion"),
    ControlMapping("dhs_cdm", "PRIV-1", "Privileged user management.",
        ("itdr",), "ITDR detections + role-creep monitoring"),
    ControlMapping("dhs_cdm", "BEHAVE-1", "Behavioural analytics.",
        ("edr", "macey"), "EDR behaviour rules + Macey GenAI"),
    ControlMapping("dhs_cdm", "BOUND-1", "Manage network boundaries.",
        ("dns_filter",), "DNS sinkhole + DLP egress watcher"),

    # ── DoD CMMC 2.0 ─────────────────────────────────────────────────
    ControlMapping("cmmc_l2", "SI.L2-3.14.1", "Identify, report, and correct flaws.",
        ("vuln", "auto_remediate"), "Vuln scan + auto-remediation audit log"),
    ControlMapping("cmmc_l2", "SI.L2-3.14.5", "Periodic scans.",
        ("daemon",), "Realtime + scheduled scan cadence"),
    ControlMapping("cmmc_l2", "AC.L2-3.1.5", "Least privilege.",
        ("hackable",), "Sudo NOPASSWD heuristic + service exposure"),

    # ── India DPDP / CERT-In ─────────────────────────────────────────
    ControlMapping("india_dpdp", "S.10",
        "Reasonable security safeguards including encryption + access control.",
        ("hwam", "itdr"), "Disk encryption + identity events"),
    ControlMapping("cert_in_6hr", "Directive 2022",
        "Mandatory 6-hour breach reporting to CERT-In.",
        ("rea",), "UREA CERT-In incident report draft"),
    ControlMapping("rbi_cyber", "Cyber-2016",
        "Cyber-Security Framework for Banks: continuous risk monitoring.",
        ("vuln", "daemon"), "Continuous scan + alert cadence"),

    # ── UAE NESA ─────────────────────────────────────────────────────
    ControlMapping("uae_nesa", "T2.4.1",
        "Asset inventory and security configuration baseline.",
        ("hwam", "swam", "stig"), "HWAM+SWAM+STIG triple"),
    ControlMapping("uae_nesa", "T6.5.1", "Vulnerability management.",
        ("vuln", "feeds.nvd"), "Vuln report + NVD feed"),

    # ── EU GDPR / NIS2 ───────────────────────────────────────────────
    ControlMapping("gdpr", "Art.32",
        "Appropriate technical and organisational measures.",
        ("hwam", "stig", "dlp"), "Encryption + STIG + DLP coverage"),
    ControlMapping("nis2", "Art.21",
        "Risk-management and incident reporting.",
        ("vuln", "rea"), "Vuln scan + UREA incident drafts"),
    ControlMapping("dora", "Art.10",
        "ICT-related incident management.",
        ("rea",), "UREA evidence with SHA-256 chain"),

    # ── NERC CIP (energy/utilities) ──────────────────────────────────
    ControlMapping("nerc_cip", "CIP-007-6 R2", "Security patch management.",
        ("vuln", "auto_remediate"), "Patch status + audit log"),
    ControlMapping("nerc_cip", "CIP-010-3 R1", "Configuration change management.",
        ("stig",), "Baseline drift detection"),

    # ── TSA Pipeline + Aviation ──────────────────────────────────────
    ControlMapping("tsa_sd02c", "II.E", "Continuous monitoring.",
        ("daemon",), "Daemon event stream"),
    ControlMapping("faa_cyber", "AC 119-1",
        "Aircraft network risk monitoring.",
        ("vuln", "edr"), "Vuln + EDR behaviour"),
    ControlMapping("iata_toolkit", "CSM-1",
        "Cyber security management system for airlines.",
        ("vuln", "stig", "malware", "edr"), "Unified airline-fleet device posture"),

    # ── FFIEC CAT (banks) ────────────────────────────────────────────
    ControlMapping("ffiec_cat", "D3.DC.Av.B.1", "Anti-malware tools across all systems.",
        ("malware", "edr"), "Malware + behaviour engine"),
    ControlMapping("ffiec_cat", "D3.DC.Th.B.4", "Threat intelligence consumption.",
        ("feeds.threat_intel",), "Threat-intel aggregator"),

    # ── HHS 405(d) (healthcare) ──────────────────────────────────────
    ControlMapping("hhs_405d", "10.S.A", "Medical device cybersecurity.",
        ("hwam", "swam"), "HWAM peripherals + SWAM versioning"),

    # ── Telecom (FCC CPNI + India TRAI) ──────────────────────────────
    ControlMapping("fcc_cpni", "47CFR64.2009", "Annual certification of CPNI safeguards.",
        ("dlp",), "DLP detection of CPNI patterns"),

    # ── State + sector ──────────────────────────────────────────────
    ControlMapping("ccpa_cpra", "1798.150",
        "Reasonable security procedures.",
        ("hwam", "stig", "dlp"), "Triple control"),
    ControlMapping("sox_itgc", "ITGC-CHG-001",
        "Change management on production systems.",
        ("stig", "auto_remediate"), "Baseline + audit log"),
]


def framework_status(framework: str) -> Dict[str, Any]:
    """Return all mappings under a framework, ready for the dashboard."""
    rows = [m for m in FRAMEWORK_CATALOG if m.framework == framework]
    return {
        "framework": framework,
        "total_controls_mapped": len(rows),
        "controls": [asdict(r) for r in rows],
    }
