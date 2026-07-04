"""
UnifiedSec MACE v2 — Universal Cross-Domain Correlation Score (CDCS v2)
=======================================================================
Patent: IN/2026/UNISEC/MACE-001 + PCT → US / CA / EU / UAE
Inventor: Vivek Sindhu — UnifiedSec Technologies Pvt. Ltd.

US PATENT PRIOR ART GAPS (confirmed May 2026 USPTO search):
  - No prior art: six-domain correlation (V+E+I+N+C+T) pre-alert weighted score
  - No prior art: MITRE ATT&CK kill-chain stage multipliers (1.0→1.5×)
  - No prior art: EPSS integration (+30% boost on high-probability exploits)
  - No prior art: jurisdiction-specific weight profiles (5 profiles)
  - No prior art: blast-radius lateral-hop multiplier in correlation formula
  - No prior art: adaptive online weight learning η=0.01 from TP/FP feedback
    combined with regulatory evidence generation

WHAT COMPETITORS CANNOT DO:
  Axonius:
    - Has NO correlation engine. Displays vulnerability and asset data in
      adjacent dashboards. Customer still pivots manually between Axonius +
      Tenable + CrowdStrike + Splunk. CDCS replaces all four with one score.
    - Has NO MITRE ATT&CK kill-chain multipliers.
    - Has NO adaptive weight learning.
    - Has NO regulatory evidence generation.

  CrowdStrike ExPRT.AI:
    - Single-domain: predicts exploitation likelihood from malware telemetry.
    - Has NO vulnerability × identity × network × compliance correlation.
    - Has NO jurisdiction weight profiles for India/UAE/EU/Canada.
    - ExPRT.AI is NOT adaptive — cannot learn from confirmed TP/FP feedback
      and renormalize weights. Static adversary intelligence model.

  Palo Alto Cortex Exposure Management:
    - AI-driven prioritization of Tenable/Qualys scan findings.
    - Still single-domain vulnerability prioritization, not 6-domain.
    - Has NO identity signal integration (impossible_travel, MFA failures).
    - Has NO compliance posture sub-score in risk formula.
    - Has NO threat intelligence sub-score as a separate weighted domain.
    - Has NO adaptive learning from feedback loop.

  Tenable One:
    - Unifies vuln + cloud + identity + web app — but still separate modules.
    - Has NO single weighted correlation score across all 6 domains pre-alert.
    - Has NO kill-chain stage multiplier.
    - Has NO EPSS boost in native vulnerability scoring.
    - Has NO CERT-In/DPDP/NESA/aeCERT evidence generation.

  Splunk SIEM:
    - Correlates events AFTER alerts are generated (post-hoc).
    - MACE generates CDCS BEFORE alerting — fundamentally different architecture.
    - Has NO asset identity layer. No probabilistic merge.
    - Has NO regulatory evidence automaton.

  SentinelOne Singularity:
    - XDR: endpoint + cloud + identity + threat intelligence.
    - Still NO cross-domain pre-alert correlation formula with adaptive weights.
    - Has NO India/UAE/EU/Canada regulatory framework support.
    - Purple AI = query assistant, NOT a correlation formula.
"""

import time
import math
import copy
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple, Any
from enum import Enum


# ════════════════════════════════════════════════════════════════════
# ENUMERATIONS
# ════════════════════════════════════════════════════════════════════

class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class KillChainStage(Enum):
    """
    MITRE ATT&CK kill-chain stage multipliers — NOVEL in asset correlation context.
    Higher stages amplify CDCS because lateral movement indicates active breach.
    No US prior art combines kill-chain multipliers with asset-graph correlation.
    """
    RECON          = "recon"
    WEAPONIZE      = "weaponize"
    DELIVERY       = "delivery"
    EXPLOIT        = "exploit"
    INSTALL        = "install"
    C2             = "c2"
    ACTIONS        = "actions"
    EXFILTRATION   = "exfiltration"
    IMPACT         = "impact"


# Kill-chain multipliers: RECON 1.0× → EXFILTRATION/IMPACT 1.5×
KILL_CHAIN_MULTIPLIERS: Dict[KillChainStage, float] = {
    KillChainStage.RECON:        1.00,
    KillChainStage.WEAPONIZE:    1.05,
    KillChainStage.DELIVERY:     1.10,
    KillChainStage.EXPLOIT:      1.20,
    KillChainStage.INSTALL:      1.25,
    KillChainStage.C2:           1.30,
    KillChainStage.ACTIONS:      1.40,
    KillChainStage.EXFILTRATION: 1.50,
    KillChainStage.IMPACT:       1.50,
}

SEVERITY_WEIGHTS: Dict[Severity, float] = {
    Severity.CRITICAL: 1.00,
    Severity.HIGH:     0.75,
    Severity.MEDIUM:   0.50,
    Severity.LOW:      0.25,
    Severity.INFO:     0.00,
}

EXPLOIT_FACTORS: Dict[str, float] = {
    "exploit_public": 1.50,
    "exploit_poc":    1.20,
    "no_exploit_known": 1.00,
}

EXPOSURE_FACTORS: Dict[str, float] = {
    "internet_facing": 1.00,
    "internal":        0.70,
    "air_gapped":      0.40,
}

# Sector multipliers — higher for regulated/critical sectors
SECTOR_MULTIPLIERS: Dict[str, float] = {
    "banking":                1.30,
    "bfsi":                   1.30,
    "financial services":     1.30,
    "defence":                1.25,
    "critical infrastructure":1.25,
    "energy":                 1.25,
    "healthcare":             1.20,
    "government":             1.20,
    "federal":                1.20,
    "telecom":                1.15,
    "default":                1.00,
}

# EPSS boost factor — Novel: no US prior art combines EPSS with asset graph
EPSS_BOOST_MAX: float = 0.30   # +30% max boost for EPSS=1.0

# Jurisdiction-specific weight profiles — Novel: 5 profiles, no US prior art.
#
# v2.1 addendum (May 2026): η is the weight of the new Endpoint-Posture
# domain (H) produced by the unified UMEA agent. H fuses HWAM exposure,
# SWAM staleness, STIG noncompliance, malware indicators and hackable-config
# heuristics into a single 0..1 sub-score. Adding H as a 7th weighted domain
# lets MACE replace the data-collection role of CrowdStrike + Tenable while
# preserving the existing CDCS contract (engines without UMEA data simply
# get H=0 and the H-weight is absorbed by the others on normalise()).
WEIGHT_PROFILES: Dict[str, Dict[str, float]] = {
    "india_cii": {
        "alpha": 0.27, "beta": 0.20, "gamma": 0.16,
        "delta": 0.11, "epsilon": 0.07, "zeta": 0.09, "eta": 0.10,
    },
    "usa_fedramp": {
        "alpha": 0.25, "beta": 0.22, "gamma": 0.18,
        "delta": 0.11, "epsilon": 0.09, "zeta": 0.05, "eta": 0.10,
    },
    "eu_gdpr": {
        "alpha": 0.22, "beta": 0.18, "gamma": 0.23,
        "delta": 0.09, "epsilon": 0.11, "zeta": 0.07, "eta": 0.10,
    },
    "canada_pipeda": {
        "alpha": 0.24, "beta": 0.20, "gamma": 0.20,
        "delta": 0.09, "epsilon": 0.11, "zeta": 0.06, "eta": 0.10,
    },
    "uae_nesa": {
        "alpha": 0.27, "beta": 0.18, "gamma": 0.16,
        "delta": 0.13, "epsilon": 0.07, "zeta": 0.09, "eta": 0.10,
    },
}

ALERT_THRESHOLD: float = 7.0
WEIGHT_MIN_FLOOR: float = 0.03


# ════════════════════════════════════════════════════════════════════
# DATA CLASSES
# ════════════════════════════════════════════════════════════════════

@dataclass
class VulnFinding:
    cve_id: str
    cvss_v3: float
    exploit_status: str
    exposure: str
    sla_days: int
    discovered_at: float = field(default_factory=time.time)
    epss_score: float = 0.0          # 0.0–1.0 EPSS probability
    affected_component: str = ""
    patch_available: bool = False


@dataclass
class SecurityEvent:
    event_id: str; event_type: str; severity: Severity
    domain: str; description: str
    timestamp: float = field(default_factory=time.time)
    fidelity: float = 1.0
    kill_chain_stage: Optional[KillChainStage] = None
    source_tool: str = ""            # e.g. "crowdstrike", "splunk"
    mitre_technique_id: str = ""     # e.g. "T1059.001"
    raw_alert: Dict[str, Any] = field(default_factory=dict)


@dataclass
class IdentitySignal:
    """
    Identity risk signals — NOVEL: combining impossible_travel with
    credential_stuffing, service_account_anomaly, lateral_account_reuse
    in a single pre-alert correlation domain.
    CrowdStrike covers MFA failures but NOT combined with vuln×network×compliance.
    """
    impossible_travel: bool = False
    mfa_failures_1h: int = 0
    privilege_escalation: bool = False
    anomalous_login_time: bool = False
    new_device: bool = False
    credential_stuffing_indicator: bool = False
    service_account_anomaly: bool = False
    lateral_account_reuse: bool = False
    password_spray_detected: bool = False
    golden_ticket_indicator: bool = False    # Kerberos golden ticket
    pass_the_hash_indicator: bool = False
    oauth_abuse_indicator: bool = False


@dataclass
class NetworkContext:
    """
    Network risk signals — NOVEL: combining lateral_movement + C2 + DNS entropy
    + data_exfil in a single domain of the pre-alert correlation score.
    Splunk has these signals but correlates post-hoc after individual alerts.
    MACE correlates ALL domains simultaneously before generating any alert.
    """
    lateral_movement_score: float = 0.0     # 0.0–1.0
    c2_beacon_score: float = 0.0
    dns_entropy_score: float = 0.0
    port_scan_detected: bool = False
    data_exfil_indicator: float = 0.0
    lateral_hop_count: int = 0
    tor_exit_node: bool = False
    ransomware_c2_ioc: bool = False
    beaconing_frequency_hz: float = 0.0
    bytes_exfiltrated_mb: float = 0.0
    suspicious_dns_domains: List[str] = field(default_factory=list)
    netflow_anomaly_score: float = 0.0


@dataclass
class CompliancePosture:
    """
    Compliance sub-score — NOVEL: combining STIG compliance ratio with
    patch status, EDR coverage, and MFA enrollment in one domain.
    No competitor integrates compliance posture into a pre-alert risk score.
    """
    stig_pass_count: int = 0
    stig_fail_count: int = 0
    stig_na_count: int = 0
    last_scan_hours_ago: float = 0.0
    missing_patches: int = 0
    edr_coverage: bool = True
    mfa_enrolled: bool = True
    endpoint_encryption: bool = True
    dlp_enabled: bool = False
    privileged_access_managed: bool = False

    def compliance_ratio(self) -> float:
        t = self.stig_pass_count + self.stig_fail_count
        return self.stig_pass_count / t if t else 0.5


@dataclass
class EndpointPosture:
    """
    Endpoint-Posture domain (H) — NOVEL 7th domain.

    Produced by the UnifiedSec MACE Endpoint Agent (UMEA) and fuses the
    on-device signals that previously required separate CrowdStrike +
    Tenable + STIG Viewer + EDR + antimalware deployments:

      • hwam_exposure          : 0..1 — secure-boot off, no disk encryption,
                                  many open ports, peripheral risk
      • swam_staleness         : 0..1 — days since last patch / EOL software ratio
      • stig_noncompliance     : 0..1 — 1 - (pass/(pass+fail))  on STIG/CIS baseline
      • malware_indicator      : 0..1 — IOC + heuristic + ClamAV combined
      • hackable_config        : 0..1 — risky-config heuristics (default creds,
                                          open mgmt ports, sudo NOPASSWD…)
      • intrusion_pressure     : 0..1 — failed-login bursts + LAN scan origins

    H = clamp(w1·hwam_exposure + w2·swam_staleness + w3·stig_noncompliance
              + w4·malware_indicator + w5·hackable_config + w6·intrusion_pressure)
    """
    hwam_exposure:       float = 0.0
    swam_staleness:      float = 0.0
    stig_noncompliance:  float = 0.0
    malware_indicator:   float = 0.0
    hackable_config:     float = 0.0
    intrusion_pressure:  float = 0.0


@dataclass
class ThreatIntelSignal:
    """
    Threat intelligence domain (ζ·T) — NOVEL 6th domain.
    No competitor integrates threat intel as a separate weighted domain
    in a unified pre-alert correlation formula with adaptive weights.
    """
    ioc_match_score: float = 0.0         # 0.0–1.0
    campaign_match: bool = False
    threat_actor_confidence: float = 0.0  # 0.0–1.0
    feed_sources: List[str] = field(default_factory=list)
    threat_actor_known: bool = False
    campaign_active: bool = False
    malware_family: str = ""
    feed_source: str = ""                 # backwards compat alias
    confidence: float = 0.0              # backwards compat alias

# Alias for backwards compatibility
ThreatIntelligence = ThreatIntelSignal


@dataclass
class CDCSWeights:
    alpha:   float = 0.27   # Vulnerability domain
    beta:    float = 0.20   # Endpoint events domain
    gamma:   float = 0.16   # Identity risk domain
    delta:   float = 0.11   # Network context domain
    epsilon: float = 0.07   # Compliance posture domain
    zeta:    float = 0.09   # Threat intelligence domain
    eta:     float = 0.10   # Endpoint posture (UMEA: HWAM+SWAM+STIG+Mal+Hack)
    learning_rate: float = 0.01

    _ATTRS = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta")

    def normalise(self):
        t = sum(getattr(self, a) for a in self._ATTRS)
        if abs(t - 1.0) > 1e-9 and t > 0:
            for a in self._ATTRS:
                setattr(self, a, getattr(self, a) / t)
        # Floor each weight
        for a in self._ATTRS:
            setattr(self, a, max(WEIGHT_MIN_FLOOR, getattr(self, a)))
        # Re-normalise after flooring
        t2 = sum(getattr(self, a) for a in self._ATTRS)
        if abs(t2 - 1.0) > 1e-6 and t2 > 0:
            for a in self._ATTRS:
                setattr(self, a, getattr(self, a) / t2)

    def to_dict(self) -> Dict[str, float]:
        return {a: round(getattr(self, a), 4) for a in self._ATTRS}


@dataclass
class CDCSResult:
    asset_id: str; cdcs: float; alert_triggered: bool
    v_score: float = 0.0; e_score: float = 0.0; i_score: float = 0.0
    n_score: float = 0.0; c_score: float = 0.0; t_score: float = 0.0
    h_score: float = 0.0          # NEW: endpoint-posture domain (UMEA agent)
    sector_multiplier: float = 1.0
    blast_radius_multiplier: float = 1.0
    kill_chain_multiplier: float = 1.0
    acs_multiplier: float = 1.0
    confidence_low: float = 0.0
    confidence_high: float = 0.0
    dominant_domain: str = ""
    weights_used: Dict[str, float] = field(default_factory=dict)
    timestamp: float = field(default_factory=time.time)

    def severity_label(self) -> str:
        if self.cdcs >= 9: return "CRITICAL"
        if self.cdcs >= 7: return "HIGH"
        if self.cdcs >= 5: return "MEDIUM"
        if self.cdcs >= 3: return "LOW"
        return "INFO"

    def to_dict(self) -> Dict[str, Any]:
        return {
            "asset_id": self.asset_id,
            "cdcs": round(self.cdcs, 3),
            "alert_triggered": self.alert_triggered,
            "severity": self.severity_label(),
            "sub_scores": {
                "vulnerability":      round(self.v_score, 3),
                "endpoint":           round(self.e_score, 3),
                "identity":           round(self.i_score, 3),
                "network":            round(self.n_score, 3),
                "compliance":         round(self.c_score, 3),
                "threat_intel":       round(self.t_score, 3),
                "endpoint_posture":   round(self.h_score, 3),
            },
            "multipliers": {
                "sector":       round(self.sector_multiplier, 3),
                "blast_radius": round(self.blast_radius_multiplier, 3),
                "kill_chain":   round(self.kill_chain_multiplier, 3),
                "acs":          round(self.acs_multiplier, 3),
            },
            "dominant_domain": self.dominant_domain,
            "confidence_interval": [round(self.confidence_low, 2),
                                     round(self.confidence_high, 2)],
            "weights": self.weights_used,
        }


# ════════════════════════════════════════════════════════════════════
# SUB-SCORE FUNCTIONS
# ════════════════════════════════════════════════════════════════════

def compute_vulnerability_score(
        vulns: Optional[List[VulnFinding]]
) -> Tuple[float, Dict[str, Any]]:
    """
    V(a,t) = max over open CVEs of:
      (CVSS/10) × SEVERITY_WEIGHT × EXPLOIT_FACTOR × EXPOSURE_FACTOR × (1 + EPSS_BOOST)

    EPSS boost: Novel. No competitor integrates EPSS in a correlation formula.
    """
    if not vulns:
        return 0.0, {}
    scores = []
    details = []
    for v in vulns:
        cvss_norm = v.cvss_v3 / 10.0
        # Severity weight from CVSS band
        if v.cvss_v3 >= 9.0:   sev_w = SEVERITY_WEIGHTS[Severity.CRITICAL]
        elif v.cvss_v3 >= 7.0: sev_w = SEVERITY_WEIGHTS[Severity.HIGH]
        elif v.cvss_v3 >= 4.0: sev_w = SEVERITY_WEIGHTS[Severity.MEDIUM]
        else:                   sev_w = SEVERITY_WEIGHTS[Severity.LOW]

        exp_f  = EXPLOIT_FACTORS.get(v.exploit_status, 1.0)
        expo_f = EXPOSURE_FACTORS.get(v.exposure, 0.70)
        epss_boost = 1.0 + EPSS_BOOST_MAX * v.epss_score

        # SLA urgency: breached SLA adds 10%
        sla_urg = 1.10 if v.sla_days <= 0 else 1.0

        raw = min(1.0, cvss_norm * sev_w * exp_f * expo_f * epss_boost * sla_urg)
        scores.append(raw)
        details.append({
            "cve_id": v.cve_id, "cvss_v3": v.cvss_v3,
            "score": round(raw, 3), "epss_score": v.epss_score,
        })

    final = min(1.0, max(scores))
    return final, {"count": len(vulns), "max_score": round(final, 3), "vulns": details}


def compute_endpoint_posture_score(posture: Optional["EndpointPosture"]) -> float:
    """
    H(a,t) = weighted sum of the six UMEA agent sub-signals.

    NOVEL: no US prior art combines HWAM + SWAM + STIG + Malware + Risky-Config
    + Intrusion-pressure into a single pre-alert domain on a correlation engine.

    Sub-weights here are *intra-domain* (they sum to 1.0) so the domain
    contribution is governed solely by the engine's η weight.
    """
    if posture is None:
        return 0.0
    score = (0.25 * posture.hwam_exposure
             + 0.18 * posture.swam_staleness
             + 0.17 * posture.stig_noncompliance
             + 0.20 * posture.malware_indicator
             + 0.12 * posture.hackable_config
             + 0.08 * posture.intrusion_pressure)
    return max(0.0, min(1.0, score))


def compute_endpoint_score(
        events: Optional[List[SecurityEvent]]
) -> Tuple[float, Dict[str, Any]]:
    """
    E(a,t) = time-decayed, kill-chain-boosted severity sum.
    Kill-chain multiplier: NOVEL — no prior art in asset correlation context.
    """
    if not events:
        return 0.0, {}
    scores = []
    for e in events:
        base = SEVERITY_WEIGHTS.get(e.severity, 0.5) * e.fidelity
        # Recency decay: events older than 24h get 70% weight
        age_h = max(0.0, (time.time() - e.timestamp) / 3600)
        recency = 0.70 if age_h > 24 else 1.0
        # Kill-chain multiplier
        kc_mult = KILL_CHAIN_MULTIPLIERS.get(e.kill_chain_stage, 1.0) \
                  if e.kill_chain_stage else 1.0
        scores.append(min(1.0, base * recency * kc_mult))

    final = min(1.0, max(scores))
    return final, {"count": len(events), "max_score": round(final, 3)}


def compute_identity_score(identity: Optional[IdentitySignal]) -> float:
    """
    I(a,t) = sum of identity risk sub-signals, capped at 1.0.
    Credential stuffing + impossible travel combination has no US prior art
    as a separate domain in a multi-domain pre-alert correlation score.
    """
    if not identity:
        return 0.0
    score = 0.0
    if identity.impossible_travel:              score += 0.50
    if identity.privilege_escalation:           score += 0.45
    if identity.credential_stuffing_indicator:  score += 0.85
    if identity.service_account_anomaly:        score += 0.60
    if identity.lateral_account_reuse:          score += 0.55
    if identity.golden_ticket_indicator:        score += 0.90
    if identity.pass_the_hash_indicator:        score += 0.80
    if identity.password_spray_detected:        score += 0.40
    if identity.oauth_abuse_indicator:          score += 0.45
    if identity.mfa_failures_1h > 5:            score += 0.30
    elif identity.mfa_failures_1h > 2:          score += 0.15
    if identity.anomalous_login_time:           score += 0.15
    if identity.new_device:                     score += 0.10
    return min(1.0, score)


def compute_network_score(network: Optional[NetworkContext]) -> float:
    """
    N(a,t) = weighted sum of network risk indicators.
    TOR + ransomware C2 + lateral hops: combination not in any US prior art
    as a domain in a six-domain pre-alert correlation formula.
    """
    if not network:
        return 0.0
    score = (
        network.lateral_movement_score * 0.30 +
        network.c2_beacon_score        * 0.28 +
        network.data_exfil_indicator   * 0.22 +
        network.dns_entropy_score      * 0.10 +
        network.netflow_anomaly_score  * 0.10
    )
    hop_bonus = min(0.20, network.lateral_hop_count * 0.05)
    score += hop_bonus
    if network.tor_exit_node:        score = min(1.0, score + 0.25)
    if network.ransomware_c2_ioc:    score = min(1.0, score + 0.35)
    if network.port_scan_detected:   score = min(1.0, score + 0.08)
    if network.bytes_exfiltrated_mb > 100:
        score = min(1.0, score + 0.15)
    elif network.bytes_exfiltrated_mb > 10:
        score = min(1.0, score + 0.08)
    return min(1.0, score)


def compute_compliance_score(posture: Optional[CompliancePosture]) -> float:
    """
    C(a,t) = inverted compliance ratio + staleness + coverage gaps.
    Integrating compliance posture into a pre-alert risk score is novel.
    No competitor (Axonius, CrowdStrike, Palo Alto, Tenable) has compliance
    as a weighted domain in a unified six-domain correlation formula.
    """
    if not posture:
        return 0.0
    fail_ratio = 1.0 - posture.compliance_ratio()
    score = fail_ratio * 0.90
    if posture.last_scan_hours_ago > 168:  score = min(1.0, score + 0.20)
    elif posture.last_scan_hours_ago > 72: score = min(1.0, score + 0.10)
    if posture.missing_patches > 10:       score = min(1.0, score + 0.15)
    elif posture.missing_patches > 5:      score = min(1.0, score + 0.08)
    if not posture.edr_coverage:           score = min(1.0, score + 0.15)
    if not posture.mfa_enrolled:           score = min(1.0, score + 0.12)
    if not posture.endpoint_encryption:    score = min(1.0, score + 0.08)
    if not posture.privileged_access_managed: score = min(1.0, score + 0.10)
    return min(1.0, score)


def compute_threat_intel_score(ti: Optional[ThreatIntelSignal]) -> float:
    """
    T(a,t) = threat intelligence sub-score.
    NOVEL 6th domain — no US prior art integrates threat intel as a
    separate domain in a six-domain weighted correlation formula with
    jurisdiction-specific weight profiles and adaptive online learning.
    """
    if not ti:
        return 0.0
    score = ti.ioc_match_score * 0.55
    if ti.campaign_match:        score += 0.40
    if ti.threat_actor_known:    score += 0.20
    if ti.campaign_active:       score += 0.15
    score += ti.threat_actor_confidence * 0.12
    if ti.malware_family:        score += 0.10
    if len(ti.feed_sources) >= 3: score = min(1.0, score + 0.08)
    return min(1.0, score)


# ════════════════════════════════════════════════════════════════════
# CDCS ENGINE
# ════════════════════════════════════════════════════════════════════

class CDCSEngine:
    """
    Cross-Domain Correlation Score Engine.

    Formula (NOVEL — no US prior art):
      CDCS = min(10, [α·V + β·E + γ·I + δ·N + ε·C + ζ·T]
                     × 10 × Smult × Blast × ACS_mult)

    Adaptive learning (NOVEL — no US prior art):
      On confirmed TP: w_dominant += η, renormalize Σw=1.0
      On confirmed FP: w_dominant -= η, renormalize
      All weights floored at WEIGHT_MIN_FLOOR=0.03
    """
    ALERT_THRESHOLD: float = ALERT_THRESHOLD

    def __init__(self, weight_profile: str = "india_cii"):
        profile = WEIGHT_PROFILES.get(weight_profile, WEIGHT_PROFILES["india_cii"])
        self.weights = CDCSWeights(**{k: v for k, v in profile.items()
                                      if k in ("alpha","beta","gamma","delta","epsilon","zeta","eta")})
        self._feedback_log: List[Dict] = []
        self._true_positives: int = 0
        self._false_positives: int = 0
        self._total_computed: int = 0
        self._alerts_fired: int = 0
        self.weight_profile = weight_profile

    def compute(
        self,
        asset_id: str,
        sector: str = "default",
        acs: float = 1.0,
        lateral_hop_count: int = 0,
        vulns: Optional[List[VulnFinding]] = None,
        events: Optional[List[SecurityEvent]] = None,
        identity: Optional[IdentitySignal] = None,
        network: Optional[NetworkContext] = None,
        compliance: Optional[CompliancePosture] = None,
        threat_intel: Optional[ThreatIntelSignal] = None,
        endpoint_posture: Optional[EndpointPosture] = None,
    ) -> CDCSResult:
        self._total_computed += 1

        # Inject hop count into network if not already set
        if network and lateral_hop_count and not network.lateral_hop_count:
            network = NetworkContext(**{**network.__dict__,
                                        "lateral_hop_count": lateral_hop_count})

        # Compute all seven sub-scores (six classic + endpoint-posture H)
        V, v_details = compute_vulnerability_score(vulns)
        E, e_details = compute_endpoint_score(events)
        I = compute_identity_score(identity)
        N = compute_network_score(network)
        C = compute_compliance_score(compliance)
        T = compute_threat_intel_score(threat_intel)
        H = compute_endpoint_posture_score(endpoint_posture)

        w = self.weights
        raw_weighted = (w.alpha * V + w.beta * E + w.gamma * I +
                        w.delta * N + w.epsilon * C + w.zeta * T +
                        w.eta * H)

        # Sector multiplier
        sector_key = sector.lower().split("/")[0].strip()
        smult = 1.0
        for k, v in SECTOR_MULTIPLIERS.items():
            if k in sector_key and v > smult:
                smult = v

        # Blast-radius multiplier (lateral hop count)
        hops = lateral_hop_count or (network.lateral_hop_count if network else 0)
        blast = 1.0 + min(0.30, hops * 0.10)

        # Kill-chain multiplier (dominant kill-chain stage from events)
        kc_mult = 1.0
        if events:
            max_kc = max(
                KILL_CHAIN_MULTIPLIERS.get(e.kill_chain_stage, 1.0)
                for e in events if e.kill_chain_stage
            ) if any(e.kill_chain_stage for e in events) else 1.0
            kc_mult = max_kc

        # ACS multiplier — low ACS attenuates score slightly
        acs_mult = max(0.50, min(1.0, acs))

        cdcs = min(10.0, raw_weighted * 10 * smult * blast * kc_mult * acs_mult)
        alert = cdcs >= self.ALERT_THRESHOLD
        if alert:
            self._alerts_fired += 1

        # Dominant domain
        domain_scores = {
            "vulnerability": w.alpha * V, "endpoint": w.beta * E,
            "identity": w.gamma * I, "network": w.delta * N,
            "compliance": w.epsilon * C, "threat_intel": w.zeta * T,
            "endpoint_posture": w.eta * H,
        }
        dominant = max(domain_scores, key=domain_scores.get)

        # Confidence interval (±fidelity variance)
        fidelity_mean = sum(e.fidelity for e in events) / max(1, len(events)) if events else 1.0
        variance = (1.0 - fidelity_mean) * 1.5
        ci_low  = max(0.0, cdcs - variance)
        ci_high = min(10.0, cdcs + variance)

        return CDCSResult(
            asset_id=asset_id, cdcs=cdcs, alert_triggered=alert,
            v_score=V, e_score=E, i_score=I, n_score=N, c_score=C, t_score=T,
            h_score=H,
            sector_multiplier=smult, blast_radius_multiplier=blast,
            kill_chain_multiplier=kc_mult, acs_multiplier=acs_mult,
            confidence_low=ci_low, confidence_high=ci_high,
            dominant_domain=dominant, weights_used=w.to_dict(),
        )

    def feedback(self, result: CDCSResult, confirmed_true_positive: bool):
        """
        Adaptive online weight learning.
        NOVEL: no US prior art combines adaptive weight adjustment with
        regulatory evidence generation in a unified pipeline.
        """
        lr = self.weights.learning_rate
        w = self.weights

        # Map domain name to weight attribute
        domain_attr = {
            "vulnerability": "alpha", "endpoint": "beta",
            "identity": "gamma", "network": "delta",
            "compliance": "epsilon", "threat_intel": "zeta",
            "endpoint_posture": "eta",
        }
        attr = domain_attr.get(result.dominant_domain, "alpha")

        if confirmed_true_positive:
            self._true_positives += 1
            setattr(w, attr, getattr(w, attr) + lr)
        else:
            self._false_positives += 1
            setattr(w, attr, max(WEIGHT_MIN_FLOOR, getattr(w, attr) - lr))

        w.normalise()
        self._feedback_log.append({
            "asset_id": result.asset_id,
            "confirmed_tp": confirmed_true_positive,
            "cdcs": round(result.cdcs, 3),
            "dominant_domain": result.dominant_domain,
            "weights_after": w.to_dict(),
            "ts": time.time(),
        })

    def stats(self) -> Dict[str, Any]:
        return {
            "total_computed": self._total_computed,
            "alerts_fired": self._alerts_fired,
            "alert_rate": round(self._alerts_fired / max(1, self._total_computed), 3),
            "true_positives": self._true_positives,
            "false_positives": self._false_positives,
            "feedback_events": len(self._feedback_log),
            "threshold": self.ALERT_THRESHOLD,
            "weight_profile": self.weight_profile,
            "weights": self.weights.to_dict(),
        }
