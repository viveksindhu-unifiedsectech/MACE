"""UnifiedSec MACE v2. Patent: IN/2026/UNISEC/MACE-001"""
from .tag  import (TemporalAssetGraph, AssetRecord, AssetVertex, AssetClass,
                   GeoPoint, LineageEvent, Jurisdiction, DataClassification,
                   MATCH_THRESHOLD, DECAY_RATES,
                   levenshtein_normalized as _levenshtein_normalized,
                   _infer_asset_class, _compute_entropy, match_score)
from .cdcs import (CDCSEngine, CDCSWeights, CDCSResult, VulnFinding, SecurityEvent,
                   IdentitySignal, NetworkContext, CompliancePosture,
                   ThreatIntelSignal, ThreatIntelligence,
                   Severity, KillChainStage, WEIGHT_PROFILES,
                   compute_vulnerability_score, compute_endpoint_score,
                   compute_identity_score, compute_network_score,
                   compute_compliance_score, compute_threat_intel_score)
from .rea  import (RegulatoryEvidenceAutomaton, EvidenceRecord,
                   RegulatoryFramework, REPORTING_SLA_HOURS, JURISDICTION_FRAMEWORKS)
from .mace import MACEEngine
__version__ = "2.0.0"
__patent__  = "IN/2026/UNISEC/MACE-001"
