"""
MACEEngineService — per-tenant engine management.
Each tenant gets its own isolated MACEEngine instance in memory.
Engines are cached in Redis for persistence across workers.
"""
import sys, os
from pathlib import Path

# Locate the UnifiedSec_MACE_v2/core package. Search order:
#   1. MACE_CORE_PATH env var
#   2. /app/core (Docker layout)
#   3. ../../UnifiedSec_MACE_v2 (repo layout: backend/app/services -> repo root)
def _ensure_core_on_path() -> None:
    candidates = []
    if env := os.environ.get("MACE_CORE_PATH"):
        candidates.append(Path(env))
    candidates.append(Path("/app"))
    here = Path(__file__).resolve()
    candidates.append(here.parents[3].parent / "UnifiedSec_MACE_v2")
    for c in candidates:
        if (c / "core" / "mace.py").exists():
            if str(c) not in sys.path:
                sys.path.insert(0, str(c))
            return
    raise ImportError(
        "Could not locate UnifiedSec_MACE_v2/core. "
        "Set MACE_CORE_PATH env var to the directory containing core/mace.py."
    )

_ensure_core_on_path()

from typing import Dict, Optional
from datetime import datetime
from app.core.config import settings
from app.models.tenant import Tenant
import asyncio
import logging

logger = logging.getLogger(__name__)

# In-memory engine registry (per-process)
_engines: Dict[str, object] = {}


def _make_engine(tenant: Tenant):
    from core.mace import MACEEngine
    return MACEEngine(
        cdcs_threshold=tenant.cdcs_alert_threshold,
        rea_threshold=tenant.rea_cdcs_threshold,
        match_threshold=settings.MACE_MATCH_THRESHOLD,
        jurisdiction=tenant.jurisdiction,
        weight_profile=tenant.weight_profile,
    )


def get_engine(tenant: Tenant):
    """Get or create the MACE engine for this tenant."""
    if tenant.id not in _engines:
        _engines[tenant.id] = _make_engine(tenant)
        logger.info(f"Created MACE engine for tenant {tenant.slug} ({tenant.weight_profile})")
    return _engines[tenant.id]


def reset_engine(tenant_id: str):
    """Force recreate — called after config changes."""
    _engines.pop(tenant_id, None)


class MACEService:
    """High-level service wrapping the MACE engine for async API use."""

    def __init__(self, tenant: Tenant):
        self.tenant = tenant
        self.engine = get_engine(tenant)

    def ingest_asset(self, record_data: dict) -> dict:
        from core.tag import AssetRecord, AssetClass, Jurisdiction, DataClassification, GeoPoint

        # Map jurisdiction string to enum
        juris_map = {
            "IN": Jurisdiction.INDIA, "US": Jurisdiction.USA, "EU": Jurisdiction.EU,
            "CA": Jurisdiction.CANADA, "AE": Jurisdiction.UAE
        }
        dc_map = {
            "public": DataClassification.PUBLIC, "internal": DataClassification.INTERNAL,
            "confidential": DataClassification.CONFIDENTIAL, "restricted": DataClassification.RESTRICTED,
        }

        geo = None
        if record_data.get("geo_lat") and record_data.get("geo_lon"):
            geo = GeoPoint(
                lat=record_data["geo_lat"], lon=record_data["geo_lon"],
                city=record_data.get("geo_city", ""),
                country_code=record_data.get("geo_country", ""),
            )

        ac_str = record_data.get("asset_class")
        ac = AssetClass(ac_str) if ac_str else None

        record = AssetRecord(
            source=record_data["source"],
            source_id=record_data["source_id"],
            hostname=record_data.get("hostname"),
            mac_address=record_data.get("mac_address"),
            ip_address=record_data.get("ip_address"),
            cert_fingerprint=record_data.get("cert_fingerprint"),
            cloud_instance_id=record_data.get("cloud_instance_id"),
            cloud_account_id=record_data.get("cloud_account_id"),
            serial_number=record_data.get("serial_number"),
            os=record_data.get("os"),
            owner=record_data.get("owner"),
            owner_email=record_data.get("owner_email"),
            sector=record_data.get("sector"),
            open_ports=record_data.get("open_ports", []),
            asset_class=ac,
            jurisdiction=juris_map.get(record_data.get("jurisdiction", "US"), Jurisdiction.USA),
            data_classification=dc_map.get(record_data.get("data_classification", "internal"),
                                           DataClassification.INTERNAL),
            is_internet_facing=record_data.get("is_internet_facing", False),
            is_critical_infra=record_data.get("is_critical_infra", False),
            geo=geo,
            tags=record_data.get("tags", {}),
            raw_attributes=record_data.get("raw_attributes", {}),
            source_confidence=record_data.get("source_confidence", 1.0),
        )

        vertex = self.engine.ingest_asset(record)
        return {
            "canonical_id": vertex.id_canonical,
            "asset_class": vertex.asset_class.value,
            "acs_score": round(vertex.acs(), 4),
            "quorum_sources": vertex.quorum_sources,
            "source_set": sorted(vertex.source_set),
            "shadow_it_flag": vertex.shadow_it_flag,
            "geo_velocity_flag": vertex.geo_velocity_flag,
            "status": vertex.status().value,
            "entropy_score": round(vertex.graph_entropy(), 3),
        }

    def attach_vuln(self, asset_id: str, vuln_data: dict):
        from core.cdcs import VulnFinding
        vuln = VulnFinding(
            cve_id=vuln_data["cve_id"],
            cvss_v3=vuln_data["cvss_v3"],
            exploit_status=vuln_data.get("exploit_status", "no_exploit_known"),
            exposure=vuln_data.get("exposure", "internal"),
            sla_days=vuln_data.get("sla_days", 30),
            epss_score=vuln_data.get("epss_score", 0.0),
            affected_component=vuln_data.get("affected_component", ""),
            patch_available=vuln_data.get("patch_available", False),
        )
        self.engine.ingest_vuln(asset_id, vuln)

    def correlate(self, asset_id: str, event_data: dict, context: dict) -> dict:
        from core.cdcs import (SecurityEvent, Severity, KillChainStage,
                               IdentitySignal, NetworkContext, CompliancePosture, ThreatIntelSignal)

        sev_map = {s: Severity(s) for s in ["CRITICAL","HIGH","MEDIUM","LOW","INFO"]}
        kc_map = {k: KillChainStage(k.lower()) for k in [
            "recon","weaponize","delivery","exploit","install","c2","actions","exfiltration","impact"
        ]}

        ev = SecurityEvent(
            event_id=event_data["event_id"],
            event_type=event_data["event_type"],
            severity=sev_map.get(event_data["severity"].upper(), Severity.MEDIUM),
            domain=event_data.get("domain", "endpoint"),
            description=event_data.get("description", ""),
            kill_chain_stage=kc_map.get(event_data.get("kill_chain_stage", ""), None),
            source_tool=event_data.get("source_tool", ""),
            mitre_technique_id=event_data.get("mitre_technique_id", ""),
            fidelity=event_data.get("fidelity", 1.0),
        )

        identity, network, compliance, threat_intel = None, None, None, None

        if context.get("identity"):
            d = context["identity"]
            identity = IdentitySignal(**{k: d.get(k, v) for k, v in IdentitySignal().__dict__.items() if not k.startswith("_")})

        if context.get("network"):
            d = context["network"]
            network = NetworkContext(**{k: d.get(k, v) for k, v in NetworkContext().__dict__.items() if not k.startswith("_")})

        if context.get("compliance"):
            d = context["compliance"]
            compliance = CompliancePosture(**{k: d.get(k, v) for k, v in CompliancePosture().__dict__.items() if not k.startswith("_")})

        if context.get("threat_intel"):
            d = context["threat_intel"]
            threat_intel = ThreatIntelSignal(
                ioc_match_score=d.get("ioc_match_score", 0.0),
                campaign_match=d.get("campaign_match", False),
                threat_actor_confidence=d.get("threat_actor_confidence", 0.0),
                threat_actor_known=d.get("threat_actor_known", False),
                campaign_active=d.get("campaign_active", False),
                malware_family=d.get("malware_family", ""),
                feed_sources=d.get("feed_sources", []),
            )

        result = self.engine.ingest_event(
            asset_id=asset_id,
            event=ev,
            identity=identity,
            network=network,
            compliance=compliance,
            threat_intel=threat_intel,
            jurisdictions=context.get("jurisdictions"),
        )
        return result

    def get_shadow_it(self) -> list:
        return [v.to_dict() for v in self.engine.get_shadow_it()]

    def get_geo_anomalies(self) -> list:
        return [v.to_dict() for v in self.engine.tag.get_geo_anomalies()]

    def get_stats(self) -> dict:
        return self.engine.full_stats()

    def get_regulatory_calendar(self) -> list:
        return self.engine.rea.regulatory_calendar()

    def get_incident_evidence(self, incident_id: str):
        return self.engine.rea._incidents.get(incident_id)
