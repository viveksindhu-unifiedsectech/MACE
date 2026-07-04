"""
Asset Processor — Pipeline Stage 2
=====================================
Runs NormalizedAsset through UTAG for probabilistic merge, ACS scoring,
shadow IT detection, geo-velocity check. Returns ProcessedAsset for correlation.
"""
import logging
import sys
from typing import List, Optional
from dataclasses import dataclass, field

sys.path.insert(0, "/home/claude/UnifiedSec_MACE_v2")

logger = logging.getLogger(__name__)


@dataclass
class ProcessedAsset:
    canonical_id: str
    asset_class: str
    acs_score: float
    quorum_sources: int
    source_set: List[str]
    shadow_it_flag: bool
    geo_velocity_flag: bool
    status: str
    entropy_score: float
    merged: bool
    source_id: str
    source: str
    hostname: Optional[str]
    ip_address: Optional[str]


class AssetProcessor:
    """Runs UTAG on incoming normalized asset records. One instance per tenant."""

    def __init__(self, tenant_id: str, jurisdiction: str = "US",
                 weight_profile: str = "usa_fedramp"):
        from core.mace import MACEEngine
        self.tenant_id = tenant_id
        self.engine = MACEEngine(jurisdiction=jurisdiction, weight_profile=weight_profile)
        logger.info(f"AssetProcessor ready — tenant={tenant_id} profile={weight_profile}")

    def process(self, asset) -> ProcessedAsset:
        """Run single NormalizedAsset through UTAG."""
        from core.tag import (AssetRecord, AssetClass, Jurisdiction,
                              DataClassification, GeoPoint)
        juris_map = {
            "US": Jurisdiction.USA, "IN": Jurisdiction.INDIA,
            "EU": Jurisdiction.EU, "CA": Jurisdiction.CANADA, "AE": Jurisdiction.UAE,
        }
        ac_map = {
            "cloud_vm": AssetClass.CLOUD_VM, "container": AssetClass.CONTAINER,
            "kubernetes_node": AssetClass.KUBERNETES_NODE,
            "serverless": AssetClass.SERVERLESS,
            "endpoint": AssetClass.ENDPOINT, "server": AssetClass.SERVER,
            "mobile": AssetClass.MOBILE, "network_device": AssetClass.NETWORK_DEVICE,
            "ot_ics": AssetClass.OT_ICS, "iot_device": AssetClass.IOT_DEVICE,
            "database": AssetClass.DATABASE,
        }
        geo = None
        if asset.geo_lat and asset.geo_lon:
            geo = GeoPoint(lat=asset.geo_lat, lon=asset.geo_lon,
                           city=asset.geo_city or "", country_code=asset.geo_country or "")

        record = AssetRecord(
            source=asset.source, source_id=asset.source_id,
            hostname=asset.hostname, mac_address=asset.mac_address,
            ip_address=asset.ip_address, cert_fingerprint=getattr(asset,'cert_fingerprint',None),
            cloud_instance_id=asset.cloud_instance_id,
            cloud_account_id=asset.cloud_account_id,
            serial_number=getattr(asset,'serial_number',None),
            os=asset.os, owner=asset.owner, owner_email=asset.owner_email,
            sector=asset.sector or "default", open_ports=asset.open_ports,
            asset_class=ac_map.get(asset.asset_class, AssetClass.ENDPOINT),
            jurisdiction=juris_map.get("US", Jurisdiction.USA),
            data_classification=DataClassification.INTERNAL,
            is_internet_facing=asset.is_internet_facing,
            is_critical_infra=asset.is_critical_infra,
            geo=geo, tags=asset.tags, raw_attributes=asset.raw,
            source_confidence=asset.source_confidence,
        )
        before = len(self.engine.tag.vertices)
        vertex = self.engine.ingest_asset(record)
        existing = len(self.engine.tag.vertices) == before  # True if merged (no new vertex)
        return ProcessedAsset(
            canonical_id=vertex.id_canonical,
            asset_class=vertex.asset_class.value,
            acs_score=round(vertex.acs(), 4),
            quorum_sources=vertex.quorum_sources,
            source_set=sorted(vertex.source_set),
            shadow_it_flag=vertex.shadow_it_flag,
            geo_velocity_flag=vertex.geo_velocity_flag,
            status=vertex.status().value,
            entropy_score=round(vertex.graph_entropy(), 3),
            merged=existing,
            source_id=asset.source_id,
            source=asset.source,
            hostname=asset.hostname,
            ip_address=asset.ip_address,
        )

    def process_batch(self, assets) -> List[ProcessedAsset]:
        results, merged, new = [], 0, 0
        for asset in assets:
            try:
                r = self.process(asset)
                results.append(r)
                if r.merged: merged += 1
                else: new += 1
            except Exception as e:
                logger.error(f"Asset {asset.source_id} processing failed: {e}")
        logger.info(f"Batch: {len(assets)} in → {new} new, {merged} merged")
        return results
