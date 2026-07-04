"""Asset endpoints — ingest, query, vulnerability attachment, shadow IT, geo anomalies."""
from fastapi import APIRouter, Depends, HTTPException, Query, BackgroundTasks
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import Optional, List
from datetime import datetime
from app.db.base import get_db
from app.auth.dependencies import get_current_user, get_analyst, get_any, CurrentUser
from app.models.asset import Asset, AssetSource, AssetClass, AssetStatus
from app.models.vulnerability import VulnerabilityFinding, Vulnerability, VulnStatus
from app.models.audit import AuditLog
from app.schemas.asset import (AssetIngestRequest, AssetIngestResponse,
                                AssetResponse, AssetListResponse, VulnAttachRequest)
from app.services.mace_engine_service import MACEService
import uuid
from datetime import datetime as dt

router = APIRouter(prefix="/assets", tags=["Assets"])


async def _sync_vertex_to_db(vertex_data: dict, record: AssetIngestRequest,
                               tenant_id: str, db: AsyncSession) -> Asset:
    """Upsert asset in database from UTAG vertex data."""
    canonical_id = vertex_data["canonical_id"]

    # Check if asset exists
    result = await db.execute(
        select(Asset).where(Asset.canonical_id == canonical_id, Asset.tenant_id == tenant_id)
    )
    asset = result.scalar_one_or_none()
    merged = asset is not None

    if not asset:
        asset = Asset(
            id=str(uuid.uuid4()),
            tenant_id=tenant_id,
            canonical_id=canonical_id,
        )

    # Update all fields from vertex
    asset.hostname = record.hostname or asset.hostname
    asset.mac_address = record.mac_address or asset.mac_address
    asset.ip_address = record.ip_address or asset.ip_address
    asset.cloud_instance_id = record.cloud_instance_id or asset.cloud_instance_id
    asset.cloud_account_id = record.cloud_account_id or asset.cloud_account_id
    asset.cert_fingerprint = record.cert_fingerprint or asset.cert_fingerprint
    asset.serial_number = record.serial_number or asset.serial_number
    asset.os = record.os or asset.os
    asset.owner = record.owner or asset.owner
    asset.owner_email = record.owner_email or asset.owner_email
    asset.sector = record.sector or asset.sector
    asset.open_ports = record.open_ports or asset.open_ports
    asset.jurisdiction = record.jurisdiction
    asset.data_classification = record.data_classification
    asset.is_internet_facing = record.is_internet_facing or asset.is_internet_facing
    asset.is_critical_infra = record.is_critical_infra or asset.is_critical_infra
    asset.tags = {**(asset.tags or {}), **(record.tags or {})}

    # From vertex
    asset.asset_class = AssetClass(vertex_data["asset_class"])
    asset.status = AssetStatus(vertex_data["status"])
    asset.acs_score = vertex_data["acs_score"]
    asset.entropy_score = vertex_data["entropy_score"]
    asset.quorum_sources = vertex_data["quorum_sources"]
    asset.source_set = vertex_data["source_set"]
    asset.shadow_it_flag = vertex_data["shadow_it_flag"]
    asset.geo_velocity_flag = vertex_data["geo_velocity_flag"]
    asset.last_seen_at = dt.utcnow()

    if record.geo_lat and record.geo_lon:
        asset.last_geo_lat = record.geo_lat
        asset.last_geo_lon = record.geo_lon
        asset.last_geo_city = record.geo_city
        asset.last_geo_country = record.geo_country

    db.add(asset)
    await db.flush()

    # Upsert source record
    src_result = await db.execute(
        select(AssetSource).where(
            AssetSource.asset_id == asset.id,
            AssetSource.source_name == record.source,
        )
    )
    src = src_result.scalar_one_or_none()
    if not src:
        src = AssetSource(
            id=str(uuid.uuid4()),
            asset_id=asset.id,
            tenant_id=tenant_id,
            source_name=record.source,
            source_id=record.source_id,
        )
    src.source_confidence = record.source_confidence
    src.raw_data = record.raw_attributes
    src.last_seen_at = dt.utcnow()
    db.add(src)

    return asset, merged


@router.post("/ingest", response_model=AssetIngestResponse, status_code=201)
async def ingest_asset(
    req: AssetIngestRequest,
    background_tasks: BackgroundTasks,
    current: CurrentUser = Depends(get_analyst),
    db: AsyncSession = Depends(get_db),
):
    """
    Ingest an asset observation. Runs UTAG probabilistic merge.
    If this record matches an existing asset, they are merged (quorum++).
    """
    svc = MACEService(current.tenant)
    vertex_data = svc.ingest_asset(req.model_dump())
    asset, merged = await _sync_vertex_to_db(vertex_data, req, current.tenant_id, db)

    background_tasks.add_task(
        _audit, db, current.tenant_id, current.id, current.email,
        "asset.ingest", "asset", asset.id,
        {"source": req.source, "merged": merged, "canonical_id": asset.canonical_id}
    )

    return AssetIngestResponse(
        canonical_id=asset.canonical_id,
        asset_id=asset.id,
        status=asset.status,
        asset_class=asset.asset_class,
        acs_score=asset.acs_score,
        quorum_sources=asset.quorum_sources,
        shadow_it_flag=asset.shadow_it_flag,
        geo_velocity_flag=asset.geo_velocity_flag,
        merged=merged,
        message=f"{'Merged with existing' if merged else 'New asset created'} — {asset.canonical_id[:8]}",
    )


@router.get("", response_model=AssetListResponse)
async def list_assets(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: Optional[AssetStatus] = None,
    asset_class: Optional[AssetClass] = None,
    shadow_it: Optional[bool] = None,
    geo_anomaly: Optional[bool] = None,
    search: Optional[str] = None,
    min_acs: Optional[float] = Query(None, ge=0.0, le=1.0),
    max_acs: Optional[float] = Query(None, ge=0.0, le=1.0),
    sort_by: str = Query("last_seen_at", regex="^(last_seen_at|acs_score|cdcs_score|hostname|created_at)$"),
    order: str = Query("desc", regex="^(asc|desc)$"),
    current: CurrentUser = Depends(get_any),
    db: AsyncSession = Depends(get_db),
):
    """List assets with filtering, sorting, pagination."""
    filters = [Asset.tenant_id == current.tenant_id]
    if status: filters.append(Asset.status == status)
    if asset_class: filters.append(Asset.asset_class == asset_class)
    if shadow_it is not None: filters.append(Asset.shadow_it_flag == shadow_it)
    if geo_anomaly is not None: filters.append(Asset.geo_velocity_flag == geo_anomaly)
    if min_acs is not None: filters.append(Asset.acs_score >= min_acs)
    if max_acs is not None: filters.append(Asset.acs_score <= max_acs)
    if search:
        from sqlalchemy import or_
        filters.append(or_(
            Asset.hostname.ilike(f"%{search}%"),
            Asset.ip_address.ilike(f"%{search}%"),
            Asset.owner.ilike(f"%{search}%"),
            Asset.canonical_id.ilike(f"%{search}%"),
        ))

    count_result = await db.execute(select(func.count()).select_from(Asset).where(*filters))
    total = count_result.scalar()

    sort_col = getattr(Asset, sort_by)
    if order == "desc": sort_col = sort_col.desc()

    result = await db.execute(
        select(Asset).where(*filters)
        .order_by(sort_col)
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    assets = result.scalars().all()

    return AssetListResponse(
        items=[AssetResponse.model_validate(a) for a in assets],
        total=total, page=page, page_size=page_size,
        has_next=(page * page_size) < total,
    )


@router.get("/{asset_id}", response_model=AssetResponse)
async def get_asset(
    asset_id: str,
    current: CurrentUser = Depends(get_any),
    db: AsyncSession = Depends(get_db),
):
    asset = await db.get(Asset, asset_id)
    if not asset or asset.tenant_id != current.tenant_id:
        raise HTTPException(404, "Asset not found")
    return AssetResponse.model_validate(asset)


@router.post("/{asset_id}/vulns", status_code=201)
async def attach_vulnerability(
    asset_id: str,
    req: VulnAttachRequest,
    current: CurrentUser = Depends(get_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Attach a CVE finding to an asset. Runs EPSS-boosted vulnerability scoring."""
    asset = await db.get(Asset, asset_id)
    if not asset or asset.tenant_id != current.tenant_id:
        raise HTTPException(404, "Asset not found")

    svc = MACEService(current.tenant)
    svc.attach_vuln(asset.canonical_id, req.model_dump())

    # Ensure Vulnerability master record exists
    vuln_result = await db.execute(
        select(Vulnerability).where(Vulnerability.cve_id == req.cve_id)
    )
    vuln = vuln_result.scalar_one_or_none()
    if not vuln:
        vuln = Vulnerability(
            id=str(uuid.uuid4()),
            cve_id=req.cve_id,
            cvss_v3=req.cvss_v3,
            epss_score=req.epss_score,
            exploit_public=req.exploit_status == "exploit_public",
            exploit_poc=req.exploit_status == "exploit_poc",
            patch_available=req.patch_available,
        )
        db.add(vuln)
        await db.flush()

    # Check for duplicate finding
    dup = await db.execute(
        select(VulnerabilityFinding).where(
            VulnerabilityFinding.asset_id == asset_id,
            VulnerabilityFinding.cve_id == req.cve_id,
            VulnerabilityFinding.status.in_([VulnStatus.OPEN, VulnStatus.IN_PROGRESS]),
        )
    )
    if not dup.scalar_one_or_none():
        finding = VulnerabilityFinding(
            id=str(uuid.uuid4()),
            tenant_id=current.tenant_id,
            asset_id=asset_id,
            vulnerability_id=vuln.id,
            cve_id=req.cve_id,
            exposure=req.exposure,
            exploit_status=req.exploit_status,
            affected_component=req.affected_component,
            sla_days_critical=1, sla_days_high=7, sla_days_medium=30,
            discovered_by=req.discovered_by,
        )
        db.add(finding)

    # Update asset vuln counts
    if req.cvss_v3 >= 9.0:
        asset.critical_vuln_count += 1
    elif req.cvss_v3 >= 7.0:
        asset.high_vuln_count += 1

    if req.cve_id not in asset.open_cves:
        asset.open_cves = asset.open_cves + [req.cve_id]

    return {"message": f"CVE {req.cve_id} attached to asset {asset_id[:8]}", "cve_id": req.cve_id}


@router.get("/shadow-it/list")
async def get_shadow_it(
    current: CurrentUser = Depends(get_any),
    db: AsyncSession = Depends(get_db),
):
    """Return all shadow IT assets detected by UTAG temporal isolation."""
    result = await db.execute(
        select(Asset).where(Asset.tenant_id == current.tenant_id, Asset.shadow_it_flag == True)
        .order_by(Asset.entropy_score.desc())
    )
    assets = result.scalars().all()
    return {
        "count": len(assets),
        "assets": [{"id": a.id, "canonical_id": a.canonical_id, "ip_address": a.ip_address,
                    "asset_class": a.asset_class.value, "entropy_score": a.entropy_score,
                    "last_seen_at": a.last_seen_at.isoformat()} for a in assets]
    }


@router.get("/geo-anomalies/list")
async def get_geo_anomalies(
    current: CurrentUser = Depends(get_any),
    db: AsyncSession = Depends(get_db),
):
    """Return assets with impossible geo-velocity (Haversine >500km/h)."""
    result = await db.execute(
        select(Asset).where(
            Asset.tenant_id == current.tenant_id,
            Asset.geo_velocity_flag == True
        ).order_by(Asset.max_geo_velocity_kmh.desc())
    )
    assets = result.scalars().all()
    return {
        "count": len(assets),
        "assets": [{"id": a.id, "hostname": a.hostname, "ip_address": a.ip_address,
                    "max_velocity_kmh": a.max_geo_velocity_kmh,
                    "last_city": a.last_geo_city, "last_country": a.last_geo_country} for a in assets]
    }


async def _audit(db, tenant_id, user_id, email, action, rtype, rid, meta):
    db.add(AuditLog(tenant_id=tenant_id, user_id=user_id, user_email=email,
                    action=action, resource_type=rtype, resource_id=rid, extra=meta))
