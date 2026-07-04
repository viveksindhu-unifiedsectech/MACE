from app.core.encryption import encrypt_credential, decrypt_credential
"""Admin endpoints — tenant management, users, API keys, connectors, billing."""
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func
from typing import Optional, List
from datetime import datetime
from app.db.base import get_db
from app.auth.dependencies import get_admin, get_current_user, CurrentUser
from app.models.user import User, UserRole, APIKey
from app.models.tenant import Tenant, TenantPlan
from app.models.connector import ConnectorConfig, ConnectorType
from app.models.subscription import Subscription
from app.models.audit import AuditLog
from app.auth.jwt import hash_password
from app.services.mace_engine_service import MACEService, reset_engine
import uuid
from datetime import datetime as dt

router = APIRouter(prefix="/admin", tags=["Admin"])


# ── TENANT ─────────────────────────────────────────────────────────
@router.get("/tenant")
async def get_tenant(current: CurrentUser = Depends(get_admin), db: AsyncSession = Depends(get_db)):
    t = current.tenant
    svc = MACEService(t)
    stats = svc.get_stats()
    return {
        "id": t.id, "name": t.name, "slug": t.slug, "plan": t.plan.value,
        "jurisdiction": t.jurisdiction, "weight_profile": t.weight_profile,
        "sector": t.sector, "data_residency": t.data_residency,
        "asset_limit": t.asset_limit, "is_fedramp": t.is_fedramp,
        "is_hipaa_baa": t.is_hipaa_baa, "soc2_compliant": t.soc2_compliant,
        "cdcs_alert_threshold": t.cdcs_alert_threshold,
        "rea_cdcs_threshold": t.rea_cdcs_threshold,
        "enabled_frameworks": t.enabled_frameworks,
        "mace_stats": stats,
        "created_at": t.created_at.isoformat(),
    }


@router.patch("/tenant/config")
async def update_tenant_config(
    jurisdiction: Optional[str] = None,
    weight_profile: Optional[str] = None,
    sector: Optional[str] = None,
    cdcs_alert_threshold: Optional[float] = None,
    rea_cdcs_threshold: Optional[float] = None,
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    """Update MACE engine configuration for this tenant. Resets engine on change."""
    t = await db.get(Tenant, current.tenant_id)
    changed = False

    if jurisdiction and jurisdiction != t.jurisdiction:
        t.jurisdiction = jurisdiction; changed = True
    if weight_profile and weight_profile != t.weight_profile:
        t.weight_profile = weight_profile; changed = True
    if sector and sector != t.sector:
        t.sector = sector
    if cdcs_alert_threshold is not None:
        t.cdcs_alert_threshold = cdcs_alert_threshold; changed = True
    if rea_cdcs_threshold is not None:
        t.rea_cdcs_threshold = rea_cdcs_threshold; changed = True

    if changed:
        reset_engine(current.tenant_id)  # Force new engine with new config

    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id, user_email=current.email,
                    action="tenant.config_update", resource_type="tenant", resource_id=current.tenant_id))

    return {"message": "Configuration updated", "engine_reset": changed}


# ── USERS ──────────────────────────────────────────────────────────
@router.get("/users")
async def list_users(
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(User).where(User.tenant_id == current.tenant_id).order_by(User.created_at.desc())
    )
    users = result.scalars().all()
    return {"users": [_user_dict(u) for u in users], "total": len(users)}


@router.post("/users", status_code=201)
async def create_user(
    email: str, full_name: str, role: UserRole, password: str,
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    existing = await db.execute(
        select(User).where(User.email == email, User.tenant_id == current.tenant_id)
    )
    if existing.scalar_one_or_none():
        raise HTTPException(409, "Email already exists in this tenant")

    user = User(id=str(uuid.uuid4()), tenant_id=current.tenant_id,
                email=email, full_name=full_name, role=role,
                hashed_password=hash_password(password), is_verified=True)
    db.add(user)
    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id, user_email=current.email,
                    action="user.create", resource_type="user", resource_id=user.id,
                    new_values={"email": email, "role": role.value}))
    return _user_dict(user)


@router.patch("/users/{user_id}")
async def update_user(
    user_id: str, role: Optional[UserRole] = None,
    is_active: Optional[bool] = None,
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    user = await db.get(User, user_id)
    if not user or user.tenant_id != current.tenant_id:
        raise HTTPException(404, "User not found")
    if role: user.role = role
    if is_active is not None: user.is_active = is_active
    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id, user_email=current.email,
                    action="user.update", resource_type="user", resource_id=user_id))
    return _user_dict(user)


# ── API KEYS ────────────────────────────────────────────────────────
@router.post("/api-keys", status_code=201)
async def create_api_key(
    name: str,
    scopes: List[str],
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    raw_key, key_hash = APIKey.generate()
    key_prefix = raw_key[:20]

    api_key = APIKey(
        id=str(uuid.uuid4()), tenant_id=current.tenant_id, user_id=current.id,
        name=name, key_prefix=key_prefix, key_hash=key_hash, scopes=scopes,
    )
    db.add(api_key)
    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id, user_email=current.email,
                    action="api_key.create", resource_type="api_key", resource_id=api_key.id,
                    new_values={"name": name, "scopes": scopes}))

    return {
        "id": api_key.id, "name": name, "scopes": scopes,
        "key": raw_key,   # ← shown ONCE, never stored in plaintext
        "prefix": key_prefix,
        "warning": "Store this key securely. It will NOT be shown again.",
    }


@router.get("/api-keys")
async def list_api_keys(
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(APIKey).where(APIKey.tenant_id == current.tenant_id)
    )
    keys = result.scalars().all()
    return {"keys": [{"id": k.id, "name": k.name, "prefix": k.key_prefix,
                       "scopes": k.scopes, "is_active": k.is_active,
                       "last_used_at": k.last_used_at.isoformat() if k.last_used_at else None}
                     for k in keys]}


@router.delete("/api-keys/{key_id}")
async def revoke_api_key(
    key_id: str,
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    key = await db.get(APIKey, key_id)
    if not key or key.tenant_id != current.tenant_id:
        raise HTTPException(404, "API key not found")
    key.is_active = False
    return {"message": f"API key {key.name} revoked"}


# ── CONNECTORS ──────────────────────────────────────────────────────
@router.get("/connectors")
async def list_connectors(
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    result = await db.execute(
        select(ConnectorConfig).where(ConnectorConfig.tenant_id == current.tenant_id)
    )
    return {"connectors": [_connector_dict(c) for c in result.scalars().all()]}


@router.post("/connectors", status_code=201)
async def create_connector(
    connector_type: ConnectorType, name: str,
    base_url: Optional[str] = None,
    client_id: Optional[str] = None,
    client_secret: Optional[str] = None,
    api_key_value: Optional[str] = None,
    sync_interval_minutes: int = 60,
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    """Create a data connector. Secrets are stored encrypted."""
    # In production, encrypt with AWS KMS / Azure Key Vault
    connector = ConnectorConfig(
        id=str(uuid.uuid4()), tenant_id=current.tenant_id,
        connector_type=connector_type, name=name,
        base_url=base_url, client_id=client_id,
        client_secret_encrypted=encrypt_credential(client_secret) if client_secret else None,
        api_key_encrypted=encrypt_credential(api_key_value) if api_key_value else None,
        sync_interval_minutes=sync_interval_minutes,
        provides_assets=True,
        provides_vulns=connector_type in [ConnectorType.TENABLE, ConnectorType.QUALYS],
        provides_events=connector_type in [ConnectorType.CROWDSTRIKE, ConnectorType.SENTINEL, ConnectorType.SPLUNK],
        provides_threat_intel=connector_type in [ConnectorType.MISP, ConnectorType.VIRUSTOTAL, ConnectorType.RECORDED_FUTURE],
    )
    db.add(connector)
    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id, user_email=current.email,
                    action="connector.create", resource_type="connector", resource_id=connector.id,
                    new_values={"type": connector_type.value, "name": name}))
    return _connector_dict(connector)


@router.delete("/connectors/{connector_id}")
async def delete_connector(
    connector_id: str,
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    conn = await db.get(ConnectorConfig, connector_id)
    if not conn or conn.tenant_id != current.tenant_id:
        raise HTTPException(404, "Connector not found")
    await db.delete(conn)
    return {"message": f"Connector {conn.name} deleted"}


# ── STATS & AUDIT ────────────────────────────────────────────────────
@router.get("/stats")
async def get_platform_stats(
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    """Dashboard stats — asset counts, incident counts, MACE engine health."""
    from app.models.asset import Asset
    from app.models.incident import Incident
    from app.models.vulnerability import VulnerabilityFinding

    asset_count = await db.execute(
        select(func.count()).select_from(Asset).where(Asset.tenant_id == current.tenant_id)
    )
    incident_count = await db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.tenant_id == current.tenant_id, Incident.status == "open"
        )
    )
    critical_count = await db.execute(
        select(func.count()).select_from(Incident).where(
            Incident.tenant_id == current.tenant_id, Incident.severity == "critical"
        )
    )
    vuln_count = await db.execute(
        select(func.count()).select_from(VulnerabilityFinding).where(
            VulnerabilityFinding.tenant_id == current.tenant_id,
            VulnerabilityFinding.status == "open"
        )
    )

    svc = MACEService(current.tenant)
    engine_stats = svc.get_stats()

    return {
        "assets": {"total": asset_count.scalar(), "limit": current.tenant.asset_limit},
        "incidents": {"open": incident_count.scalar(), "critical": critical_count.scalar()},
        "vulnerabilities": {"open": vuln_count.scalar()},
        "engine": engine_stats,
        "regulatory_calendar": svc.get_regulatory_calendar()[:5],
    }


@router.get("/audit-log")
async def get_audit_log(
    page: int = Query(1, ge=1),
    page_size: int = Query(100, le=500),
    action: Optional[str] = None,
    current: CurrentUser = Depends(get_admin),
    db: AsyncSession = Depends(get_db),
):
    filters = [AuditLog.tenant_id == current.tenant_id]
    if action: filters.append(AuditLog.action == action)
    result = await db.execute(
        select(AuditLog).where(*filters)
        .order_by(AuditLog.created_at.desc())
        .offset((page - 1) * page_size).limit(page_size)
    )
    logs = result.scalars().all()
    return {"logs": [{"id": l.id, "action": l.action, "user_email": l.user_email,
                       "resource_type": l.resource_type, "resource_id": l.resource_id,
                       "success": l.success, "ip_address": l.ip_address,
                       "created_at": l.created_at.isoformat()} for l in logs]}


def _user_dict(u: User) -> dict:
    return {"id": u.id, "email": u.email, "full_name": u.full_name,
            "role": u.role.value, "is_active": u.is_active, "is_verified": u.is_verified,
            "mfa_enabled": u.mfa_enabled, "last_login_at": u.last_login_at.isoformat() if u.last_login_at else None,
            "created_at": u.created_at.isoformat()}

def _connector_dict(c: ConnectorConfig) -> dict:
    return {"id": c.id, "type": c.connector_type.value, "name": c.name,
            "status": c.status.value, "sync_enabled": c.sync_enabled,
            "sync_interval_minutes": c.sync_interval_minutes,
            "last_sync_at": c.last_sync_at.isoformat() if c.last_sync_at else None,
            "last_sync_count": c.last_sync_count, "error_message": c.error_message,
            "provides_assets": c.provides_assets, "provides_vulns": c.provides_vulns,
            "provides_events": c.provides_events}
