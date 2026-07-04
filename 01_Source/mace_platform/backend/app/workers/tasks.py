"""Celery task implementations."""
from app.workers.celery_app import celery
import logging
import httpx
import asyncio
from datetime import datetime

logger = logging.getLogger(__name__)


@celery.task(name="app.workers.tasks.sync_all_connectors", bind=True, max_retries=3)
def sync_all_connectors(self):
    """Pull latest data from all active connectors across all tenants."""
    logger.info("Starting connector sync sweep")
    try:
        asyncio.run(_async_sync_all())
    except Exception as exc:
        logger.error(f"Connector sync failed: {exc}")
        raise self.retry(exc=exc, countdown=300)


async def _async_sync_all():
    """Async inner — query DB for active connectors and trigger sync per tenant."""
    from app.db.base import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.connector import ConnectorConfig, ConnectorStatus

    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(ConnectorConfig).where(
                ConnectorConfig.sync_enabled == True,
                ConnectorConfig.status == ConnectorStatus.ACTIVE,
            )
        )
        connectors = result.scalars().all()

    for connector in connectors:
        try:
            sync_connector.delay(connector.id)
        except Exception as e:
            logger.error(f"Failed to queue sync for connector {connector.id}: {e}")


@celery.task(name="app.workers.tasks.sync_connector", bind=True, max_retries=2)
def sync_connector(self, connector_id: str):
    """Sync a single connector — fetch data and ingest into MACE."""
    logger.info(f"Syncing connector {connector_id}")
    try:
        asyncio.run(_async_sync_connector(connector_id))
    except Exception as exc:
        logger.error(f"Connector {connector_id} sync failed: {exc}")
        raise self.retry(exc=exc, countdown=120)


async def _async_sync_connector(connector_id: str):
    from app.db.base import AsyncSessionLocal
    from app.models.connector import ConnectorConfig, ConnectorStatus, ConnectorType
    from app.models.tenant import Tenant
    from app.services.mace_engine_service import MACEService

    async with AsyncSessionLocal() as db:
        connector = await db.get(ConnectorConfig, connector_id)
        if not connector:
            return

        tenant = await db.get(Tenant, connector.tenant_id)
        svc = MACEService(tenant)

        try:
            if connector.connector_type == ConnectorType.CROWDSTRIKE:
                records = await _fetch_crowdstrike(connector)
            elif connector.connector_type == ConnectorType.TENABLE:
                records = await _fetch_tenable(connector)
            else:
                records = []

            count = 0
            for record in records:
                try:
                    svc.ingest_asset(record)
                    count += 1
                except Exception as e:
                    logger.warning(f"Failed to ingest record: {e}")

            connector.last_sync_at = datetime.utcnow()
            connector.last_sync_status = "success"
            connector.last_sync_count = count
            connector.error_message = None
            await db.commit()
            logger.info(f"Connector {connector.name}: synced {count} records")

        except Exception as e:
            connector.last_sync_status = "error"
            connector.error_message = str(e)[:500]
            await db.commit()
            raise


async def _fetch_crowdstrike(connector) -> list:
    """Fetch devices from CrowdStrike Falcon API."""
    from app.core.encryption import decrypt_credential
    if not connector.client_id or not connector.client_secret_encrypted:
        return []
    client_secret = decrypt_credential(connector.client_secret_encrypted)
    if not client_secret:
        return []
    try:
        base = connector.base_url or "https://api.crowdstrike.com"
        async with httpx.AsyncClient(timeout=30) as client:
            # Get OAuth2 token
            token_resp = await client.post(f"{base}/oauth2/token", data={
                "client_id": connector.client_id,
                "client_secret": client_secret,
                "grant_type": "client_credentials",
            })
            token = token_resp.json().get("access_token")
            if not token:
                return []

            # Get device IDs
            devices_resp = await client.get(
                f"{base}/devices/queries/devices/v1",
                headers={"Authorization": f"Bearer {token}"},
                params={"limit": 500}
            )
            device_ids = devices_resp.json().get("resources", [])
            if not device_ids:
                return []

            # Get device details
            details_resp = await client.post(
                f"{base}/devices/entities/devices/v2",
                headers={"Authorization": f"Bearer {token}"},
                json={"ids": device_ids[:100]}
            )
            devices = details_resp.json().get("resources", [])

            records = []
            for d in devices:
                records.append({
                    "source": "crowdstrike",
                    "source_id": d.get("device_id", ""),
                    "hostname": d.get("hostname"),
                    "mac_address": d.get("mac_address"),
                    "ip_address": d.get("local_ip"),
                    "os": d.get("os_version"),
                    "asset_class": _cs_asset_class(d.get("product_type_desc", "")),
                    "owner": d.get("ou"),
                    "tags": {"cs_group": d.get("groups", [""])[0]} if d.get("groups") else {},
                })
            return records
    except Exception as e:
        logger.error(f"CrowdStrike fetch error: {e}")
        return []


def _cs_asset_class(product_type: str) -> str:
    t = product_type.lower()
    if "server" in t: return "server"
    if "workstation" in t or "desktop" in t: return "endpoint"
    if "mobile" in t: return "mobile"
    return "endpoint"


async def _fetch_tenable(connector) -> list:
    """Fetch assets from Tenable.io API."""
    from app.core.encryption import decrypt_credential
    if not connector.client_id or not connector.client_secret_encrypted:
        return []
    secret_key = decrypt_credential(connector.client_secret_encrypted)
    if not secret_key:
        return []
    try:
        base = connector.base_url or "https://cloud.tenable.com"
        headers = {
            "X-ApiKeys": f"accessKey={connector.client_id};secretKey={secret_key}"
        }
        async with httpx.AsyncClient(timeout=30, headers=headers) as client:
            resp = await client.get(f"{base}/assets", params={"limit": 500})
            assets = resp.json().get("assets", [])
            records = []
            for a in assets:
                records.append({
                    "source": "tenable",
                    "source_id": a.get("id", ""),
                    "hostname": a.get("fqdn", [None])[0],
                    "ip_address": a.get("ipv4", [None])[0],
                    "mac_address": a.get("mac_address", [None])[0],
                    "os": a.get("operating_system", [None])[0],
                    "is_internet_facing": False,
                    "source_confidence": 0.90,
                })
            return records
    except Exception as e:
        logger.error(f"Tenable fetch error: {e}")
        return []


@celery.task(name="app.workers.tasks.refresh_epss_scores")
def refresh_epss_scores():
    """Download latest EPSS scores from FIRST.org and update CVE records."""
    logger.info("Refreshing EPSS scores from FIRST.org")
    try:
        asyncio.run(_async_refresh_epss())
    except Exception as e:
        logger.error(f"EPSS refresh failed: {e}")


async def _async_refresh_epss():
    from app.db.base import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.vulnerability import Vulnerability
    import csv, gzip, io

    # FIRST.org EPSS CSV endpoint
    url = "https://epss.cyentia.com/epss_scores-current.csv.gz"
    async with httpx.AsyncClient(timeout=120) as client:
        resp = await client.get(url)
        if resp.status_code != 200:
            logger.warning(f"EPSS fetch returned {resp.status_code}")
            return

        content = gzip.decompress(resp.content).decode("utf-8")
        reader = csv.DictReader(io.StringIO(content))
        epss_map = {}
        for row in reader:
            cve = row.get("cve")
            score = float(row.get("epss", 0))
            percentile = float(row.get("percentile", 0))
            if cve:
                epss_map[cve.upper()] = (score, percentile)

    async with AsyncSessionLocal() as db:
        result = await db.execute(select(Vulnerability))
        vulns = result.scalars().all()
        updated = 0
        for v in vulns:
            if v.cve_id.upper() in epss_map:
                score, pct = epss_map[v.cve_id.upper()]
                v.epss_score = score
                v.epss_percentile = pct
                v.epss_updated_at = datetime.utcnow()
                updated += 1
        await db.commit()
    logger.info(f"EPSS refresh complete: {updated} CVEs updated")


@celery.task(name="app.workers.tasks.acs_decay_sweep")
def acs_decay_sweep():
    """Recalculate ACS for all assets and update DB with current scores."""
    logger.info("Running ACS decay sweep")
    asyncio.run(_async_acs_sweep())


async def _async_acs_sweep():
    from app.db.base import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.asset import Asset, AssetStatus
    from app.models.tenant import Tenant
    from app.services.mace_engine_service import MACEService

    async with AsyncSessionLocal() as db:
        tenants = (await db.execute(select(Tenant).where(Tenant.is_active == True))).scalars().all()
        for tenant in tenants:
            svc = MACEService(tenant)
            for cid, vertex in svc.engine.tag.vertices.items():
                acs = vertex.acs()
                status = vertex.status().value
                result = await db.execute(
                    select(Asset).where(Asset.canonical_id == cid, Asset.tenant_id == tenant.id)
                )
                asset = result.scalar_one_or_none()
                if asset:
                    asset.acs_score = round(acs, 4)
                    asset.status = AssetStatus(status)
                    asset.shadow_it_flag = vertex.shadow_it_flag
        await db.commit()
    logger.info("ACS decay sweep complete")


@celery.task(name="app.workers.tasks.check_sla_breaches")
def check_sla_breaches():
    """Check all open regulatory evidence for SLA breaches. Alert if overdue."""
    asyncio.run(_async_sla_check())


async def _async_sla_check():
    from app.db.base import AsyncSessionLocal
    from sqlalchemy import select
    from app.models.evidence import RegulatoryEvidence
    from app.services.mace_engine_service import MACEService
    from app.models.tenant import Tenant

    now = datetime.utcnow()
    async with AsyncSessionLocal() as db:
        result = await db.execute(
            select(RegulatoryEvidence).where(RegulatoryEvidence.status == "open")
        )
        evidences = result.scalars().all()
        for ev in evidences:
            for framework, deadline_str in ev.reporting_deadlines.items():
                try:
                    deadline = datetime.fromisoformat(deadline_str.replace("Z", "+00:00")).replace(tzinfo=None)
                    if deadline < now and not ev.sla_breached:
                        ev.sla_breached = True
                        logger.warning(f"SLA BREACH: {ev.incident_ref} — {framework} deadline passed")
                except Exception:
                    pass
        await db.commit()
