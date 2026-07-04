"""
Correlation endpoint — the core MACE pipeline.
POST /correlate → UTAG lookup → CDCS 6-domain → UREA evidence → response
"""
from fastapi import APIRouter, Depends, HTTPException, BackgroundTasks, WebSocket, WebSocketDisconnect
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select
from typing import List
from datetime import datetime
import uuid, json
import random
import string

from app.db.base import get_db
from app.db.redis import get_redis, CacheService
from app.auth.dependencies import get_current_user, get_analyst, get_any, CurrentUser
from app.models.asset import Asset
from app.models.incident import Incident, IncidentSeverity, IncidentStatus
from app.models.evidence import RegulatoryEvidence
from app.models.audit import AuditLog
from app.schemas.correlation import (CorrelationRequest, CorrelationResponse,
                                      CDCSResponse, SubScores, Multipliers,
                                      IncidentSummary, FeedbackRequest)
from app.services.mace_engine_service import MACEService

router = APIRouter(prefix="/correlate", tags=["Correlation Engine"])

# WebSocket connection manager for real-time SOC dashboard push
class WSManager:
    def __init__(self):
        self._connections: dict[str, set[WebSocket]] = {}

    async def connect(self, tenant_id: str, ws: WebSocket):
        await ws.accept()
        self._connections.setdefault(tenant_id, set()).add(ws)

    def disconnect(self, tenant_id: str, ws: WebSocket):
        if tenant_id in self._connections:
            self._connections[tenant_id].discard(ws)

    async def broadcast(self, tenant_id: str, message: dict):
        dead = []
        for ws in list(self._connections.get(tenant_id, set())):
            try:
                await ws.send_json(message)
            except Exception:
                dead.append(ws)
        for ws in dead:
            self._connections.get(tenant_id, set()).discard(ws)

ws_manager = WSManager()


@router.post("", response_model=CorrelationResponse)
async def correlate(
    req: CorrelationRequest,
    background_tasks: BackgroundTasks,
    current: CurrentUser = Depends(get_analyst),
    db: AsyncSession = Depends(get_db),
):
    """
    Run the full MACE pipeline for an asset + security event.
    1. Look up canonical asset from DB
    2. Run CDCS six-domain correlation
    3. If CDCS >= threshold, trigger UREA evidence generation
    4. Persist incident + evidence to DB
    5. Push real-time update via WebSocket to SOC dashboard
    """
    # Look up asset
    asset_result = await db.execute(
        select(Asset).where(
            Asset.id == req.asset_id,
            Asset.tenant_id == current.tenant_id
        )
    )
    asset = asset_result.scalar_one_or_none()

    # Also try canonical_id lookup
    if not asset:
        asset_result = await db.execute(
            select(Asset).where(
                Asset.canonical_id == req.asset_id,
                Asset.tenant_id == current.tenant_id
            )
        )
        asset = asset_result.scalar_one_or_none()

    if not asset:
        raise HTTPException(404, f"Asset {req.asset_id} not found")

    # Build context dict from request
    context = {}
    if req.identity: context["identity"] = req.identity.model_dump()
    if req.network:  context["network"]   = req.network.model_dump()
    if req.compliance: context["compliance"] = req.compliance.model_dump()
    if req.threat_intel: context["threat_intel"] = req.threat_intel.model_dump()
    if req.jurisdictions: context["jurisdictions"] = req.jurisdictions

    # Run MACE engine
    svc = MACEService(current.tenant)
    result = svc.correlate(asset.canonical_id, req.event.model_dump(), context)

    cdcs_data = result["cdcs"]
    incident_data = result.get("incident")
    alert = result["alert"]

    # Build CDCS response
    cdcs_resp = CDCSResponse(
        cdcs=cdcs_data["cdcs"],
        severity=cdcs_data["severity"],
        alert_triggered=alert,
        sub_scores=SubScores(**cdcs_data["sub_scores"]),
        multipliers=Multipliers(**cdcs_data["multipliers"]),
        dominant_domain=cdcs_data["dominant_domain"],
        confidence_interval=cdcs_data["confidence_interval"],
        weights=cdcs_data["weights"],
    )

    # Update asset CDCS score in DB
    asset.cdcs_score = cdcs_data["cdcs"]
    asset.risk_level = cdcs_data["severity"]
    asset.last_scored_at = datetime.utcnow()

    incident_summary = None
    if alert and incident_data:
        # Persist regulatory evidence
        ev = RegulatoryEvidence(
            id=str(uuid.uuid4()),
            tenant_id=current.tenant_id,
            incident_ref=incident_data["incident_id"],
            dfa_state_log=[],
            chain_of_custody_hash=incident_data.get("chain_of_custody_hash", ""),
            cdcs_score=cdcs_data["cdcs"],
            severity=cdcs_data["severity"],
            event_type=req.event.event_type,
            frameworks_triggered=incident_data.get("frameworks", []),
            jurisdictions=req.jurisdictions or [current.tenant.jurisdiction],
            reporting_deadlines=incident_data.get("reporting_deadlines", {}),
            cert_in_reference=incident_data.get("cert_in_reference"),
            aecert_reference=incident_data.get("aecert_reference"),
            detected_at=datetime.utcnow(),
            asset_attributes={
                "hostname": asset.hostname, "ip_address": asset.ip_address,
                "owner": asset.owner, "sector": asset.sector,
                "jurisdiction": asset.jurisdiction,
            },
        )
        db.add(ev)
        await db.flush()

        # Create incident record
        sev_map = {"CRITICAL": IncidentSeverity.CRITICAL, "HIGH": IncidentSeverity.HIGH,
                   "MEDIUM": IncidentSeverity.MEDIUM, "LOW": IncidentSeverity.LOW}
        ref = "INC-" + "".join(random.choices(string.ascii_uppercase + string.digits, k=8))

        incident = Incident(
            id=str(uuid.uuid4()),
            tenant_id=current.tenant_id,
            asset_id=asset.id,
            incident_ref=ref,
            title=f"{cdcs_data['severity']} — {req.event.event_type} on {asset.hostname or asset.ip_address}",
            description=req.event.description,
            event_type=req.event.event_type,
            cdcs_score=cdcs_data["cdcs"],
            severity=sev_map.get(cdcs_data["severity"], IncidentSeverity.HIGH),
            status=IncidentStatus.OPEN,
            v_score=cdcs_data["sub_scores"]["vulnerability"],
            e_score=cdcs_data["sub_scores"]["endpoint"],
            i_score=cdcs_data["sub_scores"]["identity"],
            n_score=cdcs_data["sub_scores"]["network"],
            c_score=cdcs_data["sub_scores"]["compliance"],
            t_score=cdcs_data["sub_scores"]["threat_intel"],
            sector_multiplier=cdcs_data["multipliers"]["sector"],
            blast_radius_multiplier=cdcs_data["multipliers"]["blast_radius"],
            kill_chain_multiplier=cdcs_data["multipliers"]["kill_chain"],
            kill_chain_stage=req.event.kill_chain_stage,
            dominant_domain=cdcs_data["dominant_domain"],
            regulatory_evidence_id=ev.id,
            jurisdictions=req.jurisdictions or [current.tenant.jurisdiction],
            frameworks_triggered=incident_data.get("frameworks", []),
            detected_at=datetime.utcnow(),
        )
        db.add(incident)

        incident_summary = IncidentSummary(
            incident_id=incident.id,
            incident_ref=ref,
            cert_in_reference=incident_data.get("cert_in_reference"),
            aecert_reference=incident_data.get("aecert_reference"),
            chain_of_custody_hash=incident_data.get("chain_of_custody_hash"),
            frameworks=incident_data.get("frameworks", []),
            reporting_deadlines=incident_data.get("reporting_deadlines", {}),
            sla_breached=incident_data.get("sla_breached", False),
            has_gdpr_draft=incident_data.get("has_gdpr_draft", False),
            has_fedramp_sir=incident_data.get("has_fedramp_sir", False),
            has_nesa_draft=incident_data.get("has_nesa_draft", False),
            has_sec_8k=incident_data.get("has_sec_8k", False),
        )

        # Real-time push to SOC dashboard
        background_tasks.add_task(ws_manager.broadcast, current.tenant_id, {
            "type": "incident.new",
            "incident_ref": ref,
            "cdcs": cdcs_data["cdcs"],
            "severity": cdcs_data["severity"],
            "asset": asset.hostname or asset.ip_address,
            "event_type": req.event.event_type,
            "cert_in_reference": incident_data.get("cert_in_reference"),
            "aecert_reference": incident_data.get("aecert_reference"),
            "frameworks": incident_data.get("frameworks", []),
            "ts": datetime.utcnow().isoformat(),
        })

    # Audit log
    db.add(AuditLog(
        tenant_id=current.tenant_id, user_id=current.id, user_email=current.email,
        action="correlation.run", resource_type="asset", resource_id=asset.id,
        new_values={"cdcs": cdcs_data["cdcs"], "severity": cdcs_data["severity"],
                    "alert": alert, "event_type": req.event.event_type},
    ))

    return CorrelationResponse(
        asset_id=req.asset_id,
        event_id=req.event.event_id,
        event_type=req.event.event_type,
        cdcs=cdcs_resp,
        incident=incident_summary,
        alert=alert,
        processed_at=datetime.utcnow(),
    )


@router.post("/feedback")
async def submit_feedback(
    req: FeedbackRequest,
    current: CurrentUser = Depends(get_analyst),
    db: AsyncSession = Depends(get_db),
):
    """Adaptive learning feedback — confirm TP/FP to update MACE weights."""
    incident = await db.get(Incident, req.incident_id)
    if not incident or incident.tenant_id != current.tenant_id:
        raise HTTPException(404, "Incident not found")

    incident.confirmed_true_positive = req.confirmed_true_positive
    incident.feedback_at = datetime.utcnow()
    incident.feedback_by = current.email

    # Trigger adaptive weight update in MACE engine
    svc = MACEService(current.tenant)
    # Build minimal CDCSResult-like object for feedback
    from core.cdcs import CDCSResult
    mock_result = CDCSResult(
        asset_id="feedback",
        cdcs=incident.cdcs_score,
        alert_triggered=True,
        v_score=incident.v_score, e_score=incident.e_score,
        i_score=incident.i_score, n_score=incident.n_score,
        c_score=incident.c_score, t_score=incident.t_score,
        dominant_domain=incident.dominant_domain or "vulnerability",
    )
    svc.engine.cdcs.feedback(mock_result, req.confirmed_true_positive)

    db.add(AuditLog(
        tenant_id=current.tenant_id, user_id=current.id, user_email=current.email,
        action="incident.feedback", resource_type="incident", resource_id=incident.id,
        new_values={"confirmed_tp": req.confirmed_true_positive, "notes": req.notes},
    ))

    updated_weights = svc.engine.cdcs.weights.to_dict()
    return {
        "message": f"Feedback recorded. Weights updated.",
        "confirmed_true_positive": req.confirmed_true_positive,
        "updated_weights": updated_weights,
    }


@router.websocket("/ws/{tenant_id}")
async def websocket_endpoint(websocket: WebSocket, tenant_id: str):
    """WebSocket for real-time incident push to SOC dashboard."""
    await ws_manager.connect(tenant_id, websocket)
    try:
        while True:
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text("pong")
    except WebSocketDisconnect:
        ws_manager.disconnect(tenant_id, websocket)
