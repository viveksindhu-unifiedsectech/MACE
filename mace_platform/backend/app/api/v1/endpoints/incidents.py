"""Incident management endpoints — list, detail, update status, evidence download."""
from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import PlainTextResponse
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, and_
from typing import Optional, List
from datetime import datetime
from app.db.base import get_db
from app.auth.dependencies import get_current_user, get_analyst, get_any, CurrentUser
from app.models.incident import Incident, IncidentStatus, IncidentSeverity
from app.models.evidence import RegulatoryEvidence
from app.models.audit import AuditLog
from app.services.mace_engine_service import MACEService
import json

router = APIRouter(prefix="/incidents", tags=["Incidents"])


@router.get("")
async def list_incidents(
    page: int = Query(1, ge=1),
    page_size: int = Query(50, ge=1, le=200),
    status: Optional[IncidentStatus] = None,
    severity: Optional[IncidentSeverity] = None,
    event_type: Optional[str] = None,
    search: Optional[str] = None,
    current: CurrentUser = Depends(get_any),
    db: AsyncSession = Depends(get_db),
):
    filters = [Incident.tenant_id == current.tenant_id]
    if status: filters.append(Incident.status == status)
    if severity: filters.append(Incident.severity == severity)
    if event_type: filters.append(Incident.event_type == event_type)
    if search:
        from sqlalchemy import or_
        filters.append(or_(
            Incident.title.ilike(f"%{search}%"),
            Incident.incident_ref.ilike(f"%{search}%"),
            Incident.event_type.ilike(f"%{search}%"),
        ))

    count = await db.execute(select(func.count()).select_from(Incident).where(*filters))
    total = count.scalar()

    result = await db.execute(
        select(Incident).where(*filters)
        .order_by(Incident.detected_at.desc())
        .offset((page - 1) * page_size)
        .limit(page_size)
    )
    incidents = result.scalars().all()

    return {
        "items": [_incident_dict(i) for i in incidents],
        "total": total, "page": page, "page_size": page_size,
        "has_next": (page * page_size) < total,
    }


@router.get("/regulatory-calendar")
async def regulatory_calendar(
    current: CurrentUser = Depends(get_any),
    db: AsyncSession = Depends(get_db),
):
    """Return all open regulatory reporting deadlines sorted by urgency."""
    svc = MACEService(current.tenant)
    calendar = svc.get_regulatory_calendar()
    return {"items": calendar, "count": len(calendar)}


@router.get("/{incident_id}")
async def get_incident(
    incident_id: str,
    current: CurrentUser = Depends(get_any),
    db: AsyncSession = Depends(get_db),
):
    incident = await db.get(Incident, incident_id)
    if not incident or incident.tenant_id != current.tenant_id:
        raise HTTPException(404, "Incident not found")
    return _incident_dict(incident)


@router.patch("/{incident_id}/status")
async def update_status(
    incident_id: str,
    new_status: IncidentStatus,
    notes: Optional[str] = None,
    current: CurrentUser = Depends(get_analyst),
    db: AsyncSession = Depends(get_db),
):
    incident = await db.get(Incident, incident_id)
    if not incident or incident.tenant_id != current.tenant_id:
        raise HTTPException(404, "Incident not found")

    old_status = incident.status
    incident.status = new_status
    if notes:
        incident.response_notes = (incident.response_notes or "") + f"\n[{datetime.utcnow().isoformat()}] {current.email}: {notes}"

    # Update timestamps
    if new_status == IncidentStatus.CONTAINED: incident.contained_at = datetime.utcnow()
    if new_status == IncidentStatus.CLOSED: incident.resolved_at = datetime.utcnow()

    # Append to timeline
    timeline = incident.timeline or []
    timeline.append({"ts": datetime.utcnow().isoformat(), "action": f"status → {new_status.value}",
                     "user": current.email, "notes": notes})
    incident.timeline = timeline

    db.add(AuditLog(tenant_id=current.tenant_id, user_id=current.id, user_email=current.email,
                    action="incident.update_status", resource_type="incident", resource_id=incident_id,
                    old_values={"status": old_status.value}, new_values={"status": new_status.value}))

    return {"incident_ref": incident.incident_ref, "status": new_status.value}


@router.post("/{incident_id}/assign")
async def assign_incident(
    incident_id: str,
    assignee_email: str,
    current: CurrentUser = Depends(get_analyst),
    db: AsyncSession = Depends(get_db),
):
    incident = await db.get(Incident, incident_id)
    if not incident or incident.tenant_id != current.tenant_id:
        raise HTTPException(404, "Incident not found")

    incident.assigned_to = assignee_email
    if incident.status == IncidentStatus.OPEN:
        incident.status = IncidentStatus.INVESTIGATING
        incident.acknowledged_at = datetime.utcnow()

    return {"incident_ref": incident.incident_ref, "assigned_to": assignee_email}


@router.get("/{incident_id}/evidence")
async def get_evidence(
    incident_id: str,
    current: CurrentUser = Depends(get_any),
    db: AsyncSession = Depends(get_db),
):
    """Return full regulatory evidence record with all auto-generated drafts."""
    incident = await db.get(Incident, incident_id)
    if not incident or incident.tenant_id != current.tenant_id:
        raise HTTPException(404, "Incident not found")

    if not incident.regulatory_evidence_id:
        return {"message": "No regulatory evidence generated for this incident"}

    ev = await db.get(RegulatoryEvidence, incident.regulatory_evidence_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")

    return {
        "incident_ref": incident.incident_ref,
        "chain_of_custody_hash": ev.chain_of_custody_hash,
        "frameworks_triggered": ev.frameworks_triggered,
        "jurisdictions": ev.jurisdictions,
        "reporting_deadlines": ev.reporting_deadlines,
        "cert_in_reference": ev.cert_in_reference,
        "aecert_reference": ev.aecert_reference,
        "status": ev.status,
        "sla_breached": ev.sla_breached,
        "evidenced_at": ev.evidenced_at.isoformat(),
        "drafts_available": {
            "cert_in": ev.cert_in_draft is not None,
            "dpdp": ev.dpdp_draft is not None,
            "rbi": ev.rbi_draft is not None,
            "gdpr_art33": ev.gdpr_art33_draft is not None,
            "nis2": ev.nis2_draft is not None,
            "dora": ev.dora_draft is not None,
            "fedramp_sir": ev.fedramp_sir_draft is not None,
            "sec_8k": ev.sec_8k_draft is not None,
            "hipaa": ev.hipaa_draft is not None,
            "pipeda": ev.pipeda_draft is not None,
            "nesa": ev.nesa_draft is not None,
        }
    }


@router.get("/{incident_id}/evidence/{framework}/draft", response_class=PlainTextResponse)
async def download_draft(
    incident_id: str,
    framework: str,
    current: CurrentUser = Depends(get_any),
    db: AsyncSession = Depends(get_db),
):
    """Download a specific regulatory notification draft as plain text."""
    incident = await db.get(Incident, incident_id)
    if not incident or incident.tenant_id != current.tenant_id:
        raise HTTPException(404, "Incident not found")

    ev = await db.get(RegulatoryEvidence, incident.regulatory_evidence_id)
    if not ev:
        raise HTTPException(404, "Evidence not found")

    draft_map = {
        "cert_in": ev.cert_in_draft, "dpdp": ev.dpdp_draft, "rbi": ev.rbi_draft,
        "gdpr": ev.gdpr_art33_draft, "nis2": ev.nis2_draft, "dora": ev.dora_draft,
        "fedramp": ev.fedramp_sir_draft, "sec_8k": ev.sec_8k_draft,
        "hipaa": ev.hipaa_draft, "pipeda": ev.pipeda_draft, "nesa": ev.nesa_draft,
    }

    draft = draft_map.get(framework.lower())
    if not draft:
        raise HTTPException(404, f"No {framework} draft available for this incident")

    return PlainTextResponse(content=draft, media_type="text/plain")


def _incident_dict(i: Incident) -> dict:
    return {
        "id": i.id, "incident_ref": i.incident_ref, "title": i.title,
        "event_type": i.event_type, "cdcs_score": i.cdcs_score,
        "severity": i.severity.value, "status": i.status.value,
        "kill_chain_stage": i.kill_chain_stage, "dominant_domain": i.dominant_domain,
        "sub_scores": {"V": i.v_score, "E": i.e_score, "I": i.i_score,
                       "N": i.n_score, "C": i.c_score, "T": i.t_score},
        "frameworks_triggered": i.frameworks_triggered, "jurisdictions": i.jurisdictions,
        "assigned_to": i.assigned_to, "confirmed_true_positive": i.confirmed_true_positive,
        "detected_at": i.detected_at.isoformat(), "resolved_at": i.resolved_at.isoformat() if i.resolved_at else None,
        "has_evidence": i.regulatory_evidence_id is not None,
    }
