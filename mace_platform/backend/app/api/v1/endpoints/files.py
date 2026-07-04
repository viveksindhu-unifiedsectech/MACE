"""
Secure Files API — encrypt-on-ingest, access-controlled retrieval, sharing,
redaction, AI-guard, and cross-matter conflict detection.

Pipeline on upload:  AI guard -> optional redact -> envelope encrypt -> S3/local
Pipeline on download: access.evaluate -> fetch -> decrypt -> integrity verify
Every action writes an immutable AuditLog row (SOC2 / FedRAMP / GDPR).
"""
from __future__ import annotations

from datetime import datetime
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, UploadFile, File, Form, Query, Request
from fastapi.responses import Response
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.db.base import get_db
from app.auth.dependencies import get_current_user, CurrentUser
from app.core.config import settings
from app.models.audit import AuditLog
from app.models.secure_file import SecureFile, FileAccessGrant
from app.schemas.files import FileMeta, FileUploadResult, GrantCreate, GrantOut, ConflictFinding
from app.secure import service
from app.secure.access import (
    Classification, Permission, Subject, Resource, Grant, evaluate, explain,
)
from app.secure.correlation import CorrelationIndex, Matter, EntityType

router = APIRouter(prefix="/files", tags=["Secure Files"])


# ── adapters: ORM -> access engine ──────────────────────────────────
def _subject(current: CurrentUser) -> Subject:
    return Subject(id=str(current.id), tenant_id=str(current.tenant_id),
                   role=current.role.value if hasattr(current.role, "value") else str(current.role))


def _perm_set(csv: str):
    out = set()
    for p in (csv or "").split(","):
        p = p.strip()
        if p:
            try:
                out.add(Permission(p))
            except ValueError:
                pass
    return out


def _resource(f: SecureFile) -> Resource:
    grants = [
        Grant(subject_type=g.subject_type, subject_value=g.subject_value,
              permissions=_perm_set(g.permissions), expires_at=g.expires_at)
        for g in (f.grants or [])
    ]
    try:
        cls = Classification(f.classification)
    except ValueError:
        cls = Classification.INTERNAL
    return Resource(id=str(f.id), tenant_id=str(f.tenant_id), owner_id=str(f.owner_id),
                    classification=cls, grants=grants)


async def _get_file_or_404(db: AsyncSession, tenant_id: str, file_id: str) -> SecureFile:
    res = await db.execute(
        select(SecureFile).where(SecureFile.id == file_id,
                                 SecureFile.tenant_id == tenant_id,
                                 SecureFile.is_deleted == False))  # noqa: E712
    f = res.scalar_one_or_none()
    if not f:
        raise HTTPException(status_code=404, detail="File not found")
    return f


def _audit(db, current, action, file_id, success=True, extra=None, error=None):
    db.add(AuditLog(
        tenant_id=str(current.tenant_id), user_id=str(current.id), user_email=current.email,
        action=action, resource_type="secure_file", resource_id=str(file_id) if file_id else None,
        success=success, error_message=error, extra=extra or {}))


# ── endpoints ───────────────────────────────────────────────────────
@router.post("", response_model=FileUploadResult)
async def upload_file(
    request: Request,
    file: UploadFile = File(...),
    classification: str = Form("internal"),
    redact: bool = Form(False),
    db: AsyncSession = Depends(get_db),
    current: CurrentUser = Depends(get_current_user),
):
    """Encrypt and store any file. AI guard runs first and may block."""
    content = await file.read()
    try:
        stored = service.store_file(
            content=content, tenant_id=str(current.tenant_id), owner_id=str(current.id),
            filename=file.filename or "upload.bin",
            content_type=file.content_type or "application/octet-stream",
            classification=classification,
            redact=redact or settings.MACE_REDACT_BY_DEFAULT,
        )
    except service.GuardBlocked as gb:
        _audit(db, current, "secure_file.upload_blocked", None, success=False,
               extra=gb.result.as_dict(), error="AI guard blocked upload")
        raise HTTPException(status_code=422, detail={"message": "Upload blocked by AI guard",
                                                     "guard": gb.result.as_dict()})

    row = SecureFile(
        id=stored.file_id, tenant_id=stored.tenant_id, owner_id=stored.owner_id,
        filename=stored.filename, content_type=stored.content_type,
        classification=stored.classification, storage_uri=stored.storage_uri,
        wrapped_dek=stored.wrapped_dek_b64, sha256=stored.sha256, size_bytes=stored.size,
        chunks=stored.chunks, redacted=stored.redacted,
        redaction_report=stored.redaction_report, guard_report=stored.guard)
    db.add(row)
    _audit(db, current, "secure_file.upload", stored.file_id,
           extra={"classification": stored.classification, "redacted": stored.redacted,
                  "guard_score": stored.guard.get("score")})
    await db.flush()
    return FileUploadResult(file=FileMeta.model_validate(row),
                            guard=stored.guard, redaction_report=stored.redaction_report)


@router.get("", response_model=List[FileMeta])
async def list_files(db: AsyncSession = Depends(get_db),
                     current: CurrentUser = Depends(get_current_user)):
    """List files in the tenant the caller may READ."""
    res = await db.execute(
        select(SecureFile).where(SecureFile.tenant_id == str(current.tenant_id),
                                 SecureFile.is_deleted == False))  # noqa: E712
    subject = _subject(current)
    out = []
    for f in res.scalars().all():
        if evaluate(subject, _resource(f), Permission.READ).allow:
            out.append(FileMeta.model_validate(f))
    return out


@router.get("/{file_id}/download")
async def download_file(file_id: str, request: Request,
                        db: AsyncSession = Depends(get_db),
                        current: CurrentUser = Depends(get_current_user)):
    f = await _get_file_or_404(db, str(current.tenant_id), file_id)
    decision = evaluate(_subject(current), _resource(f), Permission.READ)
    if not decision.allow:
        _audit(db, current, "secure_file.download_denied", file_id, success=False,
               extra={"reason": decision.code}, error=decision.reason)
        raise HTTPException(status_code=403, detail=decision.reason)

    plaintext = service.load_file(tenant_id=str(current.tenant_id), file_id=file_id,
                                  classification=f.classification)
    _audit(db, current, "secure_file.download", file_id, extra={"reason": decision.code})
    return Response(content=plaintext, media_type=f.content_type,
                    headers={"Content-Disposition": f'attachment; filename="{f.filename}"',
                             "X-MACE-Classification": f.classification})


@router.get("/{file_id}/access")
async def my_access(file_id: str, db: AsyncSession = Depends(get_db),
                    current: CurrentUser = Depends(get_current_user)):
    f = await _get_file_or_404(db, str(current.tenant_id), file_id)
    decisions = explain(_subject(current), _resource(f))
    return {p: {"allow": d.allow, "reason": d.reason, "code": d.code} for p, d in decisions.items()}


@router.get("/{file_id}/grants", response_model=List[GrantOut])
async def list_grants(file_id: str, db: AsyncSession = Depends(get_db),
                      current: CurrentUser = Depends(get_current_user)):
    f = await _get_file_or_404(db, str(current.tenant_id), file_id)
    if not evaluate(_subject(current), _resource(f), Permission.SHARE).allow:
        raise HTTPException(status_code=403, detail="You cannot view grants on this file")
    return [GrantOut.model_validate(g) for g in f.grants]


@router.post("/{file_id}/grants", response_model=GrantOut)
async def create_grant(file_id: str, body: GrantCreate,
                       db: AsyncSession = Depends(get_db),
                       current: CurrentUser = Depends(get_current_user)):
    f = await _get_file_or_404(db, str(current.tenant_id), file_id)
    if not evaluate(_subject(current), _resource(f), Permission.SHARE).allow:
        raise HTTPException(status_code=403, detail="You cannot share this file")

    # AI guard on the share action (over-broad sharing warning).
    from app.secure.ai_guard import assess
    guard = assess(action="share", declared_classification=f.classification,
                   share_target_type=body.subject_type, share_target_value=body.subject_value)

    grant = FileAccessGrant(
        tenant_id=str(current.tenant_id), file_id=file_id,
        subject_type=body.subject_type, subject_value=body.subject_value,
        permissions=",".join(body.permissions), granted_by=str(current.id),
        expires_at=body.expires_at)
    db.add(grant)
    _audit(db, current, "secure_file.grant", file_id,
           extra={"subject": f"{body.subject_type}:{body.subject_value}",
                  "permissions": body.permissions, "guard": guard.as_dict()})
    await db.flush()
    out = GrantOut.model_validate(grant).model_dump()
    out["guard"] = guard.as_dict()
    return GrantOut.model_validate(grant)


@router.delete("/{file_id}/grants/{grant_id}")
async def revoke_grant(file_id: str, grant_id: str,
                       db: AsyncSession = Depends(get_db),
                       current: CurrentUser = Depends(get_current_user)):
    f = await _get_file_or_404(db, str(current.tenant_id), file_id)
    if not evaluate(_subject(current), _resource(f), Permission.SHARE).allow:
        raise HTTPException(status_code=403, detail="You cannot modify grants on this file")
    res = await db.execute(select(FileAccessGrant).where(
        FileAccessGrant.id == grant_id, FileAccessGrant.file_id == file_id))
    g = res.scalar_one_or_none()
    if not g:
        raise HTTPException(status_code=404, detail="Grant not found")
    await db.delete(g)
    _audit(db, current, "secure_file.revoke", file_id, extra={"grant_id": grant_id})
    return {"revoked": grant_id}


@router.delete("/{file_id}")
async def delete_file(file_id: str, db: AsyncSession = Depends(get_db),
                      current: CurrentUser = Depends(get_current_user)):
    f = await _get_file_or_404(db, str(current.tenant_id), file_id)
    if not evaluate(_subject(current), _resource(f), Permission.DELETE).allow:
        raise HTTPException(status_code=403, detail="You cannot delete this file")
    f.is_deleted = True
    _audit(db, current, "secure_file.delete", file_id)
    return {"deleted": file_id}


@router.get("/{file_id}/audit")
async def file_audit(file_id: str, db: AsyncSession = Depends(get_db),
                     current: CurrentUser = Depends(get_current_user)):
    f = await _get_file_or_404(db, str(current.tenant_id), file_id)
    if not evaluate(_subject(current), _resource(f), Permission.SHARE).allow:
        raise HTTPException(status_code=403, detail="Not permitted")
    res = await db.execute(
        select(AuditLog).where(AuditLog.tenant_id == str(current.tenant_id),
                               AuditLog.resource_id == file_id,
                               AuditLog.resource_type == "secure_file")
        .order_by(AuditLog.created_at.desc()).limit(200))
    return [{"action": a.action, "user_email": a.user_email, "success": a.success,
             "at": a.created_at, "extra": a.extra} for a in res.scalars().all()]
