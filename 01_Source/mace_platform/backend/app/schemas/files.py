"""Pydantic schemas for the Secure Files API."""
from datetime import datetime
from typing import List, Optional, Dict
from pydantic import BaseModel, Field


class FileMeta(BaseModel):
    id: str
    filename: str
    content_type: str
    classification: str
    owner_id: str
    sha256: str
    size_bytes: int
    redacted: bool
    created_at: datetime

    class Config:
        from_attributes = True


class FileUploadResult(BaseModel):
    file: FileMeta
    guard: Dict
    redaction_report: Dict


class GrantCreate(BaseModel):
    subject_type: str = Field(..., pattern="^(user|role)$")
    subject_value: str
    permissions: List[str] = Field(default_factory=lambda: ["read"])
    expires_at: Optional[datetime] = None


class GrantOut(BaseModel):
    id: str
    subject_type: str
    subject_value: str
    permissions: str
    expires_at: Optional[datetime]
    created_at: datetime

    class Config:
        from_attributes = True


class ConflictFinding(BaseModel):
    kind: str
    severity: str
    entity_type: str
    token: str
    matters: List[str]
    detail: str
