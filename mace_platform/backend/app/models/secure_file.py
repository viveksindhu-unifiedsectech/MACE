"""
Secure file metadata + access grants.

The ciphertext lives in object storage (S3/local); the DB holds only metadata,
the wrapped-DEK reference, integrity hash, classification, and grants. No
plaintext and no unwrapped key is ever persisted here.
"""
import uuid
from datetime import datetime
from typing import Optional
from sqlalchemy import String, DateTime, Boolean, JSON, Integer, ForeignKey, Text
from sqlalchemy.orm import Mapped, mapped_column, relationship
from app.db.base import Base


class SecureFile(Base):
    __tablename__ = "secure_files"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    owner_id: Mapped[str] = mapped_column(String(36), nullable=False, index=True)

    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    content_type: Mapped[str] = mapped_column(String(255), default="application/octet-stream")
    classification: Mapped[str] = mapped_column(String(20), default="internal", index=True)

    storage_uri: Mapped[str] = mapped_column(String(1024), nullable=False)  # s3://... or file path
    wrapped_dek: Mapped[str] = mapped_column(Text, nullable=False)          # base64 wrapped data key
    sha256: Mapped[str] = mapped_column(String(64), nullable=False)         # plaintext integrity hash
    size_bytes: Mapped[int] = mapped_column(Integer, default=0)
    chunks: Mapped[int] = mapped_column(Integer, default=1)

    redacted: Mapped[bool] = mapped_column(Boolean, default=False)
    redaction_report: Mapped[dict] = mapped_column(JSON, default=dict)
    guard_report: Mapped[dict] = mapped_column(JSON, default=dict)

    is_deleted: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

    grants: Mapped[list["FileAccessGrant"]] = relationship(
        "FileAccessGrant", back_populates="file", lazy="selectin",
        cascade="all, delete-orphan")


class FileAccessGrant(Base):
    """Per-file grant to a named user OR to a role. Permissions are CSV of
    read/write/share/delete. A user grant may raise clearance for that file."""
    __tablename__ = "file_access_grants"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=lambda: str(uuid.uuid4()))
    tenant_id: Mapped[str] = mapped_column(String(36), ForeignKey("tenants.id"), nullable=False, index=True)
    file_id: Mapped[str] = mapped_column(String(36), ForeignKey("secure_files.id"), nullable=False, index=True)

    subject_type: Mapped[str] = mapped_column(String(10), nullable=False)   # "user" | "role"
    subject_value: Mapped[str] = mapped_column(String(255), nullable=False)  # user id | role name
    permissions: Mapped[str] = mapped_column(String(64), default="read")     # "read,write"

    granted_by: Mapped[Optional[str]] = mapped_column(String(36), nullable=True)
    expires_at: Mapped[Optional[datetime]] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=datetime.utcnow)

    file: Mapped["SecureFile"] = relationship("SecureFile", back_populates="grants")
