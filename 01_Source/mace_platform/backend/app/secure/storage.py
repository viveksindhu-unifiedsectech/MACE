"""
Object storage backends for encrypted MACE Secure Files.

  S3Storage    — production. Puts ciphertext to S3 with SSE-KMS as a second,
                 independent layer (defence in depth: our envelope encryption +
                 AWS server-side encryption). Keys are namespaced by tenant.
  LocalStorage — dev / demo / CI. Writes under a local directory, same tenant
                 namespacing so behaviour matches prod.

Only the already-encrypted container blob is ever handed to a backend — storage
never sees plaintext. boto3 is imported lazily.
"""
from __future__ import annotations

import os
import shutil
from pathlib import Path
from typing import Optional, Protocol

from app.core.config import settings


class StorageError(RuntimeError):
    pass


def _key(tenant_id: str, file_id: str) -> str:
    # tenant-namespaced; also the S3 object key
    return f"tenants/{tenant_id}/secure-files/{file_id}.macef"


class Storage(Protocol):
    kind: str

    def put(self, tenant_id: str, file_id: str, blob: bytes) -> str: ...
    def get(self, tenant_id: str, file_id: str) -> bytes: ...
    def delete(self, tenant_id: str, file_id: str) -> None: ...


class LocalStorage:
    kind = "local"

    def __init__(self, root: Optional[str] = None):
        self.root = Path(root or os.environ.get("MACE_FILE_STORE", "/tmp/mace-secure-files"))
        self.root.mkdir(parents=True, exist_ok=True)

    def _path(self, tenant_id: str, file_id: str) -> Path:
        p = self.root / _key(tenant_id, file_id)
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def put(self, tenant_id: str, file_id: str, blob: bytes) -> str:
        p = self._path(tenant_id, file_id)
        tmp = p.with_suffix(".tmp")
        tmp.write_bytes(blob)
        os.replace(tmp, p)  # atomic
        return str(p)

    def get(self, tenant_id: str, file_id: str) -> bytes:
        p = self._path(tenant_id, file_id)
        if not p.exists():
            raise StorageError(f"object not found: {p}")
        return p.read_bytes()

    def delete(self, tenant_id: str, file_id: str) -> None:
        p = self._path(tenant_id, file_id)
        if p.exists():
            p.unlink()


class S3Storage:
    kind = "s3"

    def __init__(self, bucket: Optional[str] = None, region: Optional[str] = None,
                 kms_key_id: Optional[str] = None):
        self.bucket = bucket or settings.S3_BUCKET
        self.region = region or settings.S3_REGION
        self.kms_key_id = kms_key_id or getattr(settings, "MACE_KMS_KEY_ID", None)
        if not self.bucket:
            raise StorageError("S3_BUCKET must be set for S3 storage")
        self._client = None

    def _s3(self):
        if self._client is None:
            try:
                import boto3
            except ImportError as e:
                raise StorageError("boto3 required for S3 storage (pip install boto3)") from e
            self._client = boto3.client("s3", region_name=self.region)
        return self._client

    def put(self, tenant_id: str, file_id: str, blob: bytes) -> str:
        key = _key(tenant_id, file_id)
        extra = {}
        if self.kms_key_id:
            extra = {"ServerSideEncryption": "aws:kms", "SSEKMSKeyId": self.kms_key_id}
        else:
            extra = {"ServerSideEncryption": "AES256"}
        self._s3().put_object(Bucket=self.bucket, Key=key, Body=blob, **extra)
        return f"s3://{self.bucket}/{key}"

    def get(self, tenant_id: str, file_id: str) -> bytes:
        key = _key(tenant_id, file_id)
        try:
            resp = self._s3().get_object(Bucket=self.bucket, Key=key)
            return resp["Body"].read()
        except Exception as e:
            raise StorageError(f"S3 get failed for {key}: {e}") from e

    def delete(self, tenant_id: str, file_id: str) -> None:
        self._s3().delete_object(Bucket=self.bucket, Key=_key(tenant_id, file_id))


def get_storage() -> Storage:
    """S3 in prod when a bucket is configured; local otherwise."""
    if getattr(settings, "S3_BUCKET", None) and settings.ENVIRONMENT not in ("test",):
        return S3Storage()
    return LocalStorage()
