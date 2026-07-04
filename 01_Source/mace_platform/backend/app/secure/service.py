"""
Secure Files orchestrator — one call runs the whole safe-ingest pipeline:

    AI guard  ->  (optional) redact  ->  envelope-encrypt  ->  object storage

and the reverse for retrieval (fetch -> decrypt -> integrity-verify). DB-free:
the API layer persists the returned metadata and enforces access.evaluate()
before calling load_file(). This module is what the CLI demo and the FastAPI
endpoint both call, so the security pipeline is identical in every entry point.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from typing import Dict, Optional, Set

from app.core.config import settings
from app.secure import crypto, redaction, storage as storage_mod
from app.secure.ai_guard import GuardResult, Verdict, assess
from app.secure.access import Classification
from app.secure.keys import KeyProvider, get_key_provider


def build_context(tenant_id: str, file_id: str, classification: str) -> Dict[str, str]:
    """Encryption context — cryptographically binds ciphertext to tenant+file."""
    return {"tenant_id": tenant_id, "file_id": file_id, "classification": str(classification)}


@dataclass
class StoredFile:
    file_id: str
    tenant_id: str
    owner_id: str
    filename: str
    content_type: str
    classification: str
    storage_uri: str
    sha256: str
    size: int
    chunks: int
    wrapped_dek_b64: str
    redacted: bool
    redaction_report: Dict = field(default_factory=dict)
    guard: Dict = field(default_factory=dict)

    def as_dict(self) -> Dict:
        d = self.__dict__.copy()
        return d


class GuardBlocked(RuntimeError):
    def __init__(self, result: GuardResult):
        self.result = result
        super().__init__("AI guard blocked this upload")


def store_file(
    *,
    content: bytes,
    tenant_id: str,
    owner_id: str,
    filename: str = "",
    content_type: str = "application/octet-stream",
    classification: str = Classification.INTERNAL.value,
    redact: bool = False,
    redaction_categories: Optional[Set[str]] = None,
    enforce_guard: bool = True,
    storage=None,
    provider: Optional[KeyProvider] = None,
    anthropic_api_key: Optional[str] = None,
) -> StoredFile:
    """Run guard -> redact -> encrypt -> store. Returns metadata to persist."""
    file_id = str(uuid.uuid4())
    storage = storage or storage_mod.get_storage()
    provider = provider or get_key_provider()

    # 1. AI guard (pre-action). May block a critical, non-redacted upload.
    guard = assess(
        action="upload", content=content, filename=filename,
        declared_classification=classification, will_redact=redact,
        anthropic_api_key=anthropic_api_key
        or getattr(settings, "ANTHROPIC_API_KEY", None),
    )
    if enforce_guard and guard.verdict == Verdict.BLOCK:
        raise GuardBlocked(guard)

    # 2. Optional redaction (before encryption, so plaintext secrets never persist).
    redacted = False
    report: Dict = {}
    payload = content
    if redact:
        payload, rep, was_text = redaction.redact_bytes(content, redaction_categories)
        redacted = was_text and rep.total > 0
        report = rep.as_dict()

    # 3. Envelope-encrypt.
    ctx = build_context(tenant_id, file_id, classification)
    enc = crypto.encrypt_bytes(
        payload, context=ctx, filename=filename,
        content_type=content_type, provider=provider,
    )

    # 4. Store ciphertext only.
    uri = storage.put(tenant_id, file_id, enc.blob)

    return StoredFile(
        file_id=file_id, tenant_id=tenant_id, owner_id=owner_id,
        filename=filename, content_type=content_type, classification=str(classification),
        storage_uri=uri, sha256=enc.plaintext_sha256, size=enc.plaintext_size,
        chunks=enc.chunks, wrapped_dek_b64=enc.wrapped_dek_b64,
        redacted=redacted, redaction_report=report, guard=guard.as_dict(),
    )


def load_file(
    *,
    tenant_id: str,
    file_id: str,
    classification: str,
    storage=None,
    provider: Optional[KeyProvider] = None,
) -> bytes:
    """Fetch + decrypt + integrity-verify. Access MUST be checked by the caller."""
    storage = storage or storage_mod.get_storage()
    provider = provider or get_key_provider()
    blob = storage.get(tenant_id, file_id)
    ctx = build_context(tenant_id, file_id, classification)
    return crypto.decrypt_bytes(blob, context=ctx, provider=provider)
