"""
Envelope key management for MACE Secure Files.

Design — envelope encryption:
  * Every file gets its own random 256-bit Data Encryption Key (DEK).
  * The DEK is *wrapped* (encrypted) by a master key that never touches disk in
    plaintext. Only the wrapped DEK is stored alongside the ciphertext.
  * The wrap operation binds an EncryptionContext (tenant_id, file_id,
    classification). In AWS KMS this context is cryptographically authenticated —
    a wrapped DEK for tenant A physically cannot be unwrapped in tenant B's
    context. This is *cryptographic* tenant isolation, not just a WHERE clause.

Two providers, selected automatically:
  * KmsKeyProvider   — production. Uses AWS KMS GenerateDataKey-style wrapping.
                       boto3 is imported lazily so dev/test never needs it.
  * LocalKeyProvider — dev / demo / CI. Derives a wrapping key from SECRET_KEY
                       via HKDF-SHA256 and wraps with AES-256-GCM, using the
                       encryption context as AEAD associated data (same binding
                       property, just not backed by an HSM).

Choose with settings.MACE_KMS_ENABLED / MACE_KMS_KEY_ID, or override in code.
"""
from __future__ import annotations

import json
import os
from functools import lru_cache
from typing import Dict, Optional, Protocol

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

DEK_BYTES = 32          # AES-256
_WRAP_NONCE = 12        # GCM nonce
HKDF_SALT = b"mace-secure-files-master-v1"
HKDF_INFO = b"secure-file-dek-wrapping"


class KeyProviderError(RuntimeError):
    """Raised when key wrap/unwrap fails for a non-recoverable reason."""


def new_dek() -> bytes:
    """Return a fresh random 256-bit data encryption key."""
    return os.urandom(DEK_BYTES)


def _context_bytes(context: Optional[Dict[str, str]]) -> bytes:
    """Canonical, deterministic serialization of the encryption context (AAD)."""
    if not context:
        return b""
    return json.dumps(context, sort_keys=True, separators=(",", ":")).encode("utf-8")


class KeyProvider(Protocol):
    kind: str

    def wrap_dek(self, dek: bytes, context: Optional[Dict[str, str]] = None) -> bytes: ...
    def unwrap_dek(self, wrapped: bytes, context: Optional[Dict[str, str]] = None) -> bytes: ...


class LocalKeyProvider:
    """HKDF-derived master key + AES-256-GCM wrapping. Dev / demo / CI only."""

    kind = "local"

    def __init__(self, secret: Optional[str] = None):
        raw = (secret if secret is not None else settings.SECRET_KEY or "").encode("utf-8")
        if len(raw) < 32:
            raise KeyProviderError(
                "SECRET_KEY must be >= 32 bytes for the local key provider. "
                "Generate: python -c 'import secrets;print(secrets.token_urlsafe(64))'"
            )
        self._master = HKDF(
            algorithm=hashes.SHA256(), length=32, salt=HKDF_SALT, info=HKDF_INFO
        ).derive(raw)

    def wrap_dek(self, dek: bytes, context: Optional[Dict[str, str]] = None) -> bytes:
        nonce = os.urandom(_WRAP_NONCE)
        ct = AESGCM(self._master).encrypt(nonce, dek, _context_bytes(context))
        return nonce + ct

    def unwrap_dek(self, wrapped: bytes, context: Optional[Dict[str, str]] = None) -> bytes:
        if len(wrapped) < _WRAP_NONCE + 16:
            raise KeyProviderError("wrapped DEK too short / corrupt")
        try:
            return AESGCM(self._master).decrypt(
                wrapped[:_WRAP_NONCE], wrapped[_WRAP_NONCE:], _context_bytes(context)
            )
        except Exception as e:  # InvalidTag or otherwise
            raise KeyProviderError(
                "DEK unwrap failed — wrong tenant/context, tampered blob, or "
                "SECRET_KEY rotated without re-wrapping."
            ) from e


class KmsKeyProvider:
    """AWS KMS-backed wrapping. Production. boto3 imported lazily."""

    kind = "kms"

    def __init__(self, key_id: Optional[str] = None, region: Optional[str] = None):
        self.key_id = key_id or settings.MACE_KMS_KEY_ID
        self.region = region or settings.S3_REGION
        if not self.key_id:
            raise KeyProviderError("MACE_KMS_KEY_ID must be set to use the KMS key provider.")
        self._client = None

    def _kms(self):
        if self._client is None:
            try:
                import boto3  # lazy — prod only
            except ImportError as e:
                raise KeyProviderError(
                    "boto3 is required for the KMS key provider "
                    "(pip install boto3). Not needed for local/demo mode."
                ) from e
            self._client = boto3.client("kms", region_name=self.region)
        return self._client

    def wrap_dek(self, dek: bytes, context: Optional[Dict[str, str]] = None) -> bytes:
        try:
            resp = self._kms().encrypt(
                KeyId=self.key_id,
                Plaintext=dek,
                EncryptionContext=context or {},
            )
            return resp["CiphertextBlob"]
        except Exception as e:
            raise KeyProviderError(f"KMS wrap_dek failed: {e}") from e

    def unwrap_dek(self, wrapped: bytes, context: Optional[Dict[str, str]] = None) -> bytes:
        try:
            resp = self._kms().decrypt(
                CiphertextBlob=wrapped,
                EncryptionContext=context or {},
            )
            return resp["Plaintext"]
        except Exception as e:
            raise KeyProviderError(
                f"KMS unwrap_dek failed (wrong context / no permission / tampered): {e}"
            ) from e


@lru_cache(maxsize=1)
def get_key_provider() -> KeyProvider:
    """Return the configured key provider — KMS in prod, local otherwise."""
    if getattr(settings, "MACE_KMS_ENABLED", False) and getattr(settings, "MACE_KMS_KEY_ID", None):
        return KmsKeyProvider()
    return LocalKeyProvider()
