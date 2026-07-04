"""
Connector credential encryption — AES-256-GCM with HKDF-SHA256 key derivation.

The encryption key is derived from settings.SECRET_KEY using HKDF-SHA256.
Production path post-Series A: replace _get_key() with an AWS KMS call.

Security notes:
  - SECRET_KEY must be >= 32 bytes; we enforce 32+ chars in production.
  - Errors during encryption/decryption raise — never silently fall back
    to plaintext. Storing a credential as plaintext when the caller asked
    for ciphertext is a critical security regression.
  - Backwards compatibility: decrypt_credential treats a value as already-
    plaintext only when it fails to base64-decode (legacy rows from before
    this column was encrypted). Any value that *looks* like ciphertext but
    fails authenticated decryption raises EncryptionError.
"""
from __future__ import annotations

import base64
import logging
import os
from functools import lru_cache
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from app.core.config import settings

logger = logging.getLogger(__name__)

HKDF_SALT = b"mace-connector-creds-v1"
HKDF_INFO = b"connector-encryption"


class EncryptionError(RuntimeError):
    """Raised when encrypt/decrypt fails for a non-recoverable reason."""


@lru_cache(maxsize=1)
def _get_key() -> bytes:
    secret = (settings.SECRET_KEY or "").encode("utf-8")
    if len(secret) < 32:
        raise EncryptionError(
            "SECRET_KEY must be at least 32 bytes for connector credential "
            "encryption. Generate one with: python -c "
            "'import secrets; print(secrets.token_urlsafe(64))'"
        )
    return HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=HKDF_SALT,
        info=HKDF_INFO,
    ).derive(secret)


def encrypt_credential(plaintext: Optional[str]) -> Optional[str]:
    """Return AES-256-GCM ciphertext (base64). Empty/None passes through."""
    if not plaintext:
        return plaintext
    try:
        key = _get_key()
        nonce = os.urandom(12)
        ct = AESGCM(key).encrypt(nonce, plaintext.encode("utf-8"), None)
        return base64.b64encode(nonce + ct).decode("ascii")
    except EncryptionError:
        raise
    except Exception as e:  # noqa: BLE001 — re-raise as our own error class
        raise EncryptionError(f"encrypt_credential failed: {e}") from e


def decrypt_credential(ciphertext: Optional[str]) -> Optional[str]:
    """Return plaintext for the given AES-256-GCM ciphertext.

    Legacy rows that pre-date encryption are detected by their failure to
    base64-decode into a >= 13-byte payload (12-byte nonce + at least 1
    byte of GCM ciphertext). Those values are returned as-is.
    Any value that decodes but fails authenticated decryption raises.
    """
    if not ciphertext:
        return ciphertext
    try:
        raw = base64.b64decode(ciphertext.encode("ascii"), validate=True)
    except (ValueError, base64.binascii.Error):
        # Not base64 → legacy plaintext credential stored before encryption.
        logger.warning("decrypt_credential: non-base64 input, treating as legacy plaintext")
        return ciphertext
    if len(raw) < 13:
        logger.warning("decrypt_credential: too short for ciphertext, treating as legacy plaintext")
        return ciphertext
    try:
        key = _get_key()
        return AESGCM(key).decrypt(raw[:12], raw[12:], None).decode("utf-8")
    except InvalidTag as e:
        raise EncryptionError(
            "decrypt_credential: AES-GCM authentication tag mismatch — "
            "ciphertext was tampered with or SECRET_KEY rotated without re-encryption."
        ) from e
    except EncryptionError:
        raise
    except Exception as e:  # noqa: BLE001
        raise EncryptionError(f"decrypt_credential failed: {e}") from e
