"""Tests for the connector-credential encryption module."""
import os
import sys
from pathlib import Path

# Backend root on sys.path
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

# Set SECRET_KEY before importing settings (must satisfy validator)
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "SECRET_KEY",
    "test-key-for-encryption-tests-this-is-at-least-32-bytes-of-text-okay-yes",
)

import pytest

from app.core.encryption import (
    EncryptionError,
    decrypt_credential,
    encrypt_credential,
)


def test_roundtrip_preserves_value():
    secret = "very-confidential-api-token-xyz"
    ct = encrypt_credential(secret)
    assert ct != secret
    pt = decrypt_credential(ct)
    assert pt == secret


def test_empty_input_passes_through():
    assert encrypt_credential("") == ""
    assert encrypt_credential(None) is None
    assert decrypt_credential("") == ""
    assert decrypt_credential(None) is None


def test_ciphertext_is_nondeterministic():
    a = encrypt_credential("payload")
    b = encrypt_credential("payload")
    # Different nonces produce different ciphertexts
    assert a != b
    assert decrypt_credential(a) == decrypt_credential(b) == "payload"


def test_legacy_plaintext_round_trips_through_decrypt():
    # Pre-encryption rows are returned as-is by decrypt_credential.
    raw = "legacy-plain-token"
    assert decrypt_credential(raw) == raw


def test_tampered_ciphertext_raises():
    ct = encrypt_credential("secret")
    # Flip one ciphertext byte after the nonce
    import base64
    raw = bytearray(base64.b64decode(ct))
    raw[15] ^= 0x01
    bad = base64.b64encode(bytes(raw)).decode("ascii")
    with pytest.raises(EncryptionError):
        decrypt_credential(bad)
