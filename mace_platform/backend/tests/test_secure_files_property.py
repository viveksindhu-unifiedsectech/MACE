"""
Property-based + exhaustive-matrix tests for MACE Secure Files.

Two techniques multiply the base scenarios into thousands of checked assertions:

  1. EXHAUSTIVE MATRIX — the access-control decision is verified across the full
     Cartesian product of role × classification × permission × tenant × grant ×
     clearance-override. Each case is checked against an INDEPENDENT reference
     oracle (re-derived from the spec, not calling the engine), so a bug in the
     engine cannot hide behind a bug in the test. This yields 2,000+ cases.

  2. PROPERTY-BASED (Hypothesis) — invariants over the crypto and redaction that
     must hold for *all* inputs: decrypt(encrypt(x)) == x, ciphertext never
     contains the plaintext, any single-byte tamper is detected, wrong-tenant
     context fails closed, and redaction never leaves a detected secret behind.

Runs offline with only `cryptography` + `hypothesis`.
"""
import os
import sys
from itertools import product
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))
os.environ.setdefault("ENVIRONMENT", "test")
os.environ.setdefault(
    "SECRET_KEY", "test-secret-key-for-secure-files-property-suite-32-bytes-plus-ok")

import pytest
from hypothesis import given, settings, strategies as st, HealthCheck

from app.secure import crypto, redaction
from app.secure.keys import LocalKeyProvider
from app.secure.access import (
    Classification, Permission, Subject, Resource, Grant, evaluate,
    ROLE_CLEARANCE, ROLE_PERMISSIONS,
)

PROV = LocalKeyProvider()
_ORDER = {Classification.PUBLIC: 0, Classification.INTERNAL: 1,
          Classification.CONFIDENTIAL: 2, Classification.RESTRICTED: 3}


# ══════════════════════ 1. EXHAUSTIVE ACCESS-CONTROL MATRIX ══════════════════
ROLES = ["super_admin", "tenant_admin", "soc_analyst", "read_only", "api_user"]
CLASSES = list(Classification)
PERMS = list(Permission)
TENANT_SAME = [True, False]
# grant kinds: none | a user grant for the perm | a role grant for the perm | expired user grant
GRANTS = ["none", "user", "role", "expired_user"]
CLEARANCE_OVERRIDES = [None] + list(Classification)   # None + 4 levels = 5

_MATRIX = list(product(ROLES, CLASSES, PERMS, TENANT_SAME, GRANTS, CLEARANCE_OVERRIDES))


def _oracle(role, cls, perm, tenant_same, grant, clearance_override) -> bool:
    """Independent re-derivation of the access spec (does NOT call the engine)."""
    # 1. tenant isolation is absolute
    if not tenant_same:
        return False
    # 2. ownership: subject is deliberately NOT the owner in this matrix -> skip
    # 3. active user grant for this permission -> allow (bypasses classification)
    if grant == "user":
        return True
    # 3b. active role grant contributes permission (still subject to classification)
    role_granted = (grant == "role")
    # 4. role default permissions
    has_permission = role_granted or (perm in ROLE_PERMISSIONS.get(role, set()))
    if not has_permission:
        return False
    # 5. classification gate on READ/WRITE
    if perm in (Permission.READ, Permission.WRITE):
        eff = clearance_override or ROLE_CLEARANCE[role]
        if _ORDER[eff] < _ORDER[cls]:
            return False
    return True


@pytest.mark.parametrize("role,cls,perm,tenant_same,grant,clearance", _MATRIX)
def test_access_matrix_matches_oracle(role, cls, perm, tenant_same, grant, clearance):
    subj = Subject(id="subject", tenant_id="T1", role=role, clearance=clearance)
    grants = []
    if grant == "user":
        grants = [Grant("user", "subject", {perm})]
    elif grant == "role":
        grants = [Grant("role", role, {perm})]
    elif grant == "expired_user":
        from datetime import datetime, timedelta
        grants = [Grant("user", "subject", {perm},
                        expires_at=datetime.utcnow() - timedelta(days=1))]
    res = Resource(id="f", tenant_id=("T1" if tenant_same else "T2"),
                   owner_id="someone_else", classification=cls, grants=grants)
    decision = evaluate(subj, res, perm)
    assert bool(decision) == _oracle(role, cls, perm, tenant_same, grant, clearance), (
        f"role={role} cls={cls.value} perm={perm.value} same={tenant_same} "
        f"grant={grant} clr={clearance} -> engine={decision.code}")


def test_matrix_is_large_enough():
    # Guard: prove the matrix really is in the thousands, not silently shrunk.
    assert len(_MATRIX) >= 2000, len(_MATRIX)


# ══════════════════════ 2. CRYPTO — EXHAUSTIVE SIZE/CHUNK GRID ═══════════════
_SIZES = [0, 1, 15, 16, 17, 31, 63, 64, 65, 255, 1000, 4096, 65537]
_CHUNKS = [16, 64, 1000, 1 << 20]


@pytest.mark.parametrize("size", _SIZES)
@pytest.mark.parametrize("chunk", _CHUNKS)
def test_crypto_roundtrip_grid(size, chunk):
    payload = bytes((i * 7 + 3) & 0xFF for i in range(size))
    ctx = {"tenant_id": "t", "file_id": f"f{size}-{chunk}"}
    blob = crypto.encrypt_bytes(payload, context=ctx, chunk_size=chunk, provider=PROV).blob
    assert crypto.decrypt_bytes(blob, context=ctx, provider=PROV) == payload


# ══════════════════════ 3. PROPERTY-BASED (Hypothesis) ══════════════════════
_HSET = settings(max_examples=150, deadline=None,
                 suppress_health_check=[HealthCheck.function_scoped_fixture])


@_HSET
@given(payload=st.binary(min_size=0, max_size=4096))
def test_prop_roundtrip(payload):
    ctx = {"tenant_id": "t1", "file_id": "f1"}
    blob = crypto.encrypt_bytes(payload, context=ctx, provider=PROV).blob
    assert crypto.decrypt_bytes(blob, context=ctx, provider=PROV) == payload


@_HSET
@given(payload=st.binary(min_size=32, max_size=4096))
def test_prop_plaintext_never_in_ciphertext(payload):
    # min_size=32: shorter, low-entropy buffers can coincidentally match the
    # container's zero-filled length framing; a 32-byte buffer cannot, so this
    # cleanly asserts the plaintext itself is never emitted in the ciphertext.
    ctx = {"tenant_id": "t1", "file_id": "f1"}
    blob = crypto.encrypt_bytes(payload, context=ctx, provider=PROV).blob
    assert payload not in blob


@_HSET
@given(payload=st.binary(min_size=1, max_size=2048),
       a=st.text(min_size=1, max_size=8, alphabet="ABCD"),
       b=st.text(min_size=1, max_size=8, alphabet="WXYZ"))
def test_prop_wrong_tenant_fails_closed(payload, a, b):
    blob = crypto.encrypt_bytes(payload, context={"tenant_id": a, "file_id": "f"},
                                provider=PROV).blob
    with pytest.raises(crypto.FileCryptoError):
        crypto.decrypt_bytes(blob, context={"tenant_id": b + "x", "file_id": "f"}, provider=PROV)


@_HSET
@given(payload=st.binary(min_size=1, max_size=1024), pos=st.integers(min_value=0, max_value=10000))
def test_prop_single_byte_tamper_detected(payload, pos):
    ctx = {"tenant_id": "t", "file_id": "f"}
    blob = bytearray(crypto.encrypt_bytes(payload, context=ctx, provider=PROV).blob)
    # tamper somewhere in the ciphertext body (after the header region)
    idx = 12 + (pos % max(1, len(blob) - 12))
    if idx >= len(blob):
        return
    blob[idx] ^= 0x01
    with pytest.raises(crypto.FileCryptoError):
        crypto.decrypt_bytes(bytes(blob), context=ctx, provider=PROV)


@_HSET
@given(noise=st.text(alphabet=st.characters(blacklist_categories=("Cs",)), max_size=200))
def test_prop_redaction_leaves_no_detected_ssn(noise):
    text = f"{noise} 123-45-6789 {noise}"
    out = redaction.redact_text(text, {"SSN"})
    assert "123-45-6789" not in out
    # and a re-scan finds nothing left
    assert redaction.scan_text(out, {"SSN"}).counts.get("SSN", 0) == 0
