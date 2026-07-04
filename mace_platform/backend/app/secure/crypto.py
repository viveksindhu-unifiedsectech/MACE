"""
Chunked authenticated file encryption for MACE Secure Files.

Any file type, binary-safe. AES-256-GCM in independent chunks so large files can
be streamed without holding the whole plaintext in memory, while every chunk is
individually authenticated and bound to its position (no reorder / truncation /
splice attacks).

Container layout (the .macef blob written to storage):

    MAGIC (8)  b"MACEF\x01\x00\x00"
    HLEN  (4)  big-endian length of the header JSON
    HDR   (HLEN) UTF-8 JSON:
        { v, alg, chunk_size, chunks, wrapped_dek(b64), context,
          plaintext_sha256, plaintext_size, filename, content_type }
    then `chunks` records, each:
        NONCE (12) || GCM_CIPHERTEXT(+16 tag)
      AAD for chunk i = sha256(HDR) || uint32(i) || (0x01 if last else 0x00)

The DEK is wrapped by the key provider (KMS or local) and stored ONLY in the
header, never in the clear. Decryption re-derives the chunk AAD from the header,
so any edit to the header (e.g. swapping the wrapped DEK or classification)
breaks authentication.
"""
from __future__ import annotations

import base64
import hashlib
import json
import os
import struct
from dataclasses import dataclass
from typing import BinaryIO, Dict, Optional

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from app.secure.keys import KeyProvider, get_key_provider, new_dek

MAGIC = b"MACEF\x01\x00\x00"
DEFAULT_CHUNK = 1024 * 1024          # 1 MiB
_NONCE = 12
ALG = "AES-256-GCM/chunked"


class FileCryptoError(RuntimeError):
    """Raised on any encryption/decryption integrity failure."""


@dataclass
class EncryptResult:
    blob: bytes
    plaintext_sha256: str
    plaintext_size: int
    chunks: int
    wrapped_dek_b64: str


def _chunk_aad(header_digest: bytes, index: int, last: bool) -> bytes:
    return header_digest + struct.pack(">I", index) + (b"\x01" if last else b"\x00")


def encrypt_bytes(
    plaintext: bytes,
    *,
    context: Optional[Dict[str, str]] = None,
    filename: str = "",
    content_type: str = "application/octet-stream",
    chunk_size: int = DEFAULT_CHUNK,
    provider: Optional[KeyProvider] = None,
) -> EncryptResult:
    """Encrypt an in-memory buffer of any type. Returns the container blob."""
    provider = provider or get_key_provider()
    dek = new_dek()
    wrapped = provider.wrap_dek(dek, context)

    n = len(plaintext)
    n_chunks = max(1, (n + chunk_size - 1) // chunk_size)
    header = {
        "v": 1,
        "alg": ALG,
        "chunk_size": chunk_size,
        "chunks": n_chunks,
        "wrapped_dek": base64.b64encode(wrapped).decode("ascii"),
        "context": context or {},
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "plaintext_size": n,
        "filename": filename,
        "content_type": content_type,
    }
    hdr_bytes = json.dumps(header, sort_keys=True, separators=(",", ":")).encode("utf-8")
    hdr_digest = hashlib.sha256(hdr_bytes).digest()

    aead = AESGCM(dek)
    out = bytearray()
    out += MAGIC
    out += struct.pack(">I", len(hdr_bytes))
    out += hdr_bytes
    for i in range(n_chunks):
        piece = plaintext[i * chunk_size : (i + 1) * chunk_size]
        nonce = os.urandom(_NONCE)
        ct = aead.encrypt(nonce, piece, _chunk_aad(hdr_digest, i, i == n_chunks - 1))
        out += nonce + struct.pack(">I", len(ct)) + ct

    return EncryptResult(
        blob=bytes(out),
        plaintext_sha256=header["plaintext_sha256"],
        plaintext_size=n,
        chunks=n_chunks,
        wrapped_dek_b64=header["wrapped_dek"],
    )


def decrypt_bytes(
    blob: bytes,
    *,
    context: Optional[Dict[str, str]] = None,
    provider: Optional[KeyProvider] = None,
) -> bytes:
    """Decrypt a container blob produced by encrypt_bytes. Verifies integrity."""
    provider = provider or get_key_provider()
    mv = memoryview(blob)
    if bytes(mv[:8]) != MAGIC:
        raise FileCryptoError("bad magic — not a MACE secure-file container")
    (hlen,) = struct.unpack(">I", mv[8:12])
    hdr_bytes = bytes(mv[12 : 12 + hlen])
    try:
        header = json.loads(hdr_bytes)
    except Exception as e:
        raise FileCryptoError("corrupt header") from e
    # Fail closed on any malformed/tampered header: it must be an object with
    # the required fields of the expected types.
    if not isinstance(header, dict) or not {"wrapped_dek", "chunks"} <= header.keys():
        raise FileCryptoError("header missing required fields — tampered or not a MACE container")
    try:
        n_chunks = int(header["chunks"])
        wrapped_b64 = header["wrapped_dek"]
    except (ValueError, TypeError) as e:
        raise FileCryptoError("header field has wrong type — tampered") from e
    if n_chunks < 0:
        raise FileCryptoError("invalid chunk count in header")
    hdr_digest = hashlib.sha256(hdr_bytes).digest()

    # The caller-supplied context must match what the file was sealed with; the
    # unwrap itself is context-bound so a mismatch fails closed.
    ctx = context if context is not None else header.get("context") or {}
    try:
        wrapped = base64.b64decode(wrapped_b64)
        dek = provider.unwrap_dek(wrapped, ctx)
    except Exception as e:
        raise FileCryptoError(f"cannot unwrap DEK: {e}") from e

    aead = AESGCM(dek)
    total = len(mv)
    pos = 12 + hlen
    out = bytearray()
    for i in range(n_chunks):
        try:
            # Bounds-check every field: the length prefix is NOT authenticated,
            # so an inflated length must be rejected outright rather than being
            # silently clamped by slicing (which would let a tamper decrypt).
            if pos + _NONCE + 4 > total:
                raise FileCryptoError(f"chunk {i} truncated header")
            nonce = bytes(mv[pos : pos + _NONCE]); pos += _NONCE
            (clen,) = struct.unpack(">I", mv[pos : pos + 4]); pos += 4
            if clen < 16 or pos + clen > total:      # GCM tag is 16 bytes minimum
                raise FileCryptoError(f"chunk {i} length {clen} out of bounds — tampered")
            ct = bytes(mv[pos : pos + clen]); pos += clen
            piece = aead.decrypt(nonce, ct, _chunk_aad(hdr_digest, i, i == n_chunks - 1))
        except FileCryptoError:
            raise
        except Exception as e:
            raise FileCryptoError(
                f"chunk {i} authentication failed — tampered, truncated, or reordered."
            ) from e
        out += piece

    # Every byte must be accounted for — trailing/appended bytes are tampering.
    if pos != total:
        raise FileCryptoError("trailing bytes after final chunk — tampered")

    if hashlib.sha256(out).hexdigest() != header.get("plaintext_sha256"):
        raise FileCryptoError("plaintext checksum mismatch after decryption")
    return bytes(out)


def read_header(blob: bytes) -> Dict:
    """Return the (public, unauthenticated) header without decrypting content."""
    mv = memoryview(blob)
    if bytes(mv[:8]) != MAGIC:
        raise FileCryptoError("bad magic")
    (hlen,) = struct.unpack(">I", mv[8:12])
    return json.loads(bytes(mv[12 : 12 + hlen]))
