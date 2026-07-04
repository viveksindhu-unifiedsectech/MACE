"""
MACE Secure Files — universal encryption, access control, redaction, AI safeguard,
and cross-matter conflict detection.

Patent: IN/2026/UNISEC/MACE-001 + PCT  (file-security claims 31-40, see
03_Documents/MACE_Patent_Addendum_SecureFiles.docx)

This package turns MACE into a one-stop cybersecurity platform for data at rest:

  keys.py         Envelope key management (AWS KMS in prod, HKDF-local for dev/demo)
  crypto.py       AES-256-GCM chunked file encryption (any file type, binary-safe)
  storage.py      Object storage backend (S3 + SSE-KMS in prod, local FS for demo)
  access.py       RBAC + ABAC + data-classification + hard tenant isolation
  redaction.py    PII / secret detection + redaction before storage or sharing
  ai_guard.py     Pre-action AI safeguard — warns of the threat BEFORE it happens
  correlation.py  Privacy-preserving cross-matter conflict / privilege-leak detection
  service.py      Orchestrator wiring guard -> redact -> encrypt -> store -> audit

Everything degrades gracefully to a local, offline mode so the full pipeline runs
on a laptop for demos with no AWS account and no network.
"""

__all__ = [
    "keys",
    "crypto",
    "storage",
    "access",
    "redaction",
    "ai_guard",
    "correlation",
    "service",
]

FILE_SECURITY_VERSION = "1.0.0"
