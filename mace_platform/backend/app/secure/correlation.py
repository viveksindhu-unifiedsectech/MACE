"""
Cross-matter correlation + conflict detection — MACE's differentiator.

No commodity DLP/encryption tool does this: it correlates *entities* across
documents and "matters" (a case, an engagement, a deal, an investigation) to
catch two things automatically:

  * CONFLICT_OF_INTEREST — the same person / org / account appears on opposing
    sides of an ethical wall (e.g. a shared contact across two walled matters).
  * PRIVILEGE_LEAK       — an entity that appeared in privileged material shows
    up in a non-privileged document.

Privacy-preserving by construction: the index stores only keyed HMAC-SHA256
tokens of normalized entities, never the raw values. The index that *finds* the
conflict therefore cannot itself leak client data — findings reference an
opaque token prefix, an entity type, and the matter ids, nothing sensitive.

The HMAC key is derived from SECRET_KEY per tenant, so tokens are not comparable
across tenants (reinforcing tenant isolation).
"""
from __future__ import annotations

import enum
import hashlib
import hmac
import re
from collections import defaultdict
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set, Tuple

from app.core.config import settings


class EntityType(str, enum.Enum):
    EMAIL = "email"
    SSN = "ssn"
    ACCOUNT = "account"       # bank / matter account numbers
    PHONE = "phone"
    ORG = "org"
    PERSON = "person"


# Strength drives conflict severity: unique identifiers are near-certain matches.
_STRENGTH = {
    EntityType.SSN: "high", EntityType.ACCOUNT: "high", EntityType.EMAIL: "high",
    EntityType.PHONE: "medium", EntityType.ORG: "medium", EntityType.PERSON: "medium",
}

_EXTRACTORS = {
    EntityType.EMAIL: re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
    EntityType.SSN: re.compile(r"\b\d{3}-\d{2}-\d{4}\b"),
    EntityType.ACCOUNT: re.compile(r"\b(?:ACCT|ACC|A/C)[-#\s]?\d{6,}\b", re.IGNORECASE),
    EntityType.PHONE: re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"),
}


def _normalize(value: str, etype: EntityType) -> str:
    v = value.strip().lower()
    if etype in (EntityType.SSN, EntityType.ACCOUNT, EntityType.PHONE):
        v = re.sub(r"[^0-9]", "", v)
    return v


@dataclass
class Matter:
    id: str
    label: str = ""
    wall_id: Optional[str] = None     # matters with different wall_id are walled apart
    party: str = ""                   # e.g. "client" / "adverse" / free text


@dataclass
class Finding:
    kind: str                 # CONFLICT_OF_INTEREST | PRIVILEGE_LEAK
    severity: str
    entity_type: str
    token: str                # opaque HMAC prefix — safe to log
    matters: List[str]
    detail: str

    def as_dict(self) -> Dict:
        return self.__dict__


@dataclass
class _Posting:
    matter_id: str
    doc_id: str
    privileged: bool


class CorrelationIndex:
    """Tenant-scoped, privacy-preserving entity index."""

    def __init__(self, tenant_id: str, hmac_key: Optional[bytes] = None):
        self.tenant_id = tenant_id
        base = (hmac_key or (settings.SECRET_KEY or "").encode("utf-8"))
        # Bind the key to the tenant so tokens never collide across tenants.
        self._key = hashlib.sha256(base + b"|corr|" + tenant_id.encode()).digest()
        self._matters: Dict[str, Matter] = {}
        # (entity_type, token) -> list of postings
        self._postings: Dict[Tuple[str, str], List[_Posting]] = defaultdict(list)

    def _token(self, value: str, etype: EntityType) -> str:
        norm = _normalize(value, etype)
        return hmac.new(self._key, f"{etype.value}:{norm}".encode(), hashlib.sha256).hexdigest()

    def register_matter(self, matter: Matter) -> None:
        self._matters[matter.id] = matter

    def add_entities(self, matter_id: str, doc_id: str, privileged: bool,
                     entities: List[Tuple[EntityType, str]]) -> None:
        for etype, value in entities:
            if not value:
                continue
            tok = self._token(value, etype)
            self._postings[(etype.value, tok)].append(
                _Posting(matter_id, doc_id, privileged))

    def add_document(self, matter_id: str, doc_id: str, privileged: bool, text: str,
                     extra_entities: Optional[List[Tuple[EntityType, str]]] = None) -> int:
        """Extract entities from text (+ any explicit ones) and index them."""
        found: List[Tuple[EntityType, str]] = list(extra_entities or [])
        for etype, pattern in _EXTRACTORS.items():
            for m in pattern.finditer(text):
                found.append((etype, m.group()))
        self.add_entities(matter_id, doc_id, privileged, found)
        return len(found)

    def find_conflicts(self) -> List[Finding]:
        findings: List[Finding] = []
        for (etype, tok), postings in self._postings.items():
            matter_ids = {p.matter_id for p in postings}

            # --- Conflict of interest: shared entity across walled matters ----
            if len(matter_ids) >= 2:
                walls = {self._matters.get(mid, Matter(mid)).wall_id for mid in matter_ids}
                # Walled apart if they carry different (non-None) wall ids, or any None mixed in.
                if len(walls) >= 2:
                    findings.append(Finding(
                        kind="CONFLICT_OF_INTEREST",
                        severity=_STRENGTH.get(EntityType(etype), "medium"),
                        entity_type=etype,
                        token=tok[:12],
                        matters=sorted(matter_ids),
                        detail=(f"Shared {etype} entity appears across walled matters "
                                f"{sorted(matter_ids)} — potential conflict of interest."),
                    ))

            # --- Privilege leak: entity in privileged + non-privileged docs ---
            has_priv = any(p.privileged for p in postings)
            has_nonpriv = any(not p.privileged for p in postings)
            if has_priv and has_nonpriv:
                findings.append(Finding(
                    kind="PRIVILEGE_LEAK",
                    severity="high",
                    entity_type=etype,
                    token=tok[:12],
                    matters=sorted(matter_ids),
                    detail=(f"A {etype} entity from privileged material also appears in "
                            f"non-privileged document(s) — possible privilege waiver/leak."),
                ))
        # Deterministic ordering for stable output/tests.
        sev_rank = {"high": 0, "medium": 1, "low": 2}
        findings.sort(key=lambda f: (sev_rank.get(f.severity, 3), f.kind, f.token))
        return findings

    def stats(self) -> Dict:
        return {
            "tenant_id": self.tenant_id,
            "matters": len(self._matters),
            "indexed_tokens": len(self._postings),
            "stores_raw_values": False,
        }
