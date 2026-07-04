"""
Access control for MACE Secure Files — RBAC + ABAC + data classification, with
hard tenant isolation as the outermost, non-overridable ring.

Evaluation order (fail-closed at every step):

  1. TENANT ISOLATION   subject.tenant_id != resource.tenant_id  -> DENY, always.
                        No role, not even super_admin, crosses a tenant boundary
                        for file *data* access. This is categorical.
  2. OWNERSHIP          the file owner has full rights to their own file.
  3. EXPLICIT GRANT     a per-user grant can authorize a permission AND raise the
                        subject's effective clearance for that one file
                        ("we give this named person access based on credentials").
  4. ROLE DEFAULT       role -> default permission set, capped by role clearance.
  5. CLASSIFICATION     even with a role permission, a subject may not READ/WRITE
                        a resource above their clearance unless an explicit user
                        grant covered it in step 3.

Pure Python, no DB import — the API layer adapts ORM rows into Subject/Resource
so this engine stays unit-testable and reusable (agent, pipeline, CLI).
"""
from __future__ import annotations

import enum
from dataclasses import dataclass, field
from datetime import datetime
from typing import Dict, List, Optional, Set


class Classification(str, enum.Enum):
    PUBLIC = "public"
    INTERNAL = "internal"
    CONFIDENTIAL = "confidential"
    RESTRICTED = "restricted"


_ORDER = {
    Classification.PUBLIC: 0,
    Classification.INTERNAL: 1,
    Classification.CONFIDENTIAL: 2,
    Classification.RESTRICTED: 3,
}


class Permission(str, enum.Enum):
    READ = "read"
    WRITE = "write"
    SHARE = "share"
    DELETE = "delete"


# Role -> max data classification the role may reach by default.
ROLE_CLEARANCE: Dict[str, Classification] = {
    "super_admin": Classification.RESTRICTED,
    "tenant_admin": Classification.RESTRICTED,
    "soc_analyst": Classification.CONFIDENTIAL,
    "read_only": Classification.INTERNAL,
    "api_user": Classification.INTERNAL,
}

# Role -> default permissions within the subject's own tenant.
ROLE_PERMISSIONS: Dict[str, Set[Permission]] = {
    "super_admin": {Permission.READ, Permission.WRITE, Permission.SHARE, Permission.DELETE},
    "tenant_admin": {Permission.READ, Permission.WRITE, Permission.SHARE, Permission.DELETE},
    "soc_analyst": {Permission.READ},
    "read_only": {Permission.READ},
    "api_user": {Permission.READ, Permission.WRITE},
}


@dataclass
class Grant:
    """An access grant attached to a resource."""
    subject_type: str          # "user" | "role"
    subject_value: str         # user id OR role name
    permissions: Set[Permission]
    expires_at: Optional[datetime] = None

    def active(self, now: datetime) -> bool:
        return self.expires_at is None or self.expires_at > now


@dataclass
class Subject:
    id: str
    tenant_id: str
    role: str
    clearance: Optional[Classification] = None   # explicit override, else role default
    attributes: Dict[str, str] = field(default_factory=dict)

    def effective_clearance(self) -> Classification:
        return self.clearance or ROLE_CLEARANCE.get(self.role, Classification.PUBLIC)


@dataclass
class Resource:
    id: str
    tenant_id: str
    owner_id: str
    classification: Classification = Classification.INTERNAL
    grants: List[Grant] = field(default_factory=list)
    attributes: Dict[str, str] = field(default_factory=dict)


@dataclass
class Decision:
    allow: bool
    reason: str
    code: str                  # machine code for audit / dashboards

    def __bool__(self) -> bool:
        return self.allow


def _clears(subject_level: Classification, resource_level: Classification) -> bool:
    return _ORDER[subject_level] >= _ORDER[resource_level]


def evaluate(subject: Subject, resource: Resource, permission: Permission,
             now: Optional[datetime] = None) -> Decision:
    now = now or datetime.utcnow()

    # 1. Tenant isolation — categorical, no override.
    if subject.tenant_id != resource.tenant_id:
        return Decision(False, "cross-tenant access is never permitted", "TENANT_ISOLATION_DENY")

    # 2. Ownership — full control of your own file.
    if subject.id == resource.owner_id:
        return Decision(True, "owner", "OWNER_ALLOW")

    # 3. Explicit user grant — may authorize AND raise clearance for this file.
    for g in resource.grants:
        if g.subject_type == "user" and g.subject_value == subject.id and g.active(now):
            if permission in g.permissions:
                return Decision(True, "explicit user grant", "USER_GRANT_ALLOW")

    # 3b. Explicit role grant — authorizes, but does NOT override classification.
    role_granted = False
    for g in resource.grants:
        if g.subject_type == "role" and g.subject_value == subject.role and g.active(now):
            if permission in g.permissions:
                role_granted = True

    # 4. Role default permissions.
    role_perms = ROLE_PERMISSIONS.get(subject.role, set())
    has_permission = role_granted or (permission in role_perms)
    if not has_permission:
        return Decision(False, f"role '{subject.role}' lacks {permission.value}", "PERMISSION_DENY")

    # 5. Classification gate (applies to READ/WRITE of the data).
    if permission in (Permission.READ, Permission.WRITE):
        if not _clears(subject.effective_clearance(), resource.classification):
            return Decision(
                False,
                f"clearance '{subject.effective_clearance().value}' below "
                f"classification '{resource.classification.value}'",
                "CLASSIFICATION_DENY",
            )

    return Decision(True, f"role '{subject.role}' authorized", "ROLE_ALLOW")


def explain(subject: Subject, resource: Resource) -> Dict[str, Decision]:
    """Return the decision for every permission — handy for UIs and audits."""
    return {p.value: evaluate(subject, resource, p) for p in Permission}
