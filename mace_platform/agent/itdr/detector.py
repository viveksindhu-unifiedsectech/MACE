"""
ITDR detector — turns provider audit events into MACE IdentitySignal-shaped
findings. Provider clients (Okta/Azure/Google) all yield a normalised
`AuthEvent` so the detection logic is provider-agnostic.
"""
from __future__ import annotations
import math
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Any, Dict, List, Optional


@dataclass
class AuthEvent:
    ts: float
    user: str
    event_type: str          # mfa_challenge | mfa_approved | login | role_grant | consent
    success: bool
    source_ip: str = ""
    geo_lat: Optional[float] = None
    geo_lon: Optional[float] = None
    user_agent: str = ""
    app: str = ""             # for OAuth consent / SSO
    provider: str = ""        # okta | azure_ad | google


@dataclass
class IdentityThreat:
    kind: str               # mfa_bombing | impossible_travel | oauth_abuse | service_anomaly | role_creep
    user: str
    severity: str           # CRITICAL | HIGH | MEDIUM
    description: str
    evidence: List[Dict[str, Any]] = field(default_factory=list)


@dataclass
class IdentityThreatReport:
    threats: List[IdentityThreat] = field(default_factory=list)
    users_analysed: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"threats": [asdict(t) for t in self.threats],
                "users_analysed": self.users_analysed}


def _haversine_km(lat1, lon1, lat2, lon2) -> float:
    R = 6371.0
    p1, p2 = math.radians(lat1), math.radians(lat2)
    dp = math.radians(lat2 - lat1); dl = math.radians(lon2 - lon1)
    a = math.sin(dp/2)**2 + math.cos(p1)*math.cos(p2)*math.sin(dl/2)**2
    return R * 2 * math.asin(min(1.0, math.sqrt(a)))


def detect_identity_threats(events: List[AuthEvent]) -> IdentityThreatReport:
    rep = IdentityThreatReport()
    by_user: Dict[str, List[AuthEvent]] = defaultdict(list)
    for e in events:
        by_user[e.user].append(e)
    rep.users_analysed = len(by_user)

    for user, evs in by_user.items():
        evs.sort(key=lambda e: e.ts)
        # MFA bombing: ≥ 5 mfa_challenge events within 300 s
        challenges = [e for e in evs if e.event_type == "mfa_challenge"]
        for i in range(len(challenges) - 4):
            if challenges[i + 4].ts - challenges[i].ts <= 300:
                rep.threats.append(IdentityThreat(
                    kind="mfa_bombing", user=user, severity="HIGH",
                    description="5+ MFA challenges within 5 minutes — push-fatigue attack pattern.",
                    evidence=[asdict(e) for e in challenges[i:i+5]]))
                break

        # Impossible travel
        logins = [e for e in evs if e.event_type == "login" and e.success
                   and e.geo_lat is not None and e.geo_lon is not None]
        for a, b in zip(logins, logins[1:]):
            dt_h = max(1e-3, (b.ts - a.ts) / 3600)
            dist = _haversine_km(a.geo_lat, a.geo_lon, b.geo_lat, b.geo_lon)
            if dist / dt_h > 500:
                rep.threats.append(IdentityThreat(
                    kind="impossible_travel", user=user, severity="HIGH",
                    description=f"Velocity {dist/dt_h:.0f} km/h between successful logins.",
                    evidence=[asdict(a), asdict(b)]))
                break

        # OAuth consent abuse — third-party app receiving offline_access scope
        for e in evs:
            if e.event_type == "consent" and "offline_access" in (e.app or "").lower():
                rep.threats.append(IdentityThreat(
                    kind="oauth_abuse", user=user, severity="MEDIUM",
                    description=f"User granted offline_access to {e.app}.",
                    evidence=[asdict(e)]))

        # Role-creep — role_grant outside business hours (defined as 09-18 UTC for the demo)
        for e in evs:
            if e.event_type == "role_grant":
                hour = int((e.ts // 3600) % 24)
                if not (9 <= hour < 18):
                    rep.threats.append(IdentityThreat(
                        kind="role_creep", user=user, severity="MEDIUM",
                        description=f"Privilege grant outside business hours ({hour:02d}:00 UTC).",
                        evidence=[asdict(e)]))

    return rep
