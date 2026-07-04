"""
Identity-provider clients for ITDR.

Each `fetch_*` returns a list of `AuthEvent` normalised across providers.
HTTP calls use only stdlib so the agent has no extra dependencies.
"""
from __future__ import annotations
import json
import time
import urllib.parse
import urllib.request
from typing import List, Optional

from .detector import AuthEvent


def _http_json(url: str, token: str, timeout: int = 20) -> dict:
    req = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept": "application/json",
    })
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def fetch_okta(domain: str, token: str, since_seconds: int = 86400) -> List[AuthEvent]:
    """https://developer.okta.com/docs/reference/api/system-log/"""
    since = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - since_seconds))
    url = f"https://{domain}/api/v1/logs?since={urllib.parse.quote(since)}&limit=500"
    out: List[AuthEvent] = []
    try:
        data = _http_json(url, token)
    except Exception:
        return out
    for ev in data:
        et = ev.get("eventType", "")
        kind = ("mfa_challenge" if "factor.user.verify" in et
                else "mfa_approved" if "factor.user.activate" in et
                else "login"        if "user.session.start" in et
                else "consent"      if "application.user_consent.grant" in et
                else "role_grant"   if "group.user_membership.add" in et
                else "login")
        actor = ev.get("actor", {}) or {}
        client = ev.get("client", {}) or {}
        geo = (client.get("geographicalContext") or {})
        out.append(AuthEvent(
            ts=time.mktime(time.strptime(ev.get("published", "1970-01-01T00:00:00Z"),
                                           "%Y-%m-%dT%H:%M:%S.%fZ"))
                if "." in (ev.get("published") or "") else time.time(),
            user=actor.get("alternateId", actor.get("displayName", "")),
            event_type=kind,
            success=(ev.get("outcome", {}).get("result") == "SUCCESS"),
            source_ip=client.get("ipAddress", ""),
            geo_lat=(geo.get("geolocation") or {}).get("lat"),
            geo_lon=(geo.get("geolocation") or {}).get("lon"),
            user_agent=(client.get("userAgent") or {}).get("rawUserAgent", ""),
            app=ev.get("target", [{}])[0].get("displayName", ""),
            provider="okta",
        ))
    return out


def fetch_azure_ad(tenant: str, token: str, since_seconds: int = 86400) -> List[AuthEvent]:
    """https://learn.microsoft.com/graph/api/signin-list"""
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - since_seconds))
    url = (f"https://graph.microsoft.com/v1.0/auditLogs/signIns"
           f"?$filter=createdDateTime ge {iso}&$top=500")
    out: List[AuthEvent] = []
    try:
        data = _http_json(url, token)
    except Exception:
        return out
    for ev in data.get("value", []):
        loc = ev.get("location", {}) or {}
        coords = loc.get("geoCoordinates", {}) or {}
        out.append(AuthEvent(
            ts=time.time(),
            user=ev.get("userPrincipalName", ""),
            event_type="login",
            success=(ev.get("status", {}).get("errorCode") == 0),
            source_ip=ev.get("ipAddress", ""),
            geo_lat=coords.get("latitude"),
            geo_lon=coords.get("longitude"),
            user_agent=ev.get("clientAppUsed", ""),
            app=ev.get("appDisplayName", ""),
            provider="azure_ad",
        ))
    return out


def fetch_google(token: str, customer_id: str = "my_customer",
                  since_seconds: int = 86400) -> List[AuthEvent]:
    """https://developers.google.com/admin-sdk/reports/reference/rest/v1/activities/list"""
    iso = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(time.time() - since_seconds))
    url = (f"https://admin.googleapis.com/admin/reports/v1/activity/users/all/"
           f"applications/login?startTime={iso}&maxResults=500")
    out: List[AuthEvent] = []
    try:
        data = _http_json(url, token)
    except Exception:
        return out
    for ev in data.get("items", []):
        actor = ev.get("actor", {})
        out.append(AuthEvent(
            ts=time.time(),
            user=actor.get("email", ""),
            event_type="login",
            success=ev.get("events", [{}])[0].get("name") == "login_success",
            source_ip=ev.get("ipAddress", ""),
            provider="google",
        ))
    return out
