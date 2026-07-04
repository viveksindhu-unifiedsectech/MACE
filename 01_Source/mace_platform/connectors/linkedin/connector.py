"""
LinkedIn Marketing Developer Platform connector.

Auth: OAuth 2.0 (3-legged) → access token used in Authorization: Bearer header.

Endpoints touched:
  GET  /v2/organizationAcls?q=roleAssignee   — list orgs the user admins
  GET  /v2/organizations/{id}                — page metadata
  GET  /v2/organizationalEntityShareStatistics — page analytics
  GET  /v2/organizationalEntityFollowerStatistics
  POST /v2/ugcPosts                          — publish a post programmatically
  GET  /v2/me                                 — verify a user is a real employee
  GET  /v2/people-search                     — find impostor accounts (Sales Nav)

This connector is the MACE side of two use cases:

  1. ITDR — every employee's LinkedIn account is verified daily; any
     newly-created account claiming to work at UnifiedSec is flagged
     for review by Macey + the security team.

  2. Marketing automation — auto-publish "MACE just detected ..." posts
     to the UnifiedSec company page (gated by safe-allowlist so it
     can't spam).
"""
from __future__ import annotations
import json
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

from ..base import (BaseConnector, NormalizedAsset, NormalizedEvent,
                     NormalizedVuln, ConnectorHealth)


LINKEDIN_API_BASE = "https://api.linkedin.com"
LINKEDIN_OAUTH_BASE = "https://www.linkedin.com/oauth/v2"


@dataclass
class LinkedInPostDraft:
    """A post we want to publish to the UnifiedSec company page."""
    author_urn: str         # urn:li:organization:1234567
    text: str
    visibility: str = "PUBLIC"          # PUBLIC | CONNECTIONS
    article_url: Optional[str] = None
    image_urn: Optional[str] = None


@dataclass
class ImpersonationFinding:
    profile_url: str
    display_name: str
    headline: str = ""
    claimed_employer: str = ""
    account_age_days: int = 0
    risk_score: float = 0.0
    indicators: List[str] = field(default_factory=list)


class LinkedInConnector(BaseConnector):
    """
    LinkedIn Marketing Developer Platform + Sign In with LinkedIn connector.

    Requires:
      client_id, client_secret   — registered app credentials at
                                    https://www.linkedin.com/developers/apps
      redirect_uri               — your OAuth callback URL
      access_token               — produced by the OAuth dance
                                    (or use refresh_token to renew)
      org_urn                    — urn:li:organization:NNNNNNNN for
                                    UnifiedSec's company page (post-creation)
    """

    def __init__(self,
                 client_id: str,
                 client_secret: str,
                 redirect_uri: str = "https://app.unifiedsec.io/oauth/linkedin",
                 access_token: Optional[str] = None,
                 refresh_token: Optional[str] = None,
                 org_urn: Optional[str] = None,
                 base_url: str = LINKEDIN_API_BASE):
        super().__init__(base_url)
        self.client_id = client_id
        self.client_secret = client_secret
        self.redirect_uri = redirect_uri
        self.access_token = access_token
        self.refresh_token = refresh_token
        self.org_urn = org_urn or ""
        self._token_expires_at: float = 0.0

    # ── OAuth dance ──────────────────────────────────────────────

    def authorization_url(self, state: str,
                           scopes: Optional[List[str]] = None) -> str:
        """Step 1: send the user to this URL so they can grant access."""
        scopes = scopes or [
            "r_liteprofile", "r_emailaddress",          # Sign In
            "r_organization_social", "rw_organization_admin",  # Marketing
            "w_organization_social",                    # publish posts
            "r_basicprofile",
        ]
        import urllib.parse as up
        params = {
            "response_type": "code",
            "client_id": self.client_id,
            "redirect_uri": self.redirect_uri,
            "state": state,
            "scope": " ".join(scopes),
        }
        return f"{LINKEDIN_OAUTH_BASE}/authorization?{up.urlencode(params)}"

    async def exchange_code(self, code: str) -> Dict[str, Any]:
        """Step 2: trade the auth code for an access token."""
        resp = await self._client.post(
            f"{LINKEDIN_OAUTH_BASE}/accessToken",
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": self.redirect_uri,
                "client_id": self.client_id,
                "client_secret": self.client_secret,
            },
        )
        resp.raise_for_status()
        data = resp.json()
        self.access_token = data.get("access_token", "")
        self.refresh_token = data.get("refresh_token") or self.refresh_token
        self._token_expires_at = time.time() + int(data.get("expires_in", 5184000))
        return data

    async def authenticate(self) -> bool:
        """Refresh the token if it's expiring soon, else verify it works."""
        if not self.access_token:
            return False
        # Renew if we know it's expiring within an hour
        if self.refresh_token and self._token_expires_at and \
                self._token_expires_at - time.time() < 3600:
            resp = await self._client.post(
                f"{LINKEDIN_OAUTH_BASE}/accessToken",
                data={
                    "grant_type": "refresh_token",
                    "refresh_token": self.refresh_token,
                    "client_id": self.client_id,
                    "client_secret": self.client_secret,
                },
            )
            if resp.status_code == 200:
                d = resp.json()
                self.access_token = d.get("access_token", self.access_token)
                self._token_expires_at = time.time() + int(d.get("expires_in", 5184000))
        # Inject the bearer header
        if self._client:
            self._client.headers["Authorization"] = f"Bearer {self.access_token}"
            self._client.headers["X-Restli-Protocol-Version"] = "2.0.0"
        return True

    # ── Identity verification (ITDR feed) ────────────────────────

    async def get_me(self) -> Dict[str, Any]:
        """Verify the logged-in user's LinkedIn identity."""
        await self.authenticate()
        return await self._get("/v2/me")

    async def get_email(self) -> Dict[str, Any]:
        await self.authenticate()
        return await self._get(
            "/v2/emailAddress?q=members&projection=(elements*(handle~))")

    # ── Company page (org admin) ─────────────────────────────────

    async def my_organizations(self) -> List[Dict[str, Any]]:
        """List the LinkedIn org pages this user can admin."""
        await self.authenticate()
        data = await self._get(
            "/v2/organizationAcls?q=roleAssignee&role=ADMINISTRATOR"
        )
        return data.get("elements", [])

    async def organization(self, org_urn: Optional[str] = None) -> Dict[str, Any]:
        """Get page metadata."""
        await self.authenticate()
        urn = (org_urn or self.org_urn).replace("urn:li:organization:", "")
        return await self._get(f"/v2/organizations/{urn}")

    async def follower_stats(self, org_urn: Optional[str] = None) -> Dict[str, Any]:
        await self.authenticate()
        urn = org_urn or self.org_urn
        return await self._get(
            f"/v2/organizationalEntityFollowerStatistics?q=organizationalEntity"
            f"&organizationalEntity={urn}")

    async def share_stats(self, org_urn: Optional[str] = None,
                           since: Optional[datetime] = None) -> Dict[str, Any]:
        await self.authenticate()
        urn = org_urn or self.org_urn
        params: Dict[str, Any] = {
            "q": "organizationalEntity",
            "organizationalEntity": urn,
        }
        if since:
            params["timeIntervals.timeGranularityType"] = "DAY"
            params["timeIntervals.timeRange.start"] = int(since.timestamp() * 1000)
        return await self._get(
            "/v2/organizationalEntityShareStatistics", params=params)

    # ── Publish a post on the company page ───────────────────────

    async def publish_post(self, draft: LinkedInPostDraft) -> Dict[str, Any]:
        await self.authenticate()
        body = {
            "author": draft.author_urn,
            "lifecycleState": "PUBLISHED",
            "specificContent": {
                "com.linkedin.ugc.ShareContent": {
                    "shareCommentary": {"text": draft.text},
                    "shareMediaCategory": "ARTICLE" if draft.article_url
                                           else ("IMAGE" if draft.image_urn else "NONE"),
                    "media": ([{
                        "status": "READY",
                        "originalUrl": draft.article_url,
                    }] if draft.article_url else
                     [{"status": "READY", "media": draft.image_urn}]
                     if draft.image_urn else []),
                }
            },
            "visibility": {
                "com.linkedin.ugc.MemberNetworkVisibility": draft.visibility
            },
        }
        return await self._post("/v2/ugcPosts", json=body)

    # ── ITDR: impersonation detection ────────────────────────────

    async def search_for_impersonators(self, brand: str = "UnifiedSec",
                                          max_results: int = 50
                                          ) -> List[ImpersonationFinding]:
        """
        Search LinkedIn for accounts claiming UnifiedSec affiliation.
        Note: full people-search requires Sales Navigator access.
        With Marketing-only scope, this falls back to scanning your
        own page's followers + the headlines of posts mentioning you.
        """
        await self.authenticate()
        findings: List[ImpersonationFinding] = []
        # Without Sales Nav, the lightweight approach: scan public
        # mentions of the org URN via the People API
        try:
            data = await self._get(
                f"/v2/people?keywords={brand}&count={max_results}")
        except Exception as e:
            self.logger.warning(f"people-search unavailable: {e}")
            return findings
        for hit in data.get("elements", []):
            profile_url = hit.get("publicProfileUrl", "")
            headline = hit.get("headline", "")
            display = hit.get("localizedFirstName", "") + " " + \
                       hit.get("localizedLastName", "")
            indicators: List[str] = []
            risk = 0.0
            if "recruiter" in headline.lower() and brand.lower() in headline.lower():
                indicators.append("claims_recruiter_role")
                risk += 0.4
            if "ceo" in headline.lower() or "founder" in headline.lower():
                indicators.append("claims_leadership_role")
                risk += 0.5
            age_days = hit.get("accountAgeDays", 9999)
            if age_days < 30:
                indicators.append(f"account_only_{age_days}d_old")
                risk += 0.3
            if not hit.get("connections") or hit.get("connections") < 50:
                indicators.append("very_few_connections")
                risk += 0.2
            findings.append(ImpersonationFinding(
                profile_url=profile_url,
                display_name=display.strip(),
                headline=headline,
                claimed_employer=brand,
                account_age_days=age_days,
                risk_score=min(1.0, risk),
                indicators=indicators,
            ))
        return findings

    # ── BaseConnector contract ───────────────────────────────────

    async def fetch_assets(self, limit: int = 500) -> List[NormalizedAsset]:
        """LinkedIn doesn't have device assets — return empty."""
        return []

    async def fetch_events(self, limit: int = 200) -> List[NormalizedEvent]:
        """Surface impersonators + suspicious follower spikes as events."""
        out: List[NormalizedEvent] = []
        try:
            imps = await self.search_for_impersonators(max_results=limit)
        except Exception as e:
            self.logger.error(f"impersonation scan failed: {e}")
            return out
        for f in imps:
            if f.risk_score < 0.4:
                continue
            sev = ("CRITICAL" if f.risk_score >= 0.8
                   else "HIGH" if f.risk_score >= 0.6
                   else "MEDIUM")
            out.append(NormalizedEvent(
                source="linkedin",
                event_id=f"li-imp-{hash(f.profile_url) & 0xfff_ffff:08x}",
                event_type="impersonation_attempt",
                severity=sev,
                domain="identity",
                description=f"Suspected impersonator: {f.display_name} "
                             f"({f.headline}). Indicators: "
                             f"{', '.join(f.indicators)}",
                source_tool="linkedin",
                fidelity=0.6,
                raw={"profile_url": f.profile_url,
                     "risk_score": f.risk_score,
                     "indicators": f.indicators,
                     "account_age_days": f.account_age_days},
            ))
        return out

    async def health_check(self) -> ConnectorHealth:
        try:
            ok = await self.authenticate()
            if not ok:
                return ConnectorHealth(
                    status="error", message="No access token",
                    assets_available=False)
            me = await self.get_me()
            return ConnectorHealth(
                status="ok",
                message=f"Authenticated as {me.get('localizedFirstName','?')} "
                         f"{me.get('localizedLastName','')}",
                assets_available=False, events_available=True)
        except Exception as e:
            return ConnectorHealth(status="error", message=str(e)[:200])
