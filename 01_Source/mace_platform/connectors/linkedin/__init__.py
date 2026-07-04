"""
LinkedIn Connector
==================
Pulls employee profile data, company-page analytics, and impersonation
indicators from LinkedIn's Marketing Developer Platform + Sign In with
LinkedIn APIs.

Used by:
  • ITDR (mace_platform/agent/itdr) — flags fake recruiter / "HR" accounts
    targeting employees, plus shadow-profile detection.
  • Threat intel — surfaces fake job postings impersonating UnifiedSec
    used for credential phishing campaigns.
  • Brand monitoring — tracks impostor company pages.
"""
from .connector import LinkedInConnector

__all__ = ["LinkedInConnector"]
