"""
Identity Threat Detection & Response (ITDR).

Pulls authentication / authorization events from upstream identity
providers and turns them into IdentitySignal-shaped findings that flow
into the same CDCS γ-domain as on-device identity events.

Connectors:
  okta              — Okta System Log API (/api/v1/logs)
  azure_ad          — Microsoft Graph signIns + auditLogs
  google_workspace  — Admin SDK reports.activities.list

Detections produced:
  • MFA bombing / fatigue                  (multiple Approve prompts < 5 min)
  • OAuth-app consent abuse                 (illicit consent grant pattern)
  • Impossible travel                       (Haversine > 500 km/h between logins)
  • Lateral account reuse                   (same creds used on N+ devices)
  • Service-account anomaly                 (interactive logon from human IP)
  • Privilege escalation                    (role grant outside change window)
"""
from .detector import detect_identity_threats, IdentityThreatReport

__all__ = ["detect_identity_threats", "IdentityThreatReport"]
