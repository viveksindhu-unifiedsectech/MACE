"""
Alert Dispatcher — Pipeline Stage 5
======================================
Sends MACE alerts to:
  - WebSocket (SOC Dashboard real-time push)
  - Email (SMTP via SendGrid)
  - Slack (Incoming Webhook)
  - PagerDuty (Events API v2)
  - Microsoft Teams (Adaptive Cards)
  - Generic webhook (any SIEM/SOAR)

Configured per-tenant via dispatch_config dict.
"""
import logging
import json
import httpx
from typing import Optional, Dict, Any
from datetime import datetime

logger = logging.getLogger(__name__)


class AlertDispatcher:
    """
    Multi-channel alert dispatcher.
    Routes CDCS alerts to configured channels based on severity.
    """

    def __init__(self, config: Dict[str, Any]):
        """
        config: {
          "slack_webhook": "https://hooks.slack.com/...",
          "pagerduty_key": "...",
          "teams_webhook": "https://...",
          "generic_webhook": "https://...",
          "min_severity_email": "HIGH",
          "min_severity_pagerduty": "CRITICAL",
        }
        """
        self.config = config

    async def dispatch(self, alert: Dict[str, Any]):
        """
        Route an alert to all configured channels.
        alert = {
          incident_ref, cdcs, severity, asset, event_type,
          cert_in_reference, aecert_reference, frameworks, tenant_id, ts
        }
        """
        severity = alert.get("severity", "LOW").upper()
        tasks = []

        if self.config.get("slack_webhook"):
            tasks.append(self._send_slack(alert))

        if self.config.get("teams_webhook"):
            tasks.append(self._send_teams(alert))

        if self.config.get("generic_webhook"):
            tasks.append(self._send_webhook(alert))

        if (self.config.get("pagerduty_key") and
                _severity_gte(severity, self.config.get("min_severity_pagerduty", "CRITICAL"))):
            tasks.append(self._send_pagerduty(alert))

        import asyncio
        results = await asyncio.gather(*tasks, return_exceptions=True)
        for r in results:
            if isinstance(r, Exception):
                logger.error(f"Dispatch error: {r}")

    async def _send_slack(self, alert: Dict[str, Any]):
        """Send Slack notification with MACE alert context."""
        severity = alert.get("severity", "LOW")
        color_map = {"CRITICAL": "#ff4d4f", "HIGH": "#fa8c16",
                     "MEDIUM": "#faad14", "LOW": "#52c41a"}
        color = color_map.get(severity, "#808080")
        cdcs = alert.get("cdcs", 0)

        payload = {
            "attachments": [{
                "color": color,
                "fallback": f"MACE Alert: {alert.get('incident_ref')} — CDCS {cdcs:.1f}",
                "title": f"🚨 {severity} — {alert.get('incident_ref')}",
                "title_link": f"https://app.unifiedsec.com/incidents",
                "fields": [
                    {"title": "CDCS Score", "value": f"{cdcs:.2f}/10", "short": True},
                    {"title": "Asset", "value": alert.get("asset", "Unknown"), "short": True},
                    {"title": "Event Type", "value": alert.get("event_type", ""), "short": True},
                    {"title": "Kill Chain", "value": alert.get("kill_chain_stage", "—"), "short": True},
                ],
                "footer": "UnifiedSec MACE v2",
                "ts": int(datetime.utcnow().timestamp()),
            }]
        }

        # Add regulatory references if present
        if alert.get("cert_in_reference"):
            payload["attachments"][0]["fields"].append(
                {"title": "CERT-In Ref", "value": alert["cert_in_reference"], "short": True}
            )
        if alert.get("aecert_reference"):
            payload["attachments"][0]["fields"].append(
                {"title": "aeCERT Ref", "value": alert["aecert_reference"], "short": True}
            )
        if alert.get("frameworks"):
            payload["attachments"][0]["fields"].append(
                {"title": "Frameworks", "value": ", ".join(alert["frameworks"][:3]), "short": False}
            )

        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(self.config["slack_webhook"], json=payload)
        logger.info(f"Slack: dispatched {alert.get('incident_ref')}")

    async def _send_teams(self, alert: Dict[str, Any]):
        """Microsoft Teams Adaptive Card."""
        severity = alert.get("severity", "LOW")
        color_map = {"CRITICAL": "Attention", "HIGH": "Warning", "MEDIUM": "Warning", "LOW": "Good"}
        theme = color_map.get(severity, "Default")

        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": "FF4D4F" if severity == "CRITICAL" else "FA8C16",
            "summary": f"MACE Alert: {alert.get('incident_ref')}",
            "sections": [{
                "activityTitle": f"🚨 MACE {severity}: {alert.get('incident_ref')}",
                "activitySubtitle": f"CDCS Score: {alert.get('cdcs', 0):.2f}/10",
                "facts": [
                    {"name": "Asset", "value": alert.get("asset", "—")},
                    {"name": "Event Type", "value": alert.get("event_type", "—")},
                    {"name": "Frameworks", "value": ", ".join(alert.get("frameworks", []))},
                ],
                "markdown": True,
            }],
            "potentialAction": [{
                "@type": "OpenUri",
                "name": "View in SOC Dashboard",
                "targets": [{"os": "default", "uri": "https://app.unifiedsec.com/incidents"}]
            }]
        }
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(self.config["teams_webhook"], json=payload)
        logger.info(f"Teams: dispatched {alert.get('incident_ref')}")

    async def _send_pagerduty(self, alert: Dict[str, Any]):
        """PagerDuty Events API v2."""
        payload = {
            "routing_key": self.config["pagerduty_key"],
            "event_action": "trigger",
            "dedup_key": alert.get("incident_ref"),
            "payload": {
                "summary": f"MACE {alert.get('severity')} — {alert.get('event_type')} on {alert.get('asset')}",
                "severity": alert.get("severity", "error").lower().replace("critical", "critical"),
                "source": "UnifiedSec MACE v2",
                "component": alert.get("asset"),
                "group": alert.get("event_type"),
                "custom_details": {
                    "cdcs_score": alert.get("cdcs"),
                    "incident_ref": alert.get("incident_ref"),
                    "frameworks": alert.get("frameworks", []),
                    "cert_in_reference": alert.get("cert_in_reference"),
                    "aecert_reference": alert.get("aecert_reference"),
                }
            }
        }
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.post("https://events.pagerduty.com/v2/enqueue", json=payload)
            resp.raise_for_status()
        logger.info(f"PagerDuty: dispatched {alert.get('incident_ref')}")

    async def _send_webhook(self, alert: Dict[str, Any]):
        """Generic SIEM/SOAR webhook — sends full alert as JSON."""
        async with httpx.AsyncClient(timeout=10) as client:
            await client.post(
                self.config["generic_webhook"],
                json={"source": "unifiedsec_mace", "version": "2.0", "alert": alert},
                headers={"Content-Type": "application/json"}
            )
        logger.info(f"Webhook: dispatched {alert.get('incident_ref')}")


def _severity_gte(a: str, b: str) -> bool:
    order = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0}
    return order.get(a, 0) >= order.get(b, 0)
