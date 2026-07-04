"""
UnifiedSec MACE v2 — Data Connector Library
============================================
Normalises data from security tools into MACE AssetRecord + VulnFinding + SecurityEvent format.

Supported connectors (Session 4):
  crowdstrike    — Falcon Insight (EDR) + Device Control
  tenable        — Tenable.io + Tenable.sc (VM scanning)
  axonius        — Asset intelligence platform
  misp           — Threat intelligence (IOCs, campaigns)
  splunk         — SIEM events (Splunk HEC + Search API)
  endpoint_agent — UMEA agent (HWAM/SWAM/STIG/Vuln/Malware/EDR/DLP)
  linkedin       — LinkedIn Marketing + Sign-In (ITDR impersonation + brand)
  generic        — Generic REST API connector (custom)

All connectors share the same interface:
  connector.fetch_assets()  → List[NormalizedAsset]
  connector.fetch_vulns()   → List[NormalizedVuln]
  connector.fetch_events()  → List[NormalizedEvent]
  connector.health_check()  → ConnectorHealth
"""
from .base import BaseConnector, NormalizedAsset, NormalizedVuln, NormalizedEvent, ConnectorHealth
