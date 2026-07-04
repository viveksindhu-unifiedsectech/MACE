"""
MACE Real-time Pipeline — Session 4
=====================================
Stages:
  1. Ingest          — receive raw connector data (assets, vulns, events)
  2. Normalize       — convert to MACE internal format via connectors
  3. Enrich          — EPSS, geo-IP, threat intel cross-reference
  4. Correlate       — run UTAG + CDCS + UREA on each event
  5. Dispatch        — push alerts to WebSocket, email, Slack, PagerDuty, SIEM
"""
