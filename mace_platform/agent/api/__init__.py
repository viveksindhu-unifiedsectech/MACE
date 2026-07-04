"""
Standalone REST API for the MACE Endpoint Agent management plane.

Two ways to run it:
  • bundled with the main MACE backend (mace_platform.backend.app) — uses
    the same FastAPI app + auth and adds /agent/* endpoints.
  • standalone (mace_platform.agent.api.server) — a minimal stdlib HTTP
    server with the same endpoints, used by the demo and by air-gapped
    on-premise deployments that don't want a full FastAPI stack.

Endpoints (both flavours expose the same JSON contract):
  POST   /agent/report            — ingest a MACEAgentReport
  GET    /agent/reports           — list ingested reports
  GET    /agent/reports/{host}    — fetch one host's most-recent report
  POST   /agent/scan/{host}       — request a scan on a registered host
  POST   /agent/remediate         — approve a RemediationAction
  GET    /agent/feeds/status      — last update results from NVD/KEV/EPSS/STIG
  POST   /agent/feeds/update      — trigger an on-demand feed refresh
  GET    /agent/malware           — recent malware findings across fleet
  GET    /agent/stream            — WebSocket / SSE event stream
  POST   /cloud/aws/provision     — spin up an AWS EC2 control-plane stack
"""
from .server import run_server, AgentStore

__all__ = ["run_server", "AgentStore"]
