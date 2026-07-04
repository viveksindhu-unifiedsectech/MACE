"""
Macey — the MACE AI agent.

Macey is the conversational interface to UnifiedSec MACE. She lives in the
dashboard chat panel, in the GUI, in the CLI (`mace-agent ask "…"`), and as
the /agent/macey/chat API endpoint. The same Macey instance can be embedded
in a customer's Slack, Teams, or web app via webhook.

Capabilities
------------
Macey is *not* a wrapper around a generic chatbot. She is given a small set
of MACE-specific tools that let her actually do things:

  • scan_device(host_id?)              — kick off (or simulate) an agent scan
  • get_report(host_id)                — fetch the most recent agent report
  • list_devices()                      — list registered devices and their risk
  • lookup_cve(cve_id)                  — get CVE details + remediation
  • explain_finding(finding_id)        — write a human explanation for a finding
  • run_playbook(name, payload)         — invoke a SOAR playbook
  • search_logs(query, window_seconds)  — query intrusion / audit log
  • provision_cloud(region, …)          — spin up AWS control-plane stack
  • write_evidence(framework, …)        — generate CERT-In/DPDP/NESA draft

Provider adapters
-----------------
She works with three back-ends, in order of preference:

  • Anthropic Claude (ANTHROPIC_API_KEY)         — best tool-use fidelity
  • OpenAI GPT-4o / 4.1 (OPENAI_API_KEY)         — broadest deployment
  • Local Ollama (OLLAMA_BASE_URL)               — offline / air-gapped

If no provider is configured she falls back to a *rule-based responder*
that still handles the most common questions ("show me criticals", "scan
this device", "what is CVE-XXX?") without an LLM.

Safety
------
Tools are gated by the same allowlist as `auto_remediate.execute()`. Any
destructive operation requires either an explicit user confirmation in the
UI or a sufficient priority_score (≥ 9.0).
"""
from .agent import Macey, ask, MaceyResponse, ToolCall

__all__ = ["Macey", "ask", "MaceyResponse", "ToolCall"]
