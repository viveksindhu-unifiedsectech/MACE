"""
SOAR — Security Orchestration, Automation & Response.

Playbooks are declarative sequences of steps the agent (or the management
plane) can execute in response to a high-confidence finding. Each step is
either:

  • shell  — runs a shell command through auto_remediate.execute(), which
              enforces the safety allowlist.
  • http   — calls a webhook (notify Slack, page Pager Duty, open a Jira).
  • signal — emits an IntrusionEvent / IdentitySignal back into the pipeline.
  • wait   — sleeps N seconds (used between containment + reset steps).

Built-in playbooks cover the most common incident types we see in practice:
  pb_ransomware_isolation
  pb_phishing_user_revoke
  pb_lost_device_lock
  pb_mfa_bombing_block
  pb_critical_cve_patch
  pb_unauthorized_lan_access

Custom playbooks live in ~/.mace-agent/playbooks/*.yaml — loaded at startup.
"""
from .engine import (Playbook, PlaybookStep, PlaybookRun, run_playbook,
                      list_builtin_playbooks)

__all__ = ["Playbook", "PlaybookStep", "PlaybookRun", "run_playbook",
            "list_builtin_playbooks"]
