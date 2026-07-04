"""
Tools Macey can invoke. Each tool is a plain Python function with a docstring
and a JSON-schema-shaped parameter description so it can be exposed to any
tool-use-capable LLM (Anthropic, OpenAI, Ollama with function calling).
"""
from __future__ import annotations
from dataclasses import asdict
from typing import Any, Dict, List, Optional


# ── implementations ──────────────────────────────────────────────────

def tool_list_devices() -> Dict[str, Any]:
    from ..api.server import STORE
    return {"devices": STORE.list_reports()}


def tool_get_report(host_id: str) -> Dict[str, Any]:
    from ..api.server import STORE
    rep = STORE.reports.get(host_id)
    if not rep:
        return {"error": f"no report for host {host_id}"}
    s = rep.get("summary") or {}
    return {
        "host_id": host_id,
        "hostname": rep.get("hostname"),
        "platform": rep.get("platform"),
        "captured_at": rep.get("captured_at"),
        "device_risk_score": s.get("device_risk_score"),
        "severity": s.get("severity"),
        "vuln_count": s.get("vuln_count"),
        "vuln_critical": s.get("vuln_critical"),
        "stig_pass": s.get("stig_pass"),
        "stig_fail": s.get("stig_fail"),
        "top_findings": [{
            "cve_id": v.get("cve_id"),
            "cvss": v.get("cvss_v3"),
            "severity": v.get("severity"),
            "component": v.get("affected_component"),
            "remediation": v.get("remediation"),
        } for v in (rep.get("vulns", {}).get("hits") or [])[:8]],
        "remediation_plan": (rep.get("remediation_plan") or {}).get("actions", [])[:8],
    }


def tool_scan_device(host_id: Optional[str] = None,
                      simulate: Optional[str] = None) -> Dict[str, Any]:
    """Run a scan. If host_id is None, scan this machine."""
    from ..runner import scan_this_device, scan_simulated
    rep = scan_simulated(simulate) if simulate else scan_this_device()
    from ..api.server import STORE
    STORE.ingest(rep.to_dict())
    return {"host_id": rep.host_id, "summary": asdict(rep.summary)}


def tool_lookup_cve(cve_id: str) -> Dict[str, Any]:
    from .. import cve_db
    for r in cve_db.CVE_DATABASE:
        if r.cve_id.lower() == cve_id.lower():
            return {
                "cve_id": r.cve_id, "cvss_v3": r.cvss_v3, "severity": r.severity,
                "affected_pkg": r.affected_pkg, "fixed_version": r.fixed_version,
                "epss_score": r.epss_score, "exploit_status": r.exploit_status,
                "description": r.description, "remediation": r.remediation,
                "remediation_cmd": r.remediation_cmd,
            }
    return {"error": f"no record for {cve_id}"}


def tool_explain_finding(host_id: str, finding_id: str) -> Dict[str, Any]:
    rep = tool_get_report(host_id)
    if "error" in rep: return rep
    # Look in remediation plan
    for act in rep.get("remediation_plan", []):
        if act.get("action_id") == finding_id or finding_id in (act.get("cve_ids") or []) \
                or finding_id in (act.get("stig_ids") or []):
            return {"explanation": _explain(act), "action": act}
    return {"error": f"finding {finding_id} not found on {host_id}"}


def _explain(action: dict) -> str:
    parts = [action.get("description") or action.get("title"), ""]
    cves = action.get("cve_ids") or []
    if cves:
        parts.append(f"This action remediates {len(cves)} CVE(s): {', '.join(cves)}.")
    if action.get("stig_ids"):
        parts.append(f"It addresses STIG check(s): {', '.join(action['stig_ids'])}.")
    if action.get("remediation"):
        parts.append("How to fix: " + action["remediation"])
    if action.get("remediation_cmd"):
        parts.append("Suggested command: `" + action["remediation_cmd"] + "`")
    pri = action.get("priority_score", 0)
    parts.append(
        f"Priority is {pri:.1f}/10 ({action.get('severity')}). " +
        ("Auto-remediation is allowed when the score ≥ 9.0 and the command is "
         "on the allowlist; otherwise the analyst must approve in the dashboard."
         if pri >= 9.0 else
         "This is below the auto-remediate threshold; click Approve to apply.")
    )
    return "\n".join(p for p in parts if p)


def tool_run_playbook(name: str, payload: Dict[str, Any], dry_run: bool = True) -> Dict[str, Any]:
    from ..soar import BUILTINS, run_playbook
    pb = BUILTINS.get(name)
    if not pb:
        return {"error": f"no playbook {name}", "available": list(BUILTINS.keys())}
    return run_playbook(pb, payload, dry_run=dry_run).to_dict()


def tool_search_logs(query: str, window_seconds: int = 86400) -> Dict[str, Any]:
    from .. import intrusion
    rep = intrusion.scan(window_seconds=window_seconds)
    q = query.lower()
    hits = [asdict(e) for e in rep.events if q in (e.description.lower() + e.raw.lower())]
    return {"hits": hits[:50], "total_events": len(rep.events)}


def tool_provision_cloud(region: str = "us-east-1",
                          instance_type: str = "t3.medium",
                          dry_run: bool = True) -> Dict[str, Any]:
    from ..cloud.aws_provision import provision_stack
    return provision_stack({"region": region, "instance_type": instance_type, "dry_run": dry_run})


def tool_fix_finding(host_id: str, finding_id: str, execute: bool = False,
                      mode: str = "plan") -> Dict[str, Any]:
    """
    Resolve a finding (CVE / STIG / malware / DLP / hackable) into a concrete
    remediation plan and optionally execute it via auto_remediate.

    mode:
      'plan'  → just describe what would happen (default; safe)
      'ask'   → require analyst approval in the UI
      'auto'  → execute if allowlist match + priority >= 9.0
    """
    rep = tool_get_report(host_id)
    if "error" in rep: return rep
    # Find the matching action
    for act in (rep.get("remediation_plan") or []):
        if (act.get("action_id") == finding_id
                or finding_id in (act.get("cve_ids") or [])
                or finding_id in (act.get("stig_ids") or [])):
            from ..auto_remediate import execute as exec_safe
            result = exec_safe(act, mode=mode if execute else "plan",
                                host_id=host_id)
            return {"action_taken": result, "action": act,
                     "explanation": _explain(act)}
    return {"error": f"finding {finding_id} not found on {host_id}"}


def tool_locate_app(host_id: str, app_name: str) -> Dict[str, Any]:
    """Return install path + version + bundle id for an app on a device."""
    from ..api.server import STORE
    rep = STORE.reports.get(host_id) or {}
    apps = (rep.get("software") or {}).get("applications", [])
    matches = [a for a in apps if app_name.lower() in (a.get("name") or "").lower()]
    if not matches:
        return {"error": f"no app matching '{app_name}' on {host_id}"}
    return {"matches": matches[:10], "count": len(matches)}


TOOLS: List[Dict[str, Any]] = [
    {
        "name": "list_devices",
        "description": "List all devices that have submitted reports, with risk scores.",
        "input_schema": {"type": "object", "properties": {}, "required": []},
        "impl": tool_list_devices,
    },
    {
        "name": "get_report",
        "description": "Get the latest agent report for a host_id.",
        "input_schema": {"type": "object", "required": ["host_id"],
                          "properties": {"host_id": {"type": "string"}}},
        "impl": tool_get_report,
    },
    {
        "name": "scan_device",
        "description": "Trigger a scan. If host_id omitted, scan local device. "
                       "If simulate is one of darwin|linux|windows, scan a simulated host.",
        "input_schema": {"type": "object", "properties": {
            "host_id":   {"type": "string"},
            "simulate":  {"type": "string", "enum": ["darwin", "linux", "windows", "android", "ios"]},
        }},
        "impl": tool_scan_device,
    },
    {
        "name": "lookup_cve",
        "description": "Look up a CVE by ID and return CVSS, EPSS, severity, fixed version, remediation.",
        "input_schema": {"type": "object", "required": ["cve_id"],
                          "properties": {"cve_id": {"type": "string"}}},
        "impl": tool_lookup_cve,
    },
    {
        "name": "explain_finding",
        "description": "Write a human-readable explanation of a finding for the dashboard.",
        "input_schema": {"type": "object", "required": ["host_id", "finding_id"],
                          "properties": {"host_id": {"type": "string"},
                                          "finding_id": {"type": "string"}}},
        "impl": tool_explain_finding,
    },
    {
        "name": "run_playbook",
        "description": "Run a SOAR playbook (always dry_run by default) given a name and payload.",
        "input_schema": {"type": "object", "required": ["name", "payload"],
                          "properties": {"name": {"type": "string"},
                                          "payload": {"type": "object"},
                                          "dry_run": {"type": "boolean", "default": True}}},
        "impl": tool_run_playbook,
    },
    {
        "name": "search_logs",
        "description": "Search intrusion / audit logs for a substring within the last window.",
        "input_schema": {"type": "object", "required": ["query"],
                          "properties": {"query": {"type": "string"},
                                          "window_seconds": {"type": "integer", "default": 86400}}},
        "impl": tool_search_logs,
    },
    {
        "name": "provision_cloud",
        "description": "Plan or execute the AWS EC2 control-plane provisioning stack.",
        "input_schema": {"type": "object", "properties": {
            "region": {"type": "string", "default": "us-east-1"},
            "instance_type": {"type": "string", "default": "t3.medium"},
            "dry_run": {"type": "boolean", "default": True},
        }},
        "impl": tool_provision_cloud,
    },
    {
        "name": "fix_finding",
        "description": "Resolve a finding (CVE / STIG / malware / DLP / hackable) "
                       "into a remediation plan and optionally execute it via the "
                       "safe-allowlist auto-remediation engine.",
        "input_schema": {"type": "object", "required": ["host_id", "finding_id"],
                          "properties": {
                              "host_id":   {"type": "string"},
                              "finding_id":{"type": "string"},
                              "execute":   {"type": "boolean", "default": False},
                              "mode":      {"type": "string", "enum": ["plan","ask","auto"], "default": "plan"},
                          }},
        "impl": tool_fix_finding,
    },
    {
        "name": "locate_app",
        "description": "Find where an app is installed on a device — returns "
                       "install path, version, vendor, bundle id.",
        "input_schema": {"type": "object", "required": ["host_id", "app_name"],
                          "properties": {
                              "host_id":  {"type": "string"},
                              "app_name": {"type": "string"},
                          }},
        "impl": tool_locate_app,
    },
]


def call_tool(name: str, args: Dict[str, Any]) -> Dict[str, Any]:
    for t in TOOLS:
        if t["name"] == name:
            try:
                return {"ok": True, "result": t["impl"](**(args or {}))}
            except TypeError as e:
                return {"ok": False, "error": str(e)}
            except Exception as e:
                return {"ok": False, "error": str(e)[:300]}
    return {"ok": False, "error": f"unknown tool {name}"}
