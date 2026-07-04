"""
Standalone agent API + dashboard server (stdlib http.server based).

Designed so the demo and any air-gapped deployment can run the MACE
control plane with zero third-party dependencies. For production we
recommend the FastAPI integration at mace_platform.backend.app, which
provides auth, multi-tenancy, websockets and persistent storage.
"""
from __future__ import annotations
import json
import os
import socketserver
import threading
import time
from collections import deque
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler
from pathlib import Path
from typing import Any, Deque, Dict, List, Optional, Tuple


# ── In-memory store with optional disk persistence ────────────────────

def _guess_type(rep):
    plat = (rep.get("platform") or "").lower()
    if plat == "android" or plat == "ios": return "phone"
    if plat == "linux": return "server"
    return "laptop"


@dataclass
class AgentStore:
    reports: Dict[str, dict] = field(default_factory=dict)          # host_id → latest report
    history: Dict[str, Deque[dict]] = field(default_factory=dict)   # host_id → last N reports
    fleet_events: Deque[dict] = field(default_factory=lambda: deque(maxlen=500))
    approved_remediations: List[dict] = field(default_factory=list)
    storage_dir: Optional[Path] = None
    history_size: int = 50

    def ingest(self, payload: dict) -> dict:
        host_id = payload.get("host_id") or "unknown"
        self.reports[host_id] = payload
        self.history.setdefault(host_id, deque(maxlen=self.history_size)).append(
            {"captured_at": payload.get("captured_at"),
             "device_risk_score": (payload.get("summary") or {}).get("device_risk_score"),
             "vuln_count": (payload.get("summary") or {}).get("vuln_count")}
        )
        self.fleet_events.appendleft({
            "ts": time.time(),
            "kind": "report_received",
            "host_id": host_id,
            "hostname": payload.get("hostname"),
            "summary": payload.get("summary"),
        })
        if self.storage_dir:
            try:
                (self.storage_dir / f"{host_id}.json").write_text(json.dumps(payload))
            except Exception:
                pass
        return {"ok": True, "host_id": host_id,
                "actions_pending": len((payload.get("remediation_plan") or {}).get("actions", []))}

    def list_reports(self) -> list:
        out = []
        for hid, rep in self.reports.items():
            s = rep.get("summary") or {}
            tags = rep.get("tags") or {}
            out.append({
                "host_id": hid,
                "hostname": rep.get("hostname"),
                "platform": rep.get("platform"),
                "device_type": rep.get("device_type") or _guess_type(rep),
                "cloud_provider": rep.get("cloud_provider", ""),
                "captured_at": rep.get("captured_at"),
                "scan_type": rep.get("scan_type") or "real_time",
                "tenant_id": tags.get("tenant_id") or "self",
                "tenant":    tags.get("tenant") or "Self / Default tenant",
                "department": tags.get("department") or "",
                "city":       tags.get("city") or "",
                "sector":     tags.get("sector") or "",
                "device_risk_score": s.get("device_risk_score"),
                "severity": s.get("severity"),
                "vuln_count": s.get("vuln_count"),
                "stig_pass": s.get("stig_pass"),
                "stig_fail": s.get("stig_fail"),
            })
        out.sort(key=lambda r: r.get("device_risk_score") or 0, reverse=True)
        return out

    def approve_remediation(self, action: dict, host_id: str) -> dict:
        record = {"approved_at": time.time(), "host_id": host_id, "action": action}
        self.approved_remediations.append(record)
        self.fleet_events.appendleft({
            "ts": time.time(), "kind": "remediation_approved",
            "host_id": host_id, "title": action.get("title"),
            "priority": action.get("priority_score"),
        })
        return {"ok": True, "queued_for": host_id}


# ── Handler ──────────────────────────────────────────────────────────

STORE = AgentStore()
DASHBOARD_HTML_PATH: Optional[Path] = None


class _Handler(BaseHTTPRequestHandler):
    server_version = "MACEAgentAPI/1.0"

    def log_message(self, format, *args):  # silence default access log
        pass

    # CORS preflight
    def do_OPTIONS(self):
        self.send_response(204)
        self._cors()
        self.end_headers()

    def _cors(self):
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, Authorization")

    def _json(self, payload, status=200):
        body = json.dumps(payload, default=str).encode("utf-8")
        self.send_response(status); self._cors()
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)

    def _read_body(self) -> dict:
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b"{}"
        try:    return json.loads(raw or b"{}")
        except Exception: return {}

    # ── GET ──────────────────────────────────────────────────────────
    def do_GET(self):
        p = self.path.split("?", 1)[0]
        if p in ("/", "/index.html"):
            return self._serve_dashboard()
        if p == "/agent/reports":
            return self._json({"reports": STORE.list_reports()})
        if p.startswith("/agent/reports/"):
            host = p.rsplit("/", 1)[-1]
            rep = STORE.reports.get(host)
            return self._json(rep or {"error": "not_found"}, 200 if rep else 404)
        if p == "/agent/feeds/status":
            from ..feeds import last_update_status
            return self._json(last_update_status())
        if p == "/agent/malware":
            findings = []
            for rep in STORE.reports.values():
                for f in (rep.get("malware") or {}).get("findings", []) or []:
                    findings.append({"host_id": rep.get("host_id"), **f})
            return self._json({"findings": findings})
        if p == "/agent/events":
            return self._json({"events": list(STORE.fleet_events)[:200]})
        if p == "/agent/audit_log":
            from pathlib import Path as _P
            import json as _j
            log = _P.home() / ".mace-agent" / "audit.log"
            entries = []
            if log.exists():
                for line in log.read_text().splitlines()[-200:]:
                    try: entries.append(_j.loads(line))
                    except Exception: continue
            return self._json({"entries": entries})
        if p == "/healthz":
            return self._json({"ok": True, "reports_held": len(STORE.reports)})
        if p.startswith("/agent/compliance/industry/"):
            from ..compliance import profile_for_industry, framework_status
            key = p.rsplit("/", 1)[-1]
            prof = profile_for_industry(key)
            if not prof:
                return self._json({"error": "industry_not_found", "key": key}, 404)
            statuses = {f: framework_status(f) for f in prof.required_frameworks}
            return self._json({
                "key": key, "name": prof.name,
                "required_frameworks": prof.required_frameworks,
                "notable_buyers": prof.notable_buyers,
                "notes": prof.notes,
                "framework_status": statuses,
            })
        if p == "/agent/nexus/status":
            from .. import nexus
            return self._json(nexus.status())
        if p == "/agent/playbooks":
            from ..soar import list_builtin_playbooks
            return self._json({"playbooks": list_builtin_playbooks()})
        return self._json({"error": "not_found", "path": p}, 404)

    # ── POST ─────────────────────────────────────────────────────────
    def do_POST(self):
        p = self.path.split("?", 1)[0]
        body = self._read_body()
        if p in ("/agent/report", "/ingest"):
            return self._json(STORE.ingest(body))
        if p == "/agent/macey":
            try:
                from ..macey import ask
                resp = ask(body.get("prompt", ""))
                return self._json(resp.to_dict())
            except Exception as e:
                return self._json({"text": f"(Macey error: {e})", "provider": "error"}, 500)
        if p == "/agent/feeds/update":
            from ..feeds import update_all
            results = update_all(api_key=os.environ.get("NVD_API_KEY"),
                                  refresh_stig_catalog=bool(body.get("stig", False)))
            return self._json({"updates": [r.__dict__ for r in results]})
        if p == "/agent/remediate":
            return self._json(STORE.approve_remediation(
                body.get("action", {}), body.get("host_id", "unknown")))
        if p == "/agent/fix":
            # Run a fix immediately (mode: plan | ask | auto)
            from ..macey.tools import tool_fix_finding
            return self._json(tool_fix_finding(
                host_id=body.get("host_id", ""),
                finding_id=body.get("finding_id", ""),
                execute=bool(body.get("execute", False)),
                mode=body.get("mode", "plan"),
            ))
        if p == "/agent/ask_macey_fix":
            # Ask Macey to write a guided fix narrative for a finding
            try:
                from ..macey import ask
                prompt = (f"Explain how to fix finding {body.get('finding_id')} "
                          f"on device {body.get('host_id')}. Give exact steps "
                          f"and include the shell command. Keep it under 8 lines.")
                resp = ask(prompt)
                return self._json(resp.to_dict())
            except Exception as e:
                return self._json({"text": f"(Macey error: {e})"}, 500)
        if p == "/agent/scan":
            # In production this queues a "scan now" instruction via a return-channel
            # (websocket / MQTT / SQS) keyed by host_id.
            STORE.fleet_events.appendleft({
                "ts": time.time(), "kind": "scan_requested",
                "host_id": body.get("host_id", "fleet"),
            })
            return self._json({"queued": True, "host_id": body.get("host_id", "fleet")})
        if p == "/cloud/aws/provision":
            from ..cloud.aws_provision import provision_stack
            return self._json(provision_stack(body))
        return self._json({"error": "not_found", "path": p}, 404)

    # ── dashboard ────────────────────────────────────────────────────
    def _serve_dashboard(self):
        global DASHBOARD_HTML_PATH
        if not DASHBOARD_HTML_PATH:
            # Search a few locations: source path, PyInstaller bundle (sys._MEIPASS)
            candidates = [
                Path(__file__).parent / "dashboard.html",
                Path(getattr(__import__("sys"), "_MEIPASS", ""))
                    / "mace_platform" / "agent" / "api" / "dashboard.html",
                Path(__file__).parent.parent.parent
                    / "mace_platform" / "agent" / "api" / "dashboard.html",
            ]
            for c in candidates:
                if c and c.exists():
                    DASHBOARD_HTML_PATH = c
                    break
        try:
            html = DASHBOARD_HTML_PATH.read_text() if DASHBOARD_HTML_PATH else None
        except Exception:
            html = None
        if not html:
            html = ("<!doctype html><html><body style='font-family:system-ui;"
                    "padding:40px;background:#0b1220;color:#fff'><h1>MACE — Dashboard not bundled</h1>"
                    "<p>Hit <code>/agent/reports</code> for the JSON, or rebuild with the latest spec.</p>"
                    "</body></html>")
        body = html.encode("utf-8")
        self.send_response(200); self._cors()
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers(); self.wfile.write(body)


# ── Server runner ────────────────────────────────────────────────────

class _ThreadedHTTPServer(socketserver.ThreadingMixIn, socketserver.TCPServer):
    allow_reuse_address = True
    daemon_threads = True


def run_server(host: str = "127.0.0.1", port: int = 8765,
                storage_dir: Optional[str] = None) -> Tuple[_ThreadedHTTPServer, threading.Thread]:
    if storage_dir:
        STORE.storage_dir = Path(storage_dir)
        STORE.storage_dir.mkdir(parents=True, exist_ok=True)
    srv = _ThreadedHTTPServer((host, port), _Handler)
    t = threading.Thread(target=srv.serve_forever, name="mace-agent-api", daemon=True)
    t.start()
    return srv, t
