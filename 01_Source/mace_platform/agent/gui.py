"""
MACE Endpoint Agent — desktop GUI.

A double-clickable window that lets non-engineers run a full scan from any
machine. Used as the entry point when the agent is packaged as a standalone
executable (mace-agent.exe / MACEAgent.app / mace-agent-linux).

Stdlib only (tkinter) so PyInstaller can freeze it without extra deps.
"""
from __future__ import annotations
import json
import threading
import tkinter as tk
import urllib.request
import webbrowser
from datetime import datetime
from pathlib import Path
from tkinter import ttk, filedialog, messagebox
from typing import Optional

from .runner import scan_this_device, scan_simulated


COLORS = {
    "bg":        "#0b1220",
    "panel":     "#111b2e",
    "text":      "#e6edf3",
    "muted":     "#8b949e",
    "accent":    "#3b82f6",
    "critical":  "#ef4444",
    "high":      "#f59e0b",
    "medium":    "#fbbf24",
    "low":       "#10b981",
    "good":      "#22c55e",
}


class MACEAgentGUI(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title("UnifiedSec MACE Endpoint Agent")
        self.geometry("780x620")
        self.configure(bg=COLORS["bg"])
        self.minsize(720, 560)
        self._report = None
        self._build()

    # ── layout ───────────────────────────────────────────────────────
    def _build(self):
        header = tk.Frame(self, bg=COLORS["bg"])
        header.pack(fill="x", padx=24, pady=(24, 8))
        tk.Label(header, text="UnifiedSec MACE Endpoint Agent",
                 font=("Helvetica", 18, "bold"),
                 fg=COLORS["text"], bg=COLORS["bg"]).pack(anchor="w")
        tk.Label(header,
                 text="HWAM + SWAM + STIG + Vulnerability scan — replaces CrowdStrike + Tenable",
                 font=("Helvetica", 11),
                 fg=COLORS["muted"], bg=COLORS["bg"]).pack(anchor="w", pady=(2, 0))

        # Controls
        ctrl = tk.Frame(self, bg=COLORS["bg"])
        ctrl.pack(fill="x", padx=24, pady=8)
        self.btn_scan = tk.Button(ctrl, text="▶  Scan This Device",
                                  command=self._scan_real, bg=COLORS["accent"], fg="white",
                                  activebackground="#2563eb", activeforeground="white",
                                  bd=0, padx=18, pady=10,
                                  font=("Helvetica", 11, "bold"))
        self.btn_scan.pack(side="left")

        self.sim_var = tk.StringVar(value="")
        sim_menu = ttk.Combobox(ctrl, textvariable=self.sim_var,
            values=["", "linux", "windows", "darwin"], width=12, state="readonly")
        sim_menu.pack(side="left", padx=(12, 6))
        tk.Label(ctrl, text="(simulate OS)", bg=COLORS["bg"], fg=COLORS["muted"]).pack(side="left")

        self.btn_send = tk.Button(ctrl, text="Send to MACE…", command=self._send_to_mace,
                                  bg=COLORS["panel"], fg=COLORS["text"], bd=1, padx=12, pady=10)
        self.btn_send.pack(side="right")
        self.btn_save = tk.Button(ctrl, text="Save Report…", command=self._save_report,
                                  bg=COLORS["panel"], fg=COLORS["text"], bd=1, padx=12, pady=10)
        self.btn_save.pack(side="right", padx=(0, 8))

        # Summary cards
        cards = tk.Frame(self, bg=COLORS["bg"])
        cards.pack(fill="x", padx=24, pady=12)
        self.card_risk = self._card(cards, "Device Risk", "—", "—")
        self.card_hwam = self._card(cards, "HWAM Assets", "—", "")
        self.card_swam = self._card(cards, "SWAM Apps", "—", "")
        self.card_stig = self._card(cards, "STIG Compliance", "—", "")
        self.card_vuln = self._card(cards, "Vulnerabilities", "—", "")
        for c in (self.card_risk, self.card_hwam, self.card_swam, self.card_stig, self.card_vuln):
            c.pack(side="left", expand=True, fill="both", padx=4)

        # Log / results
        log_panel = tk.Frame(self, bg=COLORS["panel"])
        log_panel.pack(fill="both", expand=True, padx=24, pady=(8, 18))
        tk.Label(log_panel, text="Scan output", bg=COLORS["panel"], fg=COLORS["muted"],
                 font=("Helvetica", 10, "bold")).pack(anchor="w", padx=12, pady=(8, 4))
        self.log = tk.Text(log_panel, bg="#0d1626", fg=COLORS["text"], bd=0,
                           font=("Menlo", 10), height=14, padx=10, pady=8)
        self.log.pack(fill="both", expand=True, padx=12, pady=(0, 12))
        self._write_log("Ready. Click ‘Scan This Device’ to start.\n"
                        "Agent runs entirely on this machine — no data leaves until you ‘Send to MACE’.\n")

        # Footer
        ftr = tk.Frame(self, bg=COLORS["bg"])
        ftr.pack(fill="x", padx=24, pady=(0, 12))
        tk.Label(ftr,
                 text="UnifiedSec Technologies · Patent: IN/2026/UNISEC/MACE-001 + PCT",
                 fg=COLORS["muted"], bg=COLORS["bg"], font=("Helvetica", 9)).pack(side="left")
        self.status = tk.Label(ftr, text="idle", fg=COLORS["muted"], bg=COLORS["bg"],
                                font=("Helvetica", 9))
        self.status.pack(side="right")

    def _card(self, parent, title, value, sub):
        f = tk.Frame(parent, bg=COLORS["panel"])
        f.title_lbl = tk.Label(f, text=title, bg=COLORS["panel"], fg=COLORS["muted"],
                                font=("Helvetica", 9, "bold"))
        f.title_lbl.pack(anchor="w", padx=12, pady=(10, 0))
        f.value_lbl = tk.Label(f, text=value, bg=COLORS["panel"], fg=COLORS["text"],
                                font=("Helvetica", 20, "bold"))
        f.value_lbl.pack(anchor="w", padx=12, pady=(2, 0))
        f.sub_lbl = tk.Label(f, text=sub, bg=COLORS["panel"], fg=COLORS["muted"],
                              font=("Helvetica", 9))
        f.sub_lbl.pack(anchor="w", padx=12, pady=(0, 10))
        return f

    # ── actions ──────────────────────────────────────────────────────
    def _write_log(self, msg):
        self.log.insert("end", msg)
        self.log.see("end")
        self.update_idletasks()

    def _set_status(self, text):
        self.status.config(text=text)
        self.update_idletasks()

    def _scan_real(self):
        self.btn_scan.config(state="disabled")
        self._set_status("scanning…")
        self._write_log(f"\n[{_now()}] Starting full scan (HWAM + SWAM + STIG + Vuln)…\n")
        simulate = self.sim_var.get().strip() or None
        threading.Thread(target=self._scan_thread, args=(simulate,), daemon=True).start()

    def _scan_thread(self, simulate: Optional[str]):
        try:
            if simulate:
                self._write_log(f"  → simulating {simulate} platform\n")
                report = scan_simulated(simulate)
            else:
                report = scan_this_device()
            self._report = report
            self.after(0, self._render_report, report)
        except Exception as e:
            self.after(0, self._scan_error, str(e))

    def _scan_error(self, msg):
        self._write_log(f"  ✗ scan failed: {msg}\n")
        self._set_status("error")
        self.btn_scan.config(state="normal")
        messagebox.showerror("Scan failed", msg)

    def _render_report(self, report):
        s = report.summary
        self._write_log(f"  ✓ scan complete in {datetime.utcnow().isoformat()}Z\n")
        self._write_log(f"    host {report.hostname} ({report.platform})  real={report.real_collectors}\n")
        self._write_log(f"    HWAM: {s.hwam_assets} components | SWAM: {s.swam_apps} apps\n")
        self._write_log(f"    STIG: {s.stig_pass}/{s.stig_pass + s.stig_fail} passing "
                        f"({s.stig_compliance_ratio*100:.1f}%)\n")
        self._write_log(f"    Vulns: {s.vuln_count} ({s.vuln_critical} CRITICAL, {s.vuln_high} HIGH)\n")
        self._write_log(f"    Device risk: {s.device_risk_score}/10  [{s.severity}]\n")
        if report.vulns.hits[:5]:
            self._write_log("    Top findings:\n")
            for h in report.vulns.hits[:5]:
                self._write_log(f"      · {h.cve_id}  CVSS {h.cvss_v3:>4.1f}  {h.severity:<8}  {h.affected_component} {h.installed_version}\n")
        self._write_log(f"    chain-of-custody hash: {report.report_hash[:24]}…\n")

        # Cards
        risk_color = (COLORS["critical"] if s.severity == "CRITICAL"
                      else COLORS["high"] if s.severity == "HIGH"
                      else COLORS["medium"] if s.severity == "MEDIUM"
                      else COLORS["good"])
        self.card_risk.value_lbl.config(text=f"{s.device_risk_score}", fg=risk_color)
        self.card_risk.sub_lbl.config(text=s.severity)
        self.card_hwam.value_lbl.config(text=str(s.hwam_assets))
        self.card_hwam.sub_lbl.config(text=f"{len(report.hardware.disks)} disk · {len(report.hardware.interfaces)} iface")
        self.card_swam.value_lbl.config(text=str(s.swam_apps))
        self.card_swam.sub_lbl.config(text=f"{report.software.os_name} {report.software.os_version}")
        self.card_stig.value_lbl.config(text=f"{int(s.stig_compliance_ratio*100)}%")
        self.card_stig.sub_lbl.config(text=f"{s.stig_pass} pass · {s.stig_fail} fail")
        self.card_vuln.value_lbl.config(text=str(s.vuln_count),
            fg=COLORS["critical"] if s.vuln_critical else COLORS["text"])
        self.card_vuln.sub_lbl.config(text=f"{s.vuln_critical} CRIT · {s.vuln_high} HIGH")

        self._set_status("done")
        self.btn_scan.config(state="normal")

    def _save_report(self):
        if not self._report:
            messagebox.showinfo("No report", "Run a scan first.")
            return
        path = filedialog.asksaveasfilename(
            defaultextension=".json",
            filetypes=[("MACE agent report", "*.json"), ("All files", "*.*")],
            initialfile=f"mace-report-{self._report.hostname}-{int(datetime.utcnow().timestamp())}.json")
        if not path: return
        Path(path).write_text(self._report.to_json())
        self._write_log(f"  → saved report: {path}\n")

    def _send_to_mace(self):
        if not self._report:
            messagebox.showinfo("No report", "Run a scan first.")
            return
        url = SendDialog(self).show()
        if not url: return
        body = self._report.to_json().encode("utf-8")
        try:
            req = urllib.request.Request(url, data=body,
                headers={"Content-Type": "application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=15) as resp:
                self._write_log(f"  → POST {url}  HTTP {resp.status}\n")
                webbrowser.open(url.rsplit("/", 1)[0] + "/")
        except Exception as e:
            messagebox.showerror("Send failed", str(e))


class SendDialog(tk.Toplevel):
    def __init__(self, master):
        super().__init__(master)
        self.title("Send to MACE")
        self.geometry("420x140")
        self.configure(bg=COLORS["bg"])
        self.result = None
        tk.Label(self, text="MACE ingest URL:", bg=COLORS["bg"], fg=COLORS["text"]).pack(pady=(16, 4))
        self.entry = tk.Entry(self, width=50)
        self.entry.insert(0, "http://localhost:8765/ingest")
        self.entry.pack()
        btns = tk.Frame(self, bg=COLORS["bg"])
        btns.pack(pady=12)
        tk.Button(btns, text="Cancel", command=self.destroy).pack(side="left", padx=6)
        tk.Button(btns, text="Send",
                   command=lambda: (setattr(self, 'result', self.entry.get()), self.destroy()),
                   bg=COLORS["accent"], fg="white").pack(side="left", padx=6)

    def show(self):
        self.transient(self.master); self.grab_set(); self.wait_window(self)
        return self.result


def _now() -> str:
    return datetime.utcnow().strftime("%H:%M:%S")


def main():
    MACEAgentGUI().mainloop()


if __name__ == "__main__":
    main()
