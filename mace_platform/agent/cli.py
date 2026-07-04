"""
mace-agent — command-line entry point for the UnifiedSec MACE Endpoint Agent.

Usage:
  python -m mace_platform.agent.cli scan
  python -m mace_platform.agent.cli scan --json report.json
  python -m mace_platform.agent.cli scan --simulate linux
  python -m mace_platform.agent.cli post --url http://localhost:8765/ingest
"""
from __future__ import annotations
import argparse
import json
import sys
import urllib.request

from .runner import scan_this_device, scan_simulated


def _emit(report, out_path=None, summary_only=False) -> None:
    payload = report.to_dict() if not summary_only else report.summary.__dict__
    text = json.dumps(payload, default=str, indent=2, sort_keys=True)
    if out_path:
        with open(out_path, "w") as f:
            f.write(text)
        print(f"Report written: {out_path}", file=sys.stderr)
    else:
        print(text)


RESET = "\033[0m"
BOLD = "\033[1m"
DIM = "\033[2m"
def _c(name):
    return {"crit": "\033[91m", "high": "\033[93m", "med": "\033[33m",
            "low": "\033[32m", "info": "\033[90m", "head": "\033[96m",
            "ok": "\033[92m", "warn": "\033[33m"}.get(name, "")
def _sev_color(sev):
    return _c({"CRITICAL":"crit","HIGH":"high","MEDIUM":"med","LOW":"low","INFO":"info"}.get(sev,"info"))


def _export_csv(report, path: str) -> None:
    """Write CVE findings as CSV — for managers / stakeholders."""
    import csv
    with open(path, "w", newline="") as f:
        w = csv.writer(f)
        w.writerow(["host", "platform", "cve_id", "severity", "cvss_v3", "epss",
                    "exploit_status", "app", "installed_version", "fixed_version",
                    "patch_available", "description", "remediation", "remediation_cmd"])
        for v in report.vulns.hits:
            w.writerow([report.hostname, report.platform, v.cve_id, v.severity,
                        v.cvss_v3, v.epss_score, v.exploit_status,
                        v.affected_component, v.installed_version, v.fixed_version,
                        v.patch_available, v.description, v.remediation, v.remediation_cmd])


def _export_html(report, path: str) -> None:
    """Write a polished, printable HTML executive report."""
    s = report.summary
    hw = report.hardware
    sw = report.software
    def esc(x): return (str(x) if x is not None else "").replace("&","&amp;").replace("<","&lt;").replace(">","&gt;")
    sev_cls = lambda x: {"CRITICAL":"crit","HIGH":"high","MEDIUM":"med","LOW":"low"}.get(x,"info")
    html = f"""<!doctype html><html><head><meta charset="utf-8">
<title>MACE Report — {esc(report.hostname)}</title>
<style>
body{{font-family:-apple-system,Inter,sans-serif;background:#fff;color:#0b1220;padding:40px;max-width:1000px;margin:auto}}
h1{{font-size:26px;border-bottom:3px solid #3b82f6;padding-bottom:8px}}
h2{{font-size:17px;margin-top:28px;color:#1b263f}}
table{{width:100%;border-collapse:collapse;margin:8px 0;font-size:13px}}
th{{text-align:left;padding:6px;background:#f3f4f6;border-bottom:1px solid #d1d5db}}
td{{padding:6px;border-bottom:1px solid #f1f1f1}}
.kpi{{display:inline-block;padding:10px 16px;background:#f9fafb;border:1px solid #e5e7eb;border-radius:8px;margin-right:8px;margin-bottom:8px}}
.kpi b{{display:block;font-size:22px}}
.crit{{color:#ef4444;font-weight:700}}.high{{color:#fb923c;font-weight:700}}
.med{{color:#f59e0b}}.low{{color:#22c55e}}.info{{color:#6b7280}}
code{{background:#f5f5f7;padding:1px 5px;border-radius:3px;font-size:12px}}
.footer{{margin-top:40px;padding-top:14px;border-top:1px solid #ccc;font-size:11px;color:#6b7280}}
</style></head><body>
<h1>UnifiedSec MACE — Device Report</h1>
<p><b>{esc(report.hostname)}</b> ({esc(report.platform)}, {'real scan' if report.real_collectors else 'simulated profile'})<br/>
Captured {esc(report.captured_at)}</p>
<div>
  <div class="kpi"><b class="{sev_cls(s.severity)}">{s.device_risk_score}/10</b>Device risk ({s.severity})</div>
  <div class="kpi"><b>{s.swam_apps}</b>Apps</div>
  <div class="kpi"><b>{s.vuln_count}</b>CVEs ({s.vuln_critical} CRIT, {s.vuln_high} HIGH)</div>
  <div class="kpi"><b>{int(s.stig_compliance_ratio*100)}%</b>STIG compliance</div>
</div>
<h2>Hardware</h2>
<table>
<tr><th>Manufacturer</th><td>{esc(hw.manufacturer)}</td></tr>
<tr><th>Model</th><td>{esc(hw.model)}</td></tr>
<tr><th>Chip / CPU</th><td>{esc(hw.chip)} ({hw.cpu_cores} cores)</td></tr>
<tr><th>Memory</th><td>{hw.memory_gb} GB</td></tr>
<tr><th>Serial</th><td>{esc(hw.serial_number)}</td></tr>
<tr><th>Firmware</th><td>{esc(hw.firmware_version)}</td></tr>
<tr><th>Disk encryption</th><td>{'ON 🔒' if hw.disk_encryption else 'OFF ⚠'}</td></tr>
<tr><th>Secure boot</th><td>{'ON' if hw.secure_boot else 'OFF'}</td></tr>
<tr><th>Primary IP</th><td>{esc(hw.primary_ip)}</td></tr>
<tr><th>Primary MAC</th><td>{esc(hw.primary_mac)}</td></tr>
</table>
<h2>Network interfaces</h2>
<table><tr><th>Interface</th><th>Type</th><th>IP</th><th>MAC</th></tr>
""" + "".join(
    f"<tr><td>{esc(i.get('name'))}</td><td>{esc(i.get('type'))}</td><td>{esc(i.get('ip'))}</td><td>{esc(i.get('mac'))}</td></tr>"
    for i in hw.interfaces) + f"""</table>
<h2>Vulnerabilities ({len(report.vulns.hits)})</h2>
<table><tr><th>CVE</th><th>Severity</th><th>CVSS</th><th>EPSS</th><th>App</th><th>Installed → Fixed</th><th>Remediation</th></tr>
""" + "".join(
    f"<tr><td>{esc(v.cve_id)}</td><td class='{sev_cls(v.severity)}'>{esc(v.severity)}</td>"
    f"<td>{v.cvss_v3}</td><td>{v.epss_score:.2f}</td><td>{esc(v.affected_component)}</td>"
    f"<td>{esc(v.installed_version)} → {esc(v.fixed_version)}</td>"
    f"<td>{esc(v.remediation)}<br/><code>{esc(v.remediation_cmd)}</code></td></tr>"
    for v in report.vulns.hits) + f"""</table>
<h2>STIG / CIS checks ({len(report.stig.checks)})</h2>
<table><tr><th>ID</th><th>Title</th><th>Category</th><th>Result</th><th>Remediation</th></tr>
""" + "".join(
    f"<tr><td>{esc(c.check_id)}</td><td>{esc(c.title)}</td><td>{esc(c.category)}</td>"
    f"<td class='{('crit' if c.result=='FAIL' else 'low')}'>{esc(c.result)}</td>"
    f"<td>{esc(c.remediation) if c.result=='FAIL' else ''}</td></tr>"
    for c in report.stig.checks) + f"""</table>
<h2>Installed software ({len(sw.applications)})</h2>
<table><tr><th>Name</th><th>Version</th><th>Vendor</th><th>Source</th></tr>
""" + "".join(
    f"<tr><td>{esc(a.name)}</td><td>{esc(a.version)}</td><td>{esc(a.vendor)}</td><td>{esc(a.source)}</td></tr>"
    for a in sw.applications) + f"""</table>
<div class="footer">UnifiedSec MACE v2.1 — Report SHA-256: {esc(report.report_hash)}<br/>
Patent IN/2026/UNISEC/MACE-001 + PCT (US · CA · EU · UAE · IN)</div>
</body></html>"""
    with open(path, "w") as f:
        f.write(html)


def _print_summary(report) -> None:
    s = report.summary
    print()
    print(f"  {BOLD}{_c('head')}╭─ Device Scan Summary ─────────────────────────────────────────╮{RESET}")
    print(f"  {_c('head')}│{RESET} Host           : {BOLD}{report.hostname}{RESET} "
          f"({report.platform}, {_c('ok') if report.real_collectors else _c('warn')}{'REAL scan' if report.real_collectors else 'simulated'}{RESET})")
    print(f"  {_c('head')}│{RESET} Hardware       : {report.hardware.manufacturer} {report.hardware.model}")
    print(f"  {_c('head')}│{RESET} CPU / Memory   : {report.hardware.chip} ({report.hardware.cpu_cores} cores) · {report.hardware.memory_gb} GB")
    print(f"  {_c('head')}│{RESET} Primary IP/MAC : {report.hardware.primary_ip} · {report.hardware.primary_mac}")
    print(f"  {_c('head')}│{RESET} OS             : {report.software.os_name} {report.software.os_version} {report.software.os_build}")
    print(f"  {_c('head')}│{RESET} Encryption     : {'🔒 ON' if report.hardware.disk_encryption else '⚠ OFF'}   "
          f"Secure Boot: {'✓' if report.hardware.secure_boot else '✗'}   "
          f"TPM: {'✓' if report.hardware.tpm_present else '–'}")
    print(f"  {_c('head')}├───────────────────────────────────────────────────────────────┤{RESET}")
    print(f"  {_c('head')}│{RESET} Hardware components : {BOLD}{s.hwam_assets}{RESET} "
          f"({len(report.hardware.disks)} disks, {len(report.hardware.interfaces)} NICs, "
          f"{len(report.hardware.peripherals)} peripherals)")
    print(f"  {_c('head')}│{RESET} Apps installed       : {BOLD}{s.swam_apps}{RESET}     "
          f"Services: {len(report.software.services)}   Listening ports: {len(report.software.open_ports)}")
    stig_pct = int(s.stig_compliance_ratio*100)
    stig_col = _c('ok') if stig_pct >= 80 else _c('warn') if stig_pct >= 50 else _c('crit')
    print(f"  {_c('head')}│{RESET} STIG compliance      : {stig_col}{stig_pct}%{RESET}   "
          f"({s.stig_pass} pass / {s.stig_fail} fail)")
    print(f"  {_c('head')}│{RESET} Vulnerabilities      : {BOLD}{s.vuln_count}{RESET} matched   "
          f"{_c('crit')}{s.vuln_critical} CRITICAL{RESET} · "
          f"{_c('high')}{s.vuln_high} HIGH{RESET}")
    risk_col = _sev_color(s.severity)
    print(f"  {_c('head')}│{RESET} {BOLD}Device risk score    : {risk_col}{s.device_risk_score}/10  [{s.severity}]{RESET}")
    print(f"  {_c('head')}│{RESET} Report hash          : {report.report_hash[:24]}…")
    print(f"  {_c('head')}╰───────────────────────────────────────────────────────────────╯{RESET}")
    print()
    _print_vulns_table(report)
    _print_stig_failures(report)
    _print_remediation(report)


def _print_vulns_table(report) -> None:
    hits = report.vulns.hits
    if not hits:
        print(f"  {_c('ok')}✓ No CVE matches against current SWAM inventory.{RESET}\n")
        return
    print(f"  {BOLD}🐛 Vulnerabilities found ({len(hits)} total){RESET}")
    print(f"  {DIM}{'CVE ID':<18} {'SEV':<8} {'CVSS':>5}  {'App':<24} {'Installed':<14} → {'Fixed':<12} EPSS{RESET}")
    print(f"  {DIM}{'─'*100}{RESET}")
    for v in hits[:20]:
        col = _sev_color(v.severity)
        print(f"  {v.cve_id:<18} {col}{v.severity:<8}{RESET} "
              f"{v.cvss_v3:>5.1f}  {v.affected_component[:23]:<24} {v.installed_version[:13]:<14} → "
              f"{v.fixed_version[:11]:<12} {v.epss_score:>4.2f}")
        if v.description:
            print(f"      {DIM}{v.description[:96]}{RESET}")
        if v.remediation:
            print(f"      {_c('ok')}Fix:{RESET} {v.remediation[:96]}")
        if v.remediation_cmd:
            print(f"      {_c('head')}$ {v.remediation_cmd[:96]}{RESET}")
        print()
    if len(hits) > 20:
        print(f"  {DIM}… and {len(hits)-20} more. View all in the dashboard.{RESET}\n")


def _print_stig_failures(report) -> None:
    fails = [c for c in report.stig.checks if c.result == "FAIL"]
    if not fails:
        print(f"  {_c('ok')}✓ All STIG / CIS checks passing.{RESET}\n")
        return
    print(f"  {BOLD}📋 STIG / CIS failures ({len(fails)}){RESET}")
    for c in fails[:15]:
        col = _c('crit') if c.category == "CAT_I" else _c('warn') if c.category == "CAT_II" else _c('info')
        print(f"  {col}[{c.category}]{RESET} {c.check_id}: {c.title}")
        if c.remediation:
            print(f"    {DIM}Fix:{RESET} {c.remediation[:100]}")
    print()


def _print_remediation(report) -> None:
    plan = report.remediation_plan or {}
    actions = plan.get("actions", [])
    if not actions:
        return
    print(f"  {BOLD}🎯 Prioritised remediation plan ({len(actions)} actions){RESET}")
    print(f"  {DIM}{'#':>3}  {'PRI':<5} {'SEV':<8}  Action{RESET}")
    print(f"  {DIM}{'─'*100}{RESET}")
    for i, a in enumerate(actions[:10], 1):
        col = _sev_color(a.get("severity", "INFO"))
        pri = a.get("priority_score", 0)
        print(f"  {i:>3}.  {col}{pri:>4.1f}  {a.get('severity','?'):<8}{RESET}  {a.get('title','')[:80]}")
        if a.get("remediation_cmd"):
            print(f"       {_c('head')}$ {a['remediation_cmd'][:90]}{RESET}")
    print()


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="mace-agent",
        description="UnifiedSec MACE Endpoint Agent — HWAM + SWAM + STIG + Vuln scanner.")
    sub = p.add_subparsers(dest="cmd", required=True)

    sc = sub.add_parser("scan", help="Scan this device (or simulate another OS).")
    sc.add_argument("--json", dest="out", help="Write full report JSON to this path.")
    sc.add_argument("--csv",  dest="csv_out", help="Write CVE findings as CSV to this path.")
    sc.add_argument("--html", dest="html_out", help="Write a printable HTML executive report to this path.")
    sc.add_argument("--simulate", choices=["darwin", "linux", "windows"],
                    help="Run a simulated scan for a different OS.")
    sc.add_argument("--summary", action="store_true", help="Print only the summary block.")
    sc.add_argument("--quiet", action="store_true", help="Suppress human-readable summary.")

    po = sub.add_parser("post", help="Scan this device and POST the report to an ingest URL.")
    po.add_argument("--url", required=True, help="HTTP endpoint that accepts the report.")
    po.add_argument("--simulate", choices=["darwin", "linux", "windows"])

    dn = sub.add_parser("daemon", help="Run in real-time monitoring mode.")
    dn.add_argument("--url", help="Optional ingest URL — POST each rescan there.")
    dn.add_argument("--max-seconds", type=int, default=None,
                    help="Stop after N seconds (for demos / tests).")
    dn.add_argument("--debounce", type=int, default=30,
                    help="Min seconds between rescans after a triggering event.")
    dn.add_argument("--floor", type=int, default=600,
                    help="Force a rescan at least this often even with no events.")

    sub.add_parser("gui", help="Launch the desktop GUI scanner.")
    sub.add_parser("android", help="Scan a connected Android device (or simulate).")
    sub.add_parser("ios", help="Scan a connected iOS device (or simulate).")

    vs = sub.add_parser("virus-scan", help="Deep virus / malware scan (replaces McAfee).")
    vs.add_argument("--deep", action="store_true",
                     help="Also delegate to ClamAV when installed (slower).")
    vs.add_argument("--quarantine", action="store_true",
                     help="Move any hit to ~/.mace-agent/quarantine/.")
    vs.add_argument("--json", dest="vs_json", help="Write findings as JSON.")

    np_ = sub.add_parser("network-protect",
                          help="Network protection (replaces Zscaler ZIA + ZPA + Umbrella).")
    np_.add_argument("action", choices=["status","enable","disable","policy"],
                      help="status | enable (install hosts-file sinkhole) | disable | policy (show built-in)")

    args = p.parse_args(argv)

    if args.cmd == "scan":
        report = scan_simulated(args.simulate) if args.simulate else scan_this_device()
        if not args.quiet:
            _print_summary(report)
        if args.summary:
            print(json.dumps(report.summary.__dict__, default=str, indent=2))
        if args.out:
            _emit(report, out_path=args.out)
        if args.csv_out:
            _export_csv(report, args.csv_out)
            print(f"  ✓ CVE findings written to {args.csv_out}", file=sys.stderr)
        if args.html_out:
            _export_html(report, args.html_out)
            print(f"  ✓ Executive HTML report written to {args.html_out}", file=sys.stderr)
        if args.quiet and not (args.out or args.csv_out or args.html_out):
            _emit(report)
        return 0

    if args.cmd == "post":
        report = scan_simulated(args.simulate) if args.simulate else scan_this_device()
        body = report.to_json().encode("utf-8")
        req = urllib.request.Request(args.url, data=body,
            headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=15) as resp:
                print(f"Posted {len(body)} bytes — HTTP {resp.status}")
        except Exception as e:
            print(f"POST failed: {e}", file=sys.stderr)
            return 2
        _print_summary(report)
        return 0

    if args.cmd == "daemon":
        from .daemon import run_daemon, RealtimeEvent
        def _on_event(ev: RealtimeEvent):
            print(f"  · {ev.kind:<13} {ev.source:<22} {ev.severity:<5} {ev.detail[:120]}",
                  file=sys.stderr)
        def _on_rescan(report):
            print(f"\n[rescan] {report.captured_at}  risk {report.summary.device_risk_score}/10 "
                  f"[{report.summary.severity}]", file=sys.stderr)
            top = (report.remediation_plan or {}).get("actions", [])[:3]
            for a in top:
                print(f"   → {a['priority_score']:>4.1f}  {a['title']}", file=sys.stderr)
        print("Real-time MACE Endpoint Agent running. Ctrl-C to stop.", file=sys.stderr)
        run_daemon(ingest_url=args.url, on_event=_on_event, on_rescan=_on_rescan,
                   rescan_debounce_s=args.debounce, rescan_floor_s=args.floor,
                   max_seconds=args.max_seconds)
        return 0

    if args.cmd == "gui":
        from .gui import main as gui_main
        gui_main()
        return 0

    if args.cmd == "android":
        from .mobile.android import scan_android
        r = scan_android()
        _print_summary(r); _emit(r)
        return 0

    if args.cmd == "ios":
        from .mobile.ios import scan_ios
        r = scan_ios()
        _print_summary(r); _emit(r)
        return 0

    if args.cmd == "virus-scan":
        from . import malware as malware_mod
        from .edr import scan_memory_behaviour
        from .deception import check_tokens
        print(f"\n  {BOLD}🦠 MACE Virus & Malware Scan{RESET}")
        print(f"  {DIM}Scanning IOC paths, persistence, processes, honey tokens…{RESET}")
        m = malware_mod.scan(deep=args.deep)
        edr = scan_memory_behaviour()
        honey = check_tokens()
        # Quarantine if requested
        if args.quarantine and m.findings:
            qdir = Path.home() / ".mace-agent" / "quarantine"
            qdir.mkdir(parents=True, exist_ok=True)
            for f in m.findings:
                if f.path:
                    try:
                        import shutil
                        shutil.move(f.path, qdir / Path(f.path).name)
                        print(f"  {_c('warn')}quarantined{RESET} {f.path}")
                    except Exception as e:
                        print(f"  {_c('crit')}failed{RESET} to quarantine {f.path}: {e}")
        # Print
        print(f"\n  {BOLD}Signature / IOC scan:{RESET}  {m.files_scanned} items checked in {m.elapsed_s:.1f}s")
        if m.findings:
            for f in m.findings:
                col = _sev_color(f.severity)
                print(f"  {col}{f.severity:<9}{RESET} {f.family} — {f.description}")
                if f.path: print(f"           path: {f.path}")
                if f.remediation: print(f"           fix:  {f.remediation}")
        else:
            print(f"  {_c('ok')}✓ No signature / IOC matches.{RESET}")
        print(f"\n  {BOLD}Behavioural EDR:{RESET}  {edr.processes_examined} processes")
        if edr.hits:
            for h in edr.hits:
                col = _sev_color(h.severity)
                print(f"  {col}{h.severity:<9}{RESET} {h.technique} · {h.title}")
                print(f"           pid {h.pid} {h.process}  (parent {h.parent})")
                print(f"           cmd: {h.cmdline[:90]}")
        else:
            print(f"  {_c('ok')}✓ No behavioural anomalies.{RESET}")
        print(f"\n  {BOLD}Honey-tokens:{RESET}")
        if honey:
            for a in honey:
                print(f"  {_c('crit')}{a.severity:<9}{RESET} {a.token} — {a.detail}")
        else:
            print(f"  {_c('ok')}✓ All honey tokens intact (no breach indicators).{RESET}")
        if args.vs_json:
            import json as _j
            bundle = {"malware": m.to_dict(), "edr": edr.to_dict(),
                       "honeytokens": [a.__dict__ for a in honey]}
            Path(args.vs_json).write_text(_j.dumps(bundle, default=str, indent=2))
            print(f"\n  ✓ Wrote {args.vs_json}")
        return 0

    if args.cmd == "network-protect":
        from . import dns_filter
        if args.action == "status":
            p = dns_filter._hosts_path()
            try:
                txt = p.read_text()
                active = dns_filter.MARKER_BEGIN in txt
            except Exception:
                active = False
            print(f"\n  {BOLD}🛡 MACE Network Protection{RESET}")
            print(f"  Status: {_c('ok')+'ACTIVE'+RESET if active else _c('warn')+'INACTIVE'+RESET}")
            print(f"  Bundled blocklist: {len(dns_filter.BUNDLED_BLOCKLIST)} domains")
            print(f"  Mode: hosts-file sinkhole at {p}")
            return 0
        if args.action == "enable":
            r = dns_filter.install_hosts()
            print(f"  {_c('ok' if r.installed else 'crit')}{('Installed' if r.installed else 'Failed')}{RESET}: {r.domains_blocked} domains blocked.")
            if not r.installed:
                print(f"  Note: requires sudo (writes to /etc/hosts).")
            return 0 if r.installed else 2
        if args.action == "disable":
            r = dns_filter.uninstall_hosts()
            print(f"  {_c('ok' if r.installed else 'warn')}{('Removed' if r.installed else 'No active rules')}.{RESET}")
            return 0
        if args.action == "policy":
            from . import ztna
            s = ztna.status_summary()
            print(f"\n  {BOLD}Tenant {s['tenant']} · policy v{s['version']}{RESET}")
            print(f"  Rules loaded   : {s['rules_loaded']}")
            print(f"  Blocked cats   : {', '.join(s['blocked_categories'])}")
            print(f"  Blocked domains ({len(s['blocked_domains'])}):")
            for d in s['blocked_domains'][:20]:
                print(f"    · {d}")
            return 0

    return 1


if __name__ == "__main__":
    raise SystemExit(main())
