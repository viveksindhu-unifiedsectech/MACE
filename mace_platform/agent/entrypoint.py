"""
Frozen-executable entry point.

When the user double-clicks MACEAgent.app / mace-agent.exe /
mace-agent (Linux binary), this runs. It:

  1. Starts the in-process API + dashboard server on 127.0.0.1:8765.
  2. Runs a real scan of the local device + seeds a simulated fleet.
  3. Opens the dashboard in the user's default browser.
  4. Stays running until killed (so the dashboard keeps serving).

Power users can still pass CLI args — the entrypoint routes them straight
to mace_platform.agent.cli (so `mace-agent.exe daemon`, `mace-agent.exe
scan --json out.json`, etc. all work).

Headless by default — no tkinter, no Qt — so PyInstaller bundles don't
drag in OS-version-mismatched GUI frameworks. Cross-platform .exe/.app/
ELF builds are 5 MB total.
"""
from __future__ import annotations
import os
import sys
import threading
import time
import webbrowser


def _ensure_path() -> None:
    """Make the bundled package importable inside the PyInstaller bundle."""
    if getattr(sys, "frozen", False):
        bundle_dir = getattr(sys, "_MEIPASS", os.path.dirname(sys.executable))
        sys.path.insert(0, bundle_dir)


def _start_dashboard_and_open():
    from mace_platform.agent.api.server import run_server, STORE
    from mace_platform.agent.runner import scan_this_device, scan_simulated

    print()
    print("  ┌────────────────────────────────────────────────────────────────┐")
    print("  │  UnifiedSec MACE — Live Dashboard                              │")
    print("  │  http://127.0.0.1:8765/                                        │")
    print("  └────────────────────────────────────────────────────────────────┘")
    print("\n  Starting API server on 127.0.0.1:8765 …", flush=True)
    srv, _ = run_server("127.0.0.1", 8765)
    time.sleep(0.5)

    def _populate():
        # ── PRODUCTION MODE — REAL SCAN ONLY ────────────────────────────
        # When this .exe is shipped to investors / customers, it scans the
        # actual host it runs on. No dummy fleet — that's reserved for
        # demo_launch.py which is intended for the local 1000-device demo.
        print("  Running real scan of this device …", flush=True)
        try:
            r = scan_this_device()
            STORE.ingest(r.to_dict())
            print(f"    ✓ {r.hostname} — risk {r.summary.device_risk_score}/10  [{r.summary.severity}]",
                  flush=True)
            print(f"    {r.summary.swam_apps} apps · {r.summary.vuln_count} CVEs · "
                  f"STIG {int(r.summary.stig_compliance_ratio*100)}%", flush=True)
        except Exception as e:
            print(f"    ✗ real scan failed: {e}", flush=True)

    threading.Thread(target=_populate, daemon=True).start()

    # Open the browser after a beat
    def _open_browser():
        time.sleep(1.5)
        try: webbrowser.open("http://127.0.0.1:8765/")
        except Exception: pass
    threading.Thread(target=_open_browser, daemon=True).start()

    print("\n  Dashboard is now live. Browser opening …")
    print("  Press Ctrl-C in this window to stop.\n")
    try:
        while True:
            time.sleep(60)
    except KeyboardInterrupt:
        print("\n  Shutting down …")
        try: srv.shutdown()
        except Exception: pass


def main():
    _ensure_path()

    # CLI args → behave as the regular CLI (scan, daemon, etc.)
    if len(sys.argv) > 1:
        from mace_platform.agent.cli import main as cli_main
        sys.exit(cli_main())

    # No args → dashboard + browser
    _start_dashboard_and_open()


if __name__ == "__main__":
    main()
