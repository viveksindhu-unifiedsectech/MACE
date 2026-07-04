"""
MACE demo launcher — local 1000-device demo.

This is the *demo* mode (not the .exe shipped to investors). It:
  1. Synthesizes a realistic 1,000-device enterprise fleet
     (engineering, finance, legal, sales, ops, security, mobile, K8s nodes)
  2. Generates a 30-day risk timeline per device
  3. Posts each device into the local API store
  4. Adds your real Mac scan as one more entry
  5. Opens the dashboard

The .exe (MACEAgent.app) is different — it does ONLY the real scan of
the host it runs on.

Run:
    cd /Users/viveksindhu/Desktop/Unified\\ Tech/CompleteUpdatedMaceProd/UnifiedSec_MACE_Complete
    python3 demo_launch.py
"""
from __future__ import annotations
import sys
import time
import webbrowser
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from mace_platform.agent.api.server import run_server, STORE
from mace_platform.agent.runner import scan_this_device
from mace_platform.agent.demo_fleet import (synthesize_fleet,
                                              synthesize_timeline,
                                              synthesize_fleet_events)


def _print_banner():
    print()
    print("  ┌─────────────────────────────────────────────────────────────────┐")
    print("  │  UnifiedSec MACE — Live Local Demo                              │")
    print("  │  1,000-device enterprise + your Mac (real scan)                 │")
    print("  │  Patent IN/2026/UNISEC/MACE-001 + PCT (US · CA · EU · UAE · IN) │")
    print("  └─────────────────────────────────────────────────────────────────┘")
    print()


def main(n_devices: int = 1000):
    _print_banner()
    print("  Starting MACE API + Dashboard on http://127.0.0.1:8765/")
    srv, _ = run_server(host="127.0.0.1", port=8765)
    time.sleep(0.5)

    # ── 1. Synthesize the fleet ───────────────────────────────────
    print(f"\n  Synthesizing {n_devices}-device enterprise fleet…")
    t0 = time.time()
    fleet = synthesize_fleet(n_devices)
    print(f"    ✓ {len(fleet)} devices generated in {time.time()-t0:.1f}s")

    # ── 2. Timeline (30 days × 4 samples/day per device) ───────────
    print("  Generating 30-day risk timeline per device…")
    timeline = synthesize_timeline(fleet, days=30)
    STORE.fleet_timeline = timeline  # consumed by /agent/fleet/timeline
    print(f"    ✓ {sum(len(v) for v in timeline.values())} timeline data points")

    # ── 3. Ingest the fleet ───────────────────────────────────────
    print("  Ingesting fleet into the API store…")
    for rep in fleet:
        STORE.ingest(rep)
    STORE.fleet_events.extendleft(synthesize_fleet_events(fleet, n=80)[::-1])
    print(f"    ✓ {len(STORE.reports)} devices in the dashboard")

    # ── 4. Real scan of this Mac ──────────────────────────────────
    print("  Running real scan of this Mac (this may take ~10-15 sec)…")
    try:
        r = scan_this_device()
        STORE.ingest(r.to_dict())
        s = r.summary
        print(f"    ✓ {r.hostname} — risk {s.device_risk_score}/10  [{s.severity}]")
        print(f"    {s.swam_apps} apps · {s.vuln_count} CVE matches · "
               f"STIG {int(s.stig_compliance_ratio*100)}%")
    except Exception as e:
        print(f"    ✗ real scan failed: {e}")

    print(f"\n  ✓ Fleet ready: {len(STORE.reports)} devices reporting.")
    print("  Opening dashboard…\n")
    webbrowser.open("http://127.0.0.1:8765/")

    print("  ▶  CLI:        python3 -m mace_platform.agent.cli scan --summary")
    print("  ▶  Virus scan: python3 -m mace_platform.agent.cli virus-scan")
    print("  ▶  Network:    python3 -m mace_platform.agent.cli network-protect status")
    print("  ▶  Daemon:     python3 -m mace_platform.agent.cli daemon --max-seconds 120")
    print("\n  Ctrl-C to stop.\n")
    try:
        while True: time.sleep(60)
    except KeyboardInterrupt:
        print("\n  Shutting down."); srv.shutdown()


if __name__ == "__main__":
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 10000
    main(n_devices=n)
