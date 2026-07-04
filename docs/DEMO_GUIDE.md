# MACE — How to Demo

## Option 1 — Easiest: double-click `MACEAgent.app`

1. Open Finder
2. Navigate to `/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/02_Built_Apps/`
3. Double-click **`MACEAgent.app`**
4. Wait ~5-10 seconds. Your default browser opens to `http://127.0.0.1:8765/`
5. Dashboard shows:
   - **Fleet tab** — your Mac (real scan) + 5 simulated devices (Linux, Windows, K8s, Android, iPhone)
   - **Device tab** — drill into any device for HWAM, SWAM, STIG, CVEs, malware, intrusion, remediation
   - **Macey tab** — chat with the GenAI assistant
   - **Compliance tab** — pick any industry (Airlines, US Banks, Healthcare…) to see framework coverage
   - **Feeds tab** — NVD / KEV / EPSS / STIG / threat-intel status

To stop: close the Terminal window the .app opened (or quit from the menu bar).

## Option 2 — Command line

```bash
cd /Users/viveksindhu/Desktop/Unified\ Tech/MACE_FINAL/02_Built_Apps
./mace-agent-macos-arm64
```

Same result — opens browser to the dashboard.

Or for a CLI-only scan:
```bash
./mace-agent-macos-arm64 scan --summary
```

## Option 3 — From source (for inspecting the code)

```bash
cd /Users/viveksindhu/Desktop/Unified\ Tech/MACE_FINAL/01_Source
python3 demo_launch.py
```

## Investor walkthrough script (10 minutes)

| Time | What to show |
|---|---|
| 0:00 | "Let me show you MACE live on this Mac." → double-click `MACEAgent.app` |
| 0:10 | Browser opens. Point at **Fleet** tab. "This is the real scan of this Mac plus a simulated fleet — Windows laptop, Linux server, Kubernetes node, Galaxy phone, iPhone. All one binary." |
| 1:00 | Click the highest-risk device. **Device** tab opens. Point at the prioritised remediation plan. "Algorithm-driven priority: the CVSS + EPSS + exploit-status + KEV flag all feed the score. The fix command for each is allowlisted for safe auto-apply." |
| 2:00 | Scroll to **HWAM** section. "Hardware-rooted attestation — only vendor on the market doing this. The Secure Enclave / TPM signs every report." |
| 3:00 | **Macey** tab. Type "list devices". → tool-use happens visibly. Then "explain CVE-2024-3094". → real-time answer. |
| 4:00 | **Compliance** tab → pick **Airlines** then **US Banks** then **India Gov / CII**. "Same product, every industry — and every jurisdiction's regulatory evidence is generated automatically by UREA." |
| 5:00 | "All this is built on a single 7-domain correlation algorithm. The patent is being filed today in US/CA/EU/UAE/IN, with 30 claims." |
| 6:00 | "Pre-revenue strategic exits in cybersec at this IP depth are $20-40M. Our path to that is in the GTM playbook in the docs folder." |

## If anything looks broken

| Symptom | Fix |
|---|---|
| Browser doesn't open | Manually visit `http://127.0.0.1:8765/` |
| Dashboard says "no devices" | Wait 10-15 seconds — the first scan takes a moment |
| Mac shows "unidentified developer" | Right-click `MACEAgent.app` → Open → Open anyway |
| Port 8765 in use | Stop the previous run (Activity Monitor → `mace-agent` → Quit) |
| .app crashes immediately | Run from terminal to see the error: `./MACEAgent.app/Contents/MacOS/mace-agent` |
