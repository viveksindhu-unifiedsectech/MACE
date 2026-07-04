# MACE — Tech Stack + Step-by-Step Run Guide
**Everything you need installed + every command to run it, in order.**

---

## Part 1 — Tech stack inventory

This is *every* technology MACE uses, with the role each one plays.

### Runtime
| Tech | Why we use it | Version |
|---|---|---|
| **Python 3.11+** | Language for the agent + algorithm + dashboard server | 3.11 or 3.12 |
| **PyInstaller** | Bundles Python into a single .exe / .app | 6.20.0 |
| **Stdlib HTTP server** | The dashboard server (zero third-party deps) | (built into Python) |
| **Tailwind CSS via CDN** | Dashboard styling | 3.x |

### Endpoint platforms
| Platform | What we use to talk to it |
|---|---|
| macOS | `system_profiler`, `sw_vers`, `fdesetup`, `csrutil`, `defaults`, `launchctl`, `kextstat`, `lsof` |
| Linux | `/proc`, `/etc/os-release`, `dpkg` or `rpm`, `systemctl`, `inotifywait`, `journalctl` |
| Windows | `wmic`, `Get-CimInstance`, `Get-WinEvent`, Scheduled Task scheduler |
| Android | `adb shell getprop`, `pm list packages`, `dumpsys` |
| iOS | `libimobiledevice`: `ideviceinfo`, `ideviceinstaller` |

### External data feeds (auto-refreshed daily)
| Feed | Source | Used for |
|---|---|---|
| **NIST NVD 2.0** | services.nvd.nist.gov | CVE records + CVSS scores |
| **CISA KEV** | cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json | Tag actively-exploited CVEs |
| **FIRST.org EPSS** | epss.empiricalsecurity.com | Exploitation probability per CVE |
| **DISA STIG library** | dl.dod.cyber.mil | STIG XCCDF profiles |
| **abuse.ch URLhaus + Feodo** | urlhaus.abuse.ch | Known malware C2 IPs / URLs |
| **AlienVault OTX** | otx.alienvault.com | Free threat intel (needs API key) |
| **MISP** | (customer's own MISP instance) | Private threat intel |

### Build tools (only needed if rebuilding)
| Tool | Why | Install command |
|---|---|---|
| **PyInstaller** | Build .exe / .app / Linux binary | `pip install pyinstaller==6.20.0` |
| **python-docx** | Build the .docx documents | `pip install python-docx` |
| **python-pptx** | Build the .pptx slide decks | `pip install python-pptx` |
| **Android SDK** | Build the Android APK | Install Android Studio + accept SDK licenses (already done at `/opt/android-sdk`) |
| **Java JDK 17** | Required by Android Gradle | `brew install --cask temurin@17` (already done at `/Library/Java/JavaVirtualMachines/temurin-17.jdk`) |
| **Xcode** | Build the iOS .ipa | App Store → "Get Xcode" (12 GB) (already done at `/Applications/Xcode.app`) |
| **xcodegen** | Generate the Xcode project file | `brew install xcodegen` (still TODO — run in your terminal) |
| **Gradle 8.7+** | Android build orchestrator | Already at `/opt/gradle-8.7/bin/gradle` |

### Cloud / production deploy (optional — only needed when selling to customers)
| Tech | Role | Cost |
|---|---|---|
| **AWS EC2 t3.medium** | Runs the management plane | ~$30/mo |
| **AWS RDS PostgreSQL** | Multi-tenant database | ~$12/mo (db.t4g.micro) |
| **AWS S3 + Object Lock** | UREA chain-of-custody evidence storage | ~$3/mo |
| **AWS KMS** | Encryption keys per tenant | ~$3/mo |
| **AWS Route 53** | DNS for `mace.unifiedsec.io` | ~$0.50/mo |
| **AWS Certificate Manager** | TLS certs | free |
| **CloudWatch + Audit Manager** | Logs + SOC 2 evidence collection | ~$10/mo |
| **Total bare minimum** | | ~$60/mo |

---

## Part 2 — Run it on your own Mac, step-by-step

### A. See the demo (already running — verify)

```bash
# Check if demo is live
curl http://127.0.0.1:8765/healthz
# Expected output: {"ok": true, "reports_held": 10001}

# Open the dashboard in your browser
open http://127.0.0.1:8765/
```

If `curl` returns "couldn't connect", the demo isn't running. Start it:

```bash
cd "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/01_Source"
python3 demo_launch.py 10000
# Wait ~60 seconds for it to synthesize 10,000 devices
# Browser will auto-open
```

### B. Scan your own Mac (real, not simulated)

```bash
cd "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/02_Built_Apps"

# Quick summary (5 seconds)
./mace-agent-macos-arm64 scan --summary

# Full JSON report to a file
./mace-agent-macos-arm64 scan --json /tmp/my-mac.json

# Save a polished HTML report you can email
./mace-agent-macos-arm64 scan --html /tmp/my-mac.html

# CSV of every CVE found
./mace-agent-macos-arm64 scan --csv /tmp/my-mac.csv
```

### C. Run the security tools that replace McAfee + Zscaler

```bash
# Virus / malware scan
./mace-agent-macos-arm64 virus-scan
./mace-agent-macos-arm64 virus-scan --deep            # uses ClamAV if installed
./mace-agent-macos-arm64 virus-scan --quarantine      # auto-quarantines hits

# Network protection (Zscaler equivalent)
./mace-agent-macos-arm64 network-protect status      # is sinkhole on?
sudo ./mace-agent-macos-arm64 network-protect enable # install the hosts-file sinkhole
./mace-agent-macos-arm64 network-protect policy      # view ZTNA policy
sudo ./mace-agent-macos-arm64 network-protect disable
```

### D. Live monitoring daemon (replaces CrowdStrike)

```bash
./mace-agent-macos-arm64 daemon --max-seconds 120
# Watches FSEvents + process exec + logins in real time
# Re-scans on triggering events
```

### E. Just launch the GUI / dashboard from the binary

```bash
# Double-click MACEAgent.app in Finder
# OR
open "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/02_Built_Apps/MACEAgent.app"
# OR
./mace-agent-macos-arm64
```

All three open the dashboard in your default browser at `http://127.0.0.1:8765/`.

---

## Part 3 — Get the .exe / .app onto someone else's machine

### Send to your brother's Mac
```bash
# Just AirDrop or zip + email MACEAgent.app from MACE_FINAL/02_Built_Apps/
# He double-clicks. Done.
```

### Send to a Windows machine (your Dell laptop / investor / customer)

You can't build a Windows .exe on a Mac. Three options:

**Option 1 — Build on a real Windows machine (10 min)**
```powershell
# Copy MACE_FINAL/01_Source/ to the Windows machine via USB / OneDrive
# Install Python 3.11+ from python.org (tick "Add to PATH")
# Then in PowerShell as Administrator:
cd C:\path\to\01_Source
powershell -ExecutionPolicy Bypass -File mace_platform\agent\build\build_all.ps1
# Outputs: dist\mace-agent.exe (~5 MB)
```

**Option 2 — GitHub Actions cloud build (3 min, $0)**
```bash
cd "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/01_Source"
git init
git add .
git commit -m "v1.0"
git remote add origin git@github.com:unifiedsec/mace-agent.git
git push -u origin main
git tag v1.0.0
git push origin v1.0.0
# Then go to https://github.com/unifiedsec/mace-agent/actions
# Download artifact: mace-agent-windows.zip → contains mace-agent.exe
```

### Send to an Android phone

The Kotlin app is in `01_Source/mace_platform/agent/mobile/android_app/`.
Build the APK:
```bash
cd "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/01_Source/mace_platform/agent/mobile/android_app"
export ANDROID_HOME=/opt/android-sdk
export JAVA_HOME=/Library/Java/JavaVirtualMachines/temurin-17.jdk/Contents/Home
./gradlew assembleDebug
# Outputs: app/build/outputs/apk/debug/app-debug.apk
# AirDrop or email → on the phone, tap → install (you'll need to enable "Install from unknown sources")
```

### Send to an iPhone (you / exec demo)

Build the iOS .ipa locally:
```bash
# One-time in YOUR terminal (Claude can't — brew refuses to run as root):
brew install xcodegen

# Then build:
cd "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/01_Source/mace_platform/agent/mobile/ios_app"
bash build_ios.sh
# Outputs: ../../../dist/MACEAgent.ipa
```

To install on your iPhone you need either:
- Apple Developer account ($99/yr) → sign + use TestFlight
- AltStore / Sideloadly (free, sideloads via cable + Apple ID — 3 apps max, must re-sign weekly)
- Or just record the dashboard demo from your Mac while showing the simulated iPhone in the fleet

---

## Part 4 — Deploy the management plane to real production

### Step 1 — Make sure you have an AWS account
1. Go to https://aws.amazon.com → Sign up
2. Add credit card + phone verify
3. IAM → create user `vivek-admin` with `AdministratorAccess` policy
4. Create access key for that user
5. On your Mac:
```bash
brew install awscli
aws configure
# AWS Access Key ID: <paste>
# AWS Secret Access Key: <paste>
# Default region: us-east-1
# Default output: json
```
6. Verify: `aws sts get-caller-identity` → returns your account ID

### Step 2 — Provision the stack
```bash
pip3 install --user boto3
cd "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/01_Source"

# Dry run first (no resources created, no $$$)
python3 -m mace_platform.agent.cloud.bootstrap

# Apply for real (creates EC2 + RDS + S3 + KMS + VPC)
python3 -m mace_platform.agent.cloud.bootstrap --apply --region us-east-1 --admin-cidr $(curl -s ifconfig.me)/32
```

Admin credentials get saved to `~/.mace-agent/admin.credentials.json`
(chmod 600). Don't share that file.

### Step 3 — Point endpoints at it
After ~3 minutes, the EC2 instance has a public IP. On each endpoint:
```bash
mace-agent post --url https://<public-ip>/agent/report
```
Or install the launchd / systemd / Task Scheduler job (see
`mace_platform/agent/install/`) so it runs every 30 minutes.

### Step 4 — Hook the dashboard to your domain
1. Buy `unifiedsec.io` from Cloudflare Registrar (~$9/yr)
2. Create A record: `mace.unifiedsec.io → <EC2 public IP>`
3. Request ACM cert for `mace.unifiedsec.io` (DNS validation)
4. Attach cert to an ALB in front of the EC2 instance
5. Customers visit `https://mace.unifiedsec.io/` — done

### Step 5 — Tear down (save money during weekends)
```bash
python3 -m mace_platform.agent.cloud.bootstrap --destroy
# Bills ≤ $0.01 for the empty stack until re-provisioned
```

---

## Part 5 — Run the bigger demo (1,000 / 10,000 devices)

```bash
cd "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/01_Source"

# Default 10,000 devices (~60s to synthesize)
python3 demo_launch.py

# 1,000 devices (~5s to synthesize)
python3 demo_launch.py 1000

# 50,000 devices (~3 min — for big stress demos)
python3 demo_launch.py 50000

# Dashboard auto-opens
# Ctrl-C to stop
```

---

## Part 6 — Build the documents

All the .docx / .md / .pptx files in `MACE_FINAL/03_Documents/` can be
regenerated from scripts in `/Users/viveksindhu/Desktop/Unified Tech/MACEDocs/`:

```bash
cd "/Users/viveksindhu/Desktop/Unified Tech/MACEDocs"
pip3 install --user python-docx python-pptx
python3 update_patent.py            # rebuilds the patent .docx
python3 update_all_docs.py          # rebuilds the 5 supporting .docx files
python3 build_investor_deck.py      # rebuilds the 18-slide investor PPT
python3 build_target_deck.py        # rebuilds the 12-slide target-customers PPT
```

Outputs land in `/Users/viveksindhu/Desktop/Unified Tech/MACEDocs/`.

---

## Part 7 — What to do if something breaks

| Symptom | Fix |
|---|---|
| "port 8765 in use" | `pkill -f mace-agent && pkill -f demo_launch` |
| "0 devices reporting" | Wait 60 seconds (10k device synth takes time) then refresh browser |
| "MACEAgent.app says unidentified developer" | Right-click → Open → Open anyway (Apple Gatekeeper) |
| Dashboard shows "not found" | Rebuild: `cd 01_Source && python3 -m PyInstaller mace_platform/agent/build/mace-agent.spec --noconfirm` |
| Demo crashed | `cat /tmp/mace-demo.log` to see the error |
| Word doesn't open .docx | Already fixed — `chmod 644` + `xattr -c` was run on every file |
| AWS bootstrap fails | `aws sts get-caller-identity` first — if that fails, your AWS CLI isn't configured |
| Brew refuses to run | That's because Claude was running as root; YOU run brew from your normal terminal |

---

## Part 8 — Your daily run-list (founder routine)

**Mornings (8 AM):**
```bash
# Confirm the demo is still alive on your laptop
curl http://127.0.0.1:8765/healthz
# If broken: cd 01_Source && python3 demo_launch.py 10000 &
```

**Mid-week (Wed PM):**
```bash
# Refresh the threat-intel feeds (~30 s, free)
cd "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/01_Source"
python3 -c "from mace_platform.agent.feeds import update_all; print([r.feed+': '+str(r.success) for r in update_all()])"
```

**Weekends:**
```bash
# Backup the entire project
cd "/Users/viveksindhu/Desktop"
zip -qr "MACE_backup_$(date +%Y%m%d).zip" "Unified Tech"
# Move the zip to iCloud Drive or Dropbox for offsite
```

---

That's the entire stack and the entire run-list. If anything here is
unclear, file an issue in the notes app called "MACE founder gotchas"
and we'll add it to this guide.

— UnifiedSec Technologies · 2026-05-28
