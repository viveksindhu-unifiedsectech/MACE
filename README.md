# MACE — Final Demo-Ready Bundle
**UnifiedSec Technologies · 2026-05-28**

This folder contains everything you need to demo MACE to investors,
acquirers, banks, and customers. Total size: ~16 MB.

## Folder layout

```
MACE_FINAL/
├── 01_Source/                    Full source code (305 files)
│   ├── mace_platform/
│   │   ├── agent/                The UMEA agent (65 Python modules + Kotlin + Swift)
│   │   ├── backend/              FastAPI tenant plane
│   │   ├── connectors/           CrowdStrike / Tenable / Splunk / Axonius / MISP / endpoint_agent
│   │   ├── frontend/             SOC + Admin React dashboards
│   │   ├── pipeline/             UTAG → CDCS → UREA orchestrator
│   │   └── infra/                Terraform + Helm + monitoring
│   ├── UnifiedSec_MACE_v2/       Core algorithm (UTAG + CDCS + UREA)
│   ├── demo_launch.py            ▶ run this to launch the live demo
│   ├── BUILD_ALL_PLATFORMS.md
│   ├── .github/workflows/        Cloud-build YAML for Windows/Linux/Android/iOS
│   └── README.md
│
├── 02_Built_Apps/                Pre-built executables (ready to ship)
│   ├── MACEAgent.app             ▶ double-click to launch (macOS arm64)
│   └── mace-agent-macos-arm64    Standalone CLI binary
│
├── 03_Documents/                 11 docs — all updated for v2.1
│   ├── MACE_Patent_Application_US_EU_UAE.docx  (30 claims — file tonight)
│   ├── MACE_Architecture_Reference.docx
│   ├── MACE_Founders_Algorithm_Document.docx
│   ├── MACE_Investor_Proposal_v2.docx
│   ├── MACE_Shareholder_Case_v2.docx
│   ├── MACE_Installation_Operations_Guide.docx
│   ├── MACE_Investor_Banker_Deck.pptx          (18-slide deck)
│   ├── MACE_Comprehensive_Synopsis.md          (everything in one file)
│   ├── MACE_Founder_GTM_Funding_Playbook.md    (pre-revenue exit track)
│   ├── MACE_Contact_Strategy.md                (VCs + bankers + acquirers)
│   └── MACE_AWS_Infrastructure_Setup.md        (cloud deployment guide)
│
└── 04_How_To_Demo/
    └── DEMO_GUIDE.md             ▶ read this first
```

## The 60-second demo

1. Open `02_Built_Apps/MACEAgent.app` (double-click)
2. Wait ~10 seconds — browser opens at `http://127.0.0.1:8765/`
3. You see your Mac scanned for real + 5 simulated devices in the fleet
4. Click any device → drill into HWAM, SWAM, STIG, CVEs, malware, remediation
5. Click **Macey** tab → ask "list devices" or "explain CVE-2024-3094"
6. Click **Compliance** tab → pick any industry to see framework coverage

## To build for other platforms

- **Windows .exe** — copy `01_Source/` to a Windows machine, run `mace_platform\agent\build\build_all.ps1`. Or push to GitHub and use the YAML in `.github/workflows/`.
- **Linux ELF** — same project on Linux: `python3 -m PyInstaller mace_platform/agent/build/mace-agent.spec --noconfirm`.
- **Android APK** — needs Android Studio + Java JDK 17 + `./gradlew assembleRelease`.
- **iOS IPA** — needs Xcode + xcodegen → `bash mace_platform/agent/mobile/ios_app/build_ios.sh`.

The GitHub Actions YAML (`01_Source/.github/workflows/build-all.yml`)
builds all five in parallel in the cloud in ~5 minutes when you push a
tag — no local toolchain install required.

## What's inside the patent (filing tonight)

30 claims covering:
- Original three components (UTAG + CDCS + UREA) — claims 1-10
- Unified single-pass endpoint agent (UMEA) — claim 11
- Hardware-rooted attestation across Secure Enclave / TPM / Strongbox — claim 12
- Real-time event monitoring with OS event streams — claim 13
- Daily NVD + KEV + EPSS vulnerability database synthesis — claim 14
- Algorithm-driven remediation prioritisation + bundling — claim 15
- Cross-platform agent deployment (Windows / macOS / Linux / Android / iOS) — claim 16
- Allowlist-gated auto-remediation with tamper-evident audit log — claim 17
- Real-time vulnerability prioritisation with multi-feed fusion — claim 18
- Behavioural EDR over the process tree — claim 19
- Honey-token deception layer — claim 20
- Supply-chain attack detection (SBOM + typo-squat + XZ-style) — claim 21
- 7-domain CDCS (V + E + I + N + C + T + H) — claim 22
- Federated adaptive-correlation learning with differential privacy — claim 23
- Cyber digital-twin attack-path simulation — claim 24
- Post-quantum readiness inventory + migration recommendations — claim 25
- Deepfake-voice detection without audio retention — claim 26
- Cross-asset incident replay (snapshots + ledger) — claim 27
- Identity threat detection over identity providers — claim 28
- Endpoint software-defined microsegmentation (DNS sinkhole) — claim 29
- GenAI tool-using conversational security assistant — claim 30

## NEW — MACE Secure Files (universal file security)

MACE now also secures **data at rest** — a one-stop layer that encrypts any file,
pushes it to AWS securely, and lets only the right people open it:

- **Encrypt any file type** — per-file AES-256 key, wrapped by AWS KMS, bound to
  tenant identity (cryptographic tenant isolation). Code: `01_Source/mace_platform/backend/app/secure/`
- **Access control** — RBAC + ABAC + data classification; tenant isolation is
  categorical (no admin override); named-user grants unlock a single file.
- **Redaction** — strips SSNs, cards, keys, tokens *before* encryption.
- **AI safeguard** — warns/blocks a risky upload or over-broad share *before* it happens.
- **Cross-matter conflict + privilege-leak detection** — the differentiator; a
  privacy-preserving keyed-hash index that stores **no** raw data.
- **AWS-native** — KMS + S3 (SSE-KMS) + IAM Terraform module; Docker Compose adds
  Elasticsearch + Kibana for audit search. Runs fully offline for demos.

Try it: `04_How_To_Demo/SECURE_FILES_DEMO.md` · Cloud setup + what to send me:
`03_Documents/MACE_Cloud_Setup_And_Credentials_Guide.md` · New patent claims 31–40:
`03_Documents/MACE_Patent_Addendum_SecureFiles.docx` · Deck:
`03_Documents/MACE_SecureFiles_Deck_v1.pptx` · 3,287 tests pass.

## Run it locally — step by step

**Prerequisites:** Python 3.11+ (3.9 works for the offline demo), and Docker
Desktop for the full stack. No AWS account needed for local mode.

### Step 1 — Prove the security pipeline works (offline, ~60 seconds)
```bash
cd 01_Source/mace_platform/backend
python3 -m venv .venv && source .venv/bin/activate      # first time only
pip install -r requirements.txt                          # first time only
export ENVIRONMENT=test
export SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
python scripts/secure_files_demo.py                      # 5-stage end-to-end demo
```
You'll watch the AI guard block a leaked key, redaction strip an SSN before
encryption, access control enforce tenant isolation, and the conflict detector
fire — all offline.

### Step 2 — Run the tests (3,287 pass)
```bash
# from backend/, venv active
ENVIRONMENT=test python -m pytest tests/test_secure_files.py \
  tests/test_secure_files_property.py tests/test_encryption.py -q
```

### Step 3 — Launch the full stack (API + Postgres + Redis + Elasticsearch + Kibana)
```bash
cd 01_Source
docker compose up -d --build
```
Then open: **API docs** `http://localhost:8080/docs` · **Kibana**
`http://localhost:5601` · **SOC dashboard** `http://localhost:3000`.
Try the Secure Files API under `/api/v1/files` (register → authorize → upload →
download → grant). Tear down with `docker compose down` (`-v` wipes data).

### Step 4 — Talk to Macey (the AI)
Macey works offline out of the box (deterministic responder). For full answers,
set one of:
```bash
export ANTHROPIC_API_KEY=sk-ant-...        # Claude Fable 5 (most capable)
# or run your own model:
export MACEYLM_BASE_URL=http://localhost:8000/v1   # your self-hosted server
export MACEY_MODEL=mace-security-1
```
See `03_Documents/MACE_Macey_Custom_AI_Guide.md` to make Macey a proprietary,
self-hosted model, and `04_How_To_Demo/AI_GUARD_HOW_TO.md` for the AI how-to.

### Step 5 — Go cloud (AWS KMS + S3)
Fill `01_Source/mace_platform/backend/.env.cloud.template` → `.env`, set
`MACE_KMS_ENABLED=true` + `S3_BUCKET` + `MACE_KMS_KEY_ID`. Same code, now
AWS-backed. Full walkthrough + exactly what to send me:
`03_Documents/MACE_Cloud_Setup_And_Credentials_Guide.md`.

## Push it to GitHub

There is **no special connector needed** — plain `git` (already installed) does
it. The `gh` CLI is optional and just makes repo creation one command.

**Option A — with the `gh` CLI (easiest):**
```bash
brew install gh && gh auth login          # one time
cd "path/to/MACE_FINAL"
git init && git add -A
git commit -m "MACE: platform + Secure Files"
gh repo create mace-platform --private --source=. --push
```

**Option B — plain git (no gh):**
1. Create an **empty private repo** on github.com (no README/gitignore).
2. Then:
```bash
cd "path/to/MACE_FINAL"
git init && git add -A
git commit -m "MACE: platform + Secure Files"
git branch -M main
git remote add origin https://github.com/<you>/<repo>.git
git push -u origin main      # authenticate with a Personal Access Token
```
A `.gitignore` is already included — it keeps out `.env`, secrets,
`node_modules/`, `.venv/`, built binaries, and encrypted file blobs.
Once pushed, the CI in `01_Source/.github/workflows/` builds the apps on tag.

## What's already done vs. still ahead

| Item | Status |
|---|---|
| Patent — 30 claims | ✓ ready to file |
| Mac .app + binary | ✓ built, tested, ships in `02_Built_Apps/` |
| Source code | ✓ 305 files in `01_Source/` |
| Dashboard | ✓ in `01_Source/mace_platform/agent/api/dashboard.html` |
| Macey GenAI | ✓ works with fallback responder; add `ANTHROPIC_API_KEY` for full LLM |
| 6 .docx + 4 .md + 1 .pptx | ✓ all updated for v2.1 in `03_Documents/` |
| AWS provisioner | ✓ `01_Source/mace_platform/agent/cloud/bootstrap.py` |
| Admin credentials | ✓ at `~/.mace-agent/admin.credentials.json` |
| Windows .exe | Build with `build_all.ps1` on Windows, or via GitHub Actions |
| Linux ELF | Build on Linux or via GitHub Actions |
| Android APK | Source ready; needs Android Studio first-launch SDK install |
| iOS IPA | Source ready; needs `brew install xcodegen` |
| File patent | tonight |
| Push to GitHub for CI builds | when you decide on a repo name |
| First VC outreach | see `03_Documents/MACE_Contact_Strategy.md` |

— UnifiedSec Technologies · Patent IN/2026/UNISEC/MACE-001 + PCT
