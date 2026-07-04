# MACE — UnifiedSec Technologies

**A one-stop cybersecurity platform: threat correlation + secure file encryption, access control, redaction, AI safeguards, and cross-matter conflict detection. Patent-pending.**

MACE unifies two halves of security in one platform:

1. **Threat correlation** — UTAG (asset identity) → CDCS (cross-domain scoring) →
   UREA (regulatory evidence), plus the UMEA endpoint agent, EDR, deception, and SOAR.
2. **Secure Files (data at rest)** — encrypt any file with per-file AES-256 keys
   wrapped by AWS KMS, role/attribute/classification access control under hard
   tenant isolation, PII redaction, an AI safeguard that warns *before* risky
   actions, and privacy-preserving cross-matter conflict-of-interest detection.

---

## 🧭 Where to go

| I want to… | Go to |
|---|---|
| **See it work in 60s (no setup)** | `mace_platform/backend/scripts/secure_files_demo.py` |
| **Run it locally** | [Run it locally](#run-it-locally) below |
| **Run the tests (3,287)** | `mace_platform/backend/tests/` |
| **Read the secure-feature source** | `mace_platform/backend/app/secure/` |
| **Demo & troubleshooting** | `docs/SECURE_FILES_DEMO.md`, `docs/USER_GUIDE_AND_TROUBLESHOOTING.md` |
| **How to use the AI (Macey)** | `docs/AI_GUARD_HOW_TO.md` |
| **Make Macey your own model** | `docs/MACEY_CUSTOM_AI_GUIDE.md` |
| **Set up AWS cloud** | `docs/CLOUD_SETUP_AND_CREDENTIALS.md` + `mace_platform/backend/.env.cloud.template` |

## 📂 Repository layout

```
MACE/
├── README.md
├── docker-compose.yml            One-command local stack
├── docs/                         How-to, demo, troubleshooting, AI, cloud setup
├── mace_platform/
│   ├── backend/                  FastAPI multi-tenant plane
│   │   ├── app/secure/           ← Secure Files: crypto, access, redaction, AI guard, conflict
│   │   ├── app/api/v1/           REST endpoints
│   │   ├── scripts/              Runnable demos (secure_files_demo.py)
│   │   └── tests/                3,287 tests incl. property-based
│   ├── agent/                    UMEA endpoint agent + Macey GenAI (macey/)
│   ├── connectors/               CrowdStrike / Tenable / Splunk / MISP / …
│   ├── frontend/                 SOC + Admin React dashboards
│   ├── pipeline/                 UTAG → CDCS → UREA orchestrator
│   └── infra/                    Terraform + Helm + Docker Compose + monitoring
└── UnifiedSec_MACE_v2/           Core correlation algorithm
```

---

## Run it locally

**Prerequisites:** Python 3.11+ (3.9 works for the offline demo); Docker Desktop
for the full stack. No AWS account needed for local mode.

### 1 — Prove the security pipeline works (offline, ~60s)
```bash
cd mace_platform/backend
python3 -m venv .venv && source .venv/bin/activate      # first time only
pip install -r requirements.txt                          # first time only
export ENVIRONMENT=test
export SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))")
python scripts/secure_files_demo.py
```
Watch the AI guard block a leaked key, redaction strip an SSN before encryption,
access control enforce tenant isolation, and the conflict detector fire.

### 2 — Run the tests (3,287 pass)
```bash
ENVIRONMENT=test python -m pytest tests/test_secure_files.py \
  tests/test_secure_files_property.py tests/test_encryption.py -q
```

### 3 — Full stack (API + Postgres + Redis + Elasticsearch + Kibana)
```bash
docker compose up -d --build           # from the repo root
```
API docs `http://localhost:8080/docs` · Kibana `http://localhost:5601` ·
SOC dashboard `http://localhost:3000`. Try `/api/v1/files`. Tear down:
`docker compose down` (`-v` wipes data).

### 4 — Talk to Macey (the AI)
Works offline out of the box. For full answers set one of:
```bash
export ANTHROPIC_API_KEY=sk-ant-...                 # Claude Fable 5
export MACEYLM_BASE_URL=http://localhost:8000/v1    # your own self-hosted model
export MACEY_MODEL=mace-security-1
```
See `docs/MACEY_CUSTOM_AI_GUIDE.md` and `docs/AI_GUARD_HOW_TO.md`.

### 5 — Go cloud (AWS KMS + S3)
Fill `mace_platform/backend/.env.cloud.template` → `.env`, set
`MACE_KMS_ENABLED=true` + `S3_BUCKET` + `MACE_KMS_KEY_ID`. Same code, AWS-backed.
Full walkthrough: `docs/CLOUD_SETUP_AND_CREDENTIALS.md`.

---

## Security posture (honest)

The encryption, access control, redaction, AI guard, and conflict engine are
real and tested today. Before real customer data lands on a live server,
enterprise readiness additionally requires an **external penetration test**, a
**third-party code audit**, and (for many buyers) **SOC 2 Type I** — no code
alone substitutes for these. The threat model documents the exact gaps.

---

© UnifiedSec Technologies · Patent-pending IN/2026/UNISEC/MACE-001 + PCT.
Proprietary — not for redistribution.
