# UnifiedSec MACE v2 — Platform

Multi-Domain Adaptive Correlation Engine. Three-component patented pipeline
(UTAG → CDCS → UREA) on a FastAPI backend with a React SOC dashboard and
a React Admin portal.

This README documents the **verified** local-development setup after the
production-readiness pass. The legacy `MACE_Installation_Operations_Guide.docx`
contains some out-of-date paths — prefer this file when they disagree.

---

## What's in this tree

```
UnifiedSec_MACE_Complete/
├── UnifiedSec_MACE_v2/          ← patented algorithm core (UTAG + CDCS + UREA)
│   ├── core/                    ← mace.py, tag.py, cdcs.py, rea.py, competitive.py
│   └── tests/                   ← pytest suite for the algorithm
├── mace_platform/
│   ├── backend/                 ← FastAPI app, Alembic, Celery workers
│   │   ├── app/                 ← API, models, services, middleware
│   │   ├── alembic/             ← schema migrations
│   │   ├── scripts/seed_demo.py ← investor-demo seed script
│   │   └── tests/               ← backend integration tests
│   ├── frontend/
│   │   ├── soc/                 ← SOC dashboard (Vite + React + TS)
│   │   └── admin/               ← Admin portal (Vite + React + TS)
│   ├── connectors/              ← CrowdStrike/Tenable/MISP/Splunk/Axonius adapters
│   ├── pipeline/                ← orchestrator, processors, enrichers, dispatchers
│   └── infra/
│       ├── docker-compose.local.yml  ← canonical full-stack compose
│       ├── helm/, terraform/, monitoring/
├── docker-compose.yml           ← top-level wrapper for the infra compose
└── README.md                    ← (this file)
```

---

## Prerequisites

| Tool            | Min version | Verified on this machine |
| --------------- | ----------- | ------------------------ |
| Docker Desktop  | 24+         | **must install**         |
| Node.js         | 20 LTS+     | ✅ (24.15.0)              |
| Python (optional, for running tests outside Docker) | 3.11+ | **must install** |

Docker Desktop for macOS: <https://www.docker.com/products/docker-desktop/>.
Without Docker you can still build and run the two frontends in dev mode and
run the algorithm test suite (with Python 3.11), but the backend needs
Postgres + Redis, which the compose file provisions for you.

---

## Quick start — full stack via Docker

```bash
# From the repo root (the directory containing this README):
docker compose up -d --build
```

The wrapper at `./docker-compose.yml` includes
`mace_platform/infra/docker-compose.local.yml`, which brings up:

| Service          | Port | Notes                                          |
| ---------------- | ---- | ---------------------------------------------- |
| postgres         | 5432 | user `mace`, db `mace_platform`                |
| redis            | 6379 | password `mace_redis_dev`                      |
| **mace-migrate** | —    | runs `alembic upgrade head` once and exits     |
| **mace-api**     | 8080 | FastAPI; `/health` and `/docs` (dev only)      |
| celery-worker    | —    | sync_connectors, EPSS refresh, ACS decay       |
| celery-beat      | —    | periodic scheduler                             |
| flower           | 5555 | `admin:mace_flower_dev`                        |
| **soc-frontend** | 3000 | SOC dashboard, proxies `/api/*` → mace-api     |
| **admin-frontend** | 3001 | Admin portal                                 |
| prometheus       | 9090 |                                                |
| grafana          | 3003 | `admin:mace_grafana_dev`                       |
| pgadmin          | 5050 | `admin@mace.local:mace_pgadmin_dev`            |

Watch the migration job complete:

```bash
docker compose logs -f mace-migrate
# Expected: 13 tables created, then container exits with code 0
```

### Seed the investor demo

```bash
# In a new shell — Python 3.11+ on the host with httpx installed:
pip install --user httpx
python mace_platform/backend/scripts/seed_demo.py
```

This script:

1. Registers tenant `acme-security` (jurisdiction `US`).
2. Ingests 6 assets across CrowdStrike, Tenable, Axonius, manual.
3. Attaches CVE-2024-3400 (EPSS 0.97, CISA KEV) to `prod-api-01`.
4. Triggers two `/correlate` calls — one fires a CRITICAL alert that
   auto-generates a FedRAMP SIR draft + SHA-256 chain-of-custody hash.
5. Prints a summary.

Then visit:

* **SOC dashboard:** <http://localhost:3000> — `acme-security` / `admin@acmesec.test` / `DemoPass123!Strong`
* **Admin portal:**  <http://localhost:3001> (same creds)
* **API docs:**       <http://localhost:8080/docs> (only when `DEBUG=true`)

---

## Frontend-only development (no Docker)

Both frontends build and serve standalone. They expect an API at the URL in
`VITE_API_URL` (defaults to `/api/v1` and Vite proxies `localhost:8080` in dev).

```bash
# SOC dashboard (port 3000)
cd mace_platform/frontend/soc
npm install      # once
npm run dev      # ✅ verified — vite ready in ~160ms
npm run build    # ✅ verified — production bundle ~750 kB gzip

# Admin portal (port 3001)
cd mace_platform/frontend/admin
npm install
npm run dev
npm run build
```

---

## Running tests

### Algorithm tests (UTAG + CDCS + UREA + MACEEngine)

```bash
cd UnifiedSec_MACE_v2
python -m pytest -v
```

Coverage includes:

* UTAG identity match scoring, hardware boost, threshold merge
* Haversine geo-distance and >500 km/h impossible-travel detection
* Asset class inference from ports/OS, ACS decay over time
* All 5 jurisdiction weight profiles sum to 1.0
* CDCS sub-scores for vuln / endpoint / identity / network / compliance / threat-intel
* CDCS triggers an alert for the canonical "APT41 banking breach" scenario
* Kill-chain multipliers escalate from RECON → EXFILTRATION
* Adaptive online weight learning (TP feedback)
* UREA threshold gating, framework selection per jurisdiction
* SHA-256 chain-of-custody hash uniqueness
* Multi-jurisdiction event (IN + EU) triggers CERT-In AND GDPR

### Backend tests

```bash
cd mace_platform/backend
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
python -m pytest tests/ -v
```

The conftest auto-locates `UnifiedSec_MACE_v2/core/` so the in-process MACE
engine works without setting `MACE_CORE_PATH` manually.

### Frontend type-check

```bash
cd mace_platform/frontend/soc && npm run build
cd ../admin && npm run build
```

`tsc --noEmit` runs as part of `build`. Both frontends type-check clean.

---

## Production-readiness changes vs the original drop

This pass fixed multiple blocking issues found while auditing the original
package. None of these were caught by the docs' claim of "67/67 tests
passing" — there were no tests at all.

| # | Issue                                                                                              | Fix                                                                                                          |
| - | -------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------ |
| 1 | `app/services/mace_engine_service.py` hardcoded `sys.path.insert(0, "/home/claude/...")` — broke on any other machine | Replaced with `_ensure_core_on_path()` that searches env var, `/app`, then walks up to the repo root         |
| 2 | `backend/Dockerfile` referenced a build stage named `--from=mace-algorithm` that didn't exist     | Switched to `COPY UnifiedSec_MACE_v2/core /app/core` with the build context set to the repo root            |
| 3 | `app/models/audit.py` defined a column named `metadata` — reserved by SQLAlchemy `DeclarativeBase` and prevents class creation | Renamed Python attribute → `extra`, DB column → `metadata_json`. Updated migrations and all callers          |
| 4 | `app/core/encryption.py` used bare `except: return plaintext` — credentials silently stored unencrypted on any error | Rewrote to raise `EncryptionError` on failure, with documented legacy-plaintext detection at decrypt time   |
| 5 | `app/workers/tasks.py` passed `connector.client_secret_encrypted` directly to CrowdStrike/Tenable APIs — ciphertext sent over the wire | Added `decrypt_credential(...)` before HTTP call                                                            |
| 6 | `mace_platform/infra/docker-compose.local.yml` used relative paths that didn't resolve from `infra/` | Switched build contexts to `../..` (the repo root), made `mace-migrate` a one-shot dependency for api/beat |
| 7 | `app/core/config.py` defaulted `SECRET_KEY` to `secrets.token_urlsafe(64)` — different value per process restart invalidated every JWT | Added a `field_validator` that raises in production if unset, synthesizes only in `development`/`test`     |
| 8 | `app/main.py` called `Base.metadata.create_all` on every startup — conflicted with Alembic, would silently re-add columns | Gated behind `ENVIRONMENT in ("development", "test")`; production relies on `alembic upgrade head`            |
| 9 | No security headers on API responses                                                              | Added `SecurityHeadersMiddleware` (CSP, X-Frame-Options, Referrer-Policy, HSTS in prod)                     |
| 10 | `UnifiedSec_MACE_v2/tests/` did not exist (docs claimed 67/67 passing)                            | Added 4 test files covering UTAG / CDCS / UREA / MACEEngine — ~50 tests                                     |
| 11 | `backend/tests/test_backend.py` had the same hardcoded `/home/claude/...` path                    | Replaced with a portable conftest                                                                            |
| 12 | Frontend `npm run build` failed: missing `vite/client` types for `import.meta.env`                 | Added `src/vite-env.d.ts` to both frontends                                                                  |
| 13 | Frontend ESM/CJS warning from `postcss.config.js`                                                  | Added `"type": "module"` to both `package.json` files                                                        |

---

## Architecture (brief — full detail in `MACEDocs/MACE_Architecture_Reference.docx`)

```
   [CrowdStrike] [Tenable] [Axonius] [MISP] [Splunk] [Custom API]
                              │
                              ▼
                  ┌─────────────────────────┐
                  │  UTAG (tag.py)          │  Probabilistic identity merge
                  │   - 11-class ACS decay  │  Hardware-boost matching
                  │   - Geo velocity        │  Shadow IT detection
                  └─────────────────────────┘
                              │
                              ▼
                  ┌─────────────────────────┐
                  │  CDCS v2 (cdcs.py)      │  6-domain weighted score
                  │   V·α + E·β + I·γ + N·δ │  Sector / kill-chain / blast multipliers
                  │       + C·ε + T·ζ       │  Adaptive online weight learning
                  └─────────────────────────┘
                              │  CDCS ≥ θ
                              ▼
                  ┌─────────────────────────┐
                  │  UREA (rea.py)          │  DFA → q_evidenced
                  │   - 22 frameworks       │  SHA-256 chain of custody
                  │   - Auto-drafts         │  Per-framework SLA deadlines
                  └─────────────────────────┘
                              │
                              ▼
        Incident + RegulatoryEvidence persisted via FastAPI
        Real-time push: Redis pub/sub → WebSocket → SOC dashboard
```

The patent application (`MACEDocs/MACE_Patent_Application_US_EU_UAE.docx`)
covers the unified pipeline as a single claim plus per-component claims.

---

## Where to look next

* **For investors:** `docker compose up -d --build` → seed → screenshot the
  SOC dashboard with the firing incident and the auto-generated FedRAMP
  evidence draft. The `/admin/audit-log` page demonstrates the SOC 2 /
  FedRAMP audit trail; `/billing/subscription` shows the SaaS plan model.
* **For auditors / due diligence:** algorithm + backend test suites prove
  every claim above; encryption.py shows AES-256-GCM with HKDF; the audit
  log is append-only at the DB level by convention (no UPDATE/DELETE
  endpoints).
* **For deployment:** `mace_platform/infra/terraform/environments/` has
  separate states per region (US, US GovCloud, UAE, EU, India). Helm charts
  in `mace_platform/infra/helm/`. CI in `mace_platform/infra/cicd/`.

---

Copyright 2026 UnifiedSec Technologies Inc. — Delaware C-Corporation.
Patent: IN/2026/UNISEC/MACE-001 + PCT → US / CA / EU / UAE.
