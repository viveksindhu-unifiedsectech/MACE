# MACE Secure Files — How to Demo & Test

Everything here runs **offline on your laptop** — no AWS account, no network.
It proves encryption, access control, redaction, the AI safeguard, and the
cross-matter conflict detector all actually work.

---

## A. The 60-second proof (no Docker, no AWS)

From the backend folder:

```bash
cd 01_Source/mace_platform/backend

# a stable secret for the demo (any 32+ char string works)
export ENVIRONMENT=test
export SECRET_KEY="demo-secret-key-at-least-32-bytes-of-entropy-here-okay-yes"

python scripts/secure_files_demo.py
```

You will watch five stages print live:

1. **AI safeguard** BLOCKS a file containing a leaked private key
2. **Redact → encrypt → decrypt** — the SSN/card are gone before encryption; the
   on-disk bytes are ciphertext (`MACEF` magic); decryption returns the doc
3. **Access control** — analyst denied (clearance), other firm denied (tenant
   isolation), a named-user grant allowed
4. **Conflict detection** — the same contact across two walled matters is flagged
   HIGH, plus a privilege leak
5. **Privacy proof** — the index holds **no** raw client data

Ends with `✓ All five stages passed.`

---

## B. Run the automated test suite

```bash
cd 01_Source/mace_platform/backend
ENVIRONMENT=test python -m pytest tests/test_secure_files.py -v
```

Expected: **24 passed**. These cover envelope crypto (roundtrip, tenant-context
binding, tamper detection), access control (tenant isolation, clearance, grants,
expiry), redaction (Luhn, secrets, binary passthrough), the AI guard (block,
warn, over-broad share, prompt injection, executable), conflict + privilege-leak
detection, tenant-scoped token non-comparability, and the full service pipeline.

> First time only: `pip install -r requirements.txt` (needs `cryptography`,
> `pytest`). The core demo in §A needs only `cryptography`.

---

## C. The live server demo (Docker Compose — clickable API + Kibana)

```bash
cd 01_Source
docker compose up -d --build
```

Brings up: MACE API (`http://localhost:8080/docs`), Postgres, Redis,
Elasticsearch (`:9200`), Kibana (`:5601`), SOC + Admin frontends, monitoring.

Then, in the Swagger UI at `http://localhost:8080/docs`:

1. `POST /api/v1/auth/register` → create a tenant + admin, copy the token
2. Click **Authorize**, paste `Bearer <token>`
3. `POST /api/v1/files` → upload any file; set `classification=confidential`,
   `redact=true`. Watch the `guard` + `redaction_report` in the response.
4. Try uploading a text file containing `-----BEGIN RSA PRIVATE KEY-----` →
   the API returns **422 blocked by AI guard**.
5. `GET /api/v1/files` → list. `GET /api/v1/files/{id}/download` → get it back.
6. `POST /api/v1/files/{id}/grants` → share to a user or role (watch the
   over-broad-share warning if you share restricted data to a whole role).
7. `GET /api/v1/files/{id}/audit` → the immutable access trail.

Tear down: `docker compose down` (add `-v` to wipe volumes).

---

## D. Talking track — three real-world stories

Tell these as narratives; you already built all three.

1. **The privileged-file leak.** "A paralegal saves a filing that quotes a
   privileged account number. MACE's conflict engine flags a *privilege leak*
   before it's served — and it does so without ever storing the account number."
2. **The conflict of interest.** "A new matter comes in. The same contact
   already appears on the other side of an ethical wall. MACE catches the
   conflict at intake — the thing that gets firms disqualified."
3. **The risky upload.** "Someone drags in a document with an AWS secret key.
   The AI guard blocks it up front and tells them why — the threat is stopped
   before it happens, not audited after."

---

## E. Going cloud (when you have AWS)

See `03_Documents/MACE_Cloud_Setup_And_Credentials_Guide.md` for exactly what to
sign up for and what to send. In short: fill
`01_Source/mace_platform/backend/.env.cloud.template` → set `MACE_KMS_ENABLED=true`
+ `S3_BUCKET` + `MACE_KMS_KEY_ID` → the same code encrypts to AWS KMS + S3 with
no changes, and the tests re-run green against it.

---

## F. What's proven vs. what still gates production

**Proven & demoable now:** encryption, tenant-bound keys, access control,
redaction, AI guard, conflict detection, audit, IaC, 24 passing tests.

**Still required before real client data** (named in the threat model):
external penetration test, third-party code audit, SOC 2 Type I. No demo
substitutes for these — budget for them before onboarding a paying firm.
