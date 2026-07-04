# MACE Secure Files — User Guide & Troubleshooting

For everyone: **clients** deciding to trust MACE, **users** who upload and share
files, and **engineers** who run it. Start at the part that fits you.

---

## Part 1 — For clients (no tech background needed)

**What MACE Secure Files does, in one sentence:** it locks your files so only the
right people can open them, hides sensitive details automatically, warns you
before a mistake, and keeps a permanent record of who touched what.

**Why it's safe to trust:**

| Your worry | What MACE does |
|---|---|
| "Could someone steal my files?" | Every file is encrypted with its own key, and the key lives in a hardware vault (AWS KMS). Stored files are unreadable without it. |
| "Could the wrong person open one?" | Access is decided by who you are, your role, and how sensitive the file is — not just a shared folder. Different companies can never see each other's files. |
| "What if I upload something I shouldn't?" | An AI check runs first and stops obvious mistakes (a password, a card number) before the file is saved. |
| "Will I know if something happened?" | Every open, share, and denial is written to a record that can't be edited — provable to an auditor. |
| "Is this really production-grade?" | The security engine is real and tested (3,000+ automated checks). Before we hold your live data we also complete an independent penetration test and audit — we'll show you the results. |

**What we ask of you:** decide the sensitivity of your files (internal /
confidential / restricted) and who should reach them. MACE enforces the rest.

---

## Part 2 — For users (uploading, sharing, downloading)

You'll use either the **web dashboard** or the **API docs page**
(`http://<server>:8080/docs`). The flow is the same.

### Upload a file
1. Choose the file.
2. Pick a **classification**: `internal`, `confidential`, or `restricted`.
3. Turn **Redact** on if the file may contain SSNs, card numbers, or keys.
4. Submit. If the AI guard flags something, you'll see a clear reason — fix it
   or turn on redaction, then resubmit.

### Share a file
- Share to a **specific person** (best — narrow and safe), or to a **role**
  (everyone with that job). MACE warns you if you share sensitive data to a whole
  role, because that's broad.
- You can set an **expiry** so access ends automatically.

### Download a file
- If you're allowed, it downloads decrypted. If not, MACE tells you *why*
  (e.g. "clearance too low" or "different organization") — that's by design.

### The three things people ask
- **"Why can't I open this file?"** Your role/clearance is below the file's
  sensitivity, or it belongs to another organization, or your grant expired. Ask
  the file owner for a personal grant.
- **"Where did my SSN go?"** Redaction replaced it with `[REDACTED:SSN]` before
  the file was ever stored. That's intended.
- **"My upload was blocked."** The AI guard found a secret (like a private key).
  Remove it or enable redaction and try again.

---

## Part 3 — For engineers (run, operate, fix)

### Run it
```bash
# Offline proof (no AWS/DB): 5-stage end-to-end demo
cd 01_Source/mace_platform/backend
ENVIRONMENT=test SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
  python scripts/secure_files_demo.py

# Tests (3,000+ incl. property-based + full access matrix)
ENVIRONMENT=test python -m pytest tests/test_secure_files.py tests/test_secure_files_property.py -q

# Full stack (API + Postgres + Redis + Elasticsearch + Kibana)
cd 01_Source && docker compose up -d --build
```

### Go cloud
Fill `backend/.env.cloud.template` → `.env`, set `MACE_KMS_ENABLED=true` +
`S3_BUCKET` + `MACE_KMS_KEY_ID`. See `03_Documents/MACE_Cloud_Setup_And_Credentials_Guide.md`.

### Troubleshooting matrix

| Symptom | Likely cause | Fix |
|---|---|---|
| `EncryptionError: SECRET_KEY must be >= 32 bytes` | Secret too short / unset | Set a 32+ char `SECRET_KEY` (use 64+ in prod). |
| Every upload returns **422 blocked by AI guard** | File contains a secret and redact is off | Enable `redact=true`, or remove the secret. Expected behavior. |
| `FileCryptoError: cannot unwrap DEK` on download | Wrong tenant/context, rotated key, or KMS permission missing | Confirm the file's tenant matches the caller; check the `mace-app` IAM user has `kms:Decrypt` on the key. |
| `FileCryptoError: chunk ... authentication failed` | The stored blob was modified/corrupted | The file is tamper-flagged by design; restore from S3 versioning. |
| `KeyProviderError: MACE_KMS_KEY_ID must be set` | `MACE_KMS_ENABLED=true` but no key ARN | Set `MACE_KMS_KEY_ID` to the KMS ARN, or set `MACE_KMS_ENABLED=false` for local mode. |
| `StorageError: S3 get failed ... AccessDenied` | IAM policy missing S3 actions | Attach the `secure_files` IAM policy (Terraform output `iam_policy_arn`). |
| `botocore ... could not be found` / `boto3 required` | boto3 not installed | `pip install boto3` (only needed for cloud mode). |
| Download works but file looks scrambled | You fetched the raw `.macef` blob, not the API `/download` | Use the API endpoint; it decrypts. The blob on disk/S3 is *meant* to be ciphertext. |
| Kibana empty / `:5601` not loading | Elasticsearch still starting (needs ~1–2 min + ~2 GB RAM) | Wait for the ES healthcheck; `docker compose logs elasticsearch`. |
| 403 on every file for an admin | Cross-tenant access (admin is in a different tenant) | This is intentional — tenant isolation has no admin override. Use a same-tenant account. |
| Tests can't import `app` | Wrong working dir / missing deps | Run from `backend/`, `pip install -r requirements.txt`. |
| Redaction missed a value | It's a free-text name/address, not a pattern | Enable the AI-guard LLM pass (`ANTHROPIC_API_KEY`) for fuzzy content — see the AI guide. |

### Operational notes
- **Key rotation:** KMS key rotation is enabled in Terraform. Envelope design
  means rotating the KMS key does not require re-encrypting files (only the
  wrapped DEKs are re-wrapped on next write).
- **Backups:** S3 versioning is on; deletes are soft (`is_deleted`) in the DB.
- **Audit:** query `GET /api/v1/files/{id}/audit`, or search in Kibana.
- **Scaling:** move from Compose to EKS with the existing Helm charts when one
  node isn't enough.

---

## Part 4 — Escalation

If a fix above doesn't resolve it: capture the exact error, the endpoint, and
whether it's local or cloud mode, and contact the platform owner
(sindhuvick8@gmail.com). For a suspected security issue, do **not** post details
publicly — report privately and preserve the audit log.
