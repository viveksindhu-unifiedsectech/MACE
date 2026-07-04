# MACE — How to Use the AI (AI Safeguard) Guide

MACE has an **AI safeguard** that watches your files and warns you about a threat
or mistake **before** it happens — not after. This guide explains what it does,
how to turn it on, how to configure it, and how it protects your data while doing
so. Written for clients, users, and engineers.

---

## 1. What the AI actually does (plain English)

Every time someone **uploads**, **shares**, or **downloads** a file, MACE runs an
AI check first. It answers one question: *"Is this action risky, and should we
allow it, warn about it, or block it?"*

It catches things like:

- 🔑 **Leaked secrets** — a password, private key, API token, or credit-card
  number sitting inside a file.
- 📤 **Over-broad sharing** — sending a *restricted* file to a whole department
  instead of one person.
- 🧬 **Disguised malware** — a program pretending to be a PDF (a `.pdf.exe`).
- 🪤 **Prompt-injection** — text that tries to trick MACE's own AI into
  misbehaving ("ignore your instructions…"). MACE detects and flags it.
- ⚠️ **Reclassification risk** — quietly downgrading a sensitive file's label.

It returns a **verdict**: `allow`, `warn`, or `block`, plus a **risk score** and
plain-English reasons. A `block` stops the action; a `warn` lets it through with a
visible caution that's written to the audit log.

---

## 2. Two layers — and why it works even offline

MACE's AI has **two layers**, and you can run with just the first:

1. **Deterministic rules (always on, no account needed).** Fast, offline pattern
   detectors for secrets, malware signatures, over-broad shares, and prompt
   injection. This layer alone can already `block` a leaked private key. It needs
   no API key and no internet.

2. **Claude language-model pass (optional).** When you add an Anthropic API key,
   MACE asks Claude for a *second opinion* on fuzzy, free-text risks the rules
   can't catch (e.g. a sensitive narrative with no obvious pattern).

**Fail-safe design:** if the AI service is unreachable or errors, MACE keeps the
deterministic verdict. It never fails *open* on the risks the rules already
cover — the safe answer wins.

---

## 3. How your data stays private when the AI runs

This is the part clients care about most:

- MACE **never sends raw secrets to the AI.** Before any text goes to Claude, it
  is **redacted** — SSNs, cards, keys, and tokens are replaced with typed tags.
- Only a **short, scrubbed excerpt** (first ~2,000 characters, already redacted)
  plus **category counts** are sent — enough for a risk opinion, nothing
  sensitive.
- The AI is used as a **classifier**, not a store: it returns a severity + a
  one-line reason. Your file content is not retained by MACE for the AI.

In short: the AI helps decide *how risky* something is without ever seeing the
sensitive values themselves.

---

## 4. How to turn the AI's LLM pass on

The rules layer is already on. To enable the Claude second opinion:

1. Get an API key at https://console.anthropic.com → API Keys. Set a monthly
   spend cap there (the guard uses short prompts, so cost is cents per thousand
   files).
2. Put it in your `.env` (never in chat/email):
   ```
   ANTHROPIC_API_KEY=sk-ant-...
   MACE_AI_GUARD_MODEL=claude-sonnet-4-6
   ```
3. Restart the app. That's it — MACE now adds an `AI_RISK_OPINION` finding when
   the model sees elevated risk.

**Model choice:** `claude-sonnet-4-6` is the balanced default. For higher
throughput/lower cost use a smaller model; for the most careful review use a
larger one. Change `MACE_AI_GUARD_MODEL` to any current Claude model id.

---

## 5. How each person interacts with the AI

**Users:** you don't "use" it directly — it runs automatically. When you see a
warning or block, read the reason and act on it (remove the secret, enable
redaction, or narrow a share). You can proceed through a `warn`; you cannot
through a `block`.

**Clients:** think of it as a safety net that reduces human error and gives you
an auditable "we checked this before storing it" record for compliance.

**Engineers:** the guard is `app/secure/ai_guard.py`. Call `assess(...)` with the
action, content, classification, and share target. It returns a `GuardResult`
(`score`, `verdict`, `findings`, `used_ai`). It's already wired into the upload
and share endpoints and into `service.store_file` (which raises `GuardBlocked`
on a critical, non-redacted upload).

---

## 6. Try the AI yourself (30 seconds, offline)

```bash
cd 01_Source/mace_platform/backend
ENVIRONMENT=test SECRET_KEY=$(python -c "import secrets;print(secrets.token_urlsafe(48))") \
  python scripts/secure_files_demo.py
```
Stage 1 shows the AI **blocking** a file that contains a private key, with its
reasons. No API key required — that's the rules layer.

To see it in the API: open `http://<server>:8080/docs`, `POST /api/v1/files` a
text file containing `-----BEGIN RSA PRIVATE KEY-----` → you get **422, blocked
by AI guard** with the finding list.

Or on the website: the **Security** section has a live, browser-only redaction
demo that shows the same idea (sensitive values removed before storage).

---

## 7. Tuning & good practice

- **Start with rules-only** for demos and pilots; add the LLM key when you want
  fuzzy-content coverage.
- **Turn on `MACE_REDACT_BY_DEFAULT=true`** in regulated environments so uploads
  are scrubbed even if a user forgets.
- **Review `warn` findings periodically** in the audit log / Kibana — patterns
  there tell you where users need training.
- **Keep a spend cap** on the Anthropic key so cost is bounded.
- The AI **assists** decisions; the deterministic rules and access-control engine
  are the enforcement backbone. Treat the LLM opinion as advisory, not the sole
  gate — which is exactly how MACE is wired.

---

## 8. Honest limits

The AI reduces mistakes; it is not a guarantee. It won't catch every possible
sensitive item in free text, and an LLM opinion can be wrong — which is why it's a
*second* layer over deterministic rules and never the only control. For regulated
production use, pair it with the redaction defaults, classification discipline,
and the external pen test/audit noted in the threat model.
