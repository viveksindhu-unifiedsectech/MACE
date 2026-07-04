# MACE — Cloud Setup, Subscriptions & Credentials Guide
**UnifiedSec Technologies · Secure Files + AWS Cloud Security**
*What to sign up for, what it costs, and exactly what to hand me so I can wire it in.*

---

## 0. How to use this document

The MACE Secure-Files platform runs in **two modes**:

| Mode | Needs | Use it for |
|---|---|---|
| **Local / demo** | Nothing. No AWS, no accounts. | Laptop demos, the live browser demo, investor meetings, this week. |
| **Cloud / production** | The accounts below | The live demo server + real prospects storing real files |

Everything already works in **local mode today** (`scripts/secure_files_demo.py`).
You only need the accounts below to go **cloud**. Get them at your pace — each
section tells you (a) what to buy, (b) how to create it, (c) **the exact values
to paste back to me**. When you send me a filled-in `.env` (template in §8), I
flip MACE from local to AWS-backed with no code changes.

> ⚠️ **Never paste raw secret keys into a chat or email.** Put them in the
> `.env` file on the server, or send them through a password manager / AWS
> Secrets Manager share. In this doc, anywhere you see `▶ SEND ME`, that means
> the *name/ARN/ID* — not the secret value — is safe to tell me; the secret
> value goes in `.env` only.

---

## 1. AWS — the core of cloud + cloud security

**What kind of account:** a standard **AWS account** (pay-as-you-go). There is
no "subscription tier" to pick — AWS bills per-use. For a company, create an
**AWS Organization** with a separate account for `mace-prod` (best practice, and
what auditors expect). Sign up at https://aws.amazon.com → "Create an AWS Account".

**Optional but recommended:** **AWS Business Support** ($100/mo or 3% of spend)
once you have real customers — gives you a real human on outages. Not needed for
the demo server.

### 1a. Services MACE uses and why

| Service | Why MACE needs it | Rough monthly cost (small demo server) |
|---|---|---|
| **KMS** (Key Management Service) | Wraps every per-file encryption key in an HSM. This is the root of the encryption. | ~$1/key + $0.03 per 10k calls → **~$1–5** |
| **S3** | Stores the encrypted file blobs (with SSE-KMS as a 2nd layer). | **~$1–10** |
| **IAM** | The role/policy MACE runs under (least-privilege). | Free |
| **CloudTrail** | Immutable log of every KMS/S3 call — cloud-side audit. | First trail free; **~$2** |
| **EKS** (Kubernetes) | Runs the containers in production (optional — see §3). | Control plane **$73** + nodes **~$60+** |
| **ECR** | Private registry for the MACE Docker images. | **~$1** |

**Bottom line:** a demo server on **Compose + S3 + KMS** (no EKS) runs at roughly
**$10–30/month**. Add EKS only when you need multi-node autoscaling → +$130+/mo.

### 1b. What to create (step by step)

1. **IAM user for MACE (programmatic).**
   IAM → Users → *Create user* `mace-app` → *no console access* → attach a
   policy (I'll give you the exact least-privilege JSON; to start you can use
   `AmazonS3FullAccess` + `AWSKeyManagementServicePowerUser` scoped to your key).
   Create an **access key** → download the CSV.
   ▶ **SEND ME:** the region (e.g. `us-east-1`). The **Access Key ID** and
   **Secret** go into `.env` on the server, not the chat.

2. **KMS key.** KMS → *Create key* → Symmetric → alias `alias/mace-files` →
   key administrators = you, key users = the `mace-app` IAM user.
   ▶ **SEND ME:** the **key ARN** (`arn:aws:kms:us-east-1:...:key/....`) — safe to share.

3. **S3 bucket.** S3 → *Create bucket* `mace-secure-files-<yourco>` →
   **Block all public access = ON** → Default encryption = **SSE-KMS** with the
   key above → **Versioning = ON**.
   ▶ **SEND ME:** the **bucket name** — safe to share.

4. (Optional) **CloudTrail.** CloudTrail → create a trail logging S3 data events
   + KMS → store in a separate bucket. ▶ Nothing to send; I read it via the app.

> Once I have the region + KMS ARN + bucket name (safe) and you've put the
> access key/secret in `.env`, I set `MACE_KMS_ENABLED=true` and MACE encrypts to
> AWS instead of local disk — same code, same tests.

---

## 2. Docker — packaging & the live demo

**What you need:** **Docker Desktop** on the machine you build from
(https://www.docker.com/products/docker-desktop/).

**Subscription:** Docker Desktop is **free for personal use, education, and
small businesses (< 250 employees AND < $10M revenue)** — that's you, so **$0**.
You only need **Docker Pro/Team/Business ($9–24/user/mo)** if the company grows
past that threshold or you want private Docker Hub repos. For MACE we push images
to **AWS ECR** (private, §1a) instead of Docker Hub, so **you likely never need a
paid Docker plan.**

▶ **SEND ME:** nothing. Just have Docker Desktop installed on the demo server.
The `docker compose up` file is already in the repo.

---

## 3. Kubernetes (EKS) — production orchestration (optional)

Only needed when one server isn't enough (autoscaling, HA, many prospects).

**What you need:** it's just **AWS EKS** (§1) — no separate signup.
- Cost: **~$73/mo** control plane + worker nodes (**~$60–200/mo** depending on size).
- Create with: `eksctl create cluster` (I provide the config), or the Terraform
  module already in `01_Source/mace_platform/infra/terraform`.

▶ **SEND ME (when you go this route):** the **kubeconfig** file for the cluster
(or confirm the `mace-app` IAM user can run `aws eks update-kubeconfig`). The
Helm chart is already in `infra/helm/secure-files/`.

**Recommendation:** For the demo server, **skip EKS**. Use Compose (§2) on one
EC2 box or your own server. Add EKS later when a paying customer needs it.

---

## 4. Elastic (Elasticsearch + Kibana) — encrypted-file audit search

Gives you a searchable dashboard of every file access/grant/denial.

**Two options:**

| Option | Cost | What to send me |
|---|---|---|
| **Self-hosted (recommended)** — runs in the same Docker Compose | **$0** (uses your server's RAM; needs ~2 GB) | Nothing — it's in the compose file |
| **Elastic Cloud** (managed) | from **~$95/mo** | The **Cloud ID** + an **API key** (value → `.env`) |

▶ **Recommendation:** self-hosted in Compose for now. `ELASTIC_ENABLED=true`
turns on shipping audit events; Kibana comes up at `http://<server>:5601`.

---

## 5. Anthropic API — the AI safeguard's LLM pass (optional)

The AI guard **works offline** with deterministic rules. Adding an Anthropic key
turns on a second, LLM-based opinion for fuzzy/free-text risks.

**What to get:** an API key from https://console.anthropic.com → Settings → API
Keys. Pay-as-you-go; the guard uses a small model and short prompts, so cost is
**cents per thousand files**. Set a **monthly spend cap** in the console.

▶ **SEND ME:** nothing to share; put `ANTHROPIC_API_KEY=sk-ant-...` in `.env`.
Model is configurable (`MACE_AI_GUARD_MODEL`, default `claude-sonnet-4-6`).

---

## 6. Already-supported extras (only if you want them)

These are already wired in MACE's config — provide keys only if you want them on:

- **Stripe** (billing): `STRIPE_SECRET_KEY`, price IDs → `.env`.
- **SendGrid/SMTP** (email): `SMTP_PASSWORD` → `.env`.
- **SSO** (Google/Microsoft/Okta): client IDs/secrets → `.env`.

---

## 7. The short version — what I actually need from you

**To make the demo server cloud-based & cloud-secure, minimum viable set:**

1. ✅ **AWS region** (e.g. `us-east-1`) — *tell me*
2. ✅ **KMS key ARN** (`alias/mace-files`) — *tell me*
3. ✅ **S3 bucket name** (block-public + SSE-KMS + versioning) — *tell me*
4. 🔒 **AWS Access Key ID + Secret** for `mace-app` IAM user — *put in `.env`*
5. ⬜ (optional) **Anthropic API key** — *put in `.env`*
6. ⬜ (optional) **kubeconfig** if you want EKS instead of Compose
7. ⬜ (optional) **Elastic Cloud ID + API key** if you don't self-host

Send me #1–3 (safe to type), put #4–7 in the `.env` on the server, tell me
"it's filled in," and I flip MACE to full AWS mode and re-run the tests against it.

---

## 8. `.env` template (fill in, keep OFF chat)

A ready-to-fill file is written to
`01_Source/mace_platform/backend/.env.cloud.template`. Copy it to `.env` on the
server and fill the blanks. I never need to see the secret values — only that
they're set.

---

## 9. Honest note on "production-ready"

Everything above makes MACE **cloud-backed and encrypted end-to-end**, which is
real and demoable. Full enterprise "production-ready" — the kind a law firm's
security team signs off on — additionally needs an **external penetration test**,
a **third-party code audit**, and (for many buyers) a **SOC 2 Type I** report.
No coding session can substitute for those; budget for them before real client
data lands on the server. The threat model in `03_Documents/` lists the exact
gaps so there are no surprises.
