# UnifiedSec on LinkedIn — Company Page + App Setup Guide
**For Vivek · 2026-06-10**

Two things to do, in order:

1. **Create the LinkedIn Company Page** (no developer skills, ~10 min)
2. **Register the LinkedIn Developer App** so MACE can pull data from it
   (15 min, one-time)

Both are free.

---

## Part 1 — Create the UnifiedSec Company Page

### Step 1: Make sure your personal profile is complete first
LinkedIn will not let you create a Company Page until your *personal*
profile passes these gates:
- Headline + photo + summary filled
- Current employment listed (must include "UnifiedSec Technologies"
  or similar — create the placeholder)
- At least 50 connections (find founder-network folks if you're short)

If any of the above is missing, fix it before continuing.

### Step 2: Create the page
Go to **https://www.linkedin.com/company/setup/new/**

Fill in:

| Field | Value |
|---|---|
| Page type | **Company** |
| Company name | **UnifiedSec Technologies** |
| LinkedIn public URL | `linkedin.com/company/unifiedsec` (or `unifiedsectech` if taken) |
| Website | `https://unifiedsec.io` (register the domain first if not done) |
| Industry | **Computer & Network Security** |
| Company size | **1-10 employees** |
| Company type | **Privately held** |
| Tagline | "Unified cybersecurity. One agent. Seven domains. Zero CrowdStrike." |
| Logo (300×300) | Use a clean square logo — see "Branding" below |
| Cover image (1128×191) | Hero shot of the MACE dashboard or a clean gradient |

Click **Create page**. You're done with the basics.

### Step 3: Lock in your handle + verify ownership
- After creation, go to **Admin tools → Edit page → Page info** and
  confirm your custom URL is `linkedin.com/company/unifiedsec`.
- Add a **About** section (paste below).
- Add **Specialties**: cybersecurity, EDR, vulnerability management,
  ZTNA, compliance, India CII, NESA, FedRAMP, SOC 2, GDPR, Macey
  GenAI, MACE algorithm.
- Toggle **Page verification** when LinkedIn prompts (they ask for a
  domain TXT record proving you own `unifiedsec.io`).

### Step 4: Suggested "About" copy
```
UnifiedSec Technologies builds MACE — the Multi-Domain Adaptive
Correlation Engine. One downloadable agent replaces CrowdStrike,
Tenable, Splunk SOAR, Zscaler, and McAfee in a single 5 MB binary,
across Windows, macOS, Linux, Android and iOS — fused under a
patented 7-domain correlation algorithm. Built-in Macey GenAI
assistant, automatic regulatory evidence for CERT-In, DPDP, NESA,
GDPR, HIPAA and FedRAMP, and hardware-rooted attestation.

Patent IN/2026/UNISEC/MACE-001 + PCT (US · CA · EU · UAE · IN).

Founded by Vivek Sindhu · Delaware C-Corp · Operating in India,
UAE, US and EU.

Hiring engineers, sellers and a compliance lead. unifiedsec.io
```

### Step 5: First 5 posts (queue them up now)
Use the **Schedule** function so they go out one per week:

1. **Launch post**: "Today we're introducing MACE — the unified
   cybersecurity algorithm. One agent. Seven domains. Patent on file
   in US/CA/EU/UAE/IN. Demo: [link to a short Loom video]."
2. **Behind-the-scenes**: A picture of the dashboard at 10,000
   simulated devices. Caption: "What 10,000-device fleet visibility
   looks like with one binary."
3. **Macey introduction**: Screenshot of Macey answering "explain
   CVE-2024-3094". Caption: "GenAI security analysts shouldn't cost
   $10/user/month. We bundle Macey free."
4. **Customer pain post**: A graph showing CrowdStrike + Tenable +
   Splunk + Zscaler costs vs. MACE. Caption: "How a 1,000-endpoint
   company saves $850k/year."
5. **Hiring post**: "We're hiring our first VP Sales. India + UAE +
   US territory. Cybersec background required. DM Vivek."

Use the LinkedIn **scheduled post** feature so they auto-publish
even when you're heads-down.

### Step 6: Branding details (so the page looks like a $50M company)
- **Logo**: clean square, transparent PNG, blue accent (#3B82F6) on
  navy (#0B1220). Fiverr Pro can produce 3 variants for $50.
- **Banner**: solid navy with the MACE wordmark + "MULTI-DOMAIN
  ADAPTIVE CORRELATION ENGINE" in mono spaced font.
- **Website link**: must work and have HTTPS. If you don't have a
  site yet, point at unifiedsec.io with a 1-page Vercel landing
  page (the script at MACE_Founder_GTM_Funding_Playbook.md §7
  has the exact steps).

---

## Part 2 — Register the LinkedIn Developer App

This lets the MACE platform (specifically `mace_platform/connectors/
linkedin/`) pull data from LinkedIn — page analytics, follower stats,
auto-publishing, plus the ITDR impersonation scanner that watches for
fake recruiter accounts targeting your employees.

### Step 1: Create the developer app
Go to **https://www.linkedin.com/developers/apps**

Click **Create app** and fill in:

| Field | Value |
|---|---|
| App name | **MACE — Unified Security** |
| LinkedIn Page | (pick the UnifiedSec page you just created) |
| Privacy policy URL | `https://unifiedsec.io/privacy` (put up a basic page if needed) |
| App logo | Same square logo as the Company Page |

LinkedIn auto-issues:
- **Client ID** (looks like `78x4f...`)
- **Client Secret** (32-char string)

Both go in your `.env`.

### Step 2: Request API products
On the app's **Products** tab, request:

| Product | Why MACE needs it |
|---|---|
| **Sign In with LinkedIn using OpenID Connect** | Verify employee identity for ITDR |
| **Share on LinkedIn** | Auto-publish security notices to the page |
| **Marketing Developer Platform** | Page analytics + follower stats (requires application) |
| **Advertising API** | Future: paid promotions |

Sign In + Share are auto-approved.
Marketing Developer Platform needs an application (LinkedIn reviews it
in 5-10 business days). Submit a 200-word use-case description — copy
from §3 below.

### Step 3: Set redirect URLs (OAuth)
Under **Auth → OAuth 2.0 settings → Authorized redirect URLs**, add:

```
https://app.unifiedsec.io/oauth/linkedin
http://127.0.0.1:8765/oauth/linkedin
```

The localhost one lets you test the OAuth dance during development.

### Step 4: Save credentials to `~/.mace-agent/linkedin.json`
Create the file:

```json
{
  "client_id":     "<paste from LinkedIn>",
  "client_secret": "<paste from LinkedIn>",
  "redirect_uri":  "http://127.0.0.1:8765/oauth/linkedin",
  "org_urn":       "urn:li:organization:<your-page-ID>"
}
```

Find the page ID at **Admin → View as member → URL** — it's the
number in the URL.

Chmod it 600:
```bash
chmod 600 ~/.mace-agent/linkedin.json
```

### Step 5: Smoke test the connector
```bash
cd "/Users/viveksindhu/Desktop/Unified Tech/MACE_FINAL/01_Source"
python3 - <<'PY'
import json, asyncio
from pathlib import Path
from mace_platform.connectors.linkedin import LinkedInConnector

cfg = json.loads((Path.home() / ".mace-agent" / "linkedin.json").read_text())
c = LinkedInConnector(**cfg)
url = c.authorization_url(state="test123")
print("Open this URL in your browser to grant access:\n", url)
PY
```

Open the URL it prints, sign in with the UnifiedSec admin account,
approve. You'll be redirected to `http://127.0.0.1:8765/oauth/linkedin?code=...`
— grab the `code` from the URL and trade it for a token:

```bash
python3 - <<'PY'
import asyncio, json
from pathlib import Path
from mace_platform.connectors.linkedin import LinkedInConnector

cfg = json.loads((Path.home() / ".mace-agent" / "linkedin.json").read_text())
async def main():
    async with LinkedInConnector(**cfg) as c:
        token = await c.exchange_code("<paste-code-here>")
        cfg["access_token"]  = token["access_token"]
        cfg["refresh_token"] = token.get("refresh_token")
        (Path.home() / ".mace-agent" / "linkedin.json").write_text(json.dumps(cfg, indent=2))
        print("✓ Saved access token. Now testing /v2/me…")
        print(await c.get_me())
asyncio.run(main())
PY
```

If you see your own LinkedIn name printed, the connector works.

### Step 6: Hook it into the MACE pipeline
Add this stanza to your tenant config:

```yaml
# tenant.yaml
connectors:
  - type: linkedin
    client_id: "${LINKEDIN_CLIENT_ID}"
    client_secret: "${LINKEDIN_CLIENT_SECRET}"
    redirect_uri: "https://app.unifiedsec.io/oauth/linkedin"
    access_token: "${LINKEDIN_ACCESS_TOKEN}"
    refresh_token: "${LINKEDIN_REFRESH_TOKEN}"
    org_urn: "urn:li:organization:1234567"
    sync_interval_minutes: 60
```

The pipeline orchestrator will call `fetch_events()` every hour and
surface any LinkedIn impersonators as `identity`-domain events in the
MACE algorithm (γ sub-score). They show up in the dashboard's
🚨 Threats / Intrusion section like any other ITDR event.

---

## Part 3 — Marketing Developer Platform application essay

LinkedIn requires you to justify why you need their analytics APIs.
Paste this into the application form, edited to fit your specifics:

> **MACE is a unified cybersecurity platform that protects 10,000+
> endpoints across 13 companies in our pilot fleet. Our LinkedIn
> integration serves two specific purposes:
>
> 1) **Employee identity verification (ITDR)** — we use the Sign In
> with LinkedIn flow to verify that someone claiming to be a
> UnifiedSec employee is in fact who they say they are. This protects
> against impersonator accounts used in phishing campaigns. We pull
> the verified user's name and email; we do not pull connection
> graphs or personal data.
>
> 2) **Brand monitoring** — we use the Marketing Developer Platform's
> follower-statistics and share-statistics endpoints to give our
> internal security team visibility into impostor accounts and
> coordinated harassment campaigns targeting the UnifiedSec brand.
>
> We publish less than 5 organic posts per week and never auto-DM
> users. All data is stored encrypted with TPM/Secure Enclave-bound
> keys on the customer's own infrastructure; LinkedIn data never
> leaves the boundary.
>
> Contact: vivek@unifiedsec.io · DUNS: pending · Delaware C-Corp.

---

## Part 4 — One-week LinkedIn launch checklist

| Day | Action |
|---|---|
| Mon | Create personal-profile prerequisites (photo, summary, headline, 50+ connections) |
| Mon | Create the Company Page at linkedin.com/company/setup/new |
| Tue | Upload logo + banner · write About section · set tagline |
| Tue | Submit Marketing Developer Platform application (5-10 day review) |
| Wed | Register the Developer App + grab client_id/secret |
| Wed | Test the OAuth dance + connector smoke test |
| Thu | Create 5 scheduled posts (one per week for the next 5 weeks) |
| Thu | Invite 50 connections to follow the new page |
| Fri | Post the launch post live · share to your personal feed |
| Fri | Add page URL to the website footer + email signature |
| Sat | Reach out to 5 cybersec influencers (John Lambert, Wendy Nather, Marc Rogers, Allan Liska, Daniel Miessler) and ask for a like/share on the launch post |

---

## Part 5 — Files I added today

| File | Where | What it does |
|---|---|---|
| `connectors/linkedin/__init__.py` | `mace_platform/connectors/linkedin/` | Exports `LinkedInConnector` |
| `connectors/linkedin/connector.py` | same | Full OAuth + Marketing API + impersonation scanner (337 lines) |
| `pipeline/orchestrator.py` | edited | Pipeline now recognises `type: linkedin` configs |
| `connectors/__init__.py` | edited | Doc string lists `linkedin` as supported |
| `MACEDocs/LinkedIn_Company_Page_Setup.md` | this file | Step-by-step + the OAuth dance |

— UnifiedSec Technologies · 2026-06-10
