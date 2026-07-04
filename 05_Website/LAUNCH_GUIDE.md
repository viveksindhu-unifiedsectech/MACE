# Launching the MACE Website — Domain + Hosting (≈30 minutes, ≈$80–160/yr)

The site is one self-contained file: `index.html`. No build step, no dependencies.

## Step 1 — Get the domain (~10 min)

**About mace.ai:** it is already owned and listed for sale via the broker Winterline (winterline.com/marketplace/mace-ai). Premium domains like this typically run $10k–100k+. Inquire only if you want to spend that.

**Available-to-register candidates** (check at Porkbun, Namecheap, or GoDaddy — .ai costs ~$70–90/yr, often 2-year minimum):

1. `getmace.ai` — common startup pattern (gethull.ai, getharvest…)
2. `macehq.ai`
3. `trymace.ai`
4. `macesec.ai`
5. `unifiedsec.ai` — matches the company name
6. Fallback: `mace.security` or `macesec.com` (cheaper, still credible)

Recommendation: **getmace.ai** for product marketing + `unifiedsec.ai` for the corporate side if budget allows. Buy with WHOIS privacy on.

## Step 2 — Deploy free in 5 minutes (pick one)

**Option A — Netlify (easiest):**
1. Go to app.netlify.com, sign up free (GitHub or email).
2. Drag the `05_Website` folder onto the dashboard ("Deploy manually").
3. Site is live instantly at `something.netlify.app`.
4. Site settings → Domain management → Add custom domain → enter your .ai domain.
5. At your registrar, set the DNS records Netlify shows you (an A record + CNAME). HTTPS is automatic.

**Option B — Cloudflare Pages:** same flow at pages.cloudflare.com; best if you also want Cloudflare DNS/CDN.

**Option C — Vercel:** vercel.com, drag-and-drop or connect a Git repo.

All three are free for this traffic level and include SSL.

## Step 3 — Make the contact form real (~10 min)

Right now the "Request a demo" form opens the visitor's email client addressed to you (works everywhere, zero setup). To capture leads properly:
1. Sign up at formspree.io (free tier: 50 submissions/mo).
2. Replace the `<form ...>` tag's `action` with your Formspree endpoint URL and set `method="POST"`.

## Step 4 — Before announcing

- [x] Domain email done: vivek.sindhu@unifiedsectech.com is now used across the site.
- [ ] Add analytics: Plausible (paid, private) or Cloudflare Web Analytics (free) — one `<script>` tag before `</body>`.
- [ ] **Patent line:** the footer says "subject of a United States patent application." Only keep this AFTER you file the provisional (Part A of the Funding & Patent Filing Guide). If launching sooner, change to "patent application in preparation."
- [ ] OG image: create a 1200×630 banner (screenshot of the hero works) and add `<meta property="og:image" content="/og.png">` so links unfurl nicely on LinkedIn/X.

## Where to market it first

LinkedIn posts targeting compliance officers + CISOs (NIS2/DORA deadlines are live pain), r/cybersecurity and r/msp, the SBIR/design-partner outreach list in the Funding Guide, and Hacker News "Show HN" once the demo video is up.
