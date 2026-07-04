# MACE / UnifiedSec — 90-Day Action Plan
**Prepared June 10, 2026 · Owner: Vivek Sindhu**

## Where you stand today (done ✅)

Platform built, 156/156 tests passing, demo runs locally. Patent draft v3 with figures, counsel-ready. Investor proposal v3 + deck graded A−. Funding & filing guide written. Website live at **unifiedsectech.com** with pricing, full feature set, interactive demo, founder bio. Domain email address chosen. Codebase has verifiable evidence-chain API.

---

## Phase 1 — Legal foundation (Weeks 1–2) · ~$3–9k

The order matters: incorporate → assign IP → file patent. Everything else waits on these.

1. **Incorporate UnifiedSec Technologies Inc. (Delaware C-Corp)** via Clerky or Stripe Atlas (~$500 + $109 state fee). Check name availability first at icis.corp.delaware.gov.
2. **Make the email real** — vivek.sindhu@unifiedsectech.com is on the live site NOW and bounces until you set up Google Workspace ($7/mo) or Netlify/registrar forwarding. Do this today.
3. **Engage a registered patent attorney** (budget $2–8k). Hand them `MACE_Patent_Application_v3_DRAFT.docx` — the counsel-notes page lists exactly what to verify, including the India filing question.
4. **File the US provisional** ($130 small entity). The moment you have the application number, "Patent Pending" on the site becomes literally true. Calendar the 12-month non-provisional/PCT deadline with alerts at 6/9/11 months.
5. **Sign + record the IP assignment** (you → company) at the USPTO.
6. Business bank account (Mercury/Brex — free, same week as incorporation).

**Exit criteria:** company exists, patent pending is true, email works.

## Phase 2 — Launch polish (Weeks 2–4) · ~$200

7. **Fix or park macesec.com** — it still doesn't resolve. Lowest effort: in Cloudflare DNS add `A @ 75.2.60.5` (DNS only) + `CNAME www → macesec.netlify.app` (DNS only); then in Netlify set it to redirect to unifiedsectech.com. One primary domain, one redirect.
8. **Record the 3-minute demo video** — script already exists in `04_How_To_Demo/VIDEO_RECORDING_SCRIPT.md`. Screen-record `demo_launch.py`: fleet view → critical incident → evidence draft → chain verification. This video is your highest-leverage asset for every audience.
9. Contact form → Formspree (free), Cloudflare Web Analytics (free), OG image for link previews. All in `LAUNCH_GUIDE.md`.
10. **LinkedIn**: company page + your profile updated to Founder/CEO; first post = the demo video.

**Exit criteria:** one canonical domain, demo video link you can send anyone.

## Phase 3 — Money + design partners in parallel (Weeks 3–8) · $0

Two tracks, same materials. Lead every conversation with the design-partner offer, not the raise.

**Non-dilutive track:**
11. **Hub71 application** (deadline Aug 2, 2026) — UAE wedge story: NESA/aeCERT/DIFC automation no incumbent ships. Up to AED 750k + Gulf network.
12. **DHS SBIR** — watch for the mid-2026 solicitation (best topical fit, ~$175k).
13. **NSF Project Pitch** (3 pages, ~$305k Phase I potential) — frame as probabilistic asset-identity + federated-learning research.

**Design-partner / investor track:**
14. Build a list of 15 targets: 5 FedRAMP-adjacent contractors, 5 UAE critical-infrastructure (via Hub71/DIFC intros), 5 mid-market regulated US firms. Offer: 3 design-partner slots, locked pricing 3 years, founder-level support.
15. **SVCI** (CISO angel syndicate — investors who are also design-partner candidates) and **DataTribe** (cyber foundry, direct application) — apply to both.
16. Begin CTO/co-founder conversations — milestone one for any institutional check.

**Exit criteria:** 2+ grant applications submitted, 10+ design-partner conversations, 1+ signed LOI.

## Phase 4 — Validation (Weeks 8–13)

17. Convert LOIs → paid pilots ($30–60k ACV target). Even one changes everything.
18. SOC 2 Type II: pick a compliance-automation vendor and open the observation window.
19. With first pilot signed: re-approach seed investors with the proposal v3 + traction. The deck's milestone slide becomes evidence, not promise.
20. Counsel: green-light PCT planning off the provisional.

**Exit criteria:** first revenue or signed pilot; seed conversations from strength.

---

## Weekly rhythm
Mon: pipeline review (partners/grants/investors). Wed: product time-box (only what pilots demand). Fri: one public artifact — LinkedIn post, demo clip, or blog note. Always: every conversation logged, every promise dated.

## Budget before funding
Incorporation ~$650 · patent counsel $2–8k · provisional fee $130 · email/tools ~$30/mo · video mic ~$100. **Total: under $10k to be fully legitimate, patent-pending, and live.**

## The one thing that matters most
Nothing on this list compounds like **design partners**. Documents are A−; the only missing grade is a customer. Every week, the first hours go to outreach, not polish.

*Strategic guidance, not legal or financial advice — validate incorporation, patent, and securities steps with counsel.*
