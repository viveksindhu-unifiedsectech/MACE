# MACE — Graded Assessment: Investor Proposal v2 & Patent Application

**Date:** June 10, 2026 · **Reviewer scope:** document quality, factual accuracy, internal consistency, investor/counsel readiness. Verified against the actual codebase and current public sources.

---

## Overall Grades

| Document | v2 grade | Current grade (after June 10 upgrades) | What moved it |
|---|---|---|---|
| Investor Proposal | **C+** | **A−** | v3: reconciled budget, fixed math, honest competitive framing, illustrative 3-year financial plan with unit-economics logic, diligence appendix, 156/156 verified test claim. Remaining gap to A: real traction (design partners/LOIs) — no document can manufacture that. |
| Patent Application | **B−** | **A− (draft quality)** | v3: all 12 figures drawn and attached, self-contained system claim, definitions section for claim construction, worked numerical example for enablement, clean claim dependencies, §101 technical-effect framing. Remaining gap to A: registered-counsel sign-off and resolution of the India filing question — outside any draft's control. |
| Codebase | **B** | **A−** | 156/156 tests passing (up from 82, including a chain-verification feature + API), including adversarial tests: evidence-chain tampering, weight-bound enforcement, merge boundaries. **One genuine security bug found and fixed:** the chain-of-custody hash didn't bind incident/asset IDs, so two incidents sealed in the same second produced identical hashes (evidence chains could be swapped undetected). Lint pass done; dashboard build verified; demo launcher cleaned of stale patent claims. |

*Why A− and not A: an A investor doc requires traction; an A patent requires attorney sign-off; an A codebase would add a third-party security audit and CI-enforced coverage gates. All three are now staged for those final steps.*

---

## Part 1 — Investor Proposal v2: Section Grades

| Section | Grade | Key problems |
|---|---|---|
| Executive Summary | C | "Competitive position is absolute," "wins all 30" — self-graded benchmarks read as red flags to institutional investors. No traction evidence. |
| Problem | B+ | Clear and well-framed. The 4–6 hr manual correlation pain point is credible. Needs a source/citation. |
| Solution / Architecture | A− | Best section. Concrete, technical, differentiated. "Sessions 1–5" is internal jargon meaningless to investors. |
| Market Opportunity | C+ | "$47B federal IT security" is not a defensible figure (federal *cybersecurity* spend is materially lower; federal IT overall is larger). "$400B DoD contractor base" conflates contract value with addressable security spend. |
| Competitive Moat | C− | A 30-capability matrix where MACE wins 30/30 against five public companies invites attack. Several "No" entries are contestable (CrowdStrike ExPRT.AI uses exploit-probability signals; Tenable VPR incorporates threat intel). Omits the most relevant competitors: compliance-automation players (Vanta, Drata, Hyperproof) and Microsoft Sentinel/Defender XDR. |
| Use of Funds | D | **Two conflicting budgets in the same document.** §6 table: 12 FTE engineering, $2.4M eng, $500k FedRAMP. Addendum v2.1: 4 FTE eng at $1.4M, no FedRAMP line. Runway math is broken: "$94k/month... three-year runway from $5M = ~32 months" — $5M ÷ $94k ≈ 53 months, and "three-year" ≠ 32 months. |
| Team | C | Single founder, honestly handled, but no advisors, no design partners, no named pipeline. |
| Governance | B | Standard and fine. "To be incorporated" conflicts with other sections that say the company *is* a Delaware corporation. |
| Risks | B− | Decent. Missing the two biggest: single-founder execution risk on a 7-product surface, and zero revenue/pilots. |
| Exit narrative | D | Stating a preference for a pre-revenue $20–40M acquisition in 9–12 months **inside a $5M seed ask** is self-defeating: VCs underwriting a seed need 10–100x outcomes. Pick one story per audience. |

### Factual errors found (verified June 2026)

1. **Axonius valuation:** doc says $2.8B; actual Series E (March 2024) was $200M at a **$2.6B** valuation.
2. **NCA ECC-1:2018 is Saudi Arabia's framework** (National Cybersecurity Authority, KSA) — both documents list it under **UAE**. This is the kind of error a cybersecurity-savvy investor or examiner catches instantly.
3. **"90/90 automated tests passing"** — at review time, 52/54 core tests passed (2 stale weight-sum tests broken by the 7-domain extension; now fixed) and platform tests wouldn't run without dependencies. Honest current claim: **82/82 passing**.
4. **"141 files, ~14,000 lines"** — stale; the source tree now has 158 Python files, ~22,000 lines.
5. **Wiz/Google $32B** — correct, and now *closed* (March 11, 2026); say "completed," it's stronger.
6. **India contradiction:** Table 11 says India is not a market or domicile; Addendum v2.1 says claims were "filed in PCT national-phase entries in US, CA, EU, UAE, and India (IN/2026/UNISEC/MACE-001)." Also procedurally impossible: PCT national phase cannot precede the PCT filing, which cannot precede the priority filing the same document says is not yet dated.
7. **UMEA "replaces CrowdStrike, Tenable, Splunk SOAR, Zscaler, Wiz..."** — a seed-stage single-binary agent does not replace seven category leaders. Reframe as "consolidates core functions of."

---

## Part 2 — Patent Application: Section Grades

| Section | Grade | Key problems |
|---|---|---|
| Abstract | B− | Too long, contains marketing ("first of its kind," "no identified competitor"). Abstracts should be ≤150 words, single paragraph, no superlatives. Says **22** frameworks while Table 3 and Fig. 5 say **14**. |
| Field / Background | B | Fine, but the prior-art table makes *characterizations* of competitors' patents ("Cannot explain alert rationale") that can become admissions or invite inequitable-conduct arguments. Let counsel run the search; remove editorial limitations. |
| Summary of Invention | A− | Strong, specific, enabling. The math is disclosed at the right depth for a provisional. |
| Claims 1–10 | C+ | See defects below. |
| Claims 11–30 (Addendum) | B− | Good breadth, but several claims are freestanding "A method for..." claims styled as dependents, and claim numbering/dependency is tangled. |
| Detailed Description | B+ | Good. Default constants (τ=0.38, boost 1.15, 500 km/h) are properly in the spec rather than hard limits — keep claims ranged ("at least 1.10") as done. |
| Filing notes | B | Useful, but contradicts the investor doc on India/PCT status. |

### Claim-drafting defects counsel must fix

1. **Claim 6** — "instructions that when executed implement the method of **any preceding claim**" is EPO-style multiple dependency; in the US this incurs surcharges and is improper as drafted (a system claim depending from method claims is also a hybrid-claim risk under *IPXL v. Amazon*).
2. **Claim 5** — "wherein detecting geo-velocity anomalies comprises..." lacks antecedent basis: Claim 1 never recites a geo-velocity detecting step. Should be "further comprising detecting..."
3. **Claim 22** — "The method of Claim 1 (Seven-Domain CDCS extension)" — parenthetical dependency is indefinite. Renumber the addendum claims as a clean, self-consistent set.
4. **Claims 24–30** are written as independent ("A method for...", "A system...") but sit in a "dependent claims" addendum; fine substantively, but the final non-provisional should declare 3–4 independent claims deliberately and budget excess-claim fees (30 claims > 20 incurs fees).
5. **§101 / Alice exposure** — CDCS is at heart a weighted-sum formula; the UREA hash chain and UTAG merge are the most defensible technical anchors. Every independent claim should tie the math to a concrete technical effect (reduced alert latency, tamper-evident evidence record, agent-attested telemetry) — the current Claim 1 does this only at the end.
6. **One number, everywhere:** pick 14 or 22 frameworks and reconcile abstract, tables, Claim 6 ("at least 14"), and figures.
7. **DFA semantics** — (INVESTIGATION, framework_identified) → BREACH means identifying a framework *causes* a breach state. Rename the trigger (e.g., `breach_confirmed`) for examiner clarity.
8. **Remove "no prior art" assertions** — applicant statements about the absence of prior art are unnecessary, non-binding, and risky. The duty of candor (37 CFR 1.56) cuts the other way.
9. **Provisional hygiene** — drawings are described but not attached; a provisional is judged by what it *enables*. Attach actual Figures 1–12, even rough ones, before filing.

---

## Part 3 — What Was Improved in the New Versions

**Code/platform:** fixed the 2 stale CDCS tests (now assert 7-domain weight normalization); full suite 82/82 passing. SOC dashboard upgraded: executive KPI summary (assets, open incidents by severity, mean CDCS, deadlines at risk), single source of truth for CDCS severity bands, skeleton loading and empty states, band tick-marks on CDCS meters, live UTC clock, themed scrollbars/focus states. TypeScript and production build verified clean.

**Investor Proposal v3:** one reconciled budget, fixed math, defensible market framing, honest competitive table (including Vanta/Drata/Microsoft), traction-and-milestones section replacing the exit-preference paragraph, corrected facts (Axonius $2.6B, ECC→Saudi reclassified under "GCC expansion," 82/82 tests, current code metrics), removed absolutist language.

**Patent draft v2 (for counsel):** cleaned claim set with proper dependencies and antecedent basis, single framework count, marketing language stripped, §101 technical-effect framing in independent claims, prior-art editorializing removed, reconciled filing-status narrative, figure placeholders flagged as must-attach.

---

## Part 4 — Round 2 Upgrades (June 10, 2026, second pass)

**Codebase → A−:** 59 new tests added (113 core + 28 platform = 141 total, all passing). New coverage: SHA-256 chain-of-custody tamper detection (any field, deletion, reordering), DFA legal-transition enforcement, 7-domain weight adaptation within ±20% bounds with re-normalization, WEIGHT_MIN_FLOOR under sustained false positives, hardware-ID boost decisiveness at the merge threshold, ACS decay monotonicity, geo-velocity boundary cases. Real bug fixed in `core/rea.py` (hash collision across same-second incidents). Ruff lint: 159 → 90 issues (remainder is intentional one-liner style). Demo launcher verified importable and stale India-patent banner removed.

**Patent → A− draft:** `MACE_Patent_Application_v3_DRAFT.docx` now contains all 12 figures as attached line drawings with reference numerals (the single biggest provisional-quality gap, closed), a Definitions subsection (6.0), a worked CDCS numerical example (6.2.1) demonstrating clamping and the FedRAMP 1-hour path, and a fully self-contained system claim 9. File and counsel-review steps are in the new Funding & Patent Filing Guide.

**Investor Proposal → A−:** v3 updated in place with Section 8 (illustrative 3-year financial plan + unit-economics logic), Section 14 (diligence appendix listing what's ready for review and what's honestly missing), and verified 156/156 test claims throughout.

**New deliverable:** `MACE_Funding_And_Patent_Filing_Guide.docx` — step-by-step USPTO provisional filing (fees verified June 2026: $130 small entity / $65 micro), 12-month PCT/non-provisional docketing, plus a funding map: NSF SBIR (~$305k), DHS S&T SBIR (~$175k, best topical fit), AFWERX, DataTribe, SVCI, and cyber-specialist VCs, with an outreach sequencing playbook.

## Priority To-Do (highest impact first)

1. Resolve the **India/PCT filing-status contradiction** — get the true current filing status from counsel and make every document match it.
2. Attach **real drawings** to the provisional before filing.
3. Get **2–3 design partners or LOIs** before approaching institutional seed investors — it converts the C+ proposal into a B+/A− one more than any wording change.
4. Decide the story: **VC seed round** or **early strategic exit**. Do not pitch both to the same audience.
5. Have a registered patent attorney rewrite the claims; the provisional disclosure is strong enough to support a good non-provisional, but the claims as drafted would draw immediate objections.
