"""
Daily LinkedIn poster — fully autonomous.

  1. Wakes up at 09:00 local (configurable).
  2. Picks today's post theme from a 28-day rotation.
  3. Asks Claude / OpenAI to write a 800-1200 char LinkedIn post in
     MACE's voice (deterministic fallback when no LLM key is set).
  4. Publishes to the UnifiedSec company page via the official
     /v2/ugcPosts API.
  5. Logs the post + permalink to ~/.mace-agent/marketing/posts.jsonl
     so you can review the bot's output at any time.

The post themes are designed so the page never repeats and the audience
sees a coherent narrative: product education → social proof → industry
commentary → recruiting → patent / IP → customer story → and back.
"""
from __future__ import annotations
import asyncio
import datetime as _dt
import json
import os
import urllib.request
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


CONFIG_PATH = Path.home() / ".mace-agent" / "linkedin.json"
LOG_DIR = Path.home() / ".mace-agent" / "marketing"
LOG_FILE = LOG_DIR / "posts.jsonl"


# ── 28-day post-theme calendar ──────────────────────────────────────

POST_THEMES = [
    # Week 1 — what MACE is + why now
    ("product_intro",   "Introduce MACE — one binary replacing CrowdStrike + Tenable + Splunk + Zscaler + McAfee."),
    ("seven_domains",   "Explain the seven-domain CDCS algorithm and why no competitor has it."),
    ("agent_demo",      "Walk through what a single MACE agent scan finds: HWAM, SWAM, STIG, CVE, malware in one pass."),
    ("regulatory",      "Why CERT-In 6h + DPDP + NESA + GDPR all need the same evidence pipeline."),
    ("macey_intro",     "Macey — the GenAI security analyst that ships free in MACE. No $10/user/month surprise."),
    ("competitor_take", "Where Zscaler hurts customers with PoP latency, and how MACE replaces it with on-device enforcement."),
    ("hardware_attest", "Hardware-rooted attestation — only vendor on the market doing this on-endpoint."),
    # Week 2 — social proof + customer stories
    ("design_partner",  "Quiet update on our two design partners (India CII bank, UAE telco) — no names yet."),
    ("metric_post",     "What 'one tool replaces five' actually means in dollars on a 1000-endpoint estate."),
    ("compliance_save", "How MACE generates an SOC 2 evidence pack auditors actually accept."),
    ("bod_22_01",       "CISA BOD 22-01 + KEV: how MACE handles the entire mandate by Tuesday."),
    ("india_dpdp",      "India DPDP enforcement is here. What every Indian enterprise must now do, and why MACE compresses it to 1 day of work."),
    ("mitre_attack",    "Mapping the latest MITRE ATT&CK eval against MACE's behavioural EDR — public numbers."),
    ("ransomware_kill", "Ransomware canary tripwires + lockdown playbook — how we stop encryption in <50 ms."),
    # Week 3 — industry commentary + thought leadership
    ("crwd_outage_take","Lessons from the July '24 CrowdStrike outage — why one-vendor monocultures break."),
    ("ai_assistant_real","What 'AI in security' actually buys you. Honest, no marketing."),
    ("post_quantum",    "NIST PQ migration mandate by 2030. MACE's quantum-readiness inventory."),
    ("deepfake_voice",  "Deepfake voice attacks on CFOs — and the per-second authenticity score MACE computes."),
    ("supply_chain",    "XZ-utils backdoor (CVE-2024-3094) — what SBOM + supply-chain detection would have caught."),
    ("federated_ai",    "Federated learning for security models — without sharing customer data. Differential privacy in plain English."),
    ("zero_trust_real", "Zero Trust is not a product. It's seven things MACE does on every endpoint, every minute."),
    # Week 4 — recruiting + brand
    ("hiring_vp_sales", "We're hiring our first VP Sales. India + UAE territory. DM Vivek."),
    ("hiring_engineer", "Hiring 2 senior security engineers. Remote. Cybersecurity-product background required."),
    ("founder_story",   "Why I started UnifiedSec. The personal story behind MACE."),
    ("patent_filing",   "Patent IN/2026/UNISEC/MACE-001 + PCT national-phase to US/CA/EU/UAE/IN. What 30 claims cover."),
    ("press_demo",      "5-minute live demo of the dashboard at 10,000 simulated devices. Link to the recording."),
    ("nesa_uae",        "UAE NESA Tier 4 compliance: how MACE makes this a 7-day project, not 7 months."),
    ("year_in_review",  "Year in MACE — what we shipped, what we learned, what's next."),
]

SYSTEM_PROMPT = """You are the official social-media voice of UnifiedSec
Technologies — a cybersecurity startup whose flagship product MACE is a
unified endpoint agent replacing CrowdStrike, Tenable, Splunk SOAR,
Zscaler, and McAfee with one binary, under a patented seven-domain
correlation algorithm and a bundled GenAI assistant called Macey.

Voice rules:
  • Direct, plain-English, opinionated. No fluff, no buzzwords ("synergy",
    "best-in-class", "leverage", "world-class") — they are banned.
  • Lead with a fact, a number, or an opinion. Never with "we are
    excited to announce..."
  • Each post is 600-1100 characters total, line-broken every 1-3
    sentences for LinkedIn scannability.
  • Include 1 emoji at the start of each paragraph if it adds clarity;
    no emoji walls.
  • End every post with a one-line call to action ("Demo: unifiedsec.io",
    "Hiring: DM Vivek", or a single concrete question).
  • No hashtags at the end — they make posts look bot-generated.
  • Never invent customer logos, ARR numbers, or capabilities we don't
    have. If unsure, leave the claim out.

You are writing post number {post_number} of an ongoing daily cadence.
Today's theme is "{theme_id}": {theme_brief}

Write the post. Output only the post body — no preamble, no quotes."""


@dataclass
class PostRecord:
    posted_at: str
    theme_id: str
    body: str
    permalink: str = ""
    success: bool = False
    error: str = ""
    provider: str = "fallback"
    model: str = ""


def _config() -> Dict[str, Any]:
    if not CONFIG_PATH.exists():
        raise RuntimeError(
            f"Missing config at {CONFIG_PATH}. "
            f"See MACEDocs/LinkedIn_Company_Page_Setup.md Part 2 Step 4 to create it.")
    return json.loads(CONFIG_PATH.read_text())


def _today_theme() -> tuple:
    """Pick today's theme by rotating through the 28-day calendar."""
    idx = (_dt.date.today().toordinal()) % len(POST_THEMES)
    return POST_THEMES[idx]


# ── LLM provider adapters (stdlib only) ─────────────────────────────

def _anthropic_write(prompt: str) -> str:
    key = os.environ.get("ANTHROPIC_API_KEY")
    if not key: raise RuntimeError("ANTHROPIC_API_KEY not set")
    body = {
        "model": os.environ.get("ANTHROPIC_MODEL", "claude-3-5-sonnet-20241022"),
        "max_tokens": 700,
        "messages": [{"role": "user", "content": prompt}],
    }
    req = urllib.request.Request(
        "https://api.anthropic.com/v1/messages",
        data=json.dumps(body).encode(),
        headers={"x-api-key": key, "content-type": "application/json",
                  "anthropic-version": "2023-06-01"}, method="POST")
    with urllib.request.urlopen(req, timeout=45) as resp:
        out = json.loads(resp.read())
    for blk in out.get("content", []):
        if blk.get("type") == "text":
            return blk.get("text", "").strip()
    return ""


def _openai_write(prompt: str) -> str:
    key = os.environ.get("OPENAI_API_KEY")
    if not key: raise RuntimeError("OPENAI_API_KEY not set")
    body = {
        "model": os.environ.get("OPENAI_MODEL", "gpt-4o-mini"),
        "messages": [{"role": "user", "content": prompt}],
        "max_tokens": 700,
    }
    req = urllib.request.Request(
        "https://api.openai.com/v1/chat/completions",
        data=json.dumps(body).encode(),
        headers={"Authorization": f"Bearer {key}",
                  "Content-Type": "application/json"}, method="POST")
    with urllib.request.urlopen(req, timeout=45) as resp:
        out = json.loads(resp.read())
    return out["choices"][0]["message"]["content"].strip()


# ── Deterministic fallback templates (work offline) ─────────────────

FALLBACK_TEMPLATES = {
    "product_intro": (
        "🛡 Most companies pay for five security tools.\n\n"
        "CrowdStrike for EDR. Tenable for vulns. Splunk for SOAR. Zscaler "
        "for network. McAfee or Defender for AV. That stack costs about "
        "$1.2M per 1,000 endpoints per year.\n\n"
        "MACE is one 5 MB binary that does all of it — under a seven-domain "
        "correlation algorithm we patented in five jurisdictions.\n\n"
        "Demo: unifiedsec.io"),
    "macey_intro": (
        "🤖 Microsoft Copilot for Security: $4/user/hour.\n"
        "Splunk AI Assistant: separate license.\n"
        "Crowdstrike Charlotte AI: enterprise tier only.\n\n"
        "Macey ships in MACE. Free. Tool-using over every CVE, every STIG "
        "check, every device. Ask 'which devices are vulnerable to "
        "CVE-2024-3094' and she runs the scan + writes the fix command.\n\n"
        "Demo: unifiedsec.io"),
    "hiring_vp_sales": (
        "🎯 Hiring our first VP Sales at UnifiedSec.\n\n"
        "Territory: India + UAE + EU. Cybersecurity-product background "
        "required. You'll own the first 12 customer logos.\n\n"
        "Compensation: $180-220k base + 1.0% equity + uncapped commission.\n\n"
        "DM Vivek if interested."),
    "patent_filing": (
        "📜 Patent IN/2026/UNISEC/MACE-001 + PCT national-phase entries "
        "filed in US, Canada, EU, UAE, and India.\n\n"
        "30 claims. Cover the seven-domain weighted correlation algorithm, "
        "the unified endpoint agent, hardware-rooted attestation, federated "
        "adaptive learning, cyber digital-twin attack-path simulation, "
        "post-quantum readiness, deepfake-voice detection, cross-asset "
        "incident replay, and the safety-allowlist auto-remediation engine.\n\n"
        "If you're a cybersecurity acquirer evaluating IP: vivek@unifiedsec.io"),
}


def generate_post(theme_id: Optional[str] = None,
                   theme_brief: Optional[str] = None,
                   post_number: Optional[int] = None) -> tuple:
    """
    Generate today's post. Returns (theme_id, body, provider, model).

    Tries Anthropic, then OpenAI, then a deterministic fallback template.
    """
    if not theme_id:
        theme_id, theme_brief = _today_theme()
    if not theme_brief:
        for tid, brief in POST_THEMES:
            if tid == theme_id:
                theme_brief = brief; break
    if post_number is None:
        post_number = _dt.date.today().toordinal() - 739_252  # rough day counter
    prompt = SYSTEM_PROMPT.format(
        post_number=post_number, theme_id=theme_id, theme_brief=theme_brief)

    # Try Anthropic
    try:
        if os.environ.get("ANTHROPIC_API_KEY"):
            txt = _anthropic_write(prompt)
            if txt: return theme_id, txt, "anthropic", os.environ.get("ANTHROPIC_MODEL","claude-3-5-sonnet")
    except Exception as e:
        print(f"[daily_poster] Anthropic failed: {e}")

    # Try OpenAI
    try:
        if os.environ.get("OPENAI_API_KEY"):
            txt = _openai_write(prompt)
            if txt: return theme_id, txt, "openai", os.environ.get("OPENAI_MODEL","gpt-4o-mini")
    except Exception as e:
        print(f"[daily_poster] OpenAI failed: {e}")

    # Deterministic fallback (always works)
    body = FALLBACK_TEMPLATES.get(theme_id, FALLBACK_TEMPLATES["product_intro"])
    return theme_id, body, "fallback", "template"


# ── LinkedIn publish ────────────────────────────────────────────────

async def _publish(body_text: str, cfg: Dict[str, Any]) -> Dict[str, Any]:
    """Publish via the official /v2/ugcPosts endpoint."""
    from mace_platform.connectors.linkedin import LinkedInConnector
    from mace_platform.connectors.linkedin.connector import LinkedInPostDraft

    async with LinkedInConnector(
        client_id=cfg["client_id"], client_secret=cfg["client_secret"],
        redirect_uri=cfg.get("redirect_uri",""),
        access_token=cfg.get("access_token"),
        refresh_token=cfg.get("refresh_token"),
        org_urn=cfg["org_urn"],
    ) as c:
        draft = LinkedInPostDraft(author_urn=cfg["org_urn"], text=body_text)
        resp = await c.publish_post(draft)
    return resp


def _log(rec: PostRecord) -> None:
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    with LOG_FILE.open("a") as f:
        f.write(json.dumps(asdict(rec)) + "\n")


# ── Public entrypoint (called by the daemon / launchd) ──────────────

def run_daily_post(dry_run: bool = False, force_theme: Optional[str] = None) -> PostRecord:
    """Generate + publish today's post."""
    theme_id, body, provider, model = generate_post(theme_id=force_theme)
    rec = PostRecord(
        posted_at=_dt.datetime.now().isoformat(timespec="seconds"),
        theme_id=theme_id, body=body, provider=provider, model=model,
    )
    if dry_run:
        rec.success = True
        rec.permalink = "(dry-run; would have posted)"
        _log(rec)
        return rec
    try:
        cfg = _config()
        resp = asyncio.run(_publish(body, cfg))
        urn = resp.get("id") or resp.get("activity")
        if urn:
            rec.permalink = f"https://www.linkedin.com/feed/update/{urn}"
        rec.success = True
    except Exception as e:
        rec.error = str(e)[:300]
    _log(rec)
    return rec


def main(argv=None):
    """CLI entry: python -m mace_platform.marketing.linkedin_bot.daily_poster"""
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("--dry-run", action="store_true",
                    help="Generate but do not publish.")
    p.add_argument("--theme", help="Override today's theme id.")
    args = p.parse_args(argv)
    rec = run_daily_post(dry_run=args.dry_run, force_theme=args.theme)
    print(f"\n  posted_at : {rec.posted_at}")
    print(f"  theme     : {rec.theme_id}")
    print(f"  provider  : {rec.provider} ({rec.model})")
    print(f"  success   : {rec.success}")
    if rec.permalink: print(f"  permalink : {rec.permalink}")
    if rec.error:     print(f"  error     : {rec.error}")
    print(f"\n--- post body ({len(rec.body)} chars) ---\n")
    print(rec.body)
    print(f"\nLogged to {LOG_FILE}\n")


if __name__ == "__main__":
    main()
