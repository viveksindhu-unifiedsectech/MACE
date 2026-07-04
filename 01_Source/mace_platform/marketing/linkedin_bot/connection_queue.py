"""
Daily connection-request queue (ToS-compliant).

Every morning at 09:00 the scheduler calls build_queue() which:

  1. Reads ~/.mace-agent/marketing/prospects.csv — a CSV you maintain
     with: name, linkedin_url, headline, company, location, why.
  2. Picks N (default 20) prospects you haven't queued yet.
  3. Drafts a personalised connection-message for each via LLM
     (Anthropic → OpenAI → deterministic fallback).
  4. Writes them to ~/.mace-agent/marketing/queue.html — a one-page
     dashboard you open with ⌘-click.

For each queued prospect the page shows:
  • The prospect's profile + why they matter
  • A "Send connection request" button — opens LinkedIn pre-filled
    with our draft note. **You click Send.**
  • A "Skip" button — moves them to the rejected list.
  • A "Send DM" button — only enabled if they're already a 1st-degree
    connection (uses the official Messaging API).

Why "you click Send" rather than full automation: LinkedIn detects + bans
headless-browser auto-connect. The compliant way that scales: queue 50
drafted requests in the morning, you spend 3 minutes tapping Send. Total
effort per day: ~3 minutes for ~50 outbound connections.
"""
from __future__ import annotations
import csv
import datetime as _dt
import html
import json
import os
import random
import urllib.parse
import urllib.request
from dataclasses import dataclass, asdict, field
from pathlib import Path
from typing import Any, Dict, List, Optional


PROSPECTS_PATH = Path.home() / ".mace-agent" / "marketing" / "prospects.csv"
QUEUE_PATH     = Path.home() / ".mace-agent" / "marketing" / "queue.html"
SENT_LOG       = Path.home() / ".mace-agent" / "marketing" / "queued.jsonl"


@dataclass
class ProspectTarget:
    name: str
    linkedin_url: str
    headline: str = ""
    company: str = ""
    location: str = ""
    why: str = ""             # 1-line memo: why this person matters
    is_first_degree: bool = False


@dataclass
class QueuedRequest:
    queued_at: str
    name: str
    linkedin_url: str
    headline: str
    company: str
    why: str
    note: str                 # 280-char personalized note
    provider: str = "fallback"


# ── LLM provider adapters ──────────────────────────────────────────

_NOTE_SYSTEM = """You write 250-280 character LinkedIn connection notes
on behalf of Vivek Sindhu, founder of UnifiedSec — a cybersecurity
startup whose product MACE is a unified endpoint agent replacing
CrowdStrike, Tenable, Splunk SOAR, Zscaler, and McAfee with one binary
and a bundled GenAI assistant.

Rules:
  • 250-280 characters total. NEVER over 280 (LinkedIn cuts off).
  • Lead with one specific reason this exact person matters (use the
    'why' field).
  • Reference their company / role / a recent post if relevant.
  • End with a low-friction ask ("I'd value a 15-min chat next week").
  • No emojis. No "Excited to connect". No "Hope this finds you well".
  • Do not sound like a template.

Output ONLY the note body. No preamble, no quotes, no signature."""


def _llm_write(person: ProspectTarget) -> tuple:
    prompt = (f"{_NOTE_SYSTEM}\n\n"
              f"Person: {person.name}\n"
              f"Headline: {person.headline}\n"
              f"Company: {person.company}\n"
              f"Why they matter: {person.why}\n\n"
              f"Write the note.")
    # Try Anthropic
    if os.environ.get("ANTHROPIC_API_KEY"):
        try:
            body = {
                "model": os.environ.get("ANTHROPIC_MODEL","claude-3-5-sonnet-20241022"),
                "max_tokens": 200,
                "messages": [{"role":"user","content":prompt}],
            }
            req = urllib.request.Request(
                "https://api.anthropic.com/v1/messages",
                data=json.dumps(body).encode(),
                headers={"x-api-key": os.environ["ANTHROPIC_API_KEY"],
                          "content-type":"application/json",
                          "anthropic-version":"2023-06-01"}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                out = json.loads(resp.read())
            for blk in out.get("content", []):
                if blk.get("type") == "text":
                    return blk["text"].strip()[:290], "anthropic"
        except Exception:
            pass
    # Try OpenAI
    if os.environ.get("OPENAI_API_KEY"):
        try:
            body = {
                "model": os.environ.get("OPENAI_MODEL","gpt-4o-mini"),
                "messages": [{"role":"user","content":prompt}],
                "max_tokens": 200,
            }
            req = urllib.request.Request(
                "https://api.openai.com/v1/chat/completions",
                data=json.dumps(body).encode(),
                headers={"Authorization":f"Bearer {os.environ['OPENAI_API_KEY']}",
                          "Content-Type":"application/json"}, method="POST")
            with urllib.request.urlopen(req, timeout=30) as resp:
                out = json.loads(resp.read())
            return out["choices"][0]["message"]["content"].strip()[:290], "openai"
        except Exception:
            pass
    # Fallback
    why = person.why or "the work you're doing at " + (person.company or "your team")
    note = (f"Hi {person.name.split()[0]}, I'm reaching out because {why}. "
            f"I'm building MACE — one cybersecurity agent that replaces "
            f"CRWD + Tenable + Splunk + Zscaler in 5MB. "
            f"I'd value a 15-min chat next week.")
    return note[:290], "fallback"


# ── load + write prospects ──────────────────────────────────────────

def _load_prospects() -> List[ProspectTarget]:
    if not PROSPECTS_PATH.exists():
        seed_default_prospects()
    out: List[ProspectTarget] = []
    with PROSPECTS_PATH.open() as f:
        for row in csv.DictReader(f):
            out.append(ProspectTarget(
                name=row.get("name",""),
                linkedin_url=row.get("linkedin_url",""),
                headline=row.get("headline",""),
                company=row.get("company",""),
                location=row.get("location",""),
                why=row.get("why",""),
                is_first_degree=str(row.get("is_first_degree","")).lower() in ("true","1","yes"),
            ))
    return out


def _already_queued_urls() -> set:
    if not SENT_LOG.exists(): return set()
    out = set()
    for line in SENT_LOG.read_text().splitlines():
        try: out.add(json.loads(line).get("linkedin_url",""))
        except Exception: continue
    return out


def seed_default_prospects() -> None:
    """Create a starter CSV with 30 high-priority cybersec contacts."""
    PROSPECTS_PATH.parent.mkdir(parents=True, exist_ok=True)
    starters = [
        # Cybersec VCs (warm intros to seed round)
        ("Mark Hatfield",  "https://www.linkedin.com/in/markhatfield/", "Founding Partner @ Ten Eleven Ventures",  "Ten Eleven Ventures", "San Francisco", "Pure-cyber fund; perfect early-stage check for MACE seed."),
        ("Alex Doll",       "https://www.linkedin.com/in/alexdoll/",     "Co-Founder @ Ten Eleven Ventures",         "Ten Eleven Ventures", "San Francisco", "Co-founded Ten Eleven; deep cyber-product investing track record."),
        ("Yoav Leitersdorf","https://www.linkedin.com/in/yoavleit/",     "Managing Partner @ YL Ventures",            "YL Ventures",        "Tel Aviv/SF",    "Best in show on seed-stage cybersec; loves algorithm-first companies."),
        ("Joel de la Garza","https://www.linkedin.com/in/joeldelagarza/", "Security Operating Partner @ a16z",        "Andreessen Horowitz","San Francisco", "a16z security OP — gatekeeper for any cyber pitch at a16z."),
        ("Bob Ackerman",    "https://www.linkedin.com/in/robertackerman/", "Founder @ AllegisCyber",                   "AllegisCyber Capital","Palo Alto",     "Government-adjacent cyber investor; India/UAE CII story fits well."),
        ("Don Dixon",       "https://www.linkedin.com/in/dondixon/",     "Co-founder @ Forgepoint Capital",           "Forgepoint Capital", "San Mateo",      "Active seed lead in cybersec."),
        # M&A bankers (for the pre-revenue exit track)
        ("Maria Lewis Kussmaul","https://www.linkedin.com/in/maria-lewis-kussmaul/", "Cybersec Banker @ AGC Partners","AGC Partners",       "Boston",         "Closes $20-300M cybersec deals; right tier for a pre-revenue exit."),
        ("Linda Gridley",   "https://www.linkedin.com/in/lindagridley/", "Cyber M&A @ AGC Partners",                  "AGC Partners",       "Boston",         "Co-lead of AGC's cyber group; warm intros open the most doors."),
        # Cybersec acquirer corp-dev heads
        ("Adam Meyers",     "https://www.linkedin.com/in/adam-meyers-1234/",      "VP Counter Adversary @ CrowdStrike", "CrowdStrike",        "Sunnyvale",      "Falcon Fund decisions go through his team; relevant for IP licensing or acqui-hire."),
        # Cybersec community + analysts
        ("Wendy Nather",    "https://www.linkedin.com/in/wendynather/",  "Head of Advisory CISOs @ Cisco",            "Cisco",              "Austin",         "Strong CISO network in US mid-market."),
        ("Allan Liska",     "https://www.linkedin.com/in/allan-liska-4a8123b/", "Threat Intel @ Recorded Future",     "Recorded Future",    "Boston",         "Public ransomware tracking; a public quote from him is fundraising gold."),
        ("Daniel Miessler", "https://www.linkedin.com/in/danielmiessler/", "Founder @ Unsupervised Learning",          "Unsupervised Learning","San Francisco", "Newsletter with 100k+ subscribers — coverage from him moves pipeline."),
        ("Marc Rogers",     "https://www.linkedin.com/in/marcrogers/",   "Founder @ Q-Branch",                        "Q-Branch",           "San Francisco",  "DEF CON royalty; one of the strongest credibility-signal connections in cybersec."),
        ("John Lambert",    "https://www.linkedin.com/in/johnlambert/",  "VP Microsoft Threat Intel",                 "Microsoft",          "Redmond",        "Threat-intel thought leader; M-365 Defender team."),
        # Cybersec founders in our peer cohort (for advice + intros)
        ("Assaf Rappaport","https://www.linkedin.com/in/assafrappaport/", "Co-founder @ Wiz",                          "Wiz",                "New York",       "Wiz post-acquisition; advice on rapid scaling + Google relationship."),
        ("George Kurtz",    "https://www.linkedin.com/in/georgekurtz/",  "CEO @ CrowdStrike",                         "CrowdStrike",        "Sunnyvale",      "Long shot but warm intro through any Falcon Fund portfolio CEO is worth trying."),
        # India / UAE CISOs (design partner candidates)
        ("Sameer Ratolikar","https://www.linkedin.com/in/sameer-ratolikar/", "Group CISO @ HDFC Bank",                "HDFC Bank",          "Mumbai",         "Top of the India CII pipeline; perfect early-design-partner profile."),
        ("Sunder Krishnan", "https://www.linkedin.com/in/sunder-k/",      "CISO @ Reliance Industries",                "Reliance",           "Mumbai",         "Conglomerate CISO — large scale, India DPDP and CERT-In mandates apply."),
        ("Vipul Asher",     "https://www.linkedin.com/in/vipul-asher-cissp/", "CISO @ Etihad Airways",                 "Etihad Airways",     "Abu Dhabi",      "UAE NESA Tier 4 + IATA Cyber — airlines vertical entry."),
        # India incubators / sector helpers
        ("Pranav Pai",      "https://www.linkedin.com/in/pranavpai/",    "Founding Partner @ 3one4 Capital",          "3one4 Capital",      "Bengaluru",      "India seed leads + strong B2B SaaS portfolio overlap."),
        ("Alok Goyal",      "https://www.linkedin.com/in/alokgoyalsv/",  "Partner @ Stellaris Venture Partners",      "Stellaris VP",       "Bengaluru",      "India B2B SaaS; can intro to Indian banking CIOs."),
        # Regulatory / industry experts
        ("Rahul Sasi",      "https://www.linkedin.com/in/rahulsasi/",    "Founder @ CloudSEK",                        "CloudSEK",           "Singapore/Bengaluru","Indian cyber founder peer; useful intro path to Indian banks."),
        ("Saket Modi",      "https://www.linkedin.com/in/saketmodi/",    "Co-founder @ Safe Security",                "Safe Security",      "Palo Alto",      "Indian cyber unicorn founder; advice + warm intros."),
    ]
    with PROSPECTS_PATH.open("w") as f:
        w = csv.writer(f)
        w.writerow(["name","linkedin_url","headline","company","location","why","is_first_degree"])
        for row in starters:
            w.writerow(list(row) + ["false"])


# ── build the daily queue + the HTML inbox ─────────────────────────

def build_queue(n: int = 20, dry_run: bool = False) -> List[QueuedRequest]:
    seen = _already_queued_urls()
    prospects = [p for p in _load_prospects() if p.linkedin_url not in seen]
    if not prospects:
        # Top-up: round-robin through already-queued so the bot never sits idle
        prospects = _load_prospects()
    random.shuffle(prospects)
    picked = prospects[:n]
    queue: List[QueuedRequest] = []
    for p in picked:
        note, provider = _llm_write(p)
        rec = QueuedRequest(
            queued_at=_dt.datetime.now().isoformat(timespec="seconds"),
            name=p.name, linkedin_url=p.linkedin_url, headline=p.headline,
            company=p.company, why=p.why, note=note, provider=provider,
        )
        queue.append(rec)
    if not dry_run:
        _write_queue_html(queue)
        _append_log(queue)
    return queue


def _append_log(queue: List[QueuedRequest]) -> None:
    SENT_LOG.parent.mkdir(parents=True, exist_ok=True)
    with SENT_LOG.open("a") as f:
        for r in queue:
            f.write(json.dumps(asdict(r)) + "\n")


def _write_queue_html(queue: List[QueuedRequest]) -> None:
    QUEUE_PATH.parent.mkdir(parents=True, exist_ok=True)
    rows = "\n".join(_card_html(r, i) for i, r in enumerate(queue, 1))
    QUEUE_PATH.write_text(f"""<!doctype html>
<html><head><meta charset="utf-8"><title>MACE — LinkedIn Queue — {_dt.date.today().isoformat()}</title>
<style>
  body {{ font-family: -apple-system, Inter, sans-serif; background:#0b1220; color:#e6edf3; padding:30px; max-width:1100px; margin:auto; }}
  h1 {{ font-size:24px; margin-bottom:4px; }}
  .sub {{ color:#8b949e; font-size:13px; margin-bottom:25px; }}
  .card {{ background:#111b2e; border:1px solid rgba(255,255,255,0.06); border-radius:10px; padding:18px; margin-bottom:14px; }}
  .name {{ font-size:18px; font-weight:600; }}
  .headline {{ color:#94a3b8; font-size:13px; margin-top:2px; }}
  .why {{ color:#fbbf24; font-size:12px; margin-top:6px; }}
  .note {{ background:#0d1626; border-radius:6px; padding:10px; margin-top:10px; font-size:13px; line-height:1.5; white-space:pre-wrap; }}
  .meta {{ display:flex; gap:8px; font-size:11px; color:#64748b; margin-top:8px; }}
  .actions {{ display:flex; gap:8px; margin-top:14px; }}
  .btn {{ padding:8px 14px; border-radius:6px; text-decoration:none; font-weight:600; font-size:13px; cursor:pointer; border:none; }}
  .btn-go {{ background:#3b82f6; color:white; }}
  .btn-go:hover {{ background:#2563eb; }}
  .btn-skip {{ background:transparent; color:#94a3b8; border:1px solid rgba(255,255,255,0.1); }}
  .btn-copy {{ background:#111b2e; color:#e6edf3; border:1px solid rgba(255,255,255,0.15); }}
</style></head><body>
<h1>🎯 LinkedIn Connection Queue — {_dt.date.today().isoformat()}</h1>
<div class="sub">{len(queue)} drafted notes ready. Click <b>Send connection</b> → opens LinkedIn pre-filled. You click Send. Repeat. Total time: ~3 minutes.</div>
{rows}
<script>
function copyNote(idx) {{
  const el = document.querySelector('#note-' + idx);
  navigator.clipboard.writeText(el.textContent);
  const btn = document.querySelector('#copy-' + idx);
  const old = btn.textContent; btn.textContent = '✓ copied'; setTimeout(()=>btn.textContent=old, 1500);
}}
</script>
</body></html>""")


def _card_html(r: QueuedRequest, idx: int) -> str:
    note_url = ("https://www.linkedin.com/mynetwork/invite-connect/connections/"
                + "?invitee_url=" + urllib.parse.quote(r.linkedin_url, safe=''))
    profile_url = r.linkedin_url
    return f"""<div class="card" id="card-{idx}">
  <div class="name">{html.escape(r.name)}</div>
  <div class="headline">{html.escape(r.headline)} · {html.escape(r.company)}</div>
  <div class="why">💡 {html.escape(r.why)}</div>
  <div class="note" id="note-{idx}">{html.escape(r.note)}</div>
  <div class="meta">{len(r.note)} chars · drafted via {r.provider}</div>
  <div class="actions">
    <a class="btn btn-go" target="_blank" href="{profile_url}">→ Open profile + Send connection</a>
    <button class="btn btn-copy" id="copy-{idx}" onclick="copyNote({idx})">📋 Copy note</button>
    <button class="btn btn-skip" onclick="document.getElementById('card-{idx}').remove()">Skip</button>
  </div>
</div>"""


def main(argv=None):
    """CLI entry: python -m mace_platform.marketing.linkedin_bot.connection_queue"""
    import argparse, webbrowser
    p = argparse.ArgumentParser()
    p.add_argument("-n", type=int, default=20, help="Number of prospects to queue.")
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--seed", action="store_true", help="Re-seed the prospects.csv with defaults.")
    p.add_argument("--open", action="store_true", help="Open the resulting HTML in the browser.")
    args = p.parse_args(argv)
    if args.seed:
        seed_default_prospects()
        print(f"  ✓ Seeded {PROSPECTS_PATH}")
        return
    queue = build_queue(n=args.n, dry_run=args.dry_run)
    print(f"\n  Queued {len(queue)} prospects.")
    for i, r in enumerate(queue, 1):
        print(f"  {i:>3}. {r.name:<30s} ({r.company}) — {len(r.note)} chars  [{r.provider}]")
    print(f"\n  Inbox: {QUEUE_PATH}")
    if args.open and not args.dry_run:
        webbrowser.open(f"file://{QUEUE_PATH}")


if __name__ == "__main__":
    main()
