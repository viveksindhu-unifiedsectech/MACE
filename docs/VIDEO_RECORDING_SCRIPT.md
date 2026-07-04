# MACE Demo Video — Recording Script + Tools

## Why I can't directly generate the .mp4 for you

I (Claude) cannot synthesize video files in this environment — no
text-to-video model is wired into my toolchain right now. Tools like
**Synthesia**, **HeyGen**, **Runway Gen-3**, **Sora**, or **Pictory** can
auto-generate explainer videos from a script; the script below is
written so it drops into any of those services (paste the narration
column).

Far easier and 100% free: **macOS has a built-in screen recorder.**
Press **⌘⇧5**, choose "Record selected portion", record yourself walking
through the dashboard while reading the narration aloud. 5-7 minutes of
recording → drag the .mov into iMovie (also free) → export as .mp4.
Done.

If you want zero-effort: **Loom** (loom.com) or **Cap** (cap.so) record
your screen + your webcam + your voice in one click, then give you a
shareable URL or .mp4 download. Free tier covers 5-minute videos.

---

## The actual recording script (paste into Synthesia / HeyGen / read aloud)

Total runtime: ~5 minutes. Sections are timed so you can pace yourself.

---

### 🎬 INTRO — 0:00 to 0:30

> Hi, I'm Vivek Sindhu, founder of UnifiedSec Technologies. What I'm
> about to show you is **MACE** — the Multi-Domain Adaptive Correlation
> Engine. It's the first cybersecurity algorithm to fuse endpoint
> posture — hardware, software, STIG compliance, malware, and intrusion
> — with identity, network, and threat-intel into a single pre-alert
> score across seven domains.

**Show on screen:** open `MACEAgent.app` — the dashboard loads.
Camera focus: the top stats row (devices, avg risk, total CVEs).

---

### 🎬 SCALE — 0:30 to 1:00

> Right now I'm running a 10,000-device enterprise demo on this MacBook.
> Across 13 customer companies, 5 platforms — macOS, Windows, Linux,
> Android, iOS — and 18 device types from laptops to Kubernetes nodes
> to printers to OT/ICS PLCs. All scanning. All reporting in real-time.

**Show on screen:** scroll through the device cards. Use the filter bar
to show "All companies" → pick "Globex Capital", then change platform to
"Linux", then change device type to "Kubernetes node". Show that the
counts update.

---

### 🎬 ONE BINARY — 1:00 to 1:30

> One downloadable agent — this binary — replaces CrowdStrike Falcon,
> Tenable Vulnerability Management, Splunk SOAR, Cisco Umbrella, Zscaler,
> and McAfee. All in 5 megabytes. Across every device. No separate
> license, no separate console.

**Show on screen:** open a Terminal window, run:
```bash
./mace-agent scan --summary
```
Camera focus: the colorful CLI output showing HWAM, SWAM, STIG, CVE
table, remediation plan.

---

### 🎬 ALGORITHM — 1:30 to 2:15

> The patent — filed in five jurisdictions today — covers a 7-domain
> Cross-Domain Correlation Score. Vulnerability, Endpoint events,
> Identity threats, Network context, Compliance posture, Threat
> intelligence, and a brand-new domain: Endpoint Posture, sourced
> directly from the unified agent. No vendor today has all seven in
> one weighted formula.

**Show on screen:** click any device → device detail page. Point at the
device risk number, then the prioritised remediation plan. Click one
action to drill down — show the **where** (device + app path), **what's
causing it** (CVE record with CVSS, EPSS, KEV flag, NVD link), and
**how to fix** (exact command).

---

### 🎬 SELF-REMEDIATION — 2:15 to 3:00

> Every finding ships with an allowlisted fix command. Macey — our
> GenAI security assistant — can run it automatically when priority is
> 9 out of 10 or above. Below that, the analyst clicks Approve. Every
> action is logged with SHA-256 chain-of-custody. This is unique to
> MACE.

**Show on screen:** click "Fix now" on a critical CVE. The plan
appears. Click "Execute remediation". Confirm in the dialog. Show the
audit log entry appearing in the Security Tools tab.

---

### 🎬 MACEY GENAI — 3:00 to 3:45

> Macey is built in. No separate AI license, no per-user fee. I can
> ask her anything.

**Show on screen:** click the ✨ Macey tab. Type into the chat:
- "list devices"
- "which devices are vulnerable to CVE-2024-3094"
- "explain the highest-risk finding"
- "provision an AWS stack in us-east-1 dry-run"

Camera focus: Macey's responses + the tool-call meta line underneath.

---

### 🎬 SECURITY TOOLS — 3:45 to 4:30

> Built-in replacements for the rest of the stack. Network protection
> replaces Zscaler — but enforced on the endpoint with zero PoP
> latency. Virus scan replaces McAfee — but behaviour-first, not
> signature-first. Honey-tokens — unique to MACE — catch the lateral
> movement step of any breach.

**Show on screen:** click Security Tools tab. Point at each card.
Click "Scan this device now" under Virus Protection — show the output.

---

### 🎬 COMPLIANCE — 4:30 to 5:00

> Compliance is one click. Pick any industry — airlines, US banks,
> India CII, UAE telco — and MACE shows you which frameworks apply and
> which built-in modules already evidence them. SOC 2, ISO 27001,
> FedRAMP, CISA BOD 22-01, India DPDP, UAE NESA — all auto-generated.

**Show on screen:** click Compliance tab. Click "Airlines" then "US
Banks" then "India Gov / CII". Show the BOD compliance grid.

---

### 🎬 CLOSE — 5:00 to 5:15

> MACE — patent filed. Working product. Multi-tenant. Multi-jurisdiction.
> Multi-platform. Replaces five vendors. Built by one founder. Raising
> a 5 million dollar seed to close 12 logos and complete SOC 2 by year
> end. Or available for strategic acquisition. Reach me at
> vivek at unifiedsec dot io.

**Show on screen:** final card with logo + email + patent reference.

---

## Free recording workflow (15 minutes, $0)

1. Press **⌘⇧5** → "Record selected portion" → drag a rectangle around
   the browser window.
2. Open the dashboard at `http://127.0.0.1:8765/`.
3. Press the Record button.
4. Read the script above out loud, walking through the dashboard as
   indicated. Take ~5 minutes total.
5. Stop with **⌘⇧5** again → click the thumbnail that appears in the
   bottom-right corner → drag it into iMovie.
6. In iMovie: trim the head/tail dead time → File → Share → File →
   Export as 1080p MP4.

You'll have a polished demo video in about 15-20 minutes of effort.

## Paid alternatives if you want hands-free / AI-narrated

- **Synthesia.io** ($89/mo) — AI avatar reads the script. Drop the
  script above into the editor + add screen captures.
- **HeyGen** ($24-72/mo) — same as above; slightly more avatars.
- **Pictory** ($25/mo) — auto-generates a video from the script and
  stock footage + voice-over.
- **Descript** ($24/mo) — record once, edit by editing the transcript;
  excellent for retakes.
- **Runway Gen-3** ($15-95/mo) — for cinematic intro/outro shots only.
- **Sora** (OpenAI, currently invite-only) — would generate
  photorealistic footage from prompts, but not appropriate for screen
  demos.

## What ChatGPT / Sora cannot do for you here

None of those tools have direct access to your running MACE dashboard.
You will still need to:
- screen-record the dashboard yourself, **or**
- supply still screenshots + the script and let the AI service stitch
  them into a video with narration.

This is a fundamental limit of the current generation of AI video
tools — they synthesize new footage from text, not capture your live
software.

---

## Suggested visuals for an AI-generated video (Synthesia / Pictory)

If you go the AI-avatar route, instead of recording your screen you
can supply screenshots:

1. Hero shot: dashboard with 10,000 devices visible, severity donut chart
2. Filter shot: company filter dropdown open showing 13 companies
3. CVE drill-down: critical CVE expanded with NVD link visible
4. Fix-now button + audit log entry appearing
5. Macey chat with a real Q&A
6. Compliance tab with industry cards
7. Security Tools tab with the McAfee + Zscaler badges
8. CLI shot showing `mace-agent virus-scan` running
9. Patent application heading: "Multi-Domain Adaptive Correlation Engine"
10. Closing slide with logo + email

Capture each as a 1920×1080 PNG (in your browser: `⌘⇧4` → drag the
window). Upload them to your video tool of choice and the AI narrator
reads the script while displaying them.
