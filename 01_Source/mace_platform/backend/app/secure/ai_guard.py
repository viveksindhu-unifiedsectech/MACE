"""
AI Safeguard for MACE Secure Files — warns about the threat or vulnerability
BEFORE the risky action completes.

Every upload / share / download is passed through assess() first. It produces a
risk score, a verdict (allow | warn | block), and human-readable findings that
feed the audit log and the UI banner. Two layers:

  1. Deterministic rules (always on, offline): leaked secrets, malware magic
     bytes, over-broad sharing of classified data, classification downgrade,
     and prompt-injection attempts aimed at MACE's own AI.
  2. Optional Claude pass (when ANTHROPIC_API_KEY is set): a second opinion on a
     REDACTION-SAFE summary — raw secret values are never sent to the model.

Fail-safe: if the AI call errors, we keep the deterministic verdict (which can
already block), so the guard never fails *open* on the rule-covered risks.
"""
from __future__ import annotations

import enum
import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from app.secure.access import Classification
from app.secure.redaction import RedactionReport, scan_text, ALL_CATEGORIES


class Verdict(str, enum.Enum):
    ALLOW = "allow"
    WARN = "warn"
    BLOCK = "block"


@dataclass
class Finding:
    code: str
    severity: str          # low | medium | high | critical
    message: str


@dataclass
class GuardResult:
    score: int                     # 0-100 (higher = riskier)
    verdict: Verdict
    findings: List[Finding] = field(default_factory=list)
    used_ai: bool = False

    def as_dict(self) -> Dict:
        return {
            "score": self.score,
            "verdict": self.verdict.value,
            "used_ai": self.used_ai,
            "findings": [f.__dict__ for f in self.findings],
        }


_SEVERITY_WEIGHT = {"low": 10, "medium": 25, "high": 45, "critical": 80}

# Executable / script magic bytes we never want silently accepted as "documents".
_MALWARE_MAGIC = {
    b"MZ": "Windows PE executable",
    b"\x7fELF": "Linux ELF executable",
    b"\xca\xfe\xba\xbe": "Mach-O / Java class",
    b"\xcf\xfa\xed\xfe": "Mach-O executable",
    b"PK\x03\x04": None,  # zip/office — informational only, handled separately
}

_PROMPT_INJECTION = re.compile(
    r"(ignore (all |the )?(previous|prior|above) (instructions|prompts)|"
    r"disregard (your|the) (rules|instructions|system prompt)|"
    r"you are now|act as (an? )?(unrestricted|jailbroken)|"
    r"reveal (your )?(system prompt|instructions))",
    re.IGNORECASE,
)


def _classification(c) -> Classification:
    return c if isinstance(c, Classification) else Classification(str(c))


def assess(
    *,
    action: str,                       # "upload" | "share" | "download"
    content: Optional[bytes] = None,
    filename: str = "",
    declared_classification=Classification.INTERNAL,
    will_redact: bool = False,
    share_target_type: Optional[str] = None,   # "user" | "role"
    share_target_value: Optional[str] = None,
    prior_classification=None,
    anthropic_api_key: Optional[str] = None,
    model: str = "claude-sonnet-4-6",
) -> GuardResult:
    findings: List[Finding] = []
    cls = _classification(declared_classification)

    text = None
    if content is not None:
        try:
            text = content.decode("utf-8")
        except UnicodeDecodeError:
            text = None

    # --- Rule 1: leaked secrets / PII present and not being redacted ----------
    report: RedactionReport = scan_text(text, ALL_CATEGORIES) if text else RedactionReport()
    secret_cats = {"SSN", "CREDIT_CARD", "AWS_ACCESS_KEY", "AWS_SECRET_KEY",
                   "PRIVATE_KEY", "API_TOKEN", "JWT"}
    leaked = {c: n for c, n in report.counts.items() if c in secret_cats}
    if leaked:
        sev = "critical" if ({"PRIVATE_KEY", "AWS_SECRET_KEY"} & leaked.keys()) else "high"
        if will_redact:
            sev = "medium"
        findings.append(Finding(
            "SECRETS_DETECTED", sev,
            f"Sensitive values detected ({', '.join(f'{k}×{v}' for k, v in leaked.items())})"
            + (" — will be redacted before storage." if will_redact else
               " — NOT set to redact; they will be encrypted but retained."),
        ))

    # --- Rule 2: malware / executable masquerading as a document --------------
    if content:
        head = content[:4]
        for magic, label in _MALWARE_MAGIC.items():
            if label and head.startswith(magic):
                findings.append(Finding(
                    "EXECUTABLE_UPLOAD", "high",
                    f"Upload looks like a {label}, not a document.",
                ))
                break
    if filename and re.search(r"\.(pdf|docx?|txt|csv|xlsx?)\.(exe|scr|js|vbs|bat|sh)$",
                              filename, re.IGNORECASE):
        findings.append(Finding("DOUBLE_EXTENSION", "high",
                                f"Deceptive double extension in '{filename}'."))

    # --- Rule 3: over-broad sharing of classified data ------------------------
    if action == "share" and share_target_type == "role":
        broad_roles = {"read_only", "api_user", "soc_analyst"}
        if cls in (Classification.CONFIDENTIAL, Classification.RESTRICTED) \
                and share_target_value in broad_roles:
            findings.append(Finding(
                "OVERBROAD_SHARE", "high",
                f"Sharing {cls.value} data with the whole '{share_target_value}' role "
                f"exposes it broadly. Prefer a named-user grant.",
            ))

    # --- Rule 4: classification downgrade -------------------------------------
    if prior_classification is not None:
        prev = _classification(prior_classification)
        order = {Classification.PUBLIC: 0, Classification.INTERNAL: 1,
                 Classification.CONFIDENTIAL: 2, Classification.RESTRICTED: 3}
        if order[cls] < order[prev]:
            findings.append(Finding(
                "CLASSIFICATION_DOWNGRADE", "medium",
                f"Reclassifying from {prev.value} down to {cls.value} weakens controls.",
            ))

    # --- Rule 5: prompt injection aimed at MACE's own AI ----------------------
    if text and _PROMPT_INJECTION.search(text):
        findings.append(Finding(
            "PROMPT_INJECTION", "high",
            "Content contains an apparent AI prompt-injection payload.",
        ))

    # --- Optional AI second opinion (redaction-safe) --------------------------
    used_ai = False
    if anthropic_api_key and text:
        ai_finding = _ai_opinion(text, report, cls, anthropic_api_key, model)
        if ai_finding:
            findings.append(ai_finding)
            used_ai = True

    # --- Score + verdict ------------------------------------------------------
    score = min(100, sum(_SEVERITY_WEIGHT[f.severity] for f in findings))
    if any(f.severity == "critical" for f in findings) and not will_redact:
        verdict = Verdict.BLOCK
    elif score >= 45:
        verdict = Verdict.WARN
    elif score > 0:
        verdict = Verdict.WARN
    else:
        verdict = Verdict.ALLOW
    return GuardResult(score=score, verdict=verdict, findings=findings, used_ai=used_ai)


def _ai_opinion(text, report, cls, api_key, model) -> Optional[Finding]:
    """Ask Claude for a risk opinion on a REDACTION-SAFE summary. Fail-safe."""
    try:
        import httpx  # lazy
    except ImportError:
        return None
    # Never send raw secrets: send only categories/counts + a scrubbed excerpt.
    from app.secure.redaction import redact_text
    excerpt = redact_text(text[:2000], ALL_CATEGORIES)
    prompt = (
        "You are a data-security classifier. Given a REDACTED document excerpt "
        "and detector counts, reply with one line: SEVERITY=<low|medium|high> "
        "REASON=<short>. Do not ask for the raw values.\n\n"
        f"Declared classification: {cls.value}\n"
        f"Detector counts: {report.counts}\n"
        f"Redacted excerpt:\n{excerpt}\n"
    )
    try:
        resp = httpx.post(
            "https://api.anthropic.com/v1/messages",
            headers={"x-api-key": api_key, "anthropic-version": "2023-06-01",
                     "content-type": "application/json"},
            json={"model": model, "max_tokens": 100,
                  "messages": [{"role": "user", "content": prompt}]},
            timeout=8.0,
        )
        resp.raise_for_status()
        txt = resp.json()["content"][0]["text"]
        m = re.search(r"SEVERITY=(low|medium|high)", txt, re.IGNORECASE)
        sev = m.group(1).lower() if m else "low"
        rm = re.search(r"REASON=(.+)", txt)
        reason = rm.group(1).strip() if rm else txt.strip()[:160]
        return Finding("AI_RISK_OPINION", sev, f"AI review: {reason}")
    except Exception:
        return None   # fail-safe: keep deterministic verdict
