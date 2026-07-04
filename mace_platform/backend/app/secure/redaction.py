"""
Redaction engine for MACE Secure Files.

Reads a file's text content and removes information that should not leave the
security boundary — PII and leaked secrets — BEFORE it is stored or shared.
Every detector reports what it removed (category + count + byte offsets) so the
action is fully auditable; the raw values are never written to the audit log.

Detectors are deterministic regex + validators (Luhn for cards). This is the
offline, no-dependency baseline; ai_guard.py can layer an LLM pass on top for
free-text names/addresses the regexes miss.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set

_TOKEN = "[REDACTED:{}]"


def _luhn_ok(digits: str) -> bool:
    ds = [int(c) for c in digits if c.isdigit()]
    if len(ds) < 13:
        return False
    checksum, parity = 0, len(ds) % 2
    for i, d in enumerate(ds):
        if i % 2 == parity:
            d *= 2
            if d > 9:
                d -= 9
        checksum += d
    return checksum % 10 == 0


# category -> (compiled regex, optional validator)
_DETECTORS = {
    "SSN": (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), None),
    "CREDIT_CARD": (re.compile(r"\b(?:\d[ -]?){13,19}\b"), _luhn_ok),
    "EMAIL": (re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"), None),
    "PHONE": (re.compile(r"\b(?:\+?1[-.\s]?)?\(?\d{3}\)?[-.\s]?\d{3}[-.\s]?\d{4}\b"), None),
    "AWS_ACCESS_KEY": (re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), None),
    "AWS_SECRET_KEY": (re.compile(r"(?<![A-Za-z0-9/+=])[A-Za-z0-9/+=]{40}(?![A-Za-z0-9/+=])"), None),
    "PRIVATE_KEY": (re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----.*?-----END (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----", re.DOTALL), None),
    "API_TOKEN": (re.compile(r"\b(?:sk-[A-Za-z0-9]{20,}|ghp_[A-Za-z0-9]{36}|xox[baprs]-[A-Za-z0-9-]{10,})\b"), None),
    "JWT": (re.compile(r"\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b"), None),
    "IPV4": (re.compile(r"\b(?:(?:25[0-5]|2[0-4]\d|1?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|1?\d?\d)\b"), None),
}

# Sensible default: redact secrets + strong PII, leave emails/phones/IPs unless asked.
DEFAULT_CATEGORIES: Set[str] = {
    "SSN", "CREDIT_CARD", "AWS_ACCESS_KEY", "AWS_SECRET_KEY",
    "PRIVATE_KEY", "API_TOKEN", "JWT",
}
ALL_CATEGORIES: Set[str] = set(_DETECTORS)


@dataclass
class RedactionReport:
    counts: Dict[str, int] = field(default_factory=dict)
    spans: List[Dict] = field(default_factory=list)   # {category, start, end}
    total: int = 0

    def as_dict(self) -> Dict:
        return {"total": self.total, "counts": self.counts, "spans": self.spans}


def scan_text(text: str, categories: Optional[Set[str]] = None) -> RedactionReport:
    """Find sensitive spans without modifying the text."""
    cats = categories or DEFAULT_CATEGORIES
    report = RedactionReport()
    for cat in cats:
        if cat not in _DETECTORS:
            continue
        pattern, validator = _DETECTORS[cat]
        for m in pattern.finditer(text):
            if validator and not validator(m.group()):
                continue
            report.counts[cat] = report.counts.get(cat, 0) + 1
            report.spans.append({"category": cat, "start": m.start(), "end": m.end()})
            report.total += 1
    report.spans.sort(key=lambda s: s["start"])
    return report


def redact_text(text: str, categories: Optional[Set[str]] = None) -> (str):
    """Return the redacted text (values replaced with typed tags)."""
    redacted, _ = redact_text_with_report(text, categories)
    return redacted


def redact_text_with_report(text: str, categories: Optional[Set[str]] = None):
    cats = categories or DEFAULT_CATEGORIES
    report = scan_text(text, cats)
    # Replace right-to-left so offsets stay valid.
    out = text
    for span in sorted(report.spans, key=lambda s: s["start"], reverse=True):
        token = _TOKEN.format(span["category"])
        out = out[: span["start"]] + token + out[span["end"] :]
    return out, report


def redact_bytes(data: bytes, categories: Optional[Set[str]] = None):
    """Redact text-decodable bytes. Returns (redacted_bytes, report, was_text)."""
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        # Binary (image, pdf, zip...) — regex redaction not applicable.
        return data, RedactionReport(), False
    redacted, report = redact_text_with_report(text, categories)
    return redacted.encode("utf-8"), report, True
