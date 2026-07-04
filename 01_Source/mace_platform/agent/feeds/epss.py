"""
EPSS daily score feed (FIRST.org).

Source: https://epss.empiricalsecurity.com/epss_scores-current.csv.gz

Pulls today's CSV (cve, epss, percentile) and patches the local CVE DB so
the same CVE has its current exploitation-probability score.
"""
from __future__ import annotations
import csv
import gzip
import io
import urllib.request
from typing import Dict

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"


def fetch_epss_scores(timeout: int = 30) -> Dict[str, float]:
    try:
        with urllib.request.urlopen(EPSS_URL, timeout=timeout) as resp:
            buf = resp.read()
        text = gzip.decompress(buf).decode("utf-8", errors="ignore")
    except Exception:
        return {}
    out: Dict[str, float] = {}
    reader = csv.reader(io.StringIO(text))
    for row in reader:
        if not row or not row[0].startswith("CVE-"):
            continue
        try:
            out[row[0]] = float(row[1])
        except Exception:
            continue
    return out


def apply_epss(scores: Dict[str, float]) -> int:
    """Patch in-memory CVE DB with current EPSS scores. Returns count updated."""
    from dataclasses import replace
    from .. import cve_db
    n = 0
    new_records = []
    for rec in cve_db.CVE_DATABASE:
        s = scores.get(rec.cve_id)
        if s is not None and abs(s - rec.epss_score) > 1e-4:
            new_records.append(replace(rec, epss_score=round(s, 4)))
            n += 1
        else:
            new_records.append(rec)
    cve_db.CVE_DATABASE[:] = new_records
    return n
