"""
NVD 2.0 daily CVE pull.

Endpoint:
  https://services.nvd.nist.gov/rest/json/cves/2.0?lastModStartDate=...&lastModEndDate=...

The NVD JSON-2.0 schema gives us:
  cve.id, metrics.cvssMetricV31[0].cvssData.baseScore + .severity,
  configurations.nodes[].cpeMatch[] (criteria + versionStartIncluding /
  versionEndExcluding etc.), descriptions[0].value, references[].

We translate that into our CVERecord shape and merge with the bundled
database, biased toward fresher upstream data.
"""
from __future__ import annotations
import json
import os
import time
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from ..cve_db import CVERecord

NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
DEFAULT_USER_AGENT = "UnifiedSec-MACE-Agent/1.0 (+https://unifiedsec.io)"
CACHE_DIR = Path(os.environ.get("MACE_CACHE_DIR", str(Path.home() / ".mace-agent" / "cache")))


def _ensure_cache():
    CACHE_DIR.mkdir(parents=True, exist_ok=True)


def _fetch_window(start: datetime, end: datetime,
                   api_key: Optional[str], timeout: int = 30) -> Dict[str, Any]:
    params = {
        "lastModStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "lastModEndDate":   end.strftime("%Y-%m-%dT%H:%M:%S.000+00:00"),
        "resultsPerPage":   "2000",
    }
    url = f"{NVD_BASE}?{urllib.parse.urlencode(params)}"
    headers = {"User-Agent": DEFAULT_USER_AGENT}
    if api_key:
        headers["apiKey"] = api_key
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as resp:
        return json.loads(resp.read())


def _translate(item: Dict[str, Any]) -> Optional[CVERecord]:
    cve = item.get("cve", {})
    cve_id = cve.get("id") or ""
    if not cve_id.startswith("CVE-"):
        return None
    metrics = cve.get("metrics", {})
    base = 0.0
    sev  = "MEDIUM"
    for k in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        m = metrics.get(k)
        if m:
            base = float(m[0].get("cvssData", {}).get("baseScore", 0.0))
            sev  = (m[0].get("cvssData", {}).get("baseSeverity")
                    or _band(base))
            break
    description = ""
    for d in cve.get("descriptions") or []:
        if d.get("lang") == "en":
            description = d.get("value", "")
            break
    pkg = ""
    predicate = "any"
    fixed = ""
    for cfg in cve.get("configurations") or []:
        for node in cfg.get("nodes") or []:
            for m in node.get("cpeMatch") or []:
                cpe = m.get("criteria", "")
                if not cpe.startswith("cpe:2.3:"): continue
                parts = cpe.split(":")
                if len(parts) >= 5:
                    vendor, product = parts[3], parts[4]
                    pkg = product
                    vEnd = m.get("versionEndExcluding") or m.get("versionEndIncluding")
                    if vEnd:
                        op = "<" if "Excluding" in (m.get("versionEndExcluding") and "Excluding" or "Including") else "<="
                        predicate = f"{op}{vEnd}"
                        fixed = vEnd
                        break
            if pkg: break
        if pkg: break

    return CVERecord(
        cve_id=cve_id,
        cvss_v3=round(base, 1),
        severity=sev,
        affected_pkg=pkg or "unknown",
        predicate=predicate,
        fixed_version=fixed,
        epss_score=0.0,
        exploit_status="no_exploit_known",
        description=description[:400],
        remediation=f"Apply vendor patch upgrading {pkg or 'affected component'} to {fixed or 'a fixed version'}.",
        remediation_cmd="",
    )


def _band(score: float) -> str:
    if score >= 9: return "CRITICAL"
    if score >= 7: return "HIGH"
    if score >= 4: return "MEDIUM"
    if score > 0:  return "LOW"
    return "NONE"


def fetch_recent_cves(days: int = 1,
                       api_key: Optional[str] = None,
                       max_results: int = 2000) -> List[CVERecord]:
    """Pull CVEs modified in the last `days` days from the live NVD API."""
    end = datetime.now(timezone.utc)
    start = end - timedelta(days=max(1, days))
    out: List[CVERecord] = []
    try:
        payload = _fetch_window(start, end, api_key)
    except Exception as e:
        # Cached fallback
        cache = _read_cache()
        if cache:
            return cache[:max_results]
        raise
    for item in payload.get("vulnerabilities", [])[:max_results]:
        rec = _translate(item)
        if rec:
            out.append(rec)
    _write_cache(out)
    return out


def _cache_path() -> Path:
    _ensure_cache()
    return CACHE_DIR / "nvd_recent.json"


def _write_cache(records: Iterable[CVERecord]) -> None:
    try:
        from dataclasses import asdict
        data = {"fetched_at": time.time(), "records": [asdict(r) for r in records]}
        _cache_path().write_text(json.dumps(data))
    except Exception:
        pass


def _read_cache() -> List[CVERecord]:
    try:
        raw = json.loads(_cache_path().read_text())
        return [CVERecord(**r) for r in raw.get("records", [])]
    except Exception:
        return []


def merge_into_db(new_records: Iterable[CVERecord]) -> int:
    """Merge fresh NVD records into the bundled in-memory DB; returns count added."""
    from .. import cve_db
    existing = {r.cve_id for r in cve_db.CVE_DATABASE}
    added = 0
    for rec in new_records:
        if rec.cve_id in existing: continue
        cve_db.CVE_DATABASE.append(rec)
        existing.add(rec.cve_id)
        added += 1
    # Rebuild package index
    cve_db._INDEX = {}
    for rec in cve_db.CVE_DATABASE:
        cve_db._INDEX.setdefault(cve_db._normalise_pkg(rec.affected_pkg), []).append(rec)
    return added
