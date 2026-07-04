"""
EPSS Enricher — Pipeline Stage 3a
====================================
Enriches CVE findings with current EPSS scores from FIRST.org.
Also looks up CISA KEV (Known Exploited Vulnerabilities).
Results cached in Redis with 24h TTL to avoid hammering the API.
"""
import logging
import httpx
import csv
import gzip
import io
from typing import Dict, Optional, Tuple
from datetime import datetime, timedelta

logger = logging.getLogger(__name__)

# In-memory cache (process-local, reloaded daily)
_epss_cache: Dict[str, Tuple[float, float]] = {}
_cache_loaded_at: Optional[datetime] = None
_cisa_kev: set = set()

EPSS_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


async def get_epss_score(cve_id: str) -> Tuple[float, float]:
    """
    Returns (epss_score, epss_percentile) for a CVE.
    Loads full EPSS dataset on first call, then serves from cache.
    """
    global _epss_cache, _cache_loaded_at

    cve_upper = cve_id.upper()

    # Refresh cache if older than 24h
    if not _epss_cache or (
        _cache_loaded_at and datetime.utcnow() - _cache_loaded_at > timedelta(hours=24)
    ):
        await _refresh_epss_cache()

    return _epss_cache.get(cve_upper, (0.0, 0.0))


async def is_cisa_kev(cve_id: str) -> bool:
    """Check if CVE is on CISA's Known Exploited Vulnerabilities list."""
    global _cisa_kev
    if not _cisa_kev:
        await _refresh_cisa_kev()
    return cve_id.upper() in _cisa_kev


async def _refresh_epss_cache():
    global _epss_cache, _cache_loaded_at
    logger.info("Refreshing EPSS cache from FIRST.org...")
    try:
        async with httpx.AsyncClient(timeout=60) as client:
            resp = await client.get(EPSS_URL)
            if resp.status_code != 200:
                logger.warning(f"EPSS fetch returned {resp.status_code}")
                return
            content = gzip.decompress(resp.content).decode("utf-8")
            reader = csv.DictReader(io.StringIO(content))
            new_cache = {}
            for row in reader:
                cve = row.get("cve", "").upper()
                if cve:
                    new_cache[cve] = (
                        float(row.get("epss", 0)),
                        float(row.get("percentile", 0))
                    )
            _epss_cache = new_cache
            _cache_loaded_at = datetime.utcnow()
            logger.info(f"EPSS cache loaded: {len(_epss_cache)} CVEs")
    except Exception as e:
        logger.error(f"EPSS cache refresh failed: {e}")


async def _refresh_cisa_kev():
    global _cisa_kev
    logger.info("Refreshing CISA KEV list...")
    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(CISA_KEV_URL)
            if resp.status_code == 200:
                data = resp.json()
                _cisa_kev = {v.get("cveID", "").upper()
                             for v in data.get("vulnerabilities", [])}
                logger.info(f"CISA KEV loaded: {len(_cisa_kev)} CVEs")
    except Exception as e:
        logger.error(f"CISA KEV refresh failed: {e}")


def enrich_vuln_with_epss(vuln, epss_score: float, epss_percentile: float,
                           is_kev: bool = False):
    """Mutate a NormalizedVuln with EPSS data and KEV flag."""
    vuln.epss_score = epss_score
    if is_kev:
        vuln.exploit_status = "exploit_public"
    elif epss_score > 0.5 and vuln.exploit_status == "no_exploit_known":
        vuln.exploit_status = "exploit_poc"
    return vuln
