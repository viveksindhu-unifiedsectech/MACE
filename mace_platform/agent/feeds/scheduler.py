"""
Daily feed updater — invoked at startup by the daemon and once per day by
the platform timer (launchd / systemd / Task Scheduler).

`mace-agent update` runs this on demand. Failures are non-fatal.
"""
from __future__ import annotations
import json
import time
from dataclasses import dataclass, asdict
from pathlib import Path
from typing import List, Optional

from . import cisa_kev, epss, nvd, stig as stig_feed


STATUS_FILE = Path.home() / ".mace-agent" / "feed_status.json"


@dataclass
class FeedUpdate:
    feed: str
    success: bool
    count: int
    message: str = ""
    elapsed_s: float = 0.0


def update_all(api_key: Optional[str] = None,
                refresh_stig_catalog: bool = False) -> List[FeedUpdate]:
    out: List[FeedUpdate] = []

    # NVD recent CVEs
    t0 = time.time()
    try:
        records = nvd.fetch_recent_cves(days=1, api_key=api_key)
        added = nvd.merge_into_db(records)
        out.append(FeedUpdate("nvd", True, added,
                               f"{len(records)} fetched, {added} new",
                               round(time.time()-t0, 2)))
    except Exception as e:
        out.append(FeedUpdate("nvd", False, 0, str(e)[:200], round(time.time()-t0, 2)))

    # CISA KEV
    t0 = time.time()
    try:
        ids = cisa_kev.fetch_kev_ids()
        marked = cisa_kev.annotate_known_exploited(ids)
        out.append(FeedUpdate("cisa_kev", True, marked,
                               f"{len(ids)} CVE IDs in KEV, {marked} matched locally",
                               round(time.time()-t0, 2)))
    except Exception as e:
        out.append(FeedUpdate("cisa_kev", False, 0, str(e)[:200], round(time.time()-t0, 2)))

    # EPSS
    t0 = time.time()
    try:
        scores = epss.fetch_epss_scores()
        updated = epss.apply_epss(scores) if scores else 0
        out.append(FeedUpdate("epss", True, updated,
                               f"{len(scores)} EPSS rows, {updated} local CVEs updated",
                               round(time.time()-t0, 2)))
    except Exception as e:
        out.append(FeedUpdate("epss", False, 0, str(e)[:200], round(time.time()-t0, 2)))

    # STIG catalog (heavy — only when explicitly requested)
    if refresh_stig_catalog:
        t0 = time.time()
        try:
            res = stig_feed.refresh_catalog()
            total = sum(res.values())
            out.append(FeedUpdate("stig", True, total,
                                   f"{len(res)} profiles, {total} rules",
                                   round(time.time()-t0, 2)))
        except Exception as e:
            out.append(FeedUpdate("stig", False, 0, str(e)[:200], round(time.time()-t0, 2)))

    # Persist status
    try:
        STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
        STATUS_FILE.write_text(json.dumps({
            "updated_at": time.time(),
            "feeds": [asdict(u) for u in out],
        }))
    except Exception:
        pass
    return out


def last_update_status() -> dict:
    if not STATUS_FILE.exists():
        return {"updated_at": None, "feeds": []}
    try:
        return json.loads(STATUS_FILE.read_text())
    except Exception:
        return {"updated_at": None, "feeds": []}
