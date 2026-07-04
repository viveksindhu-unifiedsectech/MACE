"""
Cross-asset incident replay — "Tivo for breaches".

Records the full state of every asset that touched an incident
(processes, network connections, identity events, file changes) into
a deterministic time-indexed timeline. Analysts can then scrub
forwards and backwards through the incident to see exactly what
happened minute-by-minute across the whole graph, not just one device.

Storage model:
  ~/.mace-agent/replay/<incident_id>/
    timeline.jsonl       — append-only event ledger (one JSON per line)
    snapshots/<ts>.json  — periodic full-state snapshots (every 30 s)
    index.json           — incident metadata + cursor pointers

Replay API:
  Recorder.start(incident_id)
  Recorder.append(ts, kind, asset, event)
  Recorder.snapshot(ts, full_state)
  Replayer(incident_id).seek(ts) → returns reconstructed state
  Replayer(incident_id).range(t0, t1) → events in window
"""
from __future__ import annotations
import json
import os
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional

REPLAY_ROOT = Path(os.environ.get("MACE_REPLAY_DIR",
                                    str(Path.home() / ".mace-agent" / "replay")))


@dataclass
class ReplayEvent:
    ts: float
    kind: str               # process | network | identity | file | finding | alert
    asset: str
    detail: Dict[str, Any] = field(default_factory=dict)


class Recorder:
    def __init__(self, incident_id: str):
        self.incident_id = incident_id
        self.root = REPLAY_ROOT / incident_id
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "snapshots").mkdir(exist_ok=True)
        self.timeline = self.root / "timeline.jsonl"
        self._fh = self.timeline.open("a")
        self.idx_path = self.root / "index.json"
        if not self.idx_path.exists():
            self.idx_path.write_text(json.dumps({
                "incident_id": incident_id,
                "created_at": time.time(),
                "first_ts": None,
                "last_ts": None,
                "asset_count": 0,
                "event_count": 0,
            }))

    def append(self, event: ReplayEvent) -> None:
        self._fh.write(json.dumps(asdict(event)) + "\n")
        self._fh.flush()
        self._touch_index(event.ts)

    def snapshot(self, ts: float, state: Dict[str, Any]) -> None:
        (self.root / "snapshots" / f"{int(ts)}.json").write_text(
            json.dumps(state, default=str))

    def _touch_index(self, ts: float):
        try:
            idx = json.loads(self.idx_path.read_text())
        except Exception:
            return
        idx["first_ts"] = idx.get("first_ts") or ts
        idx["last_ts"]  = ts
        idx["event_count"] = idx.get("event_count", 0) + 1
        self.idx_path.write_text(json.dumps(idx))

    def close(self):
        try: self._fh.close()
        except Exception: pass


class Replayer:
    def __init__(self, incident_id: str):
        self.root = REPLAY_ROOT / incident_id

    def list_events(self) -> List[ReplayEvent]:
        p = self.root / "timeline.jsonl"
        if not p.exists(): return []
        out: List[ReplayEvent] = []
        for line in p.read_text().splitlines():
            try:
                d = json.loads(line)
                out.append(ReplayEvent(**d))
            except Exception:
                continue
        return out

    def range(self, t0: float, t1: float) -> List[ReplayEvent]:
        return [e for e in self.list_events() if t0 <= e.ts <= t1]

    def seek(self, ts: float) -> Dict[str, Any]:
        """Return reconstructed state at time ts (uses nearest snapshot + replay)."""
        snap_dir = self.root / "snapshots"
        chosen = None
        if snap_dir.is_dir():
            for f in sorted(snap_dir.glob("*.json")):
                try:
                    snap_ts = int(f.stem)
                    if snap_ts <= ts: chosen = f
                except Exception:
                    pass
        state: Dict[str, Any] = {}
        if chosen:
            try: state = json.loads(chosen.read_text())
            except Exception: pass
        # Replay events after snapshot
        snap_ts = float(chosen.stem) if chosen else 0.0
        for e in self.list_events():
            if snap_ts <= e.ts <= ts:
                state.setdefault("events", []).append(asdict(e))
        return state

    def metadata(self) -> Dict[str, Any]:
        idx = self.root / "index.json"
        if not idx.exists(): return {}
        try: return json.loads(idx.read_text())
        except Exception: return {}


def list_incidents() -> List[Dict[str, Any]]:
    if not REPLAY_ROOT.exists(): return []
    out: List[Dict[str, Any]] = []
    for d in REPLAY_ROOT.iterdir():
        if not d.is_dir(): continue
        idx = d / "index.json"
        if idx.exists():
            try: out.append(json.loads(idx.read_text()))
            except Exception: continue
    out.sort(key=lambda i: i.get("last_ts") or 0, reverse=True)
    return out
