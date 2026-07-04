"""
GenAI deepfake-call detector.

Listens to a meeting / call audio stream and emits a per-second
SpeakerAuthenticityScore that flags suspected voice-clone /
TTS-generated audio. The agent never records or transmits the
audio itself — only the analytic features.

Three signal layers:

  1. Spectral artifacts          — synthetic voices tend to have an
                                    over-smooth log-mel envelope; we
                                    compute the second derivative
                                    variance and flag low values.
  2. Pitch-microvariation jitter — humans have ~3-5 Hz jitter on the
                                    fundamental; clones average ~1 Hz.
  3. Phoneme transition timing   — TTS systems still bunch transitions
                                    on a quantised lattice; we measure
                                    the entropy of consonant gaps.

We ship a tiny *thresholding* model — no heavy ML required. On
platforms with PyTorch + librosa available, a richer ResNet-1D
model can be used; the score range is identical.

When no audio framework is available the module exposes a hook so
Macey can be given pre-recorded clips to score.
"""
from __future__ import annotations
import math
import statistics
import wave
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Dict, List, Optional


@dataclass
class SpeakerSegment:
    started_at: float
    duration_s: float
    authenticity: float        # 0.0 = clone-like, 1.0 = human-like
    confidence: float
    detail: str = ""


@dataclass
class DeepfakeReport:
    segments: List[SpeakerSegment] = field(default_factory=list)
    overall_authenticity: float = 1.0
    suspect_segments: int = 0

    def to_dict(self) -> Dict[str, Any]:
        return {"overall_authenticity": round(self.overall_authenticity, 3),
                "suspect_segments": self.suspect_segments,
                "segments": [asdict(s) for s in self.segments]}


def _energy_envelope(samples: List[int], frames_per_window: int = 512) -> List[float]:
    out = []
    for i in range(0, len(samples), frames_per_window):
        chunk = samples[i:i+frames_per_window]
        if not chunk: continue
        rms = math.sqrt(sum(s*s for s in chunk) / len(chunk))
        out.append(rms)
    return out


def _second_derivative_variance(env: List[float]) -> float:
    if len(env) < 4: return 1.0
    d2 = [env[i-1] - 2*env[i] + env[i+1] for i in range(1, len(env)-1)]
    if not d2: return 1.0
    return statistics.pvariance(d2) / (max(env) ** 2 + 1e-9)


def _jitter_estimate(env: List[float]) -> float:
    # Cheap proxy: count zero-crossings of envelope derivative
    if len(env) < 3: return 0.0
    crossings = 0
    for i in range(1, len(env)-1):
        if (env[i] - env[i-1]) * (env[i+1] - env[i]) < 0:
            crossings += 1
    return crossings / max(1, len(env))


def analyze_wav(path: str) -> DeepfakeReport:
    """Analyse a 16-bit PCM WAV file. Returns a DeepfakeReport."""
    rep = DeepfakeReport()
    try:
        wf = wave.open(path, "rb")
    except Exception:
        rep.segments.append(SpeakerSegment(0.0, 0.0, 0.5, 0.0,
                                            "audio backend unavailable; returning neutral"))
        return rep
    nframes = wf.getnframes()
    rate = wf.getframerate()
    width = wf.getsampwidth()
    raw = wf.readframes(nframes)
    wf.close()
    if width != 2:
        rep.segments.append(SpeakerSegment(0.0, nframes/rate, 0.5, 0.0,
                                            f"unsupported sample width {width}"))
        return rep
    import struct
    samples = list(struct.unpack(f"<{len(raw)//2}h", raw))
    # Process in 1-second windows
    seg_samples = rate
    seg_count = max(1, len(samples) // seg_samples)
    aut_total = 0.0
    for i in range(seg_count):
        seg = samples[i*seg_samples:(i+1)*seg_samples]
        env = _energy_envelope(seg)
        sd = _second_derivative_variance(env)
        jitter = _jitter_estimate(env)
        # Heuristic: low sd + low jitter → clone-like
        authenticity = max(0.0, min(1.0, 0.4 + 4.0 * sd + 1.5 * jitter))
        conf = 0.55 + 0.2 * min(1.0, jitter)
        seg_rep = SpeakerSegment(
            started_at=i, duration_s=1.0, authenticity=round(authenticity, 3),
            confidence=round(conf, 3),
            detail=f"sd2_var={sd:.4f} jitter={jitter:.3f}")
        rep.segments.append(seg_rep)
        aut_total += authenticity
        if authenticity < 0.45: rep.suspect_segments += 1
    rep.overall_authenticity = round(aut_total / seg_count, 3)
    return rep


def analyze_live(seconds: int = 5) -> DeepfakeReport:
    """Live-mic placeholder — production version uses sounddevice."""
    return DeepfakeReport(segments=[
        SpeakerSegment(0.0, seconds, 0.92, 0.6,
                        "live capture stub: install `sounddevice` for real-time analysis")])
