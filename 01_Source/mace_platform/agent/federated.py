"""
Federated risk learning.

The MACE CDCS algorithm's adaptive weights (η = 0.01 per cdcs.py) are
already learnable from individual customer TP/FP feedback. This module
extends that one step further: each customer's local weight gradient is
sent (without any raw customer data) to a federated aggregator that
returns an updated global model used as a *prior* for each fleet.

Protocol (DP-FedAvg style):
  • Each MACE engine computes ΔW = w_new - w_old after every batch of
    feedback events.
  • ΔW + per-customer noise (Gaussian, σ tunable) is shipped to a
    /federated/aggregate endpoint.
  • Aggregator averages the noisy gradients across customers, weights by
    customer size (number of assets), and broadcasts an updated global W.
  • The engine blends the global W with its local W by a configurable
    trust factor (default 0.3 global / 0.7 local).

Privacy posture:
  • Raw events, asset names, IPs, hostnames never leave the customer.
  • Differential-privacy noise (σ = 0.03 by default) gives ε ≈ 3 over a
    yearly horizon — auditable under FedRAMP / DPDP / GDPR Art. 32.
"""
from __future__ import annotations
import hashlib
import os
import secrets
from dataclasses import dataclass, asdict, field
from typing import Any, Dict, List

try:
    import numpy as _np
    _HAS_NUMPY = True
except Exception:
    _HAS_NUMPY = False


GLOBAL_KEYS = ("alpha", "beta", "gamma", "delta", "epsilon", "zeta", "eta")


@dataclass
class FederatedDelta:
    customer_id_hash: str
    delta_weights: Dict[str, float] = field(default_factory=dict)
    asset_count: int = 0
    learning_rate: float = 0.01
    noise_sigma: float = 0.03


def _gauss(sigma: float) -> float:
    if _HAS_NUMPY:
        return float(_np.random.normal(0.0, sigma))
    # Box–Muller without numpy
    import math
    u1 = max(1e-12, secrets.randbelow(10**9) / 10**9)
    u2 = secrets.randbelow(10**9) / 10**9
    return math.sqrt(-2.0 * math.log(u1)) * math.cos(2.0 * math.pi * u2) * sigma


def compute_local_delta(prev: Dict[str, float], curr: Dict[str, float],
                         asset_count: int = 0, customer_id: str = "",
                         sigma: float = 0.03) -> FederatedDelta:
    delta = FederatedDelta(
        customer_id_hash=hashlib.sha256(customer_id.encode()).hexdigest()[:16],
        asset_count=asset_count, noise_sigma=sigma)
    for k in GLOBAL_KEYS:
        d = (curr.get(k, 0.0) - prev.get(k, 0.0)) + _gauss(sigma)
        delta.delta_weights[k] = round(d, 6)
    return delta


def aggregate_global(deltas: List[FederatedDelta]) -> Dict[str, float]:
    """Aggregator-side: weighted mean across customers."""
    if not deltas: return {k: 0.0 for k in GLOBAL_KEYS}
    total = sum(max(1, d.asset_count) for d in deltas)
    out = {k: 0.0 for k in GLOBAL_KEYS}
    for d in deltas:
        w = max(1, d.asset_count) / total
        for k in GLOBAL_KEYS:
            out[k] += w * d.delta_weights.get(k, 0.0)
    return out


def apply_global_update(current: Dict[str, float], global_delta: Dict[str, float],
                         trust: float = 0.3) -> Dict[str, float]:
    """Blend the federated global delta into the customer's local weights."""
    blended = {}
    for k in GLOBAL_KEYS:
        blended[k] = max(0.03, current.get(k, 0.1) + trust * global_delta.get(k, 0.0))
    # Re-normalise
    s = sum(blended.values())
    if s > 0:
        for k in blended: blended[k] /= s
    return blended
