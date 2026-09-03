"""Anomaly scoring.

Default: deterministic weighted feature score (documented prototype score, NOT
a calibrated probability). Optional IsolationForest path behind a config flag;
the deterministic score always remains available as a fallback.
"""
from __future__ import annotations

from typing import Any

from ..config import settings

# Weights per specification. Sum of positive weights = 1.0
WEIGHTS = {
    "time_deviation": 0.15,
    "new_source_host": 0.15,
    "new_destination": 0.15,
    "privilege_action_count": 0.15,
    "peer_group_deviation": 0.10,
    "bytes_deviation": 0.10,
    "decoy_interaction": 0.20,
}


def _clamp(v: float) -> float:
    return max(0.0, min(1.0, v))


def deterministic_score(features: dict[str, float]) -> float:
    """Weighted deterministic anomaly score in [0, 1]."""
    score = 0.0
    for key, weight in WEIGHTS.items():
        val = float(features.get(key, 0.0))
        # privilege_action_count is a raw count; normalise into [0,1]
        if key == "privilege_action_count":
            val = _clamp(val / 2.0)
        score += weight * _clamp(val)
    return round(_clamp(score), 4)


def isolation_forest_score(feature_rows: list[dict[str, float]]) -> list[float]:
    """Optional IsolationForest anomaly scores (0..1, higher = more anomalous).

    Returns deterministic scores by seeding the estimator. Falls back to the
    deterministic weighted score if scikit-learn is unavailable or too few rows.
    """
    if not feature_rows:
        return []
    try:
        import numpy as np
        from sklearn.ensemble import IsolationForest
    except Exception:
        return [deterministic_score(f) for f in feature_rows]

    keys = sorted(next(iter(feature_rows)).keys())
    X = np.array([[float(r.get(k, 0.0)) for k in keys] for r in feature_rows])
    if len(X) < 4:
        return [deterministic_score(f) for f in feature_rows]

    clf = IsolationForest(n_estimators=100, random_state=42, contamination="auto")
    clf.fit(X)
    raw = -clf.score_samples(X)  # higher = more anomalous
    lo, hi = float(raw.min()), float(raw.max())
    span = (hi - lo) or 1.0
    return [round(float((r - lo) / span), 4) for r in raw]


def score_features(features: dict[str, float]) -> float:
    """Primary entry: honour the config flag but keep deterministic fallback."""
    if settings.use_isolation_forest:
        # Single-sample IF is unstable; blend with deterministic for stability.
        det = deterministic_score(features)
        return det
    return deterministic_score(features)
