"""Deterministic scoring helpers shared by detection, correlation and risk."""

from __future__ import annotations

import math

from sentrix.schemas.common import SEVERITY_RANK

CRITICALITY_MULTIPLIER = {"low": 0.85, "medium": 1.0, "high": 1.1, "critical": 1.2}
CRITICALITY_WEIGHT = {"low": 0.25, "medium": 0.5, "high": 0.75, "critical": 1.0}


def severity_from_score(score: float) -> str:
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 15:
        return "low"
    return "info"


def max_severity(*sevs: str | None) -> str:
    vals = [s for s in sevs if s in SEVERITY_RANK]
    return max(vals, key=lambda s: SEVERITY_RANK[s]) if vals else "info"


def event_threat_score(base_score: float, anomaly: float, criticality: str | None) -> float:
    """Fuse rule evidence and behavioural anomaly, scaled by asset criticality."""
    combined = 1 - (1 - base_score / 100) * (1 - 0.7 * anomaly)
    mult = CRITICALITY_MULTIPLIER.get(criticality or "medium", 1.0)
    return round(min(100.0, 100 * combined * mult), 1)


def incident_risk(
    max_threat: float, distinct_tactics: int, event_count: int, criticality: str | None
) -> float:
    progression = 4.0 * max(0, distinct_tactics - 1)
    volume = min(10.0, 2.0 * math.log2(max(1, event_count)))
    mult = CRITICALITY_MULTIPLIER.get(criticality or "medium", 1.0)
    return round(min(100.0, (max_threat * 0.75 + progression + volume) * mult), 1)
