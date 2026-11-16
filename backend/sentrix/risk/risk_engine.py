"""Enterprise risk assessment (deterministic).

Asset risk (0-100) combines:
  * threat    - highest risk score of active incidents touching the asset
  * exposure  - internet exposure and matched known-exploited vulnerabilities
  * behaviour - mean anomaly score of the asset's events in the last 24h
  * impact    - asset criticality weight

    likelihood = 1 - (1 - threat)(1 - 0.5*exposure)(1 - 0.5*behaviour)
    asset_risk = 100 * likelihood * (0.4 + 0.6 * impact)

Enterprise risk = 0.6 * highest asset risk + 0.4 * criticality-weighted mean asset
risk, so one critical asset at high risk dominates, while breadth still counts.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from sentrix.db.models import Asset, Incident, SecurityEvent, utcnow
from sentrix.detection.correlation import ACTIVE_STATUSES
from sentrix.detection.scoring import CRITICALITY_WEIGHT
from sentrix.intel.knowledge import match_vulnerabilities


def risk_level(score: float) -> str:
    if score >= 75:
        return "critical"
    if score >= 50:
        return "high"
    if score >= 25:
        return "medium"
    return "low"


def asset_risks(db: Session, persist: bool = False) -> list[dict[str, Any]]:
    assets = db.scalars(select(Asset)).all()
    incidents = db.scalars(select(Incident).where(Incident.status.in_(ACTIVE_STATUSES))).all()
    threat_by_host: dict[str, float] = defaultdict(float)
    incidents_by_host: dict[str, list[str]] = defaultdict(list)
    for inc in incidents:
        for h in inc.hostnames or []:
            threat_by_host[h] = max(threat_by_host[h], inc.risk_score)
            incidents_by_host[h].append(inc.ref)
    since = utcnow() - timedelta(hours=24)
    anomaly_rows = db.execute(
        select(SecurityEvent.hostname, func.avg(SecurityEvent.anomaly_score))
        .where(SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.hostname)
    ).all()
    anomaly_by_host = {h: float(a or 0) for h, a in anomaly_rows if h}

    out = []
    for a in assets:
        vulns = match_vulnerabilities(a.software or [])
        exposure = min(1.0, (0.4 if a.internet_facing else 0.0) + 0.25 * len(vulns))
        threat = threat_by_host.get(a.hostname, 0.0) / 100
        behaviour = anomaly_by_host.get(a.hostname, 0.0)
        impact = CRITICALITY_WEIGHT.get(a.criticality, 0.5)
        likelihood = 1 - (1 - threat) * (1 - 0.5 * exposure) * (1 - 0.5 * behaviour)
        score = round(100 * likelihood * (0.4 + 0.6 * impact), 1)
        if persist:
            a.risk_score = score
        out.append({
            "hostname": a.hostname,
            "criticality": a.criticality,
            "zone": a.network_zone,
            "risk_score": score,
            "level": risk_level(score),
            "factors": {
                "threat": round(threat, 3),
                "exposure": round(exposure, 3),
                "behaviour": round(behaviour, 3),
                "impact": impact,
            },
            "active_incidents": incidents_by_host.get(a.hostname, []),
            "vulnerabilities": [v["id"] for v in vulns],
            "internet_facing": a.internet_facing,
        })
    if persist:
        db.commit()
    out.sort(key=lambda r: r["risk_score"], reverse=True)
    return out


def enterprise_risk(db: Session, persist: bool = False) -> dict[str, Any]:
    per_asset = asset_risks(db, persist=persist)
    score = 0.0
    if per_asset:
        weights = [CRITICALITY_WEIGHT.get(r["criticality"], 0.5) for r in per_asset]
        weighted_mean = sum(r["risk_score"] * w for r, w in zip(per_asset, weights, strict=True)) / sum(weights)
        score = round(0.6 * per_asset[0]["risk_score"] + 0.4 * weighted_mean, 1)
    # Assets are optional: fall back to incident-only risk if no inventory exists.
    if not per_asset:
        open_risk = db.scalars(
            select(Incident.risk_score).where(Incident.status.in_(ACTIVE_STATUSES))
        ).all()
        prod = 1.0
        for r in open_risk:
            prod *= 1 - r / 100 * 0.5
        score = round(100 * (1 - prod), 1)
    return {
        "score": score,
        "level": risk_level(score),
        "method": "0.6 x max asset risk + 0.4 x criticality-weighted mean (deterministic)",
        "assets": per_asset,
        "drivers": [r for r in per_asset if r["risk_score"] >= 25][:5],
    }


def trends(db: Session, days: int = 14) -> dict[str, Any]:
    since = utcnow() - timedelta(days=days)
    ev = db.execute(
        select(func.date(SecurityEvent.timestamp), SecurityEvent.severity, func.count())
        .where(SecurityEvent.timestamp >= since)
        .group_by(func.date(SecurityEvent.timestamp), SecurityEvent.severity)
    ).all()
    inc = db.execute(
        select(func.date(Incident.first_seen), Incident.severity, func.count())
        .where(Incident.first_seen >= since)
        .group_by(func.date(Incident.first_seen), Incident.severity)
    ).all()
    tactics = db.execute(
        select(SecurityEvent.mitre_tactic, func.count())
        .where(SecurityEvent.mitre_tactic.is_not(None))
        .where(SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.mitre_tactic)
    ).all()
    techniques = db.execute(
        select(SecurityEvent.mitre_technique, func.count())
        .where(SecurityEvent.mitre_technique.is_not(None))
        .where(SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.mitre_technique)
        .order_by(func.count().desc())
        .limit(15)
    ).all()
    users = db.execute(
        select(SecurityEvent.user, func.max(SecurityEvent.threat_score), func.avg(SecurityEvent.anomaly_score),
               func.count())
        .where(SecurityEvent.user.is_not(None))
        .where(SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.user)
        .order_by(func.max(SecurityEvent.threat_score).desc())
        .limit(10)
    ).all()

    def pivot(rows):
        by_day: dict[str, Counter] = defaultdict(Counter)
        for d, sev, c in rows:
            by_day[str(d)][sev] += c
        return [{"date": d, **dict(c), "total": sum(c.values())} for d, c in sorted(by_day.items())]

    return {
        "days": days,
        "events_by_day": pivot(ev),
        "incidents_by_day": pivot(inc),
        "tactics": [{"tactic": t, "count": c} for t, c in sorted(tactics, key=lambda x: -x[1])],
        "top_techniques": [{"technique": t, "count": c} for t, c in techniques],
        "risky_users": [
            {"user": u, "max_threat": round(m or 0, 1), "avg_anomaly": round(a or 0, 3), "events": c}
            for u, m, a, c in users
        ],
    }
