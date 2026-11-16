"""Behavioral anomaly detection (UEBA).

Two complementary techniques are combined:

1. **Per-entity statistical baselines** (deterministic): for the user and the
   host involved in an event we build a baseline from stored history
   (hour-of-day distribution, known processes, known destinations, known
   logon sources, event-type frequencies, hourly event rate) and score how far
   the new event deviates. Each deviation is an explainable *indicator*.
2. **Isolation Forest** (unsupervised ML, scikit-learn): trained on numeric
   feature vectors of the stored event history once enough data exists. Its
   outlier score is added as one more indicator.

Indicator contributions are fused with a noisy-OR: ``1 - prod(1 - c_i)``.
"""

from __future__ import annotations

import ipaddress
import math
import threading
from collections import Counter
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Any

import numpy as np
from sklearn.ensemble import IsolationForest
from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from sentrix.core.config import get_settings
from sentrix.core.logging import get_logger
from sentrix.db.models import SecurityEvent
from sentrix.ingestion.normalizer import NormalizedEvent

log = get_logger("ueba")

HISTORY_DAYS = 30
HISTORY_LIMIT = 3000
ML_MIN_EVENTS = 200


def is_external(ip: str | None) -> bool:
    if not ip:
        return False
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return not (a.is_private or a.is_loopback or a.is_link_local or a.is_reserved)


def _entropy(s: str) -> float:
    if not s:
        return 0.0
    c = Counter(s)
    n = len(s)
    return -sum(v / n * math.log2(v / n) for v in c.values())


@dataclass
class AnomalyResult:
    score: float
    indicators: list[dict[str, Any]] = field(default_factory=list)
    baseline: dict[str, Any] = field(default_factory=dict)

    def as_dict(self) -> dict[str, Any]:
        return {
            "score": self.score,
            "indicators": self.indicators,
            "baseline": self.baseline,
            "method": "statistical-baseline + isolation-forest",
        }


def feature_vector(
    hour: int, weekday: int, cmd: str | None, dst_port: int | None, dst_ip: str | None,
    type_freq: float,
) -> list[float]:
    cmd = cmd or ""
    return [
        math.sin(2 * math.pi * hour / 24),
        math.cos(2 * math.pi * hour / 24),
        1.0 if weekday >= 5 else 0.0,
        min(len(cmd), 2000) / 2000,
        _entropy(cmd) / 8,
        0.0 if dst_port is None else (1.0 if dst_port > 1024 else 0.5),
        1.0 if is_external(dst_ip) else 0.0,
        type_freq,
    ]


class _ForestCache:
    """Caches one Isolation Forest per database, retrained as history grows."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._model: IsolationForest | None = None
        self._trained_on = 0
        self._type_freq: dict[str, float] = {}

    def get(self, db: Session) -> tuple[IsolationForest | None, dict[str, float]]:
        total = db.scalar(select(func.count(SecurityEvent.id))) or 0
        if total < ML_MIN_EVENTS:
            return None, {}
        with self._lock:
            if self._model is not None and total < self._trained_on * 1.25:
                return self._model, self._type_freq
            rows = db.execute(
                select(
                    SecurityEvent.timestamp,
                    SecurityEvent.command_line,
                    SecurityEvent.dst_port,
                    SecurityEvent.dst_ip,
                    SecurityEvent.event_type,
                )
                .order_by(SecurityEvent.id.desc())
                .limit(5000)
            ).all()
            types = Counter(r.event_type for r in rows)
            n = len(rows)
            type_freq = {t: c / n for t, c in types.items()}
            X = np.array(
                [
                    feature_vector(
                        r.timestamp.hour, r.timestamp.weekday(), r.command_line,
                        r.dst_port, r.dst_ip, type_freq.get(r.event_type, 0.0),
                    )
                    for r in rows
                ]
            )
            model = IsolationForest(n_estimators=150, contamination="auto", random_state=42)
            model.fit(X)
            self._model, self._trained_on, self._type_freq = model, total, type_freq
            log.info("Isolation Forest trained on %d events", n)
            return model, type_freq

    def reset(self) -> None:
        with self._lock:
            self._model, self._trained_on, self._type_freq = None, 0, {}


forest_cache = _ForestCache()


def _history(db: Session, column, value: str, before: datetime) -> list[SecurityEvent]:
    return list(
        db.scalars(
            select(SecurityEvent)
            .where(column == value)
            .where(SecurityEvent.timestamp < before)
            .where(SecurityEvent.timestamp >= before - timedelta(days=HISTORY_DAYS))
            .order_by(SecurityEvent.timestamp.desc())
            .limit(HISTORY_LIMIT)
        )
    )


def analyze(db: Session, ev: NormalizedEvent) -> AnomalyResult:
    settings = get_settings()
    min_n = settings.anomaly_min_baseline_events
    ts = ev.timestamp
    indicators: list[dict[str, Any]] = []

    def add(name: str, contribution: float, detail: str, entity: str | None = None) -> None:
        c = round(max(0.0, min(0.95, contribution)), 3)
        if c > 0:
            indicators.append({"indicator": name, "contribution": c, "detail": detail, "entity": entity})

    user_hist = _history(db, SecurityEvent.user, ev.user, ts) if ev.user else []
    host_hist = _history(db, SecurityEvent.hostname, ev.hostname, ts) if ev.hostname else []
    user_ok = len(user_hist) >= min_n
    host_ok = len(host_hist) >= min_n
    et = ev.event_type.lower()

    # 1. Time-of-day deviation ---------------------------------------
    ref = user_hist if user_ok else host_hist if host_ok else []
    entity = ev.user if user_ok else ev.hostname
    if ref:
        hours = Counter(e.timestamp.hour for e in ref)
        p = (hours.get(ts.hour, 0) + 0.5) / (len(ref) + 12)
        if p < 0.02:
            add("unusual_time", 0.4 * (1 - p / 0.02) + 0.1,
                f"activity at {ts.hour:02d}:00 UTC is rare for this entity (p={p:.3f})", entity)
    elif ts.hour < 6 or ts.hour >= 22:
        add("off_hours", 0.12, f"activity at {ts.hour:02d}:00 UTC outside business hours (no baseline yet)")

    # 2. Rare event type for the entity --------------------------------
    if ref:
        freq = sum(1 for e in ref if e.event_type == ev.event_type) / len(ref)
        if freq == 0:
            add("first_seen_event_type", 0.3, f"'{ev.event_type}' never observed for this entity", entity)
        elif freq < 0.01:
            add("rare_event_type", 0.15, f"'{ev.event_type}' is rare for this entity ({freq:.1%})", entity)

    # 3. New process on host --------------------------------------------
    if ev.process and host_ok:
        known = {(e.process or "").lower() for e in host_hist}
        if ev.process.lower() not in known:
            add("new_process", 0.25, f"process '{ev.process}' never seen on {ev.hostname}", ev.hostname)

    # 4. New destination ------------------------------------------------
    if ev.dst_ip and host_ok:
        known = {e.dst_ip for e in host_hist if e.dst_ip}
        if ev.dst_ip not in known:
            c = 0.3 if is_external(ev.dst_ip) else 0.12
            add("new_destination", c, f"first connection from {ev.hostname} to {ev.dst_ip}", ev.hostname)

    # 5. New logon source for user -------------------------------------
    if ev.user and ev.src_ip and "logon" in et and "fail" not in et and user_ok:
        known = {e.src_ip for e in user_hist if e.src_ip}
        if ev.src_ip not in known:
            c = 0.4 if is_external(ev.src_ip) else 0.25
            add("new_logon_source", c, f"{ev.user} logged on from new source {ev.src_ip}", ev.user)

    # 6. Failed-logon burst / password spraying ------------------------
    window = ts - timedelta(minutes=10)
    if "fail" in et and ("logon" in et or "login" in et or "credential" in et):
        conds = []
        if ev.user:
            conds.append(SecurityEvent.user == ev.user)
        if ev.src_ip:
            conds.append(SecurityEvent.src_ip == ev.src_ip)
        if conds:
            recent = db.scalars(
                select(SecurityEvent)
                .where(SecurityEvent.event_type == ev.event_type)
                .where(SecurityEvent.timestamp >= window, SecurityEvent.timestamp <= ts)
                .where(or_(*conds))
            ).all()
            count = len(recent) + 1
            if count >= 5:
                add("failed_logon_burst", 0.15 * count - 0.45,
                    f"{count} failed logons in 10 minutes", ev.user or ev.src_ip)
            if ev.src_ip:
                users = {e.user for e in recent if e.src_ip == ev.src_ip and e.user} | {ev.user}
                users.discard(None)
                if len(users) >= 5:
                    add("password_spray", 0.75,
                        f"{len(users)} different accounts failed from {ev.src_ip}", ev.src_ip)

    # 7. Successful logon after failures ------------------------------
    if ev.user and "successful logon" in et:
        fails = db.scalar(
            select(func.count(SecurityEvent.id))
            .where(SecurityEvent.user == ev.user)
            .where(SecurityEvent.event_type.ilike("%failed%"))
            .where(SecurityEvent.timestamp >= ts - timedelta(minutes=30), SecurityEvent.timestamp <= ts)
        ) or 0
        if fails >= 5:
            add("success_after_failures", 0.65,
                f"successful logon for {ev.user} after {fails} failures in 30 minutes", ev.user)

    # 8. Host fan-out (lateral movement) --------------------------------
    if ev.user and ev.hostname:
        hosts_1h = {
            h
            for (h,) in db.execute(
                select(SecurityEvent.hostname)
                .where(SecurityEvent.user == ev.user)
                .where(SecurityEvent.timestamp >= ts - timedelta(hours=1), SecurityEvent.timestamp <= ts)
            )
            if h
        } | {ev.hostname}
        if len(hosts_1h) >= 4:
            add("host_fanout", min(0.7, 0.12 * len(hosts_1h)),
                f"{ev.user} active on {len(hosts_1h)} hosts within 1 hour", ev.user)

    # 9. Event-rate spike on host --------------------------------------
    if host_ok and ev.hostname:
        span_h = max(1.0, (ts - host_hist[-1].timestamp).total_seconds() / 3600)
        mean_rate = len(host_hist) / span_h
        last_hour = sum(1 for e in host_hist if e.timestamp >= ts - timedelta(hours=1)) + 1
        std = max(1.0, math.sqrt(mean_rate))
        z = (last_hour - mean_rate) / std
        if z > 3:
            add("event_rate_spike", min(0.45, 0.08 * z),
                f"{last_hour} events in last hour vs baseline {mean_rate:.1f}/h (z={z:.1f})", ev.hostname)

    # 10. Isolation Forest outlier -------------------------------------
    model, type_freq = forest_cache.get(db)
    if model is not None:
        x = np.array([feature_vector(ts.hour, ts.weekday(), ev.command_line, ev.dst_port, ev.dst_ip,
                                     type_freq.get(ev.event_type, 0.0))])
        df = float(model.decision_function(x)[0])  # < 0 means outlier
        if df < 0:
            add("ml_outlier", min(0.45, -df * 3),
                f"Isolation Forest outlier (decision={df:.3f})")

    prod = 1.0
    for i in indicators:
        prod *= 1 - i["contribution"]
    score = round(1 - prod, 3)
    return AnomalyResult(
        score=score,
        indicators=sorted(indicators, key=lambda i: i["contribution"], reverse=True),
        baseline={
            "user_events": len(user_hist),
            "host_events": len(host_hist),
            "user_baseline_ready": user_ok,
            "host_baseline_ready": host_ok,
            "min_events": min_n,
            "ml_model": "trained" if model is not None else f"waiting for {ML_MIN_EVENTS} events",
        },
    )
