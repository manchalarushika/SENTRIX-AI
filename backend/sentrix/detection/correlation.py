"""Threat correlation: groups related events into incidents.

Events are correlated when they share an entity (host or user) and fall
within ``CORRELATION_WINDOW_MINUTES`` of an open incident's activity.
Low-signal events (reconnaissance noise) are stored but only attached when a
meaningful incident exists, at which point they are back-filled so the
incident timeline shows the full attack narrative.
"""

from __future__ import annotations

from collections import Counter
from datetime import timedelta

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from sentrix.core.config import get_settings
from sentrix.db.models import Asset, Incident, SecurityEvent
from sentrix.detection.rules import TACTIC_ORDER
from sentrix.detection.scoring import incident_risk, max_severity
from sentrix.schemas.common import SEVERITY_RANK

ATTACH_THRESHOLD = 15.0   # minimum event threat score to join an incident
CREATE_THRESHOLD = 45.0   # minimum event threat score to open a new incident
CREATE_ANOMALY = 0.6      # ...or minimum behavioural anomaly score
ACTIVE_STATUSES = ("open", "investigating", "contained")


def _entities(ev: SecurityEvent) -> tuple[set[str], set[str]]:
    hosts = {ev.hostname} if ev.hostname else set()
    src_host = ((ev.classification or {}).get("extra") or {}).get("src_host")
    if src_host:
        hosts.add(src_host)  # lateral movement: source host links the two footholds
    users = {ev.user} if ev.user and ev.user != "SYSTEM" else set()
    return hosts, users


def find_incident(db: Session, ev: SecurityEvent) -> Incident | None:
    window = timedelta(minutes=get_settings().correlation_window_minutes)
    hosts, users = _entities(ev)
    if not hosts and not users:
        return None
    candidates = db.scalars(
        select(Incident)
        .where(Incident.status.in_(ACTIVE_STATUSES))
        .where(Incident.last_seen >= ev.timestamp - window)
        .where(Incident.first_seen <= ev.timestamp + window)
        .order_by(Incident.last_seen.desc())
        .limit(200)
    ).all()
    best, best_overlap = None, 0
    for inc in candidates:
        overlap = len(hosts & set(inc.hostnames or [])) * 2 + len(users & set(inc.users or []))
        if overlap > best_overlap:
            best, best_overlap = inc, overlap
    return best


def _primary_criticality(db: Session, inc: Incident) -> str:
    if not inc.hostnames:
        return "medium"
    crits = db.scalars(select(Asset.criticality).where(Asset.hostname.in_(inc.hostnames))).all()
    return max_severity(*crits) if crits else "medium"


def refresh_incident(db: Session, inc: Incident) -> None:
    """Recompute incident aggregates from its events."""
    events = db.scalars(
        select(SecurityEvent).where(SecurityEvent.incident_id == inc.id).order_by(SecurityEvent.timestamp)
    ).all()
    if not events:
        return
    host_counts = Counter(e.hostname for e in events if e.hostname)
    inc.hostnames = sorted(host_counts)
    inc.users = sorted({e.user for e in events if e.user and e.user != "SYSTEM"})
    tactics = {e.mitre_tactic for e in events if e.mitre_tactic}
    inc.tactics = [t for t in TACTIC_ORDER if t in tactics]
    inc.techniques = sorted({e.mitre_technique for e in events if e.mitre_technique})
    inc.event_count = len(events)
    inc.first_seen = events[0].timestamp
    inc.last_seen = events[-1].timestamp
    worst = max(events, key=lambda e: (e.threat_score, SEVERITY_RANK.get(e.severity, 0)))
    inc.category = worst.category if worst.category != "Other" else inc.category
    inc.primary_hostname = host_counts.most_common(1)[0][0] if host_counts else None
    crit = _primary_criticality(db, inc)
    inc.risk_score = incident_risk(worst.threat_score, len(inc.tactics), len(events), crit)
    # New evidence can raise severity; it never silently lowers it.
    inc.severity = max_severity(inc.severity, *(e.severity for e in events))
    if not inc.title_locked:
        where = inc.primary_hostname or (inc.users[0] if inc.users else "unknown entity")
        who = f" ({inc.users[0]})" if inc.users and inc.primary_hostname else ""
        inc.title = f"{inc.category} on {where}{who}"


def correlate(db: Session, ev: SecurityEvent) -> Incident | None:
    """Attach the event to an incident, creating one when evidence is strong enough."""
    if ev.threat_score < ATTACH_THRESHOLD and ev.anomaly_score < 0.4:
        return None
    inc = find_incident(db, ev)
    if inc is None:
        if ev.threat_score < CREATE_THRESHOLD and ev.anomaly_score < CREATE_ANOMALY:
            return None
        inc = Incident(
            ref="PENDING",
            title=f"{ev.category if ev.category != 'Other' else 'Suspicious Activity'} on "
            f"{ev.hostname or ev.user or 'unknown entity'}",
            category=ev.category if ev.category != "Other" else "Suspicious Activity",
            severity=ev.severity,
            first_seen=ev.timestamp,
            last_seen=ev.timestamp,
            hostnames=[],
            users=[],
            tactics=[],
            techniques=[],
            title_locked=False,
            analysis_version=0,
            event_count=0,
            risk_score=0.0,
            confidence=0.0,
            status="open",
        )
        db.add(inc)
        db.flush()
        inc.ref = f"INC-{inc.id:05d}"
        _backfill(db, inc, ev)
    ev.incident_id = inc.id
    db.flush()
    refresh_incident(db, inc)
    return inc


def _backfill(db: Session, inc: Incident, ev: SecurityEvent) -> None:
    window = timedelta(minutes=get_settings().correlation_window_minutes)
    hosts, users = _entities(ev)
    conds = []
    if hosts:
        conds.append(SecurityEvent.hostname.in_(hosts))
    if users:
        conds.append(SecurityEvent.user.in_(users))
    prior = db.scalars(
        select(SecurityEvent)
        .where(SecurityEvent.incident_id.is_(None))
        .where(SecurityEvent.id != ev.id)
        .where(SecurityEvent.timestamp >= ev.timestamp - window)
        .where(SecurityEvent.timestamp <= ev.timestamp + window)
        .where(or_(SecurityEvent.threat_score >= ATTACH_THRESHOLD, SecurityEvent.anomaly_score >= 0.4))
        .where(or_(*conds))
    ).all()
    for p in prior:
        p.incident_id = inc.id
