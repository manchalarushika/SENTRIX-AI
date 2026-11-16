"""Event ingestion pipeline.

normalize -> resolve asset -> behavioural anomaly -> threat classification
-> threat score -> persist -> correlate into incidents
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from sentrix.core.logging import get_logger
from sentrix.db.models import Asset, SecurityEvent
from sentrix.detection import anomaly, classifier, correlation
from sentrix.detection.scoring import event_threat_score, max_severity, severity_from_score
from sentrix.ingestion.normalizer import normalize
from sentrix.schemas.events import EventIngest

log = get_logger("ingest")


@dataclass
class IngestOutcome:
    accepted: list[int] = field(default_factory=list)
    duplicates: int = 0
    errors: list[dict[str, Any]] = field(default_factory=list)
    incidents: set[int] = field(default_factory=set)


def _resolve_asset(db: Session, hostname: str | None, *ips: str | None) -> Asset | None:
    conds = []
    if hostname:
        conds.append(Asset.hostname == hostname)
    for ip in ips:
        if ip:
            conds.append(Asset.ip_address == ip)
    if not conds:
        return None
    return db.scalars(select(Asset).where(or_(*conds)).limit(1)).first()


def ingest_one(db: Session, payload: EventIngest) -> tuple[SecurityEvent | None, bool]:
    """Process a single event. Returns (event, is_duplicate)."""
    ev = normalize(payload)
    fp = ev.fingerprint()
    existing = db.scalar(select(SecurityEvent).where(SecurityEvent.fingerprint == fp))
    if existing is not None:
        return existing, True

    asset = _resolve_asset(db, ev.hostname, None if ev.hostname else ev.src_ip)
    if asset is not None and not ev.hostname:
        ev.hostname = asset.hostname

    # Resolve the source IP to a managed asset: links lateral movement across hosts.
    if ev.src_ip:
        src_asset = db.scalars(select(Asset).where(Asset.ip_address == ev.src_ip).limit(1)).first()
        if src_asset is not None and src_asset.hostname != ev.hostname:
            ev.extra["src_host"] = src_asset.hostname

    anom = anomaly.analyze(db, ev)
    cls = classifier.classify(ev)
    criticality = asset.criticality if asset else None
    threat = event_threat_score(cls.base_score, anom.score, criticality)
    hint = ev.severity_hint
    if hint and not cls.base_score and hint in ("high", "critical"):
        # Unclassified events keep the source's severity hint, capped at 'medium':
        # escalation beyond that needs rule or behavioural evidence.
        hint = "medium"
    severity = max_severity(severity_from_score(threat), hint)

    row = SecurityEvent(
        fingerprint=fp,
        timestamp=ev.timestamp,
        source=ev.source,
        source_format=ev.source_format,
        event_type=ev.event_type,
        category=cls.category,
        severity=severity,
        asset_id=asset.id if asset else None,
        hostname=ev.hostname,
        user=ev.user,
        src_ip=ev.src_ip,
        dst_ip=ev.dst_ip,
        dst_port=ev.dst_port,
        process=ev.process,
        command_line=ev.command_line,
        description=ev.description,
        raw=ev.raw or None,
        mitre_technique=cls.technique,
        mitre_tactic=cls.tactic,
        classification={**cls.as_dict(), "extra": ev.extra},
        anomaly_score=anom.score,
        anomaly_details=anom.as_dict(),
        threat_score=threat,
    )
    db.add(row)
    db.flush()
    if asset is not None:
        if asset.last_seen is None or ev.timestamp > asset.last_seen:
            asset.last_seen = ev.timestamp
    correlation.correlate(db, row)
    return row, False


def ingest_many(db: Session, payloads: list[EventIngest]) -> IngestOutcome:
    out = IngestOutcome()
    # Process in chronological order so baselines and correlation see history first.
    def _key(item: tuple[int, EventIngest]) -> datetime:
        ts = item[1].timestamp
        if ts is None:
            return datetime.max
        return ts.astimezone(UTC).replace(tzinfo=None) if ts.tzinfo else ts

    ordered = sorted(enumerate(payloads), key=_key)
    for idx, payload in ordered:
        try:
            with db.begin_nested():
                row, dup = ingest_one(db, payload)
            if dup:
                out.duplicates += 1
                continue
            assert row is not None
            out.accepted.append(row.id)
            if row.incident_id:
                out.incidents.add(row.incident_id)
        except Exception as exc:  # one bad event must not fail the batch
            log.exception("failed to ingest event #%d", idx)
            out.errors.append({"index": idx, "error": str(exc)[:300]})
    db.commit()
    return out
