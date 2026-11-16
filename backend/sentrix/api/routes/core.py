"""System, dashboard, assets, users and audit endpoints."""

from __future__ import annotations

import csv
import hashlib
import hmac
import io
import os
from datetime import datetime, timedelta

from fastapi import APIRouter, HTTPException, Query, Response
from sqlalchemy import func, or_, select, text
from sqlalchemy.exc import IntegrityError

from sentrix import APP_DESCRIPTION, APP_NAME, __version__
from sentrix.api.deps import DB, CurrentActor, get_or_404
from sentrix.core.config import get_settings
from sentrix.db.models import (
    AgentRun,
    Asset,
    AuditLog,
    CouncilDecision,
    Incident,
    IntelDocument,
    ResponseAction,
    SecurityEvent,
    User,
    utcnow,
)
from sentrix.detection.anomaly import forest_cache
from sentrix.detection.correlation import ACTIVE_STATUSES
from sentrix.llm.client import llm
from sentrix.risk.risk_engine import enterprise_risk
from sentrix.schemas.assets import AssetCreate, AssetOut, AssetUpdate
from sentrix.schemas.common import Message, Page
from sentrix.schemas.incidents import AuditOut
from sentrix.schemas.misc import UserCreate, UserOut, UserUpdate
from sentrix.services import audit

router = APIRouter()


# ------------------------------------------------------------------ system
@router.get("/health", tags=["System"])
def health(db: DB):
    db.execute(text("SELECT 1"))
    return {"status": "ok", "service": APP_NAME, "version": __version__}


@router.get("/system/status", tags=["System"])
def system_status(db: DB):
    s = get_settings()
    count = lambda m: db.scalar(select(func.count(m.id))) or 0  # noqa: E731
    return {
        "application": APP_NAME,
        "description": APP_DESCRIPTION,
        "version": __version__,
        "environment": s.app_env,
        "database": s.database_url.split("://", 1)[0],
        "api_key_required_for_writes": bool(s.api_key and s.api_key.get_secret_value()),
        "llm": llm.status(),
        "soar_webhook_configured": bool(s.soar_webhook_url),
        "ml_model": {
            "isolation_forest": "trained" if forest_cache._model is not None else "not trained yet",
            "trained_on_events": forest_cache._trained_on,
        },
        "counts": {
            "assets": count(Asset), "events": count(SecurityEvent), "incidents": count(Incident),
            "intel_documents": count(IntelDocument), "council_decisions": count(CouncilDecision),
            "agent_runs": count(AgentRun), "response_actions": count(ResponseAction),
            "audit_logs": count(AuditLog),
        },
        "council_weights": s.council_weights,
        "correlation_window_minutes": s.correlation_window_minutes,
        "twin_simulation_runs": s.twin_simulation_runs,
        "capabilities": {
            "deterministic": ["normalization", "MITRE classification", "correlation", "attack graph",
                              "risk scoring", "council consensus", "explainable AI"],
            "machine_learning": ["Isolation Forest anomaly detection", "TF-IDF retrieval"],
            "simulation": ["Monte Carlo digital twin"],
            "llm_optional": ["incident narrative", "grounded RAG answers"],
        },
    }


@router.get("/dashboard/summary", tags=["Dashboard"])
def dashboard_summary(db: DB):
    since = utcnow() - timedelta(hours=24)
    sev_open = dict(db.execute(
        select(Incident.severity, func.count()).where(Incident.status.in_(ACTIVE_STATUSES))
        .group_by(Incident.severity)
    ).all())
    status_counts = dict(db.execute(select(Incident.status, func.count()).group_by(Incident.status)).all())
    events_24h = db.scalar(select(func.count(SecurityEvent.id)).where(SecurityEvent.received_at >= since)) or 0
    ev_sev = dict(db.execute(
        select(SecurityEvent.severity, func.count()).where(SecurityEvent.timestamp >= since)
        .group_by(SecurityEvent.severity)
    ).all())
    hourly = db.execute(
        select(func.strftime("%Y-%m-%d %H:00", SecurityEvent.timestamp), func.count(),
               func.max(SecurityEvent.threat_score))
        .where(SecurityEvent.timestamp >= since)
        .group_by(func.strftime("%Y-%m-%d %H:00", SecurityEvent.timestamp))
        .order_by(func.strftime("%Y-%m-%d %H:00", SecurityEvent.timestamp))
    ).all() if get_settings().database_url.startswith("sqlite") else []
    recent = db.scalars(select(Incident).order_by(Incident.last_seen.desc()).limit(8)).all()
    decisions = db.scalars(select(CouncilDecision).order_by(CouncilDecision.id.desc()).limit(5)).all()
    pending = db.scalar(select(func.count(ResponseAction.id)).where(ResponseAction.status == "proposed")) or 0
    risk = enterprise_risk(db)
    tactics = db.execute(
        select(SecurityEvent.mitre_tactic, func.count()).where(SecurityEvent.mitre_tactic.is_not(None))
        .group_by(SecurityEvent.mitre_tactic)
    ).all()
    mttr = db.execute(
        select(Incident.first_seen, Incident.updated_at).where(Incident.status.in_(("resolved", "closed")))
    ).all()
    mttr_h = (sum((u - f).total_seconds() for f, u in mttr) / len(mttr) / 3600) if mttr else None
    return {
        "enterprise_risk": {"score": risk["score"], "level": risk["level"]},
        "top_risky_assets": risk["assets"][:6],
        "open_incidents": sum(sev_open.values()),
        "open_by_severity": sev_open,
        "incidents_by_status": status_counts,
        "events_24h": events_24h,
        "events_by_severity_24h": ev_sev,
        "events_hourly": [{"hour": h, "count": c, "max_threat": m} for h, c, m in hourly],
        "tactics": [{"tactic": t, "count": c} for t, c in tactics],
        "pending_approvals": pending,
        "mean_time_to_resolve_hours": round(mttr_h, 2) if mttr_h is not None else None,
        "recent_incidents": [
            {"id": i.id, "ref": i.ref, "title": i.title, "severity": i.severity, "status": i.status,
             "risk_score": i.risk_score, "last_seen": i.last_seen.isoformat()}
            for i in recent
        ],
        "recent_decisions": [
            {"id": d.id, "incident_id": d.incident_id, "playbook": d.decided_playbook_name,
             "consensus": d.consensus_score, "agreement": d.agreement, "created_at": d.created_at.isoformat()}
            for d in decisions
        ],
    }


# ------------------------------------------------------------------ assets
@router.get("/assets", response_model=list[AssetOut], tags=["Assets"])
def list_assets(db: DB, q: str | None = None, criticality: str | None = None, zone: str | None = None):
    stmt = select(Asset).order_by(Asset.hostname)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Asset.hostname.ilike(like), Asset.ip_address.ilike(like),
                              Asset.owner.ilike(like), Asset.department.ilike(like)))
    if criticality:
        stmt = stmt.where(Asset.criticality == criticality)
    if zone:
        stmt = stmt.where(Asset.network_zone == zone)
    return db.scalars(stmt).all()


@router.get("/assets/{asset_id}", response_model=AssetOut, tags=["Assets"])
def get_asset(asset_id: int, db: DB):
    return get_or_404(db, Asset, asset_id, "Asset")


@router.post("/assets", response_model=AssetOut, status_code=201, tags=["Assets"])
def create_asset(body: AssetCreate, db: DB, actor: CurrentActor):
    row = Asset(**body.model_dump(), status="online", risk_score=0.0)
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "An asset with this hostname or IP already exists") from None
    audit.record(db, actor, "asset.create", "asset", row.id, {"hostname": row.hostname})
    db.commit()
    return row


@router.put("/assets/{asset_id}", response_model=AssetOut, tags=["Assets"])
def update_asset(asset_id: int, body: AssetUpdate, db: DB, actor: CurrentActor):
    row = get_or_404(db, Asset, asset_id, "Asset")
    changes = body.model_dump(exclude_unset=True)
    for k, v in changes.items():
        setattr(row, k, v.value if hasattr(v, "value") else v)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "IP address already used by another asset") from None
    audit.record(db, actor, "asset.update", "asset", row.id, {"fields": sorted(changes)})
    db.commit()
    return row


@router.delete("/assets/{asset_id}", response_model=Message, tags=["Assets"])
def delete_asset(asset_id: int, db: DB, actor: CurrentActor):
    row = get_or_404(db, Asset, asset_id, "Asset")
    audit.record(db, actor, "asset.delete", "asset", row.id, {"hostname": row.hostname})
    db.delete(row)
    db.commit()
    return {"message": "Asset deleted"}


# ------------------------------------------------------------------ users
def hash_password(password: str, salt: bytes | None = None) -> str:
    salt = salt or os.urandom(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 310_000)
    return f"pbkdf2_sha256$310000${salt.hex()}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    _, it, salt, digest = stored.split("$")
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(it))
    return hmac.compare_digest(dk.hex(), digest)


@router.get("/users", response_model=list[UserOut], tags=["Users"])
def list_users(db: DB):
    return db.scalars(select(User).order_by(User.username)).all()


@router.post("/users", response_model=UserOut, status_code=201, tags=["Users"])
def create_user(body: UserCreate, db: DB, actor: CurrentActor):
    row = User(username=body.username, email=body.email, role=body.role,
               hashed_password=hash_password(body.password))
    db.add(row)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Username or email already exists") from None
    audit.record(db, actor, "user.create", "user", row.id, {"username": row.username, "role": row.role})
    db.commit()
    return row


@router.put("/users/{user_id}", response_model=UserOut, tags=["Users"])
def update_user(user_id: int, body: UserUpdate, db: DB, actor: CurrentActor):
    row = get_or_404(db, User, user_id, "User")
    changes = body.model_dump(exclude_unset=True)
    if "password" in changes:
        row.hashed_password = hash_password(changes.pop("password"))
        changes["password"] = "***"
    for k, v in changes.items():
        if k != "password":
            setattr(row, k, v)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise HTTPException(409, "Email already exists") from None
    audit.record(db, actor, "user.update", "user", row.id, {"fields": sorted(changes)})
    db.commit()
    return row


@router.delete("/users/{user_id}", response_model=Message, tags=["Users"])
def delete_user(user_id: int, db: DB, actor: CurrentActor):
    row = get_or_404(db, User, user_id, "User")
    audit.record(db, actor, "user.delete", "user", row.id, {"username": row.username})
    db.delete(row)
    db.commit()
    return {"message": "User deleted"}


# ------------------------------------------------------------------ audit
def _audit_query(actor: str | None, action: str | None, entity_type: str | None,
                 since: datetime | None, until: datetime | None):
    stmt = select(AuditLog)
    if actor:
        stmt = stmt.where(AuditLog.actor.ilike(f"%{actor}%"))
    if action:
        stmt = stmt.where(AuditLog.action.ilike(f"%{action}%"))
    if entity_type:
        stmt = stmt.where(AuditLog.entity_type == entity_type)
    if since:
        stmt = stmt.where(AuditLog.timestamp >= since.replace(tzinfo=None))
    if until:
        stmt = stmt.where(AuditLog.timestamp <= until.replace(tzinfo=None))
    return stmt


@router.get("/audit", response_model=Page[AuditOut], tags=["Audit"])
def list_audit(db: DB, actor: str | None = None, action: str | None = None, entity_type: str | None = None,
               since: datetime | None = None, until: datetime | None = None,
               limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    stmt = _audit_query(actor, action, entity_type, since, until)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(AuditLog.id.desc()).limit(limit).offset(offset)).all()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/audit/export.csv", tags=["Audit"])
def export_audit(db: DB, actor: str | None = None, action: str | None = None,
                 entity_type: str | None = None, since: datetime | None = None, until: datetime | None = None):
    rows = db.scalars(_audit_query(actor, action, entity_type, since, until).order_by(AuditLog.id)).all()
    buf = io.StringIO()
    w = csv.writer(buf)
    w.writerow(["id", "timestamp", "actor", "ip", "action", "entity_type", "entity_id", "outcome", "details"])
    for r in rows:
        w.writerow([r.id, r.timestamp.isoformat(), r.actor, r.ip or "", r.action, r.entity_type,
                    r.entity_id or "", r.outcome, r.details or {}])
    return Response(buf.getvalue(), media_type="text/csv",
                    headers={"Content-Disposition": "attachment; filename=sentrix_audit_log.csv"})
