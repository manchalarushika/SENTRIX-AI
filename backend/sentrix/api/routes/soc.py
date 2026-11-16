"""Event ingestion, incidents, response actions, agents and council endpoints."""

from __future__ import annotations

import csv
import io
import json
from datetime import datetime

from fastapi import APIRouter, File, HTTPException, Query, Response, UploadFile
from pydantic import ValidationError
from sqlalchemy import String, cast, func, or_, select

from sentrix.agents.specialists import PIPELINE
from sentrix.api.deps import DB, CurrentActor, get_or_404, run_analyses
from sentrix.core.config import get_settings
from sentrix.core.realtime import hub
from sentrix.db.models import AgentRun, CouncilDecision, Incident, IncidentNote, ResponseAction, SecurityEvent
from sentrix.response import actions as response
from sentrix.schemas.common import Page
from sentrix.schemas.events import EventBatch, EventIngest, EventOut, IngestResult
from sentrix.schemas.incidents import (
    ActionReview,
    AgentRunOut,
    AnalyzeRequest,
    CouncilDecisionOut,
    IncidentDetail,
    IncidentOut,
    IncidentUpdate,
    NoteCreate,
    NoteOut,
    ResponseActionOut,
)
from sentrix.services import audit
from sentrix.services.ingest import ingest_many
from sentrix.services.report import incident_report_markdown

router = APIRouter()
MAX_UPLOAD_BYTES = 5 * 1024 * 1024


def _ingest(db, payloads: list[EventIngest], actor, analyze: bool, rejected: list | None = None) -> dict:
    out = ingest_many(db, payloads)
    analyzed = run_analyses(db, out.incidents) if analyze else []
    errors = (rejected or []) + out.errors
    audit.record(db, actor, "events.ingest", "event", None, {
        "accepted": len(out.accepted), "duplicates": out.duplicates, "rejected": len(errors),
        "incidents": sorted(out.incidents),
    }, commit=True)
    if out.accepted:
        hub.publish("events_ingested", {"count": len(out.accepted), "incidents": sorted(out.incidents)})
    return {
        "accepted": len(out.accepted), "duplicates": out.duplicates, "rejected": len(errors),
        "errors": errors[:50], "event_ids": out.accepted, "incidents_touched": sorted(out.incidents),
        "incidents_analyzed": analyzed,
    }


# ------------------------------------------------------------------ events
@router.post("/events", response_model=IngestResult, status_code=201, tags=["Events"])
def ingest_event(body: EventIngest, db: DB, actor: CurrentActor, analyze: bool = True):
    return _ingest(db, [body], actor, analyze)


@router.post("/events/batch", response_model=IngestResult, status_code=201, tags=["Events"])
def ingest_batch(body: EventBatch, db: DB, actor: CurrentActor):
    return _ingest(db, body.events, actor, body.analyze)


@router.post("/events/upload", response_model=IngestResult, status_code=201, tags=["Events"])
async def upload_events(db: DB, actor: CurrentActor, file: UploadFile = File(...),
                        format: str = Query("generic", pattern="^(generic|windows|sysmon|syslog|firewall|edr|cloud)$"),
                        analyze: bool = True):
    """Upload a JSON array, JSON Lines or CSV file of events (max 5 MB, 5,000 events).

    JSON objects are treated as normalized events when they contain ``event_type``
    or ``description``; otherwise they are treated as raw vendor payloads of ``format``.
    """
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(413, "File exceeds 5 MB limit")
    try:
        text = data.decode("utf-8-sig")
    except UnicodeDecodeError:
        raise HTTPException(400, "File must be UTF-8 encoded") from None
    name = (file.filename or "").lower()
    records: list[dict] = []
    try:
        if name.endswith(".csv"):
            records = [dict(r) for r in csv.DictReader(io.StringIO(text))]
            for r in records:
                for k in list(r):
                    if r[k] in ("", None):
                        r.pop(k)
                if "dst_port" in r:
                    r["dst_port"] = int(r["dst_port"])
        elif text.lstrip().startswith("["):
            records = json.loads(text)
        else:
            records = [json.loads(line) for line in text.splitlines() if line.strip()]
    except (json.JSONDecodeError, ValueError) as exc:
        raise HTTPException(400, f"Could not parse file: {exc}") from None
    if not isinstance(records, list) or len(records) > 5000:
        raise HTTPException(400, "Expected a list of at most 5,000 events")
    fields = set(EventIngest.model_fields)
    payloads, rejected = [], []
    for i, r in enumerate(records):
        if not isinstance(r, dict):
            rejected.append({"index": i, "error": "not an object"})
            continue
        try:
            if r.keys() & {"event_type", "description"} and r.keys() <= fields:
                payloads.append(EventIngest(**{"source": "upload", **r}))
            else:
                payloads.append(EventIngest(format=format, source="upload", raw=r))
        except ValidationError as exc:
            rejected.append({"index": i, "error": exc.errors()[0]["msg"]})
    if not payloads:
        raise HTTPException(400, {"message": "No valid events in file", "errors": rejected[:20]})
    return _ingest(db, payloads, actor, analyze, rejected)


@router.get("/events", response_model=Page[EventOut], tags=["Events"])
def list_events(
    db: DB, severity: str | None = None, hostname: str | None = None, user: str | None = None,
    event_type: str | None = None, incident_id: int | None = None, tactic: str | None = None,
    min_threat: float | None = Query(None, ge=0, le=100), q: str | None = Query(None, max_length=200),
    since: datetime | None = None, exclude_baseline: bool = False,
    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0),
):
    stmt = select(SecurityEvent)
    if severity:
        stmt = stmt.where(SecurityEvent.severity.in_(severity.split(",")))
    if hostname:
        stmt = stmt.where(SecurityEvent.hostname == hostname.upper())
    if user:
        stmt = stmt.where(SecurityEvent.user == user.lower())
    if event_type:
        stmt = stmt.where(SecurityEvent.event_type == event_type)
    if incident_id is not None:
        stmt = stmt.where(SecurityEvent.incident_id == incident_id)
    if tactic:
        stmt = stmt.where(SecurityEvent.mitre_tactic == tactic)
    if min_threat is not None:
        stmt = stmt.where(SecurityEvent.threat_score >= min_threat)
    if since:
        stmt = stmt.where(SecurityEvent.timestamp >= since.replace(tzinfo=None))
    if exclude_baseline:
        stmt = stmt.where(SecurityEvent.source != "baseline-synthetic")
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(SecurityEvent.description.ilike(like), SecurityEvent.event_type.ilike(like),
                              SecurityEvent.command_line.ilike(like), SecurityEvent.hostname.ilike(like),
                              SecurityEvent.mitre_technique.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(SecurityEvent.timestamp.desc(), SecurityEvent.id.desc())
                       .limit(limit).offset(offset)).all()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/events/{event_id}", tags=["Events"])
def get_event(event_id: int, db: DB):
    e = get_or_404(db, SecurityEvent, event_id, "Event")
    return {**EventOut.model_validate(e).model_dump(), "raw": e.raw}


# ------------------------------------------------------------------ incidents
@router.get("/incidents", response_model=Page[IncidentOut], tags=["Incidents"])
def list_incidents(
    db: DB, status: str | None = None, severity: str | None = None, category: str | None = None,
    hostname: str | None = None, q: str | None = Query(None, max_length=200),
    sort: str = Query("last_seen", pattern="^(last_seen|risk_score|first_seen|severity)$"),
    limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0),
):
    stmt = select(Incident)
    if status:
        stmt = stmt.where(Incident.status.in_(status.split(",")))
    if severity:
        stmt = stmt.where(Incident.severity.in_(severity.split(",")))
    if category:
        stmt = stmt.where(Incident.category == category)
    if hostname:
        stmt = stmt.where(cast(Incident.hostnames, String).ilike(f'%"{hostname.upper()}"%'))
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(Incident.title.ilike(like), Incident.ref.ilike(like), Incident.summary.ilike(like)))
    order = {"last_seen": Incident.last_seen.desc(), "risk_score": Incident.risk_score.desc(),
             "first_seen": Incident.first_seen.desc(), "severity": Incident.risk_score.desc()}[sort]
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(order).limit(limit).offset(offset)).all()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/incidents/{incident_id}", response_model=IncidentDetail, tags=["Incidents"])
def get_incident(incident_id: int, db: DB):
    return get_or_404(db, Incident, incident_id, "Incident")


@router.patch("/incidents/{incident_id}", response_model=IncidentOut, tags=["Incidents"])
def update_incident(incident_id: int, body: IncidentUpdate, db: DB, actor: CurrentActor):
    inc = get_or_404(db, Incident, incident_id, "Incident")
    changes = body.model_dump(exclude_unset=True)
    before = {k: getattr(inc, k) for k in changes}
    for k, v in changes.items():
        setattr(inc, k, v.value if hasattr(v, "value") else v)
    if "title" in changes:
        inc.title_locked = True
    audit.record(db, actor, "incident.update", "incident", inc.id,
                 {"ref": inc.ref, "before": before, "after": {k: getattr(inc, k) for k in changes}})
    db.commit()
    hub.publish("incident_updated", {"incident_id": inc.id, "changes": list(changes)})
    return inc


@router.post("/incidents/{incident_id}/notes", response_model=NoteOut, status_code=201, tags=["Incidents"])
def add_note(incident_id: int, body: NoteCreate, db: DB, actor: CurrentActor):
    inc = get_or_404(db, Incident, incident_id, "Incident")
    note = IncidentNote(incident_id=inc.id, author=actor.name, body=body.body)
    db.add(note)
    db.flush()
    audit.record(db, actor, "incident.note", "incident", inc.id, {"note_id": note.id})
    db.commit()
    return note


@router.post("/incidents/{incident_id}/analyze", tags=["Incidents"])
def reanalyze(incident_id: int, body: AnalyzeRequest, db: DB, actor: CurrentActor):
    inc = get_or_404(db, Incident, incident_id, "Incident")
    done = run_analyses(db, [inc.id], use_llm=body.use_llm)
    if not done:
        raise HTTPException(500, "Analysis failed - see server logs")
    audit.record(db, actor, "incident.analyze", "incident", inc.id,
                 {"ref": inc.ref, "version": inc.analysis_version, "use_llm": body.use_llm}, commit=True)
    db.refresh(inc)
    return {"incident_id": inc.id, "analysis_version": inc.analysis_version, "analysis": inc.analysis}


@router.get("/incidents/{incident_id}/events", response_model=list[EventOut], tags=["Incidents"])
def incident_events(incident_id: int, db: DB):
    get_or_404(db, Incident, incident_id, "Incident")
    return db.scalars(select(SecurityEvent).where(SecurityEvent.incident_id == incident_id)
                      .order_by(SecurityEvent.timestamp)).all()


@router.get("/incidents/{incident_id}/actions", response_model=list[ResponseActionOut], tags=["Incidents"])
def incident_actions(incident_id: int, db: DB):
    get_or_404(db, Incident, incident_id, "Incident")
    return db.scalars(select(ResponseAction).where(ResponseAction.incident_id == incident_id)
                      .order_by(ResponseAction.id.desc())).all()


@router.get("/incidents/{incident_id}/decisions", response_model=list[CouncilDecisionOut], tags=["Incidents"])
def incident_decisions(incident_id: int, db: DB):
    get_or_404(db, Incident, incident_id, "Incident")
    return db.scalars(select(CouncilDecision).where(CouncilDecision.incident_id == incident_id)
                      .order_by(CouncilDecision.id.desc())).all()


@router.get("/incidents/{incident_id}/report", tags=["Incidents"])
def incident_report(incident_id: int, db: DB, actor: CurrentActor,
                    format: str = Query("markdown", pattern="^(markdown|json)$")):
    inc = get_or_404(db, Incident, incident_id, "Incident")
    audit.record(db, actor, "incident.report", "incident", inc.id, {"format": format}, commit=True)
    if format == "json":
        events = db.scalars(select(SecurityEvent).where(SecurityEvent.incident_id == inc.id)
                            .order_by(SecurityEvent.timestamp)).all()
        body = {
            "incident": IncidentDetail.model_validate(inc).model_dump(mode="json"),
            "events": [EventOut.model_validate(e).model_dump(mode="json") for e in events],
        }
        return Response(json.dumps(body, indent=2, default=str), media_type="application/json",
                        headers={"Content-Disposition": f"attachment; filename={inc.ref}.json"})
    return Response(incident_report_markdown(db, inc), media_type="text/markdown",
                    headers={"Content-Disposition": f"attachment; filename={inc.ref}.md"})


# ------------------------------------------------------------------ response actions
@router.get("/actions", response_model=Page[ResponseActionOut], tags=["Response"])
def list_actions(db: DB, status: str | None = None, incident_id: int | None = None,
                 risk_level: str | None = None,
                 limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    stmt = select(ResponseAction)
    if status:
        stmt = stmt.where(ResponseAction.status.in_(status.split(",")))
    if incident_id is not None:
        stmt = stmt.where(ResponseAction.incident_id == incident_id)
    if risk_level:
        stmt = stmt.where(ResponseAction.risk_level == risk_level)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(ResponseAction.id.desc()).limit(limit).offset(offset)).all()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("/actions/{action_id}/review", response_model=ResponseActionOut, tags=["Response"])
def review_action(action_id: int, body: ActionReview, db: DB, actor: CurrentActor):
    action = get_or_404(db, ResponseAction, action_id, "Action")
    try:
        response.review(db, action, body.decision, actor.name, body.note)
    except response.ReviewError as exc:
        audit.record(db, actor, f"action.{body.decision}", "response_action", action.id,
                     {"error": str(exc)}, outcome="denied", commit=True)
        raise HTTPException(409, str(exc)) from None
    audit.record(db, actor, f"action.{body.decision}", "response_action", action.id, {
        "incident_id": action.incident_id, "type": action.action_type, "target": action.target,
        "risk_level": action.risk_level, "note": body.note, "status": action.status,
    })
    db.commit()
    hub.publish("action_reviewed", {"action_id": action.id, "status": action.status})
    return action


@router.post("/actions/{action_id}/complete", response_model=ResponseActionOut, tags=["Response"])
def complete_action(action_id: int, db: DB, actor: CurrentActor, body: NoteCreate | None = None):
    action = get_or_404(db, ResponseAction, action_id, "Action")
    try:
        response.complete(action, actor.name, body.body if body else None)
    except response.ReviewError as exc:
        raise HTTPException(409, str(exc)) from None
    audit.record(db, actor, "action.complete", "response_action", action.id,
                 {"incident_id": action.incident_id, "type": action.action_type, "target": action.target})
    db.commit()
    return action


# ------------------------------------------------------------------ agents & council
@router.get("/agents", tags=["Agents"])
def list_agents(db: DB):
    weights = get_settings().council_weights
    stats = {
        a: {"runs": n, "avg_ms": round(ms or 0, 1), "avg_confidence": round(c or 0, 3), "errors": 0}
        for a, n, ms, c in db.execute(
            select(AgentRun.agent, func.count(), func.avg(AgentRun.duration_ms), func.avg(AgentRun.confidence))
            .group_by(AgentRun.agent)
        ).all()
    }
    for a, n in db.execute(select(AgentRun.agent, func.count()).where(AgentRun.status == "error")
                           .group_by(AgentRun.agent)).all():
        stats.setdefault(a, {})["errors"] = n
    agents = [
        {"name": a.name, "role": a.role, "method": a.method, "votes_in_council": a.votes,
         "council_weight": weights.get(a.name) if a.votes else None, **stats.get(a.name, {"runs": 0})}
        for a in PIPELINE
    ]
    agents.append({"name": "Narrator", "role": "LLM incident narrative (optional, non-voting)",
                   "method": "llm", "votes_in_council": False, "council_weight": None,
                   **stats.get("Narrator", {"runs": 0})})
    return agents


@router.get("/agents/runs", response_model=Page[AgentRunOut], tags=["Agents"])
def list_agent_runs(db: DB, agent: str | None = None, incident_id: int | None = None,
                    status: str | None = None,
                    limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    stmt = select(AgentRun)
    if agent:
        stmt = stmt.where(AgentRun.agent == agent)
    if incident_id is not None:
        stmt = stmt.where(AgentRun.incident_id == incident_id)
    if status:
        stmt = stmt.where(AgentRun.status == status)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(AgentRun.id.desc()).limit(limit).offset(offset)).all()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/council/decisions", response_model=Page[CouncilDecisionOut], tags=["Council"])
def list_decisions(db: DB, playbook: str | None = None,
                   limit: int = Query(25, ge=1, le=200), offset: int = Query(0, ge=0)):
    stmt = select(CouncilDecision)
    if playbook:
        stmt = stmt.where(CouncilDecision.decided_playbook == playbook)
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(CouncilDecision.id.desc()).limit(limit).offset(offset)).all()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.get("/council/decisions/{decision_id}", response_model=CouncilDecisionOut, tags=["Council"])
def get_decision(decision_id: int, db: DB):
    return get_or_404(db, CouncilDecision, decision_id, "Decision")
