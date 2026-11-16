"""Threat intelligence, attack graph, digital twin, risk and demo endpoints."""

from __future__ import annotations

import json

from fastapi import APIRouter, File, HTTPException, Query, UploadFile
from sqlalchemy import delete, func, or_, select

from sentrix.api.deps import DB, CurrentActor, get_or_404, run_analyses
from sentrix.core.config import get_settings
from sentrix.db.models import (
    AgentRun,
    CouncilDecision,
    Incident,
    IncidentNote,
    IntelDocument,
    ResponseAction,
    SecurityEvent,
)
from sentrix.detection.anomaly import forest_cache
from sentrix.graph import attack_graph
from sentrix.intel import knowledge, rag
from sentrix.risk import risk_engine
from sentrix.schemas.common import Page
from sentrix.schemas.misc import IntelDocCreate, IntelDocOut, IntelQuery, ScenarioRun, TwinRequest
from sentrix.services import audit, demo
from sentrix.services.ingest import ingest_many
from sentrix.twin.digital_twin import simulate

router = APIRouter()


# ------------------------------------------------------------------ intel / RAG
@router.post("/intel/search", tags=["Threat Intel"])
def intel_search(body: IntelQuery, db: DB, actor: CurrentActor):
    result = rag.answer(db, body.query, top_k=body.top_k, synthesize=body.synthesize)
    if body.synthesize:
        audit.record(db, actor, "intel.synthesize", "intel", None,
                     {"query": body.query[:200], "llm": result.get("llm", {}).get("status")}, commit=True)
    return result


@router.get("/intel/documents", response_model=Page[IntelDocOut], tags=["Threat Intel"])
def list_docs(db: DB, doc_type: str | None = None, q: str | None = Query(None, max_length=200),
              limit: int = Query(50, ge=1, le=500), offset: int = Query(0, ge=0)):
    stmt = select(IntelDocument)
    if doc_type:
        stmt = stmt.where(IntelDocument.doc_type == doc_type)
    if q:
        like = f"%{q}%"
        stmt = stmt.where(or_(IntelDocument.title.ilike(like), IntelDocument.doc_id.ilike(like),
                              IntelDocument.body.ilike(like)))
    total = db.scalar(select(func.count()).select_from(stmt.subquery())) or 0
    items = db.scalars(stmt.order_by(IntelDocument.doc_type, IntelDocument.doc_id).limit(limit).offset(offset)).all()
    return {"items": items, "total": total, "limit": limit, "offset": offset}


@router.post("/intel/documents", response_model=IntelDocOut, status_code=201, tags=["Threat Intel"])
def create_doc(body: IntelDocCreate, db: DB, actor: CurrentActor):
    if db.scalar(select(IntelDocument).where(IntelDocument.doc_id == body.doc_id)):
        raise HTTPException(409, "A document with this doc_id already exists")
    row = IntelDocument(**body.model_dump())
    db.add(row)
    db.flush()
    audit.record(db, actor, "intel.create", "intel_document", row.doc_id, {"title": row.title})
    db.commit()
    rag.retriever.invalidate()
    return row


@router.delete("/intel/documents/{doc_id}", tags=["Threat Intel"])
def delete_doc(doc_id: str, db: DB, actor: CurrentActor):
    row = db.scalar(select(IntelDocument).where(IntelDocument.doc_id == doc_id))
    if row is None:
        raise HTTPException(404, "Document not found")
    audit.record(db, actor, "intel.delete", "intel_document", doc_id, {"title": row.title})
    db.delete(row)
    db.commit()
    rag.retriever.invalidate()
    return {"message": "Document deleted"}


@router.post("/intel/import", tags=["Threat Intel"])
async def import_intel(db: DB, actor: CurrentActor, file: UploadFile = File(...),
                       kind: str = Query(..., pattern="^(cisa_kev|mitre_stix)$")):
    """Import the official CISA KEV JSON feed or MITRE ATT&CK STIX bundle (max 60 MB)."""
    data = await file.read(60 * 1024 * 1024 + 1)
    if len(data) > 60 * 1024 * 1024:
        raise HTTPException(413, "File too large")
    try:
        payload = json.loads(data)
    except json.JSONDecodeError:
        raise HTTPException(400, "File is not valid JSON") from None
    docs = knowledge.parse_cisa_kev(payload) if kind == "cisa_kev" else knowledge.parse_mitre_stix(payload)
    if not docs:
        raise HTTPException(400, f"No {kind} records found in file")
    added, updated = knowledge.upsert_docs(db, docs)
    audit.record(db, actor, "intel.import", "intel_document", None,
                 {"kind": kind, "added": added, "updated": updated}, commit=True)
    rag.retriever.invalidate()
    return {"kind": kind, "added": added, "updated": updated}


# ------------------------------------------------------------------ graph / twin / risk
@router.get("/graph/enterprise", tags=["Attack Graph"])
def graph_enterprise(db: DB):
    return attack_graph.enterprise_exposure(db)


@router.get("/graph/incident/{incident_id}", tags=["Attack Graph"])
def graph_incident(incident_id: int, db: DB):
    inc = get_or_404(db, Incident, incident_id, "Incident")
    return {"incident_id": inc.id, "ref": inc.ref, **attack_graph.analyze(db, inc.hostnames)}


@router.get("/twin/playbooks", tags=["Digital Twin"])
def twin_playbooks():
    return knowledge.playbooks()


@router.post("/twin/simulate", tags=["Digital Twin"])
def twin_simulate(body: TwinRequest, db: DB):
    idx = knowledge.playbook_index()
    ids = body.playbooks or list(idx)
    unknown = [p for p in ids if p not in idx]
    if unknown:
        raise HTTPException(422, f"Unknown playbooks: {', '.join(unknown)}")
    g = attack_graph.build_graph(db)
    hosts = [h.strip().upper() for h in body.entry_hostnames]
    return simulate(g, hosts, [idx[p] for p in ids], runs=body.runs, seed=body.seed)


@router.get("/risk/overview", tags=["Risk"])
def risk_overview(db: DB):
    return risk_engine.enterprise_risk(db)


@router.get("/risk/trends", tags=["Risk"])
def risk_trends(db: DB, days: int = Query(14, ge=1, le=90)):
    return risk_engine.trends(db, days)


# ------------------------------------------------------------------ demo (synthetic data)
@router.get("/demo/scenarios", tags=["Demo"])
def demo_scenarios():
    return demo.list_scenarios()


@router.post("/demo/setup", tags=["Demo"])
def demo_setup(db: DB, actor: CurrentActor):
    """Load the fictional 'Meridian Energy' asset inventory and 7 days of benign baseline telemetry."""
    assets = demo.load_assets(db)
    base = demo.load_baseline(db)
    audit.record(db, actor, "demo.setup", "demo", None,
                 {"assets_added": assets, "baseline_events": len(base.accepted)}, commit=True)
    return {"assets_added": assets, "baseline_events_added": len(base.accepted),
            "note": "All demo data is synthetic."}


@router.post("/demo/run", tags=["Demo"])
def demo_run(body: ScenarioRun, db: DB, actor: CurrentActor):
    try:
        events = demo.scenario_events(body.scenario)
    except FileNotFoundError:
        raise HTTPException(404, "Unknown scenario") from None
    out = ingest_many(db, events)
    analyzed = run_analyses(db, out.incidents)
    audit.record(db, actor, "demo.run", "demo", body.scenario,
                 {"events": len(out.accepted), "incidents": sorted(out.incidents)}, commit=True)
    return {"scenario": body.scenario, "events_ingested": len(out.accepted), "duplicates": out.duplicates,
            "incidents": sorted(out.incidents), "incidents_analyzed": analyzed}


@router.post("/demo/reset", tags=["Demo"])
def demo_reset(db: DB, actor: CurrentActor, confirm: str = Query(..., description="Must be 'RESET'")):
    """Delete events, incidents, decisions and actions. Assets, intel and the audit log are preserved."""
    if get_settings().app_env == "production":
        raise HTTPException(403, "Reset is disabled in production")
    if confirm != "RESET":
        raise HTTPException(400, "Pass confirm=RESET to delete operational data")
    counts = {}
    for model in (ResponseAction, CouncilDecision, AgentRun, IncidentNote, SecurityEvent, Incident):
        counts[model.__tablename__] = db.execute(delete(model)).rowcount
    forest_cache.reset()
    audit.record(db, actor, "demo.reset", "demo", None, counts)
    db.commit()
    return {"deleted": counts}
