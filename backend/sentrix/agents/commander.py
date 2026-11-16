"""Commander: orchestrates the multi-agent analysis of an incident.

    Observer -> Behavior -> Oracle -> Sentinel -> Intel -> GraphAI
             -> DigitalTwin -> Risk -> Business
             -> AI Council (weighted consensus)
             -> Explainable AI
             -> Narrator (optional LLM)
             -> Response proposals (human approval required)

Every agent run is persisted (``agent_runs``) with timing, method and
output, so analysts can audit exactly how a decision was reached. A failing
agent is recorded and skipped; the council deliberates with the remaining
voters.
"""

from __future__ import annotations

import time
import traceback
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from sentrix.agents.base import AgentOutput, AnalysisContext
from sentrix.agents.narrator import narrate
from sentrix.agents.specialists import PIPELINE
from sentrix.core.config import get_settings
from sentrix.core.logging import get_logger
from sentrix.core.realtime import hub
from sentrix.council.consensus import deliberate
from sentrix.db.models import AgentRun, Asset, CouncilDecision, Incident, SecurityEvent, utcnow
from sentrix.graph.attack_graph import build_graph
from sentrix.intel.knowledge import playbook_index, playbooks
from sentrix.response import actions as response
from sentrix.risk.risk_engine import enterprise_risk

log = get_logger("commander")


def candidate_playbooks(events: list[SecurityEvent], category: str) -> list[dict[str, Any]]:
    cats = {category} | {e.category for e in events if e.threat_score >= 30}
    out = [p for p in playbooks() if "*" in p["categories"] or set(p["categories"]) & cats]
    if len(out) < 3:
        idx = playbook_index()
        for pid in ("PB-ISOLATE", "PB-CRED", "PB-SEGMENT"):
            if idx[pid] not in out:
                out.append(idx[pid])
            if len(out) >= 3:
                break
    return out


def analyze_incident(db: Session, incident_id: int, use_llm: bool = True) -> dict[str, Any]:
    incident = db.get(Incident, incident_id)
    if incident is None:
        raise ValueError(f"incident {incident_id} not found")
    events = list(db.scalars(
        select(SecurityEvent).where(SecurityEvent.incident_id == incident.id).order_by(SecurityEvent.timestamp)
    ))
    assets = {a.hostname: a for a in db.scalars(select(Asset))}
    version = incident.analysis_version + 1
    ctx = AnalysisContext(
        db=db, incident=incident, events=events, assets=assets,
        candidates=candidate_playbooks(events, incident.category),
        graph=build_graph(db), use_llm=use_llm,
    )
    hub.publish("analysis_started", {"incident_id": incident.id, "ref": incident.ref})

    runs: list[dict[str, Any]] = []
    for agent in PIPELINE:
        started = utcnow()
        t0 = time.perf_counter()
        try:
            out: AgentOutput = agent.run(ctx)
            ctx.results[agent.name] = out
            status, err = "success", None
        except Exception as exc:  # isolate agent failures
            log.error("agent %s failed on %s: %s", agent.name, incident.ref, exc)
            log.debug(traceback.format_exc())
            out = AgentOutput(agent=agent.name, role=agent.role, method=agent.method, confidence=0.0,
                              summary=f"Agent failed: {type(exc).__name__}")
            status, err = "error", f"{type(exc).__name__}: {exc}"[:1000]
        ms = round((time.perf_counter() - t0) * 1000, 1)
        findings = dict(out.findings)
        findings.pop("graph", None)  # large; kept only in incident.analysis
        db.add(AgentRun(
            incident_id=incident.id, analysis_version=version, agent=agent.name, role=agent.role,
            method=agent.method, status=status, confidence=out.confidence, summary=out.summary,
            output={"findings": findings, "votes": out.votes}, error=err, duration_ms=ms, started_at=started,
        ))
        runs.append({"agent": agent.name, "status": status, "duration_ms": ms, "method": agent.method})
        hub.publish("agent_run", {"incident_id": incident.id, "agent": agent.name, "status": status,
                                  "summary": out.summary})

    settings = get_settings()
    council = deliberate(ctx.results, settings.council_weights, ctx.candidates)
    from sentrix.xai.explainer import explain  # local import keeps module graph acyclic

    xai = explain(ctx, council)
    narrative = narrate(ctx, council)
    db.add(AgentRun(
        incident_id=incident.id, analysis_version=version, agent="Narrator",
        role="LLM incident narrative (optional)", method="llm",
        status={"ok": "success", "error": "error"}.get(narrative["status"], "skipped"),
        confidence=0.0, summary=narrative.get("reason") or "LLM narrative generated",
        output={"provider": narrative.get("provider"), "model": narrative.get("model")},
        error=narrative.get("reason") if narrative["status"] == "error" else None,
        duration_ms=narrative.get("latency_ms", 0.0),
    ))

    decision = CouncilDecision(
        incident_id=incident.id, analysis_version=version,
        decided_playbook=council["decision"], decided_playbook_name=council["decision_name"],
        consensus_score=council["consensus_score"], agreement=council["agreement"],
        ranking=council["ranking"], votes=council["votes"], weights=council["weights"],
        dissent=council["dissent"], rationale=council["rationale"],
    )
    db.add(decision)
    db.flush()
    proposed = response.propose(db, incident, decision.id, playbook_index()[council["decision"]],
                                ctx.results["Observer"].findings if "Observer" in ctx.results else {})

    voting = [o for o in ctx.results.values() if o.votes]
    incident.confidence = round(
        sum(o.confidence for o in voting) / len(voting) * council["agreement"] ** 0.5, 3
    ) if voting else 0.0
    sentinel = ctx.results.get("Sentinel")
    incident.summary = " ".join(xai["narrative"][:2])
    incident.analysis = {
        "version": version,
        "analyzed_at": utcnow().isoformat(),
        "agents": {n: o.as_dict() for n, o in ctx.results.items()},
        "pipeline": runs,
        "candidates": [{"id": p["id"], "name": p["name"]} for p in ctx.candidates],
        "council": {**council, "decision_id": decision.id},
        "xai": xai,
        "llm": narrative,
        "verdict": sentinel.findings.get("verdict") if sentinel else None,
        "proposed_action_ids": [a.id for a in proposed],
    }
    incident.analysis_version = version
    incident.analyzed_at = utcnow()
    if incident.status == "open":
        incident.status = "investigating"
    db.commit()
    # Persist asset risk after commit so it reflects the updated incident
    enterprise_risk(db, persist=True)
    hub.publish("analysis_completed", {
        "incident_id": incident.id, "ref": incident.ref, "decision": council["decision_name"],
        "consensus": council["consensus_score"], "actions_proposed": len(proposed),
    })
    log.info("analysed %s v%d -> %s (%.2f)", incident.ref, version, council["decision"],
             council["consensus_score"])
    return incident.analysis
