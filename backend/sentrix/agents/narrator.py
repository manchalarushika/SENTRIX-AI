"""Narrator: optional LLM-generated incident analysis.

The LLM receives a compact, structured summary of the deterministic analysis
(never raw log payloads) and returns a narrative for analysts. Its output is
stored separately under ``analysis.llm`` and labelled as LLM-generated; it
has no influence on scores, council votes or response actions.
"""

from __future__ import annotations

import json
from typing import Any

from sentrix.agents.base import AnalysisContext
from sentrix.llm.client import LLMError, llm

SYSTEM = (
    "You are a senior SOC incident responder. You receive the structured output of deterministic "
    "detection engines and an AI council. Explain the incident for an analyst. Do not invent facts, "
    "hosts, users, IPs or CVEs that are not in the input. If something is uncertain, say so. "
    'Return JSON with keys: "executive_summary" (2-3 sentences), "attack_narrative" (string), '
    '"attacker_objective" (string), "recommended_next_steps" (array of strings, max 6), '
    '"open_questions" (array of strings, max 4).'
)


def narrate(ctx: AnalysisContext, council: dict[str, Any]) -> dict[str, Any]:
    if not ctx.use_llm:
        return {"status": "skipped", "reason": "LLM narrative not requested"}
    if not llm.available:
        return {"status": "disabled", "reason": "No LLM provider configured (see LLM_PROVIDER in .env)"}
    inc = ctx.incident
    payload = {
        "incident": {"ref": inc.ref, "category": inc.category, "severity": inc.severity,
                     "risk_score": inc.risk_score, "hosts": inc.hostnames, "users": inc.users,
                     "tactics": inc.tactics, "techniques": inc.techniques},
        "timeline": [
            {k: t[k] for k in ("timestamp", "event_type", "hostname", "user", "technique")}
            for t in ctx.results["Observer"].findings["timeline"][:25]
        ],
        "agents": {n: o.summary for n, o in ctx.results.items()},
        "council": {k: council[k] for k in ("decision_name", "consensus_score", "strength", "rationale")},
    }
    try:
        data, resp = llm.complete_json(SYSTEM, json.dumps(payload, default=str))
    except LLMError as exc:
        return {"status": "error", "reason": str(exc)}
    return {
        "status": "ok",
        "provider": resp.provider,
        "model": resp.model,
        "latency_ms": resp.latency_ms,
        "label": "LLM-generated narrative - verify against the evidence before acting",
        "content": {
            "executive_summary": str(data.get("executive_summary", ""))[:2000],
            "attack_narrative": str(data.get("attack_narrative", ""))[:4000],
            "attacker_objective": str(data.get("attacker_objective", ""))[:500],
            "recommended_next_steps": [str(s)[:400] for s in data.get("recommended_next_steps", [])][:6],
            "open_questions": [str(s)[:400] for s in data.get("open_questions", [])][:4],
        },
    }
