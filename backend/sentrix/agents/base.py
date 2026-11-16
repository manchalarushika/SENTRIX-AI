"""Multi-agent framework primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

import networkx as nx
from sqlalchemy.orm import Session

from sentrix.db.models import Asset, Incident, SecurityEvent

# How each agent arrives at its output - surfaced in the UI so analysts can
# distinguish deterministic algorithms, ML and LLM-generated content.
METHOD_DETERMINISTIC = "deterministic"
METHOD_ML = "machine-learning"
METHOD_SIMULATION = "simulation"
METHOD_RETRIEVAL = "retrieval"
METHOD_LLM = "llm"


@dataclass
class AgentOutput:
    agent: str
    role: str
    method: str
    confidence: float
    summary: str
    findings: dict[str, Any] = field(default_factory=dict)
    votes: dict[str, dict[str, Any]] | None = None  # playbook_id -> {score, reason}

    def as_dict(self) -> dict[str, Any]:
        return {
            "agent": self.agent,
            "role": self.role,
            "method": self.method,
            "confidence": round(self.confidence, 3),
            "summary": self.summary,
            "findings": self.findings,
            "votes": self.votes,
        }


@dataclass
class AnalysisContext:
    db: Session
    incident: Incident
    events: list[SecurityEvent]
    assets: dict[str, Asset]
    candidates: list[dict[str, Any]]
    graph: nx.DiGraph
    use_llm: bool = True
    results: dict[str, AgentOutput] = field(default_factory=dict)

    @property
    def candidate_ids(self) -> list[str]:
        return [p["id"] for p in self.candidates]


class Agent:
    name: str = "Agent"
    role: str = ""
    method: str = METHOD_DETERMINISTIC
    votes: bool = False

    def run(self, ctx: AnalysisContext) -> AgentOutput:  # pragma: no cover - interface
        raise NotImplementedError


def intensity_votes(
    ctx: AnalysisContext,
    target_intensity: float,
    focus_categories: list[str],
    reason: str,
    blend: float = 0.5,
) -> dict[str, dict[str, Any]]:
    """Score every candidate playbook by how well its aggressiveness matches the
    response intensity this agent believes is warranted, and how well its
    category coverage matches the agent's focus."""
    t = max(0.0, min(1.0, target_intensity))
    focus = set(focus_categories)
    out = {}
    for pb in ctx.candidates:
        fit = 1 - abs(pb["aggressiveness"] - t)
        cats = set(pb["categories"])
        if focus and cats & focus:
            affinity = 1.0
        elif "*" in cats:
            affinity = 0.6
        elif not focus:
            affinity = 0.7
        else:
            affinity = 0.3
        score = round(blend * fit + (1 - blend) * affinity, 4)
        out[pb["id"]] = {"score": score, "reason": reason}
    return out
