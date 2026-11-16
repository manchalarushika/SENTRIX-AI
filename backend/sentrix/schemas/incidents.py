from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

from sentrix.schemas.common import IncidentStatus, ORMModel, Severity


class IncidentOut(ORMModel):
    id: int
    ref: str
    title: str
    status: str
    severity: str
    category: str
    risk_score: float
    confidence: float
    primary_hostname: str | None
    hostnames: list[str]
    users: list[str]
    tactics: list[str]
    techniques: list[str]
    event_count: int
    first_seen: datetime
    last_seen: datetime
    assignee: str | None
    summary: str
    analysis_version: int
    analyzed_at: datetime | None
    created_at: datetime
    updated_at: datetime


class NoteOut(ORMModel):
    id: int
    author: str
    body: str
    created_at: datetime


class IncidentDetail(IncidentOut):
    analysis: dict[str, Any] | None
    notes: list[NoteOut]


class IncidentUpdate(BaseModel):
    status: IncidentStatus | None = None
    severity: Severity | None = None
    assignee: str | None = Field(None, max_length=100)
    title: str | None = Field(None, min_length=3, max_length=255)


class NoteCreate(BaseModel):
    body: str = Field(..., min_length=1, max_length=5000)


class AnalyzeRequest(BaseModel):
    use_llm: bool = Field(True, description="Use the configured LLM for narrative analysis if available")


class ActionReview(BaseModel):
    decision: Literal["approve", "reject"]
    note: str | None = Field(None, max_length=2000)


class ResponseActionOut(ORMModel):
    id: int
    incident_id: int
    decision_id: int | None
    playbook: str
    action_type: str
    target: str
    description: str
    risk_level: str
    requires_approval: bool
    status: str
    requested_by: str
    reviewed_by: str | None
    reviewed_at: datetime | None
    review_note: str | None
    dispatch_result: dict[str, Any] | None
    created_at: datetime


class CouncilDecisionOut(ORMModel):
    id: int
    incident_id: int
    analysis_version: int
    decided_playbook: str
    decided_playbook_name: str
    consensus_score: float
    agreement: float
    ranking: list[dict[str, Any]]
    votes: list[dict[str, Any]]
    weights: dict[str, float]
    dissent: list[dict[str, Any]]
    rationale: str
    created_at: datetime


class AgentRunOut(ORMModel):
    id: int
    incident_id: int | None
    analysis_version: int
    agent: str
    role: str
    method: str
    status: str
    confidence: float
    summary: str
    output: dict[str, Any] | None
    error: str | None
    duration_ms: float
    started_at: datetime


class AuditOut(ORMModel):
    id: int
    timestamp: datetime
    actor: str
    ip: str | None
    action: str
    entity_type: str
    entity_id: str | None
    outcome: str
    details: dict[str, Any] | None
