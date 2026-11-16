"""SQLAlchemy ORM models for SENTRIX AI."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from sqlalchemy import (
    JSON,
    Boolean,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from sentrix.db.session import Base


def utcnow() -> datetime:
    return datetime.now(UTC).replace(tzinfo=None)


class User(Base):
    """SOC analyst account (preserved from AEGIS-X)."""

    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(100), unique=True, nullable=False)
    email: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    role: Mapped[str] = mapped_column(String(50), default="analyst")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Asset(Base):
    __tablename__ = "assets"

    id: Mapped[int] = mapped_column(primary_key=True)
    hostname: Mapped[str] = mapped_column(String(100), unique=True, nullable=False, index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), unique=True, nullable=True)
    operating_system: Mapped[str] = mapped_column(String(100), default="Unknown")
    asset_type: Mapped[str] = mapped_column(String(64), default="workstation")
    department: Mapped[str] = mapped_column(String(100), default="General")
    criticality: Mapped[str] = mapped_column(String(16), default="medium")
    network_zone: Mapped[str] = mapped_column(String(64), default="corporate")
    owner: Mapped[str] = mapped_column(String(100), default="unassigned")
    status: Mapped[str] = mapped_column(String(32), default="online")
    internet_facing: Mapped[bool] = mapped_column(Boolean, default=False)
    business_value_per_hour: Mapped[float] = mapped_column(Float, default=1000.0)
    software: Mapped[list[str]] = mapped_column(JSON, default=list)
    connects_to: Mapped[list[str]] = mapped_column(JSON, default=list)
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    last_seen: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class Incident(Base):
    __tablename__ = "incidents"

    id: Mapped[int] = mapped_column(primary_key=True)
    ref: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    title: Mapped[str] = mapped_column(String(255))
    title_locked: Mapped[bool] = mapped_column(Boolean, default=False)
    status: Mapped[str] = mapped_column(String(32), default="open", index=True)
    severity: Mapped[str] = mapped_column(String(16), default="medium", index=True)
    category: Mapped[str] = mapped_column(String(64), default="Suspicious Activity")
    risk_score: Mapped[float] = mapped_column(Float, default=0.0)
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    primary_hostname: Mapped[str | None] = mapped_column(String(100), nullable=True)
    hostnames: Mapped[list[str]] = mapped_column(JSON, default=list)
    users: Mapped[list[str]] = mapped_column(JSON, default=list)
    tactics: Mapped[list[str]] = mapped_column(JSON, default=list)
    techniques: Mapped[list[str]] = mapped_column(JSON, default=list)
    event_count: Mapped[int] = mapped_column(Integer, default=0)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    assignee: Mapped[str | None] = mapped_column(String(100), nullable=True)
    summary: Mapped[str] = mapped_column(Text, default="")
    analysis: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    analysis_version: Mapped[int] = mapped_column(Integer, default=0)
    analyzed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, onupdate=utcnow)

    events: Mapped[list[SecurityEvent]] = relationship(back_populates="incident")
    notes: Mapped[list[IncidentNote]] = relationship(
        back_populates="incident", cascade="all, delete-orphan", order_by="IncidentNote.id"
    )


class SecurityEvent(Base):
    __tablename__ = "security_events"
    __table_args__ = (Index("ix_events_host_time", "hostname", "timestamp"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, index=True)
    received_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    source: Mapped[str] = mapped_column(String(64))
    source_format: Mapped[str] = mapped_column(String(32), default="generic")
    event_type: Mapped[str] = mapped_column(String(100), index=True)
    category: Mapped[str] = mapped_column(String(64), default="Other")
    severity: Mapped[str] = mapped_column(String(16), default="info", index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("assets.id", ondelete="SET NULL"))
    hostname: Mapped[str | None] = mapped_column(String(100), nullable=True)
    user: Mapped[str | None] = mapped_column(String(100), nullable=True, index=True)
    src_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dst_port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    process: Mapped[str | None] = mapped_column(String(255), nullable=True)
    command_line: Mapped[str | None] = mapped_column(Text, nullable=True)
    description: Mapped[str] = mapped_column(Text, default="")
    raw: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    mitre_technique: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mitre_tactic: Mapped[str | None] = mapped_column(String(64), nullable=True)
    classification: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    anomaly_score: Mapped[float] = mapped_column(Float, default=0.0)
    anomaly_details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    threat_score: Mapped[float] = mapped_column(Float, default=0.0)
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="SET NULL"), index=True
    )

    incident: Mapped[Incident | None] = relationship(back_populates="events")


class IncidentNote(Base):
    __tablename__ = "incident_notes"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(ForeignKey("incidents.id", ondelete="CASCADE"))
    author: Mapped[str] = mapped_column(String(100))
    body: Mapped[str] = mapped_column(Text)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

    incident: Mapped[Incident] = relationship(back_populates="notes")


class AgentRun(Base):
    __tablename__ = "agent_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int | None] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    analysis_version: Mapped[int] = mapped_column(Integer, default=1)
    agent: Mapped[str] = mapped_column(String(64), index=True)
    role: Mapped[str] = mapped_column(String(255))
    method: Mapped[str] = mapped_column(String(32))
    status: Mapped[str] = mapped_column(String(16))
    confidence: Mapped[float] = mapped_column(Float, default=0.0)
    summary: Mapped[str] = mapped_column(Text, default="")
    output: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    duration_ms: Mapped[float] = mapped_column(Float, default=0.0)
    started_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class CouncilDecision(Base):
    __tablename__ = "council_decisions"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    analysis_version: Mapped[int] = mapped_column(Integer, default=1)
    decided_playbook: Mapped[str] = mapped_column(String(64))
    decided_playbook_name: Mapped[str] = mapped_column(String(128))
    consensus_score: Mapped[float] = mapped_column(Float)
    agreement: Mapped[float] = mapped_column(Float)
    ranking: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    votes: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    weights: Mapped[dict[str, float]] = mapped_column(JSON, default=dict)
    dissent: Mapped[list[dict[str, Any]]] = mapped_column(JSON, default=list)
    rationale: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)


class ResponseAction(Base):
    __tablename__ = "response_actions"

    id: Mapped[int] = mapped_column(primary_key=True)
    incident_id: Mapped[int] = mapped_column(
        ForeignKey("incidents.id", ondelete="CASCADE"), index=True
    )
    decision_id: Mapped[int | None] = mapped_column(
        ForeignKey("council_decisions.id", ondelete="SET NULL")
    )
    playbook: Mapped[str] = mapped_column(String(64))
    action_type: Mapped[str] = mapped_column(String(64))
    target: Mapped[str] = mapped_column(String(255))
    description: Mapped[str] = mapped_column(Text)
    risk_level: Mapped[str] = mapped_column(String(16))
    requires_approval: Mapped[bool] = mapped_column(Boolean, default=True)
    status: Mapped[str] = mapped_column(String(16), default="proposed", index=True)
    requested_by: Mapped[str] = mapped_column(String(100), default="SENTRIX Council")
    reviewed_by: Mapped[str | None] = mapped_column(String(100), nullable=True)
    reviewed_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    review_note: Mapped[str | None] = mapped_column(Text, nullable=True)
    dispatch_result: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)


class AuditLog(Base):
    __tablename__ = "audit_logs"

    id: Mapped[int] = mapped_column(primary_key=True)
    timestamp: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(100), index=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(64), index=True)
    entity_type: Mapped[str] = mapped_column(String(64), index=True)
    entity_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    outcome: Mapped[str] = mapped_column(String(16), default="success")
    details: Mapped[dict[str, Any] | None] = mapped_column(JSON, nullable=True)


class IntelDocument(Base):
    __tablename__ = "intel_documents"

    id: Mapped[int] = mapped_column(primary_key=True)
    doc_id: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    doc_type: Mapped[str] = mapped_column(String(32), index=True)
    title: Mapped[str] = mapped_column(String(255))
    body: Mapped[str] = mapped_column(Text)
    tags: Mapped[list[str]] = mapped_column(JSON, default=list)
    source: Mapped[str] = mapped_column(String(128), default="custom")
    url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
