from __future__ import annotations

import ipaddress
from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

from sentrix.schemas.common import ORMModel, Severity

SourceFormat = Literal["generic", "windows", "sysmon", "syslog", "firewall", "edr", "cloud"]


def _ip(v: str | None) -> str | None:
    if v in (None, ""):
        return None
    try:
        return str(ipaddress.ip_address(str(v).strip()))
    except ValueError as exc:
        raise ValueError(f"invalid IP address: {v}") from exc


class EventIngest(BaseModel):
    """A single security event submitted for ingestion.

    Either supply normalized fields directly (``event_type``, ``hostname`` ...)
    or provide a vendor payload in ``raw`` with a matching ``format`` - the
    normalizer will extract the fields. Explicit fields always win.
    """

    format: SourceFormat = "generic"
    source: str = Field("api", min_length=1, max_length=64)
    timestamp: datetime | None = None
    event_type: str | None = Field(None, max_length=100)
    severity: Severity | None = None
    hostname: str | None = Field(None, max_length=100)
    user: str | None = Field(None, max_length=100)
    src_ip: str | None = None
    dst_ip: str | None = None
    dst_port: int | None = Field(None, ge=0, le=65535)
    process: str | None = Field(None, max_length=255)
    command_line: str | None = Field(None, max_length=8192)
    description: str | None = Field(None, max_length=4000)
    raw: dict[str, Any] | None = None

    _src = field_validator("src_ip")(lambda cls, v: _ip(v))
    _dst = field_validator("dst_ip")(lambda cls, v: _ip(v))

    @model_validator(mode="after")
    def _has_content(self) -> EventIngest:
        if not (self.event_type or self.raw or self.description):
            raise ValueError("an event needs at least one of: event_type, description, raw")
        return self


class EventBatch(BaseModel):
    events: list[EventIngest] = Field(..., min_length=1, max_length=1000)
    analyze: bool = Field(True, description="Run multi-agent analysis on affected incidents")


class EventOut(ORMModel):
    id: int
    timestamp: datetime
    received_at: datetime
    source: str
    source_format: str
    event_type: str
    category: str
    severity: str
    hostname: str | None
    user: str | None
    src_ip: str | None
    dst_ip: str | None
    dst_port: int | None
    process: str | None
    command_line: str | None
    description: str
    mitre_technique: str | None
    mitre_tactic: str | None
    classification: dict[str, Any] | None
    anomaly_score: float
    anomaly_details: dict[str, Any] | None
    threat_score: float
    incident_id: int | None
    asset_id: int | None


class IngestResult(BaseModel):
    accepted: int
    duplicates: int
    rejected: int
    errors: list[dict[str, Any]]
    event_ids: list[int]
    incidents_touched: list[int]
    incidents_analyzed: list[int]
