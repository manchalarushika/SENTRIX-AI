from __future__ import annotations

from enum import StrEnum
from typing import Generic, TypeVar

from pydantic import BaseModel, ConfigDict

T = TypeVar("T")


class Severity(StrEnum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


SEVERITY_RANK = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


class Criticality(StrEnum):
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"


class IncidentStatus(StrEnum):
    open = "open"
    investigating = "investigating"
    contained = "contained"
    resolved = "resolved"
    false_positive = "false_positive"
    closed = "closed"


class ORMModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class Page(BaseModel, Generic[T]):
    items: list[T]
    total: int
    limit: int
    offset: int


class Message(BaseModel):
    message: str
