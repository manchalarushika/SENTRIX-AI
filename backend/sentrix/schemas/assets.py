from __future__ import annotations

import ipaddress
import re
from datetime import datetime

from pydantic import BaseModel, Field, field_validator

from sentrix.schemas.common import Criticality, ORMModel

HOSTNAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._\-]{0,99}$")


def _validate_hostname(v: str) -> str:
    v = v.strip()
    if not HOSTNAME_RE.match(v):
        raise ValueError("hostname may contain letters, digits, '.', '_' and '-' only")
    return v.upper()


def _validate_ip(v: str | None) -> str | None:
    if v in (None, ""):
        return None
    return str(ipaddress.ip_address(v.strip()))


class AssetBase(BaseModel):
    hostname: str = Field(..., min_length=1, max_length=100)
    ip_address: str | None = None
    operating_system: str = Field("Unknown", max_length=100)
    asset_type: str = Field("workstation", max_length=64)
    department: str = Field("General", max_length=100)
    criticality: Criticality = Criticality.medium
    network_zone: str = Field("corporate", max_length=64)
    owner: str = Field("unassigned", max_length=100)
    internet_facing: bool = False
    business_value_per_hour: float = Field(1000.0, ge=0, le=10_000_000)
    software: list[str] = Field(default_factory=list, max_length=50)
    connects_to: list[str] = Field(default_factory=list, max_length=100)

    _h = field_validator("hostname")(lambda cls, v: _validate_hostname(v))
    _ip = field_validator("ip_address")(lambda cls, v: _validate_ip(v))

    @field_validator("connects_to")
    @classmethod
    def _links(cls, v: list[str]) -> list[str]:
        return sorted({_validate_hostname(h) for h in v})


class AssetCreate(AssetBase):
    pass


class AssetUpdate(BaseModel):
    ip_address: str | None = None
    operating_system: str | None = Field(None, max_length=100)
    asset_type: str | None = Field(None, max_length=64)
    department: str | None = Field(None, max_length=100)
    criticality: Criticality | None = None
    network_zone: str | None = Field(None, max_length=64)
    owner: str | None = Field(None, max_length=100)
    status: str | None = Field(None, max_length=32)
    internet_facing: bool | None = None
    business_value_per_hour: float | None = Field(None, ge=0, le=10_000_000)
    software: list[str] | None = None
    connects_to: list[str] | None = None

    _ip = field_validator("ip_address")(lambda cls, v: _validate_ip(v))

    @field_validator("connects_to")
    @classmethod
    def _links(cls, v: list[str] | None) -> list[str] | None:
        return None if v is None else sorted({_validate_hostname(h) for h in v})


class AssetOut(ORMModel):
    id: int
    hostname: str
    ip_address: str | None
    operating_system: str
    asset_type: str
    department: str
    criticality: str
    network_zone: str
    owner: str
    status: str
    internet_facing: bool
    business_value_per_hour: float
    software: list[str]
    connects_to: list[str]
    risk_score: float
    last_seen: datetime | None
    created_at: datetime
