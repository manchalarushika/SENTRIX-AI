from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, EmailStr, Field, field_validator

from sentrix.schemas.common import ORMModel


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=100, pattern=r"^[A-Za-z0-9_.\-]+$")
    email: EmailStr
    password: str = Field(..., min_length=10, max_length=128)
    role: str = Field("analyst", pattern=r"^(analyst|lead|admin|viewer)$")


class UserUpdate(BaseModel):
    email: EmailStr | None = None
    role: str | None = Field(None, pattern=r"^(analyst|lead|admin|viewer)$")
    password: str | None = Field(None, min_length=10, max_length=128)


class UserOut(ORMModel):
    id: int
    username: str
    email: str
    role: str
    created_at: datetime


class IntelDocCreate(BaseModel):
    doc_id: str = Field(..., min_length=2, max_length=64, pattern=r"^[A-Za-z0-9_.:\-]+$")
    doc_type: str = Field("custom", pattern=r"^(mitre_technique|cve|advisory|playbook|custom)$")
    title: str = Field(..., min_length=3, max_length=255)
    body: str = Field(..., min_length=10, max_length=20000)
    tags: list[str] = Field(default_factory=list, max_length=30)
    source: str = Field("custom", max_length=128)
    url: str | None = Field(None, max_length=512)

    @field_validator("url")
    @classmethod
    def _url(cls, v: str | None) -> str | None:
        if v and not v.startswith(("https://", "http://")):
            raise ValueError("url must start with http:// or https://")
        return v


class IntelDocOut(ORMModel):
    id: int
    doc_id: str
    doc_type: str
    title: str
    body: str
    tags: list[str]
    source: str
    url: str | None
    created_at: datetime


class IntelQuery(BaseModel):
    query: str = Field(..., min_length=2, max_length=1000)
    top_k: int = Field(5, ge=1, le=20)
    synthesize: bool = Field(False, description="Ask the configured LLM to synthesise an answer from retrieved docs")


class TwinRequest(BaseModel):
    entry_hostnames: list[str] = Field(..., min_length=1, max_length=20)
    playbooks: list[str] | None = None
    runs: int | None = Field(None, ge=50, le=5000)
    seed: int = Field(7, ge=0)


class ScenarioRun(BaseModel):
    scenario: str = Field(..., pattern=r"^[a-z0-9_]+$")
