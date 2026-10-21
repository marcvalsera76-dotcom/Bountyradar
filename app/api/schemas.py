"""Esquemas Pydantic v2 de entrada/salida de la API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import Exploitability, Platform, ScopeStatus, TriageStatus


class ProgramCreate(BaseModel):
    name: str = Field(min_length=1, max_length=255)
    platform: Platform
    external_program_id: str | None = Field(default=None, max_length=255)


class ProgramOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    name: str
    platform: Platform
    external_program_id: str | None
    scope_version: int
    is_active: bool


class ScopeImportIn(BaseModel):
    in_scope: list[str] = Field(default_factory=list)
    out_of_scope: list[str] = Field(default_factory=list)


class ScopeImportOut(BaseModel):
    added: list[str]
    skipped: list[str]
    rejected: list[tuple[str, str]]
    scope_version: int


class AssetIn(BaseModel):
    hostname: str = Field(min_length=1, max_length=255)
    source: str | None = Field(default=None, max_length=128)


class AssetOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    hostname: str
    scope_status: ScopeStatus
    scope_reason: str | None
    source: str | None
    last_seen_at: datetime


class ReconImportIn(BaseModel):
    hosts: list[str] = Field(default_factory=list)
    source: str = Field(default="import", max_length=128)


class ReconImportOut(BaseModel):
    source: str
    total_lines: int
    new_assets: int
    updated_assets: int
    in_scope: list[str]
    out_of_scope: list[str]
    invalid: list[tuple[str, str]]
    task_id: int | None


class FindingIn(BaseModel):
    host: str = Field(min_length=1, max_length=255)
    vuln_type: str = Field(min_length=1, max_length=64)
    title: str = Field(min_length=1, max_length=512)
    path: str = Field(default="/", max_length=2048)
    evidence_pattern: str = Field(default="", max_length=512)
    severity: str | None = Field(default=None, max_length=32)
    poc_available: bool = False


class CandidateOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: int
    title: str
    vuln_type: str | None
    severity: str | None
    confidence: int
    exploitability: Exploitability
    poc_available: bool
    triage_status: TriageStatus
    triage_reason: str | None
    seen_count: int


class TriageOut(BaseModel):
    candidate: CandidateOut
    is_duplicate: bool
    dedup_probability: float
    reason: str
