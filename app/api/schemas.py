"""Esquemas Pydantic v2 de entrada/salida de la API."""

from __future__ import annotations

from datetime import datetime

from pydantic import BaseModel, ConfigDict, Field

from app.db.models import Platform, ScopeStatus


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
