"""Modelos SQLAlchemy 2.x (núcleo del Hito 3).

Subconjunto central del modelo de datos del spec v3.4: Program, Asset,
Endpoint, VulnerabilityCandidate, Task y AuditEvent. Otros (Evidence, PoC,
ExploitChain) se añadirán en hitos posteriores.
"""

from __future__ import annotations

from datetime import UTC, datetime
from enum import StrEnum

from sqlalchemy import (
    Boolean,
    DateTime,
    Enum,
    ForeignKey,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.db.base import Base


def _utcnow() -> datetime:
    return datetime.now(UTC)


class Platform(StrEnum):
    HACKERONE = "HACKERONE"
    BUGCROWD = "BUGCROWD"
    INTIGRITI = "INTIGRITI"
    PRIVATE = "PRIVATE"


class ScanMode(StrEnum):
    PASSIVE = "PASSIVE"
    SAFE_ACTIVE = "SAFE_ACTIVE"
    FULL_ACTIVE = "FULL_ACTIVE"
    EXPLOIT_HUNT = "EXPLOIT_HUNT"


class ScopeStatus(StrEnum):
    IN_SCOPE = "IN_SCOPE"
    OUT_OF_SCOPE = "OUT_OF_SCOPE"
    UNKNOWN = "UNKNOWN"


class TriageStatus(StrEnum):
    NEW = "NEW"
    IN_REVIEW = "IN_REVIEW"
    CONFIRMED = "CONFIRMED"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    REPORTED = "REPORTED"


class Exploitability(StrEnum):
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"


class TaskStatus(StrEnum):
    PENDING = "PENDING"
    APPROVED = "APPROVED"
    RUNNING = "RUNNING"
    FINISHED = "FINISHED"
    CANCELLED = "CANCELLED"
    FAILED = "FAILED"


class Program(Base):
    __tablename__ = "program"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    name: Mapped[str] = mapped_column(String(255))
    platform: Mapped[Platform] = mapped_column(Enum(Platform, native_enum=False))
    external_program_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    scope_version: Mapped[int] = mapped_column(Integer, default=1)
    scan_mode: Mapped[ScanMode] = mapped_column(
        Enum(ScanMode, native_enum=False), default=ScanMode.PASSIVE
    )
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    exploit_hunt_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    autopilot_enabled: Mapped[bool] = mapped_column(Boolean, default=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    assets: Mapped[list[Asset]] = relationship(
        back_populates="program", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("platform", "external_program_id"),)


class ScopeRule(Base):
    __tablename__ = "scope_rule"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("program.id"), index=True)
    kind: Mapped[str] = mapped_column(String(8))  # 'in' | 'out'
    pattern: Mapped[str] = mapped_column(String(512))
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    __table_args__ = (UniqueConstraint("program_id", "kind", "pattern"),)


class Asset(Base):
    __tablename__ = "asset"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("program.id"), index=True)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    ip_address: Mapped[str | None] = mapped_column(String(64), nullable=True)
    asset_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    source: Mapped[str | None] = mapped_column(String(128), nullable=True)
    scope_status: Mapped[ScopeStatus] = mapped_column(
        Enum(ScopeStatus, native_enum=False), default=ScopeStatus.UNKNOWN
    )
    scope_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    waf_detected: Mapped[bool] = mapped_column(Boolean, default=False)
    discovered_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    program: Mapped[Program] = relationship(back_populates="assets")
    endpoints: Mapped[list[Endpoint]] = relationship(
        back_populates="asset", cascade="all, delete-orphan"
    )

    __table_args__ = (UniqueConstraint("program_id", "hostname"),)


class Endpoint(Base):
    __tablename__ = "endpoint"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    asset_id: Mapped[int] = mapped_column(ForeignKey("asset.id"), index=True)
    url: Mapped[str] = mapped_column(String(2048))
    scheme: Mapped[str | None] = mapped_column(String(16), nullable=True)
    host: Mapped[str | None] = mapped_column(String(255), nullable=True)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status_code: Mapped[int | None] = mapped_column(Integer, nullable=True)
    content_type: Mapped[str | None] = mapped_column(String(128), nullable=True)
    technology_stack: Mapped[str | None] = mapped_column(Text, nullable=True)
    first_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    last_seen_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)

    asset: Mapped[Asset] = relationship(back_populates="endpoints")


class VulnerabilityCandidate(Base):
    __tablename__ = "vulnerability_candidate"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("program.id"), index=True)
    asset_id: Mapped[int | None] = mapped_column(ForeignKey("asset.id"), nullable=True)
    endpoint_id: Mapped[int | None] = mapped_column(ForeignKey("endpoint.id"), nullable=True)
    title: Mapped[str] = mapped_column(String(512))
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    vuln_type: Mapped[str | None] = mapped_column(String(64), nullable=True)
    dedup_key: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    location_key: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    severity: Mapped[str | None] = mapped_column(String(32), nullable=True)
    confidence: Mapped[int] = mapped_column(Integer, default=0)
    exploitability: Mapped[Exploitability] = mapped_column(
        Enum(Exploitability, native_enum=False), default=Exploitability.LOW
    )
    poc_available: Mapped[bool] = mapped_column(Boolean, default=False)
    triage_status: Mapped[TriageStatus] = mapped_column(
        Enum(TriageStatus, native_enum=False), default=TriageStatus.NEW
    )
    triage_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    reproduction_steps: Mapped[str | None] = mapped_column(Text, nullable=True)
    impact: Mapped[str | None] = mapped_column(Text, nullable=True)
    seen_count: Mapped[int] = mapped_column(Integer, default=1)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=_utcnow, onupdate=_utcnow
    )

    __table_args__ = (UniqueConstraint("program_id", "dedup_key"),)


class Task(Base):
    __tablename__ = "task"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    program_id: Mapped[int] = mapped_column(ForeignKey("program.id"), index=True)
    mode: Mapped[ScanMode] = mapped_column(Enum(ScanMode, native_enum=False))
    operation: Mapped[str] = mapped_column(String(128))
    status: Mapped[TaskStatus] = mapped_column(
        Enum(TaskStatus, native_enum=False), default=TaskStatus.PENDING
    )
    pipeline_step: Mapped[str | None] = mapped_column(String(64), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    approved_by: Mapped[str | None] = mapped_column(String(128), nullable=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)


class Evidence(Base):
    __tablename__ = "evidence"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    finding_id: Mapped[int] = mapped_column(
        ForeignKey("vulnerability_candidate.id"), index=True
    )
    request_method: Mapped[str | None] = mapped_column(String(16), nullable=True)
    request_url: Mapped[str | None] = mapped_column(String(2048), nullable=True)
    request_headers_redacted: Mapped[str | None] = mapped_column(Text, nullable=True)
    response_status: Mapped[int | None] = mapped_column(Integer, nullable=True)
    response_body_sha256: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_name: Mapped[str | None] = mapped_column(String(64), nullable=True)
    tool_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    observed_at_utc: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
    integrity_hash: Mapped[str] = mapped_column(String(64))
    retention_until: Mapped[datetime | None] = mapped_column(
        DateTime(timezone=True), nullable=True
    )


class AuditEvent(Base):
    __tablename__ = "audit_event"

    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    actor: Mapped[str] = mapped_column(String(128))
    operation: Mapped[str] = mapped_column(String(128))
    destination: Mapped[str | None] = mapped_column(String(512), nullable=True)
    scope_decision: Mapped[str | None] = mapped_column(String(32), nullable=True)
    policy_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    correlation_id: Mapped[str | None] = mapped_column(String(64), index=True, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=_utcnow)
