"""Focus: detección temprana y panel "Dónde mirar hoy".

Resalta lo que merece atención ahora: activos in-scope descubiertos
recientemente (diffing entre ciclos por fecha de descubrimiento) y las
candidatas abiertas priorizadas por explotabilidad y confianza. Solo lectura.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime, timedelta

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import (
    Asset,
    Exploitability,
    Program,
    ScopeStatus,
    TriageStatus,
    VulnerabilityCandidate,
)

# Orden de prioridad de explotabilidad (mayor primero).
_EXP_RANK = {Exploitability.HIGH: 0, Exploitability.MEDIUM: 1, Exploitability.LOW: 2}


@dataclass
class FocusAsset:
    hostname: str
    discovered_at: datetime
    source: str | None


@dataclass
class FocusFinding:
    id: int
    title: str
    vuln_type: str | None
    exploitability: str
    confidence: int
    poc_available: bool


@dataclass
class FocusReport:
    program: str
    new_assets: list[FocusAsset] = field(default_factory=list)
    open_findings: list[FocusFinding] = field(default_factory=list)
    total_in_scope: int = 0
    total_open_findings: int = 0


def recently_discovered(
    session: Session, program: Program, *, hours: int = 24, now: datetime | None = None
) -> list[Asset]:
    """Activos IN_SCOPE descubiertos en las últimas `hours` horas."""
    now = now or datetime.now(UTC)
    cutoff = now - timedelta(hours=hours)
    rows = session.scalars(
        select(Asset)
        .where(
            Asset.program_id == program.id,
            Asset.scope_status == ScopeStatus.IN_SCOPE,
            Asset.discovered_at >= cutoff,
        )
        .order_by(Asset.discovered_at.desc())
    )
    return list(rows)


def open_findings(
    session: Session, program: Program, *, limit: int = 10
) -> list[VulnerabilityCandidate]:
    """Candidatas abiertas (NEW/IN_REVIEW) priorizadas por explotabilidad y confianza."""
    rows = list(
        session.scalars(
            select(VulnerabilityCandidate).where(
                VulnerabilityCandidate.program_id == program.id,
                VulnerabilityCandidate.triage_status.in_(
                    [TriageStatus.NEW, TriageStatus.IN_REVIEW]
                ),
            )
        )
    )
    rows.sort(key=lambda c: (_EXP_RANK.get(c.exploitability, 9), -c.confidence))
    return rows[:limit]


def where_to_look_today(
    session: Session, program: Program, *, hours: int = 24, now: datetime | None = None
) -> FocusReport:
    """Construye el panel 'Dónde mirar hoy'."""
    new_assets = recently_discovered(session, program, hours=hours, now=now)
    findings = open_findings(session, program)
    report = FocusReport(program=program.name)
    report.new_assets = [
        FocusAsset(hostname=a.hostname, discovered_at=a.discovered_at, source=a.source)
        for a in new_assets
    ]
    report.open_findings = [
        FocusFinding(
            id=c.id,
            title=c.title,
            vuln_type=c.vuln_type,
            exploitability=c.exploitability.value,
            confidence=c.confidence,
            poc_available=c.poc_available,
        )
        for c in findings
    ]
    report.total_in_scope = len(
        list(
            session.scalars(
                select(Asset.id).where(
                    Asset.program_id == program.id,
                    Asset.scope_status == ScopeStatus.IN_SCOPE,
                )
            )
        )
    )
    report.total_open_findings = len(
        list(
            session.scalars(
                select(VulnerabilityCandidate.id).where(
                    VulnerabilityCandidate.program_id == program.id,
                    VulnerabilityCandidate.triage_status.in_(
                        [TriageStatus.NEW, TriageStatus.IN_REVIEW]
                    ),
                )
            )
        )
    )
    return report
