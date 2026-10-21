"""Tests de ReportGenerator y quality gate."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import (
    Exploitability,
    Platform,
    Program,
    TriageStatus,
    VulnerabilityCandidate,
)
from app.services.report import check_quality, generate_report


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    engine.dispose()


@pytest.fixture()
def program(session):
    p = Program(name="Acme", platform=Platform.HACKERONE, external_program_id="acme")
    session.add(p)
    session.flush()
    return p


def _candidate(program, **kw) -> VulnerabilityCandidate:
    base = dict(
        program_id=program.id,
        title="IDOR en /api/invoices",
        vuln_type="IDOR",
        exploitability=Exploitability.HIGH,
        confidence=60,
    )
    base.update(kw)
    return VulnerabilityCandidate(**base)


def test_quality_fails_when_incomplete(session, program):
    c = _candidate(program)
    session.add(c)
    session.flush()
    q = check_quality(c)
    assert q.ready is False
    assert "severity" in q.missing
    assert "reproduction_steps" in q.missing


def test_quality_passes_when_complete(session, program):
    c = _candidate(
        program,
        severity="HIGH",
        reproduction_steps="1. login A 2. GET /api/invoices/2",
        impact="Acceso a facturas ajenas",
        poc_available=True,
        confidence=80,
    )
    session.add(c)
    session.flush()
    q = check_quality(c)
    assert q.ready is True
    assert q.missing == []


def test_report_marks_draft_when_incomplete(session, program):
    c = _candidate(program)
    session.add(c)
    session.flush()
    md = generate_report(c, program.name)
    assert "BORRADOR" in md
    assert "No enviar" in md


def test_report_marks_ready_when_complete(session, program):
    c = _candidate(
        program,
        severity="HIGH",
        reproduction_steps="pasos",
        impact="impacto",
        poc_available=True,
        confidence=80,
    )
    session.add(c)
    session.flush()
    md = generate_report(c, program.name)
    assert "listo para revisar" in md
    assert "# IDOR en /api/invoices" in md


def test_report_includes_core_sections(session, program):
    c = _candidate(program, severity="HIGH")
    session.add(c)
    session.flush()
    md = generate_report(c, program.name)
    for section in ("## Resumen", "## Pasos de reproducción", "## Impacto", "## Limitaciones"):
        assert section in md


def test_report_notes_reported_status(session, program):
    c = _candidate(
        program,
        severity="HIGH",
        reproduction_steps="x",
        impact="y",
        poc_available=True,
        confidence=80,
        triage_status=TriageStatus.REPORTED,
    )
    session.add(c)
    session.flush()
    md = generate_report(c, program.name)
    assert "decisión humana" in md
