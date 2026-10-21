"""Tests de FindingTriage: dedup, clasificación, severidad/confianza separadas."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import Exploitability, Platform, Program, TriageStatus
from app.services.triage import (
    FindingInput,
    FindingTriage,
    classify_exploitability,
    compute_confidence,
)


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


def _f(**kw) -> FindingInput:
    base = dict(host="api.acme.com", vuln_type="IDOR", title="IDOR en /api/invoices")
    base.update(kw)
    return FindingInput(**base)


# clasificación
def test_high_value_with_evidence_is_high():
    exp, _ = classify_exploitability("IDOR", has_evidence=True)
    assert exp is Exploitability.HIGH


def test_high_value_without_evidence_is_medium():
    exp, _ = classify_exploitability("SSRF", has_evidence=False)
    assert exp is Exploitability.MEDIUM


def test_low_value_always_low():
    exp, _ = classify_exploitability("MISSING_HEADER", has_evidence=True)
    assert exp is Exploitability.LOW


def test_unknown_type_is_low():
    exp, _ = classify_exploitability("WHATEVER", has_evidence=True)
    assert exp is Exploitability.LOW


# confianza separada de severidad
def test_confidence_scales_with_evidence():
    assert compute_confidence(False, False) == 20
    assert compute_confidence(True, False) == 60
    assert compute_confidence(True, True) == 90


# triaje
def test_triage_creates_new_candidate(session, program):
    res = FindingTriage(session).triage(program, _f(evidence_pattern="id=2 devuelve datos ajenos"))
    assert res.is_duplicate is False
    assert res.candidate.triage_status is TriageStatus.NEW
    assert res.candidate.exploitability is Exploitability.HIGH


def test_triage_dedup_exact(session, program):
    t = FindingTriage(session)
    t.triage(program, _f(evidence_pattern="x"))
    res2 = t.triage(program, _f(evidence_pattern="x"))
    assert res2.is_duplicate is True
    assert res2.dedup_probability == 1.0
    assert res2.candidate.seen_count == 2


def test_triage_near_duplicate_probability(session, program):
    t = FindingTriage(session)
    t.triage(program, _f(evidence_pattern="evidencia A"))
    res2 = t.triage(program, _f(evidence_pattern="evidencia B"))  # misma ubicación
    assert res2.is_duplicate is False
    assert res2.dedup_probability == 0.7


def test_triage_never_auto_confirms(session, program):
    res = FindingTriage(session).triage(program, _f(poc_available=True, evidence_pattern="poc"))
    assert res.candidate.triage_status is TriageStatus.NEW


def test_triage_low_value_finding_is_observation(session, program):
    res = FindingTriage(session).triage(
        program, _f(vuln_type="MISSING_HEADER", title="Falta CSP", evidence_pattern="")
    )
    assert res.candidate.exploitability is Exploitability.LOW
