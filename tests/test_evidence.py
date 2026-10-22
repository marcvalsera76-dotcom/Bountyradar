"""Tests del EvidenceRecorder: redacción, hashes e integridad."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import Platform, Program, VulnerabilityCandidate
from app.services.evidence import EvidenceRecorder, redact_headers, sha256_text


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    engine.dispose()


@pytest.fixture()
def finding(session):
    p = Program(name="Acme", platform=Platform.HACKERONE, external_program_id="acme")
    session.add(p)
    session.flush()
    c = VulnerabilityCandidate(program_id=p.id, title="IDOR")
    session.add(c)
    session.flush()
    return c


def test_redact_hides_sensitive_headers():
    out = redact_headers({"Authorization": "Bearer x", "Accept": "*/*", "Cookie": "s=1"})
    assert out["Authorization"] == "[REDACTED]"
    assert out["Cookie"] == "[REDACTED]"
    assert out["Accept"] == "*/*"


def test_sha256_is_deterministic():
    assert sha256_text("abc") == sha256_text("abc")
    assert sha256_text("abc") != sha256_text("abd")


def test_record_stores_redacted_and_hashes(session, finding):
    ev = EvidenceRecorder(session).record(
        finding.id,
        request_method="GET",
        request_url="https://api.acme.com/invoices/2",
        request_headers={"Authorization": "Bearer secret", "Accept": "*/*"},
        response_status=200,
        response_body="datos ajenos",
        tool_name="httpx",
        tool_version="1.0",
    )
    assert "Bearer secret" not in (ev.request_headers_redacted or "")
    assert "[REDACTED]" in ev.request_headers_redacted
    assert ev.response_body_sha256 == sha256_text("datos ajenos")
    assert ev.integrity_hash


def test_verify_detects_tampering(session, finding):
    rec = EvidenceRecorder(session)
    ev = rec.record(finding.id, request_method="GET", response_status=200, response_body="x")
    assert EvidenceRecorder.verify(ev) is True
    ev.response_status = 500  # manipulación
    assert EvidenceRecorder.verify(ev) is False


def test_retention_until_set(session, finding):
    ev = EvidenceRecorder(session, retention_days=30).record(finding.id)
    assert ev.retention_until is not None


def test_retention_none_when_disabled(session, finding):
    ev = EvidenceRecorder(session, retention_days=None).record(finding.id)
    assert ev.retention_until is None
