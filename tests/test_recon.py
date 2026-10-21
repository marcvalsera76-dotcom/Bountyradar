"""Tests del recon pasivo por archivo (sin red)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.core.audit import AuditLogger
from app.db.base import Base
from app.db.models import Platform, Program, Task, TaskStatus
from app.recon.passive import PassiveReconService, normalize_hosts
from app.services.scope_import import import_scope


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
    import_scope(session, p, in_scope=["*.acme.com"], out_of_scope=["admin.acme.com"])
    return p


# --------------------------------------------------------------------------- #
# normalize_hosts
# --------------------------------------------------------------------------- #


def test_normalize_dedupes_and_sorts():
    valid, invalid = normalize_hosts(["b.acme.com", "a.acme.com", "A.ACME.COM"])
    assert valid == ["a.acme.com", "b.acme.com"]
    assert invalid == []


def test_normalize_ignores_blank_and_comments():
    valid, invalid = normalize_hosts(["", "  ", "# comentario", "api.acme.com"])
    assert valid == ["api.acme.com"]


def test_normalize_collects_invalid():
    valid, invalid = normalize_hosts(["api.acme.com", "no válido", "user:pass@x.com"])
    assert "api.acme.com" in valid
    assert len(invalid) == 2


def test_normalize_extracts_host_from_url():
    valid, _ = normalize_hosts(["https://api.acme.com/path"])
    assert valid == ["api.acme.com"]


# --------------------------------------------------------------------------- #
# PassiveReconService
# --------------------------------------------------------------------------- #


def test_ingest_classifies_hosts(session, program):
    svc = PassiveReconService(session)
    res = svc.ingest_hosts(
        program,
        ["api.acme.com", "admin.acme.com", "evil.com"],
        source="subfinder",
    )
    assert res.in_scope == ["api.acme.com"]
    assert set(res.out_of_scope) == {"admin.acme.com", "evil.com"}
    assert res.new_assets == 3


def test_ingest_creates_finished_task(session, program):
    svc = PassiveReconService(session)
    res = svc.ingest_hosts(program, ["api.acme.com"])
    task = session.get(Task, res.task_id)
    assert task is not None
    assert task.status is TaskStatus.FINISHED
    assert task.operation == "recon.passive"
    assert task.finished_at is not None


def test_ingest_second_run_updates_not_duplicates(session, program):
    svc = PassiveReconService(session)
    svc.ingest_hosts(program, ["api.acme.com"])
    res2 = svc.ingest_hosts(program, ["api.acme.com", "new.acme.com"])
    assert res2.new_assets == 1
    assert res2.updated_assets == 1


def test_ingest_records_audit(session, program):
    audit = AuditLogger()
    svc = PassiveReconService(session, audit=audit)
    svc.ingest_hosts(program, ["api.acme.com", "admin.acme.com"])
    assert len(audit.by_decision("ALLOW")) == 1
    assert len(audit.by_decision("DENY")) == 1


def test_ingest_reports_invalid(session, program):
    svc = PassiveReconService(session)
    res = svc.ingest_hosts(program, ["api.acme.com", "no válido"])
    assert len(res.invalid) == 1
    assert res.new_assets == 1
