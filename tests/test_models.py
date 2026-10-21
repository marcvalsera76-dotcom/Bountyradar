"""Tests de modelos SQLAlchemy sobre SQLite en memoria."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import (
    Asset,
    Endpoint,
    Exploitability,
    Platform,
    Program,
    ScanMode,
    ScopeStatus,
    TriageStatus,
    VulnerabilityCandidate,
)


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    engine.dispose()


def _program(**kw) -> Program:
    defaults = dict(name="Acme", platform=Platform.HACKERONE, external_program_id="acme")
    defaults.update(kw)
    return Program(**defaults)


def test_create_program_defaults(session):
    p = _program()
    session.add(p)
    session.commit()
    assert p.id is not None
    assert p.scan_mode is ScanMode.PASSIVE
    assert p.is_active is True
    assert p.exploit_hunt_enabled is False
    assert p.created_at is not None


def test_program_asset_relationship(session):
    p = _program()
    p.assets.append(Asset(hostname="api.acme.com"))
    session.add(p)
    session.commit()
    assert p.assets[0].program_id == p.id
    assert p.assets[0].scope_status is ScopeStatus.UNKNOWN


def test_asset_endpoint_cascade_delete(session):
    p = _program()
    a = Asset(hostname="api.acme.com")
    a.endpoints.append(Endpoint(url="https://api.acme.com/v1/users"))
    p.assets.append(a)
    session.add(p)
    session.commit()
    assert session.query(Endpoint).count() == 1
    session.delete(a)
    session.commit()
    assert session.query(Endpoint).count() == 0


def test_unique_asset_per_program(session):
    p = _program()
    p.assets.append(Asset(hostname="dup.acme.com"))
    p.assets.append(Asset(hostname="dup.acme.com"))
    session.add(p)
    with pytest.raises(IntegrityError):
        session.commit()


def test_candidate_defaults(session):
    p = _program()
    session.add(p)
    session.commit()
    c = VulnerabilityCandidate(program_id=p.id, title="IDOR en /api/invoices")
    session.add(c)
    session.commit()
    assert c.triage_status is TriageStatus.NEW
    assert c.exploitability is Exploitability.LOW
    assert c.poc_available is False


def test_unique_program_platform_external_id(session):
    session.add(_program())
    session.commit()
    session.add(_program())
    with pytest.raises(IntegrityError):
        session.commit()
