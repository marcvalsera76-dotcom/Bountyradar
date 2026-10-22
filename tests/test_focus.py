"""Tests del panel 'Dónde mirar hoy' (focus)."""

from datetime import UTC, datetime, timedelta

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import Asset, Platform, Program, ScopeStatus
from app.services.focus import open_findings, recently_discovered, where_to_look_today
from app.services.scope_import import import_scope
from app.services.triage import FindingInput, FindingTriage


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
    import_scope(session, p, in_scope=["*.acme.com"])
    return p


def _asset(program, host, status=ScopeStatus.IN_SCOPE, days_ago=0):
    ts = datetime.now(UTC) - timedelta(days=days_ago)
    return Asset(
        program_id=program.id,
        hostname=host,
        scope_status=status,
        discovered_at=ts,
        last_seen_at=ts,
    )


def test_recently_discovered_filters_by_window(session, program):
    session.add(_asset(program, "new.acme.com", days_ago=0))
    session.add(_asset(program, "old.acme.com", days_ago=5))
    session.flush()
    recent = recently_discovered(session, program, hours=24)
    assert [a.hostname for a in recent] == ["new.acme.com"]


def test_recently_discovered_excludes_out_of_scope(session, program):
    session.add(_asset(program, "bad.acme.com", status=ScopeStatus.OUT_OF_SCOPE, days_ago=0))
    session.flush()
    assert recently_discovered(session, program, hours=24) == []


def test_open_findings_sorted_by_exploitability(session, program):
    t = FindingTriage(session)
    t.triage(program, FindingInput(host="a.acme.com", vuln_type="MISSING_HEADER", title="low"))
    t.triage(
        program,
        FindingInput(host="b.acme.com", vuln_type="IDOR", title="high", evidence_pattern="ev"),
    )
    findings = open_findings(session, program)
    assert findings[0].title == "high"  # HIGH antes que LOW


def test_where_to_look_today_summary(session, program):
    session.add(_asset(program, "new.acme.com", days_ago=0))
    session.flush()
    FindingTriage(session).triage(
        program,
        FindingInput(host="a.acme.com", vuln_type="SSRF", title="ssrf", evidence_pattern="x"),
    )
    report = where_to_look_today(session, program, hours=24)
    assert report.program == "Acme"
    assert len(report.new_assets) == 1
    assert report.total_open_findings == 1
    assert report.open_findings[0].exploitability == "HIGH"
