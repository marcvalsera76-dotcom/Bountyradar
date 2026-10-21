"""Tests de fuentes pasivas (crt.sh, Wayback) sin red (fetcher falso)."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import Platform, Program
from app.recon.passive import PassiveReconService
from app.recon.sources import CrtShSource, WaybackSource, parse_crtsh, parse_wayback
from app.services.scope_import import import_scope


def test_parse_crtsh_extracts_and_dedupes():
    data = [
        {"name_value": "api.acme.com\n*.acme.com"},
        {"name_value": "api.acme.com"},
        {"name_value": "www.other.com"},  # fuera de dominio
    ]
    assert parse_crtsh(data, "acme.com") == ["acme.com", "api.acme.com"]


def test_parse_crtsh_ignores_invalid():
    data = [{"name_value": "no válido"}, {"name_value": "ok.acme.com"}]
    assert parse_crtsh(data, "acme.com") == ["ok.acme.com"]


def test_parse_wayback_extracts_hosts():
    rows = [
        ["original"],
        ["https://api.acme.com/path"],
        ["http://shop.acme.com/x?y=1"],
        ["https://evil.com/"],  # fuera de dominio
    ]
    assert parse_wayback(rows, "acme.com") == ["api.acme.com", "shop.acme.com"]


def test_crtsh_source_with_fake_fetcher():
    src = CrtShSource(fetcher=lambda url: [{"name_value": "a.acme.com\nb.acme.com"}])
    assert src.hosts("acme.com") == ["a.acme.com", "b.acme.com"]


def test_wayback_source_with_fake_fetcher():
    rows = [["original"], ["https://a.acme.com/"]]
    src = WaybackSource(fetcher=lambda url: rows)
    assert src.hosts("acme.com") == ["a.acme.com"]


def test_source_handles_non_list_response():
    src = CrtShSource(fetcher=lambda url: {"error": "rate limited"})
    assert src.hosts("acme.com") == []


@pytest.fixture()
def session():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    with Session(engine) as s:
        yield s
    engine.dispose()


def test_ingest_from_source_classifies(session):
    p = Program(name="Acme", platform=Platform.HACKERONE, external_program_id="acme")
    session.add(p)
    session.flush()
    import_scope(session, p, in_scope=["*.acme.com"], out_of_scope=["admin.acme.com"])

    src = CrtShSource(fetcher=lambda url: [{"name_value": "api.acme.com\nadmin.acme.com"}])
    res = PassiveReconService(session).ingest_from_source(p, src, "acme.com")
    assert res.source == "crt.sh"
    assert res.in_scope == ["api.acme.com"]
    assert res.out_of_scope == ["admin.acme.com"]
