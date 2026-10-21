"""Tests de importación de scope e inventario de activos."""

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import Session

from app.db.base import Base
from app.db.models import Platform, Program, ScopeStatus
from app.services.inventory import AssetInventory, build_validator
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
    return p


# --------------------------------------------------------------------------- #
# import_scope
# --------------------------------------------------------------------------- #


def test_import_adds_valid_rules(session, program):
    res = import_scope(session, program, in_scope=["*.acme.com"], out_of_scope=["admin.acme.com"])
    assert res.added == ["*.acme.com", "admin.acme.com"]
    assert res.scope_version == 2  # arrancaba en 1


def test_import_rejects_invalid_rules(session, program):
    res = import_scope(session, program, in_scope=["*.acme.com", "not a domain"])
    assert "*.acme.com" in res.added
    assert len(res.rejected) == 1
    assert res.rejected[0][0] == "not a domain"


def test_import_skips_duplicates(session, program):
    import_scope(session, program, in_scope=["*.acme.com"])
    res = import_scope(session, program, in_scope=["*.acme.com"])
    assert res.added == []
    assert res.skipped == ["*.acme.com"]


def test_import_without_changes_does_not_bump_version(session, program):
    import_scope(session, program, in_scope=["*.acme.com"])
    v1 = program.scope_version
    import_scope(session, program, in_scope=["*.acme.com"])  # duplicado
    assert program.scope_version == v1


# --------------------------------------------------------------------------- #
# build_validator + AssetInventory
# --------------------------------------------------------------------------- #


def test_build_validator_reflects_rules(session, program):
    import_scope(session, program, in_scope=["*.acme.com"], out_of_scope=["admin.acme.com"])
    v = build_validator(session, program)
    assert v.is_in_scope("api.acme.com") is True
    assert v.is_in_scope("admin.acme.com") is False
    assert v.is_in_scope("evil.com") is False


def test_inventory_classifies_in_scope(session, program):
    import_scope(session, program, in_scope=["*.acme.com"])
    inv = AssetInventory(session)
    asset = inv.add_or_update(program, "api.acme.com", source="subfinder")
    assert asset.scope_status is ScopeStatus.IN_SCOPE
    assert asset.source == "subfinder"


def test_inventory_classifies_out_of_scope(session, program):
    import_scope(session, program, in_scope=["*.acme.com"], out_of_scope=["admin.acme.com"])
    inv = AssetInventory(session)
    asset = inv.add_or_update(program, "admin.acme.com")
    assert asset.scope_status is ScopeStatus.OUT_OF_SCOPE


def test_inventory_default_deny(session, program):
    import_scope(session, program, in_scope=["*.acme.com"])
    inv = AssetInventory(session)
    asset = inv.add_or_update(program, "other.org")
    assert asset.scope_status is ScopeStatus.OUT_OF_SCOPE


def test_inventory_dedupes_and_updates(session, program):
    import_scope(session, program, in_scope=["*.acme.com"])
    inv = AssetInventory(session)
    a1 = inv.add_or_update(program, "api.acme.com")
    a2 = inv.add_or_update(program, "API.acme.com.", source="katana")
    assert a1.id == a2.id  # mismo activo (normalizado)
    assert a2.source == "katana"


def test_inventory_in_scope_filter(session, program):
    import_scope(session, program, in_scope=["*.acme.com"], out_of_scope=["admin.acme.com"])
    inv = AssetInventory(session)
    inv.add_or_update(program, "api.acme.com")
    inv.add_or_update(program, "admin.acme.com")
    inv.add_or_update(program, "other.org")
    in_scope = inv.in_scope_assets(program)
    assert {a.hostname for a in in_scope} == {"api.acme.com"}
