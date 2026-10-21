"""Test de migración ida/vuelta: upgrade head -> downgrade base -> upgrade head.

Se ejecuta sobre una BD SQLite TEMPORAL y desechable (no una BD real), que es
exactamente el test up/down exigido por el guardarraíl.
"""

import os
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, inspect

PROJECT_ROOT = Path(__file__).resolve().parent.parent
EXPECTED_TABLES = {
    "program",
    "asset",
    "endpoint",
    "vulnerability_candidate",
    "task",
    "audit_event",
}


@pytest.fixture()
def alembic_cfg(tmp_path, monkeypatch):
    db_path = tmp_path / "roundtrip.db"
    url = f"sqlite:///{db_path}"
    monkeypatch.setenv("BOUNTYRADAR_DB_URL", url)
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "migrations"))
    return cfg, url


def _tables(url: str) -> set[str]:
    engine = create_engine(url)
    try:
        names = set(inspect(engine).get_table_names())
    finally:
        engine.dispose()
    return names - {"alembic_version"}


def test_upgrade_creates_all_tables(alembic_cfg):
    cfg, url = alembic_cfg
    command.upgrade(cfg, "head")
    assert EXPECTED_TABLES.issubset(_tables(url))


def test_downgrade_removes_tables(alembic_cfg):
    cfg, url = alembic_cfg
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    assert _tables(url) == set()


def test_full_round_trip(alembic_cfg):
    cfg, url = alembic_cfg
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    command.upgrade(cfg, "head")
    assert EXPECTED_TABLES.issubset(_tables(url))


def test_no_real_db_touched():
    # El guardarraíl prohíbe aplicar la migración a una BD real sin confirmación.
    # Confirmamos que no existe un bountyradar.db persistido tras los tests.
    assert not (PROJECT_ROOT / "bountyradar.db").exists()
    assert "BOUNTYRADAR_DB_URL" not in os.environ or "/tmp" in os.environ.get(
        "BOUNTYRADAR_DB_URL", ""
    )
