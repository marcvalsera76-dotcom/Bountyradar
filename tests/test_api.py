"""Tests de la API FastAPI (MVP PASSIVE) con TestClient."""

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import StaticPool

from app.db.base import Base
from app.db.session import get_session
from app.main import app


@pytest.fixture()
def client():
    engine = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    TestingSession = sessionmaker(bind=engine, expire_on_commit=False)

    def _override():
        session: Session = TestingSession()
        try:
            yield session
            session.commit()
        except Exception:
            session.rollback()
            raise
        finally:
            session.close()

    app.dependency_overrides[get_session] = _override
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()
    engine.dispose()


def _create_program(client, name="Acme"):
    r = client.post(
        "/api/v1/programs",
        json={"name": name, "platform": "HACKERONE", "external_program_id": name.lower()},
    )
    assert r.status_code == 201
    return r.json()


def test_health(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.json() == {"status": "ok"}


def test_create_and_list_programs(client):
    _create_program(client)
    r = client.get("/api/v1/programs")
    assert r.status_code == 200
    assert len(r.json()) == 1
    assert r.json()[0]["name"] == "Acme"


def test_create_program_validation_error(client):
    r = client.post("/api/v1/programs", json={"name": "", "platform": "HACKERONE"})
    assert r.status_code == 422


def test_import_scope_endpoint(client):
    p = _create_program(client)
    r = client.post(
        f"/api/v1/programs/{p['id']}/scope/import",
        json={"in_scope": ["*.acme.com"], "out_of_scope": ["admin.acme.com"]},
    )
    assert r.status_code == 200
    body = r.json()
    assert "*.acme.com" in body["added"]
    assert body["scope_version"] == 2


def test_import_scope_rejects_invalid(client):
    p = _create_program(client)
    r = client.post(
        f"/api/v1/programs/{p['id']}/scope/import",
        json={"in_scope": ["bad input"]},
    )
    assert r.status_code == 200
    assert len(r.json()["rejected"]) == 1


def test_add_and_list_assets_classified(client):
    p = _create_program(client)
    client.post(
        f"/api/v1/programs/{p['id']}/scope/import",
        json={"in_scope": ["*.acme.com"], "out_of_scope": ["admin.acme.com"]},
    )
    r1 = client.post(
        f"/api/v1/programs/{p['id']}/assets",
        json={"hostname": "api.acme.com", "source": "subfinder"},
    )
    assert r1.status_code == 201
    assert r1.json()["scope_status"] == "IN_SCOPE"

    r2 = client.post(f"/api/v1/programs/{p['id']}/assets", json={"hostname": "admin.acme.com"})
    assert r2.json()["scope_status"] == "OUT_OF_SCOPE"

    r3 = client.get(f"/api/v1/programs/{p['id']}/assets")
    assert len(r3.json()) == 2


def test_asset_on_missing_program_404(client):
    r = client.post("/api/v1/programs/999/assets", json={"hostname": "x.acme.com"})
    assert r.status_code == 404


def test_dashboard_renders(client):
    _create_program(client, name="Globex")
    r = client.get("/")
    assert r.status_code == 200
    assert "BountyRadar" in r.text
    assert "Globex" in r.text


def test_recon_passive_import_endpoint(client):
    p = _create_program(client)
    client.post(
        f"/api/v1/programs/{p['id']}/scope/import",
        json={"in_scope": ["*.acme.com"], "out_of_scope": ["admin.acme.com"]},
    )
    r = client.post(
        f"/api/v1/programs/{p['id']}/recon/passive/import",
        json={"hosts": ["api.acme.com", "admin.acme.com", "evil.com"], "source": "subfinder"},
    )
    assert r.status_code == 200
    body = r.json()
    assert body["in_scope"] == ["api.acme.com"]
    assert body["new_assets"] == 3
    assert body["task_id"] is not None
