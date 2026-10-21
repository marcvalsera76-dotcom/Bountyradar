"""Aplicación FastAPI de BountyRadar (MVP modo PASSIVE).

Expone gestión de programas, importación de scope e inventario de activos.
No ejecuta recon activo ni explotación: eso requiere los hitos posteriores
y los gates de aprobación del spec.
"""

from __future__ import annotations

from pathlib import Path
from typing import Annotated

from fastapi import Depends, FastAPI, HTTPException
from fastapi.responses import HTMLResponse
from sqlalchemy import select
from sqlalchemy.orm import Session

from app.api.schemas import (
    AssetIn,
    AssetOut,
    ProgramCreate,
    ProgramOut,
    ScopeImportIn,
    ScopeImportOut,
)
from app.db.models import Asset, Program
from app.db.session import get_session
from app.services.inventory import AssetInventory
from app.services.scope_import import import_scope

app = FastAPI(title="BountyRadar", version="0.1.0")

SessionDep = Annotated[Session, Depends(get_session)]

_TEMPLATES = Path(__file__).parent / "web" / "templates"


def _get_program(session: Session, program_id: int) -> Program:
    program = session.get(Program, program_id)
    if program is None:
        raise HTTPException(status_code=404, detail="programa no encontrado")
    return program


@app.get("/health")
def health() -> dict[str, str]:
    return {"status": "ok"}


@app.post("/api/v1/programs", response_model=ProgramOut, status_code=201)
def create_program(payload: ProgramCreate, session: SessionDep) -> Program:
    program = Program(
        name=payload.name,
        platform=payload.platform,
        external_program_id=payload.external_program_id,
    )
    session.add(program)
    session.flush()
    return program


@app.get("/api/v1/programs", response_model=list[ProgramOut])
def list_programs(session: SessionDep) -> list[Program]:
    return list(session.scalars(select(Program).order_by(Program.id)))


@app.post("/api/v1/programs/{program_id}/scope/import", response_model=ScopeImportOut)
def import_program_scope(
    program_id: int, payload: ScopeImportIn, session: SessionDep
) -> ScopeImportOut:
    program = _get_program(session, program_id)
    res = import_scope(session, program, payload.in_scope, payload.out_of_scope)
    return ScopeImportOut(
        added=res.added,
        skipped=res.skipped,
        rejected=res.rejected,
        scope_version=res.scope_version,
    )


@app.post("/api/v1/programs/{program_id}/assets", response_model=AssetOut, status_code=201)
def add_asset(
    program_id: int, payload: AssetIn, session: SessionDep
) -> Asset:
    program = _get_program(session, program_id)
    inv = AssetInventory(session)
    return inv.add_or_update(program, payload.hostname, source=payload.source)


@app.get("/api/v1/programs/{program_id}/assets", response_model=list[AssetOut])
def list_assets(program_id: int, session: SessionDep) -> list[Asset]:
    _get_program(session, program_id)
    return list(
        session.scalars(
            select(Asset).where(Asset.program_id == program_id).order_by(Asset.hostname)
        )
    )


@app.get("/", response_class=HTMLResponse)
def dashboard(session: SessionDep) -> str:
    programs = list(session.scalars(select(Program).order_by(Program.id)))
    rows = "".join(
        f"<tr><td>{p.id}</td><td>{p.name}</td><td>{p.platform}</td>"
        f"<td>v{p.scope_version}</td></tr>"
        for p in programs
    )
    if not rows:
        rows = '<tr><td colspan="4">Sin programas todavía.</td></tr>'
    return f"""<!doctype html>
<html lang="es"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>BountyRadar</title>
<script src="https://cdnjs.cloudflare.com/ajax/libs/htmx/2.0.3/htmx.min.js"></script>
<style>
 body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
 table{{width:100%;border-collapse:collapse}}
 th,td{{border:1px solid #ccc;padding:.4rem .6rem;text-align:left}}
 .badge{{background:#eee;border-radius:4px;padding:.1rem .4rem;font-size:.8rem}}
</style></head>
<body>
<h1>BountyRadar <span class="badge">MVP · PASSIVE</span></h1>
<p>Plataforma de bug bounty autorizado. Modo pasivo (sin recon activo).</p>
<h2>Programas</h2>
<table><thead><tr><th>ID</th><th>Nombre</th><th>Plataforma</th><th>Scope</th></tr></thead>
<tbody>{rows}</tbody></table>
<p><small>API: <code>/docs</code> · salud: <code>/health</code></small></p>
</body></html>"""
