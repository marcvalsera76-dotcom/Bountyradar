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
    CandidateOut,
    FindingIn,
    ProgramCreate,
    ProgramOut,
    ReconImportIn,
    ReconImportOut,
    ReportOut,
    ScopeImportIn,
    ScopeImportOut,
    TriageOut,
)
from app.db.models import Asset, Program, VulnerabilityCandidate
from app.db.session import get_session
from app.recon.passive import PassiveReconService
from app.services.inventory import AssetInventory
from app.services.report import check_quality, generate_report
from app.services.scope_import import import_scope
from app.services.triage import FindingInput, FindingTriage

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


@app.post(
    "/api/v1/programs/{program_id}/recon/passive/import", response_model=ReconImportOut
)
def recon_passive_import(
    program_id: int, payload: ReconImportIn, session: SessionDep
) -> ReconImportOut:
    program = _get_program(session, program_id)
    service = PassiveReconService(session)
    res = service.ingest_hosts(program, payload.hosts, source=payload.source)
    return ReconImportOut(
        source=res.source,
        total_lines=res.total_lines,
        new_assets=res.new_assets,
        updated_assets=res.updated_assets,
        in_scope=res.in_scope,
        out_of_scope=res.out_of_scope,
        invalid=res.invalid,
        task_id=res.task_id,
    )


@app.post("/api/v1/programs/{program_id}/findings", response_model=TriageOut)
def submit_finding(program_id: int, payload: FindingIn, session: SessionDep) -> TriageOut:
    program = _get_program(session, program_id)
    triage = FindingTriage(session)
    res = triage.triage(
        program,
        FindingInput(
            host=payload.host,
            vuln_type=payload.vuln_type,
            title=payload.title,
            path=payload.path,
            evidence_pattern=payload.evidence_pattern,
            severity=payload.severity,
            poc_available=payload.poc_available,
        ),
    )
    return TriageOut(
        candidate=CandidateOut.model_validate(res.candidate),
        is_duplicate=res.is_duplicate,
        dedup_probability=res.dedup_probability,
        reason=res.reason,
    )


@app.get("/api/v1/programs/{program_id}/findings", response_model=list[CandidateOut])
def list_findings(program_id: int, session: SessionDep) -> list[VulnerabilityCandidate]:
    _get_program(session, program_id)
    return list(
        session.scalars(
            select(VulnerabilityCandidate)
            .where(VulnerabilityCandidate.program_id == program_id)
            .order_by(VulnerabilityCandidate.id)
        )
    )


@app.get("/api/v1/findings/{finding_id}/report", response_model=ReportOut)
def finding_report(finding_id: int, session: SessionDep) -> ReportOut:
    candidate = session.get(VulnerabilityCandidate, finding_id)
    if candidate is None:
        raise HTTPException(status_code=404, detail="candidata no encontrada")
    program = session.get(Program, candidate.program_id)
    quality = check_quality(candidate)
    markdown = generate_report(candidate, program.name if program else None)
    return ReportOut(ready=quality.ready, missing=quality.missing, markdown=markdown)


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
