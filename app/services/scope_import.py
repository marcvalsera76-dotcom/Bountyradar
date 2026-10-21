"""Importación y normalización de scope hacia la BD.

Valida cada regla con el parser del ScopeValidator; las reglas inválidas se
rechazan (no se almacenan). Al importar, incrementa scope_version del programa.
"""

from __future__ import annotations

from dataclasses import dataclass, field

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.scope import ScopeError, parse_rule
from app.db.models import Program, ScopeRule


@dataclass
class ImportResult:
    added: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)  # ya existían
    rejected: list[tuple[str, str]] = field(default_factory=list)  # (patrón, motivo)
    scope_version: int = 0


def _existing_patterns(session: Session, program_id: int, kind: str) -> set[str]:
    rows = session.scalars(
        select(ScopeRule.pattern).where(
            ScopeRule.program_id == program_id, ScopeRule.kind == kind
        )
    )
    return set(rows)


def import_scope(
    session: Session,
    program: Program,
    in_scope: list[str] | None = None,
    out_of_scope: list[str] | None = None,
) -> ImportResult:
    """Importa reglas in/out para un programa. Rechaza las no normalizables."""
    result = ImportResult()
    groups = (("in", in_scope or []), ("out", out_of_scope or []))

    any_added = False
    for kind, patterns in groups:
        existing = _existing_patterns(session, program.id, kind)
        for raw in patterns:
            try:
                parse_rule(raw)  # valida sintaxis/normalización
            except ScopeError as exc:
                result.rejected.append((raw, str(exc)))
                continue
            norm = raw.strip().lower().rstrip(".")
            if norm in existing:
                result.skipped.append(raw)
                continue
            session.add(ScopeRule(program_id=program.id, kind=kind, pattern=norm))
            existing.add(norm)
            result.added.append(raw)
            any_added = True

    if any_added:
        program.scope_version += 1
    session.flush()
    result.scope_version = program.scope_version
    return result
