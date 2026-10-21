"""AssetInventory: alta/actualización de activos con clasificación de scope.

Deduplica por (programa, hostname) y clasifica cada activo (IN_SCOPE /
OUT_OF_SCOPE) usando el ScopeValidator construido a partir de las reglas
almacenadas. No realiza ninguna conexión de red.
"""

from __future__ import annotations

from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.core.scope import ScopeValidator
from app.db.models import Asset, Program, ScopeRule, ScopeStatus


def build_validator(session: Session, program: Program) -> ScopeValidator:
    """Construye un ScopeValidator a partir de las reglas del programa."""
    rows = session.execute(
        select(ScopeRule.kind, ScopeRule.pattern).where(ScopeRule.program_id == program.id)
    ).all()
    in_rules = [p for k, p in rows if k == "in"]
    out_rules = [p for k, p in rows if k == "out"]
    return ScopeValidator(
        in_scope=in_rules,
        out_of_scope=out_rules,
        program=program.name,
        scope_version=str(program.scope_version),
    )


class AssetInventory:
    """Inventario de activos con deduplicación y clasificación de scope."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def add_or_update(
        self,
        program: Program,
        hostname: str,
        *,
        source: str | None = None,
        validator: ScopeValidator | None = None,
    ) -> Asset:
        hostname = hostname.strip().lower().rstrip(".")
        validator = validator or build_validator(self.session, program)
        allowed, reason = validator.check(hostname)
        status = ScopeStatus.IN_SCOPE if allowed else ScopeStatus.OUT_OF_SCOPE

        existing = self.session.scalar(
            select(Asset).where(Asset.program_id == program.id, Asset.hostname == hostname)
        )
        now = datetime.now(UTC)
        if existing is not None:
            existing.scope_status = status
            existing.scope_reason = reason
            existing.last_seen_at = now
            if source:
                existing.source = source
            self.session.flush()
            return existing

        asset = Asset(
            program_id=program.id,
            hostname=hostname,
            source=source,
            scope_status=status,
            scope_reason=reason,
        )
        self.session.add(asset)
        self.session.flush()
        return asset

    def in_scope_assets(self, program: Program) -> list[Asset]:
        return list(
            self.session.scalars(
                select(Asset).where(
                    Asset.program_id == program.id,
                    Asset.scope_status == ScopeStatus.IN_SCOPE,
                )
            )
        )
