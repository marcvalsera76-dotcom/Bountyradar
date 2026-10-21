"""AuditLogger: registro auditable de decisiones (scope, policy, rate).

Cada autorización o denegación se registra con actor, operación, destino,
decisión, motivo, programa y versión de scope. El sink es inyectable para
poder persistir en BD más adelante sin acoplar este módulo.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime


def _utcnow() -> datetime:
    return datetime.now(UTC)


@dataclass(frozen=True)
class AuditRecord:
    """Entrada inmutable del registro de auditoría."""

    actor: str
    operation: str
    decision: str  # 'ALLOW' | 'DENY'
    destination: str | None = None
    program: str | None = None
    scope_version: str | None = None
    reason: str | None = None
    correlation_id: str | None = None
    created_at: datetime = field(default_factory=_utcnow)


class AuditLogger:
    """Registra AuditRecords en un sink (por defecto, en memoria)."""

    def __init__(
        self,
        sink: Callable[[AuditRecord], None] | None = None,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._events: list[AuditRecord] = []
        self._sink = sink
        self._clock = clock or _utcnow

    def record(
        self,
        actor: str,
        operation: str,
        decision: str,
        *,
        destination: str | None = None,
        program: str | None = None,
        scope_version: str | None = None,
        reason: str | None = None,
        correlation_id: str | None = None,
    ) -> AuditRecord:
        if decision not in ("ALLOW", "DENY"):
            raise ValueError("decision debe ser 'ALLOW' o 'DENY'")
        rec = AuditRecord(
            actor=actor,
            operation=operation,
            decision=decision,
            destination=destination,
            program=program,
            scope_version=scope_version,
            reason=reason,
            correlation_id=correlation_id,
            created_at=self._clock(),
        )
        self._events.append(rec)
        if self._sink is not None:
            self._sink(rec)
        return rec

    def allow(self, actor: str, operation: str, **kw: object) -> AuditRecord:
        return self.record(actor, operation, "ALLOW", **kw)  # type: ignore[arg-type]

    def deny(self, actor: str, operation: str, **kw: object) -> AuditRecord:
        return self.record(actor, operation, "DENY", **kw)  # type: ignore[arg-type]

    @property
    def events(self) -> list[AuditRecord]:
        return list(self._events)

    def by_decision(self, decision: str) -> list[AuditRecord]:
        return [e for e in self._events if e.decision == decision]

    def by_correlation(self, correlation_id: str) -> list[AuditRecord]:
        return [e for e in self._events if e.correlation_id == correlation_id]
