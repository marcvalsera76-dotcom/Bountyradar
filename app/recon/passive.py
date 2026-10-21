"""Recon pasivo por archivo: ingesta de hosts con revalidación de scope.

No realiza ninguna conexión de red (DNS, HTTP, etc.). Normaliza y deduplica
los nombres, valida contra el scope del programa y los incorpora al inventario
clasificados IN/OUT_OF_SCOPE. Registra la ejecución como Task PASSIVE.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import UTC, datetime

from sqlalchemy.orm import Session

from app.core.audit import AuditLogger
from app.core.scope import ScopeError, normalize_target
from app.db.models import ScanMode, ScopeStatus, Task, TaskStatus
from app.services.inventory import AssetInventory, build_validator


@dataclass
class ReconIngestResult:
    source: str
    total_lines: int = 0
    valid_hosts: list[str] = field(default_factory=list)
    invalid: list[tuple[str, str]] = field(default_factory=list)  # (línea, motivo)
    in_scope: list[str] = field(default_factory=list)
    out_of_scope: list[str] = field(default_factory=list)
    new_assets: int = 0
    updated_assets: int = 0
    task_id: int | None = None


def normalize_hosts(lines: list[str]) -> tuple[list[str], list[tuple[str, str]]]:
    """Normaliza y deduplica hosts. Devuelve (válidos_ordenados, inválidos).

    Ignora líneas vacías y comentarios (#). No toca la red.
    """
    seen: set[str] = set()
    valid: list[str] = []
    invalid: list[tuple[str, str]] = []
    for raw in lines:
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        try:
            target = normalize_target(line)
        except ScopeError as exc:
            invalid.append((line, str(exc)))
            continue
        host = str(target)
        if host not in seen:
            seen.add(host)
            valid.append(host)
    valid.sort()
    return valid, invalid


class PassiveReconService:
    """Ingesta pasiva de hosts desde una lista (archivo/fuente pública)."""

    def __init__(self, session: Session, audit: AuditLogger | None = None) -> None:
        self.session = session
        self.audit = audit

    def ingest_hosts(
        self, program, lines: list[str], *, source: str = "import"
    ) -> ReconIngestResult:
        result = ReconIngestResult(source=source, total_lines=len(lines))
        valid, invalid = normalize_hosts(lines)
        result.valid_hosts = valid
        result.invalid = invalid

        now = datetime.now(UTC)
        task = Task(
            program_id=program.id,
            mode=ScanMode.PASSIVE,
            operation="recon.passive",
            status=TaskStatus.RUNNING,
            pipeline_step="RECON",
            started_at=now,
        )
        self.session.add(task)
        self.session.flush()

        validator = build_validator(self.session, program)
        inventory = AssetInventory(self.session)

        for host in valid:
            existed = self._asset_exists(program.id, host)
            asset = inventory.add_or_update(program, host, source=source, validator=validator)
            if existed:
                result.updated_assets += 1
            else:
                result.new_assets += 1
            if asset.scope_status is ScopeStatus.IN_SCOPE:
                result.in_scope.append(host)
            else:
                result.out_of_scope.append(host)
            if self.audit is not None:
                decision = "ALLOW" if asset.scope_status is ScopeStatus.IN_SCOPE else "DENY"
                self.audit.record(
                    actor=f"recon:{source}",
                    operation="recon.passive",
                    decision=decision,
                    destination=host,
                    program=program.name,
                    scope_version=str(program.scope_version),
                    reason=asset.scope_reason,
                )

        task.status = TaskStatus.FINISHED
        task.finished_at = datetime.now(UTC)
        self.session.flush()
        result.task_id = task.id
        return result

    def ingest_from_source(self, program, source, domain: str) -> ReconIngestResult:
        """Ingesta hosts desde una fuente pasiva (crt.sh, wayback)."""
        hosts = source.hosts(domain)
        return self.ingest_hosts(program, hosts, source=source.name)

    def _asset_exists(self, program_id: int, hostname: str) -> bool:
        from sqlalchemy import select

        from app.db.models import Asset

        return (
            self.session.scalar(
                select(Asset.id).where(
                    Asset.program_id == program_id, Asset.hostname == hostname
                )
            )
            is not None
        )
