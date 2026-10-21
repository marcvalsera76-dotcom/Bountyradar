"""PolicyEngine: autorización por modo de operación y aprobaciones graduales.

Modelo de aprobaciones del spec v3.4:
- PASSIVE: fuentes públicas, sin conexiones directas. Permitido por defecto.
- SAFE_ACTIVE: requiere habilitación expresa por programa.
- FULL_ACTIVE: requiere habilitación + aprobación manual por tarea/campaña.
- EXPLOIT_HUNT: requiere SAFE_ACTIVE o FULL_ACTIVE habilitado + aprobación
  explícita por tipo de exploit.

Reglas transversales:
- Deny-by-default: una operación desconocida se deniega.
- Acciones prohibidas (DoS, brute force, phishing, destructivas...) se
  deniegan SIEMPRE, en cualquier modo.
- La validación humana nunca se puede anular desde aquí.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum


class OperationMode(StrEnum):
    """Modos de operación, de menor a mayor privilegio."""

    PASSIVE = "PASSIVE"
    SAFE_ACTIVE = "SAFE_ACTIVE"
    FULL_ACTIVE = "FULL_ACTIVE"
    EXPLOIT_HUNT = "EXPLOIT_HUNT"
    AUTOPILOT = "AUTOPILOT"


class ExploitType(StrEnum):
    """Tipos de exploit aprobables (spec: modelo PoC)."""

    IDOR = "IDOR"
    SSRF = "SSRF"
    SQLI = "SQLI"
    XSS = "XSS"
    REDIRECT = "REDIRECT"
    SSTI = "SSTI"
    CMDI = "CMDI"
    TRAVERSAL = "TRAVERSAL"
    TAKEOVER = "TAKEOVER"


@dataclass(frozen=True)
class Operation:
    """Operación del catálogo con el modo mínimo que exige."""

    name: str
    required_mode: OperationMode
    description: str = ""
    prohibited: bool = False
    is_exploit: bool = False


# Catálogo de operaciones autorizables, mapeadas a su modo mínimo.
_OPS: tuple[Operation, ...] = (
    # PASSIVE
    Operation("scope.import", OperationMode.PASSIVE, "Importar/normalizar scope"),
    Operation("recon.passive", OperationMode.PASSIVE, "Recon pasivo (fuentes públicas)"),
    Operation("ct.monitor", OperationMode.PASSIVE, "Certificate Transparency"),
    Operation("asset.inventory", OperationMode.PASSIVE, "Inventario/correlación de activos"),
    # SAFE_ACTIVE
    Operation("dns.resolve", OperationMode.SAFE_ACTIVE, "Resolución DNS controlada"),
    Operation("http.probe", OperationMode.SAFE_ACTIVE, "Sonda HTTP de bajo impacto"),
    Operation("tech.detect", OperationMode.SAFE_ACTIVE, "Detección de tecnologías"),
    Operation("endpoint.check", OperationMode.SAFE_ACTIVE, "Comprobar endpoints conocidos"),
    # FULL_ACTIVE (requiere aprobación por tarea)
    Operation("content.discovery", OperationMode.FULL_ACTIVE, "Fuzzing dirigido (ffuf)"),
    Operation("port.scan", OperationMode.FULL_ACTIVE, "Escaneo de puertos (naabu)"),
    Operation("template.scan", OperationMode.FULL_ACTIVE, "Plantillas allowlist (nuclei)"),
    # EXPLOIT_HUNT (requiere tipo de exploit aprobado)
    Operation("exploit.validate", OperationMode.EXPLOIT_HUNT, "Validar PoC", is_exploit=True),
    Operation("poc.generate", OperationMode.EXPLOIT_HUNT, "Generar PoC", is_exploit=True),
    # Prohibidas SIEMPRE
    Operation("dos", OperationMode.FULL_ACTIVE, "Denegación de servicio", prohibited=True),
    Operation("stress", OperationMode.FULL_ACTIVE, "Stress testing", prohibited=True),
    Operation("bruteforce", OperationMode.FULL_ACTIVE, "Fuerza bruta masiva", prohibited=True),
    Operation("password_spray", OperationMode.FULL_ACTIVE, "Password spraying", prohibited=True),
    Operation(
        "credential_stuffing", OperationMode.FULL_ACTIVE, "Credential stuffing", prohibited=True
    ),
    Operation("phishing", OperationMode.PASSIVE, "Phishing", prohibited=True),
    Operation("spam", OperationMode.PASSIVE, "Envío masivo de correo", prohibited=True),
    Operation(
        "data_destroy", OperationMode.FULL_ACTIVE, "Borrado destructivo", prohibited=True
    ),
)

OPERATIONS: dict[str, Operation] = {op.name: op for op in _OPS}


@dataclass(frozen=True)
class ProgramPolicy:
    """Habilitaciones y aprobaciones de un programa concreto."""

    name: str
    safe_active_enabled: bool = False
    full_active_enabled: bool = False
    exploit_hunt_enabled: bool = False
    approved_exploit_types: frozenset[ExploitType] = field(default_factory=frozenset)


@dataclass(frozen=True)
class Decision:
    """Resultado auditable de una evaluación de política."""

    allowed: bool
    reason: str
    required_mode: OperationMode | None = None


class PolicyEngine:
    """Decide si una operación está autorizada para un programa."""

    def evaluate(
        self,
        policy: ProgramPolicy,
        operation: str,
        *,
        exploit_type: ExploitType | None = None,
        task_approved: bool = False,
    ) -> Decision:
        op = OPERATIONS.get(operation)
        if op is None:
            return Decision(False, f"denegado: operación desconocida {operation!r}")

        if op.prohibited:
            return Decision(
                False,
                f"denegado: acción prohibida por defecto ({op.name})",
                op.required_mode,
            )

        mode = op.required_mode

        if mode is OperationMode.PASSIVE:
            return Decision(True, f"permitido: {op.name} es PASSIVE", mode)

        if mode is OperationMode.SAFE_ACTIVE:
            if not policy.safe_active_enabled:
                return Decision(False, "denegado: SAFE_ACTIVE no habilitado", mode)
            return Decision(True, f"permitido: {op.name} bajo SAFE_ACTIVE", mode)

        if mode is OperationMode.FULL_ACTIVE:
            if not policy.full_active_enabled:
                return Decision(False, "denegado: FULL_ACTIVE no habilitado", mode)
            if not task_approved:
                return Decision(
                    False, "denegado: FULL_ACTIVE requiere aprobación por tarea", mode
                )
            return Decision(True, f"permitido: {op.name} bajo FULL_ACTIVE aprobado", mode)

        if mode is OperationMode.EXPLOIT_HUNT:
            if not (policy.safe_active_enabled or policy.full_active_enabled):
                return Decision(
                    False,
                    "denegado: EXPLOIT_HUNT requiere SAFE_ACTIVE o FULL_ACTIVE",
                    mode,
                )
            if not policy.exploit_hunt_enabled:
                return Decision(False, "denegado: EXPLOIT_HUNT no habilitado", mode)
            if exploit_type is None:
                return Decision(
                    False, "denegado: EXPLOIT_HUNT requiere tipo de exploit", mode
                )
            if exploit_type not in policy.approved_exploit_types:
                return Decision(
                    False,
                    f"denegado: tipo de exploit {exploit_type.value} no aprobado",
                    mode,
                )
            return Decision(
                True, f"permitido: {op.name} ({exploit_type.value}) bajo EXPLOIT_HUNT", mode
            )

        return Decision(False, f"denegado por defecto: modo no manejado {mode}", mode)

    def allowed(
        self,
        policy: ProgramPolicy,
        operation: str,
        *,
        exploit_type: ExploitType | None = None,
        task_approved: bool = False,
    ) -> bool:
        """Firma booleana estable para callers."""
        return self.evaluate(
            policy, operation, exploit_type=exploit_type, task_approved=task_approved
        ).allowed

    def autopilot_modes(self, policy: ProgramPolicy) -> frozenset[OperationMode]:
        """Modos que AUTOPILOT puede encadenar según habilitaciones.

        Spec: si SAFE_ACTIVE no está habilitado, AUTOPILOT solo ejecuta
        PASSIVE + DETECT + DRAFT_REPORT (modelado como solo PASSIVE aquí).
        """
        modes = {OperationMode.PASSIVE}
        if policy.safe_active_enabled:
            modes.add(OperationMode.SAFE_ACTIVE)
        if policy.full_active_enabled:
            modes.add(OperationMode.FULL_ACTIVE)
        if policy.exploit_hunt_enabled and (
            policy.safe_active_enabled or policy.full_active_enabled
        ):
            modes.add(OperationMode.EXPLOIT_HUNT)
        return frozenset(modes)
