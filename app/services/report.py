"""ReportGenerator: borradores Markdown por candidata con quality gate.

El reporte es el producto final. Antes de marcarse "listo" pasa un quality
gate; si falla, queda como BORRADOR con la lista de lo que falta. Nunca se
envía automáticamente (eso siempre requiere revisión humana).
"""

from __future__ import annotations

from dataclasses import dataclass, field

from app.db.models import TriageStatus, VulnerabilityCandidate

# Campos mínimos para que un reporte sea "listo para revisar".
_REQUIRED = ("title", "severity", "reproduction_steps", "impact")


@dataclass
class QualityResult:
    ready: bool
    missing: list[str] = field(default_factory=list)


def check_quality(candidate: VulnerabilityCandidate) -> QualityResult:
    """Comprueba los requisitos mínimos del reporte."""
    missing: list[str] = []
    for fld in _REQUIRED:
        if not getattr(candidate, fld, None):
            missing.append(fld)
    if not candidate.poc_available:
        missing.append("poc_available")
    # Un output sin evidencia no es confirmable.
    if candidate.confidence < 50:
        missing.append("confidence>=50")
    return QualityResult(ready=not missing, missing=missing)


def _field(value: object, fallback: str = "_pendiente_") -> str:
    return str(value) if value not in (None, "") else fallback


def generate_report(candidate: VulnerabilityCandidate, program_name: str | None = None) -> str:
    """Genera el borrador Markdown de una candidata."""
    quality = check_quality(candidate)
    header = (
        "> ✅ Reporte listo para revisar."
        if quality.ready
        else f"> ⚠️ BORRADOR — faltan: {', '.join(quality.missing)}. No enviar."
    )

    lines = [
        f"# {_field(candidate.title)}",
        "",
        header,
        "",
        f"- **Programa:** {_field(program_name)}",
        f"- **Tipo:** {_field(candidate.vuln_type)}",
        f"- **Severidad:** {_field(candidate.severity)}",
        f"- **Explotabilidad:** {candidate.exploitability.value}",
        f"- **Confianza:** {candidate.confidence}/100",
        f"- **PoC disponible:** {'sí' if candidate.poc_available else 'no'}",
        f"- **Estado de triaje:** {candidate.triage_status.value}",
        "",
        "## Resumen",
        _field(candidate.description),
        "",
        "## Pasos de reproducción",
        _field(candidate.reproduction_steps),
        "",
        "## Impacto",
        _field(candidate.impact),
        "",
        "## Limitaciones y confianza",
        f"Confianza estimada {candidate.confidence}/100. "
        f"Clasificación: {_field(candidate.triage_reason)}.",
    ]
    if candidate.cwe_id:
        lines.insert(10, f"- **CWE:** {candidate.cwe_id}")

    # Nunca marcar como enviado ni confirmado automáticamente.
    if candidate.triage_status is TriageStatus.REPORTED:
        lines.append("")
        lines.append("_Marcado REPORTED por decisión humana._")
    return "\n".join(lines)
