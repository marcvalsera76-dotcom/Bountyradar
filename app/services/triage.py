"""FindingTriage: deduplicación semántica y clasificación de hallazgos.

Principios del spec:
- Distingue observación / indicio / candidata (nunca marca CONFIRMED solo).
- Severidad y confianza son dimensiones SEPARADAS.
- Deduplicación semántica por host + path + tipo + patrón de evidencia.
- Explotabilidad HIGH/MEDIUM/LOW; una cabecera ausente o una versión detectada
  nunca se presentan como explotabilidad automática.
- Registra el motivo de cada clasificación.
"""

from __future__ import annotations

import hashlib
from dataclasses import dataclass
from datetime import UTC, datetime

from sqlalchemy import select
from sqlalchemy.orm import Session

from app.db.models import Exploitability, Program, TriageStatus, VulnerabilityCandidate

# Clases de vulnerabilidad por potencial de explotabilidad (spec).
HIGH_VALUE_TYPES = frozenset(
    {"IDOR", "SSRF", "SQLI", "AUTH_BYPASS", "AUTHZ_BYPASS", "RCE", "TAKEOVER", "REDIRECT"}
)
MEDIUM_VALUE_TYPES = frozenset({"XSS", "SSTI", "CMDI", "INFO_DISCLOSURE"})
# Ruido de bajo valor: solo observación, nunca explotabilidad automática.
LOW_VALUE_TYPES = frozenset(
    {"MISSING_HEADER", "VERSION_DETECTED", "SOFT_404", "WAF_GENERIC", "MISCONFIG_NO_IMPACT"}
)


def classify_exploitability(vuln_type: str, has_evidence: bool) -> tuple[Exploitability, str]:
    """Devuelve (explotabilidad, motivo). Separada de la severidad."""
    vt = vuln_type.upper()
    if vt in LOW_VALUE_TYPES:
        return Exploitability.LOW, f"{vt}: ruido de bajo valor, solo observación"
    if vt in HIGH_VALUE_TYPES:
        if has_evidence:
            return Exploitability.HIGH, f"{vt} con evidencia: explotabilidad alta"
        return Exploitability.MEDIUM, f"{vt} sin evidencia: requiere validación manual"
    if vt in MEDIUM_VALUE_TYPES:
        if has_evidence:
            return Exploitability.MEDIUM, f"{vt} con evidencia: validación manual"
        return Exploitability.LOW, f"{vt} sin evidencia: indicio débil"
    return Exploitability.LOW, f"tipo desconocido {vt}: tratado como observación"


def compute_confidence(has_evidence: bool, poc_available: bool) -> int:
    """Confianza 0-100 derivada de la evidencia verificable (no de la severidad)."""
    score = 20
    if has_evidence:
        score += 40
    if poc_available:
        score += 30
    return min(100, score)


def _norm(host: str, path: str, vuln_type: str) -> tuple[str, str, str]:
    return (
        host.strip().lower().rstrip("."),
        path.strip() or "/",
        vuln_type.strip().upper(),
    )


def location_key(program_id: int, host: str, path: str, vuln_type: str) -> str:
    """Clave de ubicación: host + path + tipo (sin evidencia)."""
    h, p, vt = _norm(host, path, vuln_type)
    raw = "|".join([str(program_id), h, p, vt])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


def dedup_key(program_id: int, host: str, path: str, vuln_type: str, evidence_pattern: str) -> str:
    """Firma semántica completa: ubicación + patrón de evidencia."""
    h, p, vt = _norm(host, path, vuln_type)
    raw = "|".join([str(program_id), h, p, vt, evidence_pattern.strip().lower()])
    return hashlib.sha256(raw.encode()).hexdigest()[:32]


@dataclass
class FindingInput:
    host: str
    vuln_type: str
    title: str
    path: str = "/"
    evidence_pattern: str = ""
    severity: str | None = None
    poc_available: bool = False
    asset_id: int | None = None
    endpoint_id: int | None = None


@dataclass
class TriageResult:
    candidate: VulnerabilityCandidate
    is_duplicate: bool
    dedup_probability: float
    reason: str


class FindingTriage:
    """Incorpora hallazgos deduplicando y clasificando, sin confirmar nunca solo."""

    def __init__(self, session: Session) -> None:
        self.session = session

    def triage(self, program: Program, finding: FindingInput) -> TriageResult:
        key = dedup_key(
            program.id, finding.host, finding.path, finding.vuln_type, finding.evidence_pattern
        )
        loc = location_key(program.id, finding.host, finding.path, finding.vuln_type)

        existing = self.session.scalar(
            select(VulnerabilityCandidate).where(
                VulnerabilityCandidate.program_id == program.id,
                VulnerabilityCandidate.dedup_key == key,
            )
        )
        if existing is not None:
            existing.seen_count += 1
            existing.updated_at = datetime.now(UTC)
            self.session.flush()
            return TriageResult(existing, True, 1.0, "duplicado exacto (misma firma)")

        # Casi-duplicado: misma ubicación (host+path+tipo) con otra evidencia.
        same_location = self.session.scalar(
            select(VulnerabilityCandidate.id).where(
                VulnerabilityCandidate.program_id == program.id,
                VulnerabilityCandidate.location_key == loc,
            )
        )
        probability = 0.7 if same_location is not None else 0.0

        has_evidence = bool(finding.evidence_pattern.strip())
        exploitability, exp_reason = classify_exploitability(finding.vuln_type, has_evidence)
        confidence = compute_confidence(has_evidence, finding.poc_available)

        candidate = VulnerabilityCandidate(
            program_id=program.id,
            asset_id=finding.asset_id,
            endpoint_id=finding.endpoint_id,
            title=finding.title,
            vuln_type=finding.vuln_type.upper(),
            dedup_key=key,
            location_key=loc,
            severity=finding.severity,
            confidence=confidence,
            exploitability=exploitability,
            poc_available=finding.poc_available,
            triage_status=TriageStatus.NEW,  # nunca CONFIRMED automáticamente
            triage_reason=exp_reason,
        )
        self.session.add(candidate)
        self.session.flush()
        return TriageResult(candidate, False, probability, exp_reason)
