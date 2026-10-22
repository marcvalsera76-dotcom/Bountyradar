"""EvidenceRecorder: cadena de custodia de evidencias.

Guarda solo lo necesario para verificar un hallazgo, con cabeceras sensibles
REDACTADAS, hash SHA-256 del cuerpo de respuesta, timestamps UTC y un hash de
integridad sobre el conjunto. Nunca inventa IPs, cabeceras, respuestas ni
comandos: solo registra lo que se le pasa.
"""

from __future__ import annotations

import hashlib
from collections.abc import Mapping
from datetime import UTC, datetime, timedelta

from sqlalchemy.orm import Session

from app.db.models import Evidence

# Cabeceras que nunca se guardan en claro.
_SENSITIVE_HEADERS = frozenset(
    {"authorization", "cookie", "set-cookie", "x-api-key", "x-auth-token", "proxy-authorization"}
)
_REDACTED = "[REDACTED]"


def redact_headers(headers: Mapping[str, str] | None) -> dict[str, str]:
    """Devuelve las cabeceras con los valores sensibles redactados."""
    if not headers:
        return {}
    out: dict[str, str] = {}
    for key, value in headers.items():
        out[key] = _REDACTED if key.lower() in _SENSITIVE_HEADERS else value
    return out


def sha256_text(text: str | None) -> str:
    return hashlib.sha256((text or "").encode("utf-8", errors="replace")).hexdigest()


def _integrity_hash(fields: list[str]) -> str:
    return hashlib.sha256("|".join(fields).encode()).hexdigest()


class EvidenceRecorder:
    """Registra evidencias reproducibles y redactadas."""

    def __init__(self, session: Session, retention_days: int | None = 90) -> None:
        self.session = session
        self.retention_days = retention_days

    def record(
        self,
        finding_id: int,
        *,
        request_method: str | None = None,
        request_url: str | None = None,
        request_headers: Mapping[str, str] | None = None,
        response_status: int | None = None,
        response_body: str | None = None,
        tool_name: str | None = None,
        tool_version: str | None = None,
        observed_at: datetime | None = None,
    ) -> Evidence:
        observed_at = observed_at or datetime.now(UTC)
        redacted = redact_headers(request_headers)
        headers_str = "; ".join(f"{k}: {v}" for k, v in redacted.items())
        body_hash = sha256_text(response_body)
        integrity = _integrity_hash(
            [
                str(finding_id),
                request_method or "",
                request_url or "",
                headers_str,
                str(response_status or ""),
                body_hash,
                observed_at.isoformat(),
            ]
        )
        retention_until = (
            observed_at + timedelta(days=self.retention_days)
            if self.retention_days is not None
            else None
        )
        evidence = Evidence(
            finding_id=finding_id,
            request_method=request_method,
            request_url=request_url,
            request_headers_redacted=headers_str or None,
            response_status=response_status,
            response_body_sha256=body_hash,
            tool_name=tool_name,
            tool_version=tool_version,
            observed_at_utc=observed_at,
            integrity_hash=integrity,
            retention_until=retention_until,
        )
        self.session.add(evidence)
        self.session.flush()
        return evidence

    @staticmethod
    def verify(evidence: Evidence) -> bool:
        """Recalcula el hash de integridad y lo compara con el almacenado."""
        expected = _integrity_hash(
            [
                str(evidence.finding_id),
                evidence.request_method or "",
                evidence.request_url or "",
                evidence.request_headers_redacted or "",
                str(evidence.response_status or ""),
                evidence.response_body_sha256 or "",
                evidence.observed_at_utc.isoformat(),
            ]
        )
        return expected == evidence.integrity_hash
