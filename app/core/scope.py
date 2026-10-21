"""ScopeValidator: autorización de destinos deny-by-default.

Comprobación puramente SINTÁCTICA: nunca resuelve DNS ni abre conexiones.
Reglas del spec v3.4 (Scope Enforcer):
- Política por defecto: deny-by-default.
- Normalizar IDNA, minúsculas, puntos finales, URLs, puertos e IPs.
- Dominios exactos, comodines DNS (*.example.com), IPs individuales y CIDRs.
- Un comodín *.example.com NO autoriza example.com.
- Anti-sufijo inseguro: notexample.com no pertenece a example.com.
- Las reglas out-of-scope tienen prioridad sobre las in-scope.
- Rechazar credenciales, hosts malformados, IP ambiguas y notaciones
  numéricas alternativas.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass
from encodings import idna as _idna
from urllib.parse import urlsplit

IPAddress = ipaddress.IPv4Address | ipaddress.IPv6Address
IPNetwork = ipaddress.IPv4Network | ipaddress.IPv6Network

_LABEL_RE = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?$")


class ScopeError(ValueError):
    """Entrada de scope no normalizable o malformada."""


@dataclass(frozen=True)
class Target:
    """Destino normalizado: tipo 'domain' (str) o 'ip' (objeto ipaddress)."""

    kind: str  # 'domain' | 'ip'
    value: object

    def __str__(self) -> str:
        return str(self.value)


@dataclass(frozen=True)
class Rule:
    """Regla de scope normalizada."""

    kind: str  # 'exact' | 'wildcard' | 'ip' | 'cidr'
    value: object
    raw: str

    def __str__(self) -> str:
        return self.raw


def _idna_label(label: str) -> str:
    """Normaliza una etiqueta de dominio a ASCII (IDNA) en minúsculas."""
    if not label:
        raise ScopeError("etiqueta vacía")
    try:
        if label.isascii():
            out = label.lower()
        else:
            out = _idna.ToASCII(label).decode("ascii").lower()
    except (UnicodeError, ValueError) as exc:
        raise ScopeError(f"etiqueta no normalizable: {label!r}") from exc
    if len(out) > 63:
        raise ScopeError(f"etiqueta demasiado larga: {out!r}")
    if not _LABEL_RE.match(out):
        raise ScopeError(f"etiqueta inválida: {out!r}")
    return out


def _normalize_domain(host: str) -> str:
    """Normaliza un nombre de dominio (sin resolver DNS)."""
    host = host.strip().rstrip(".")
    if not host:
        raise ScopeError("dominio vacío")
    labels = host.split(".")
    if len(labels) < 2:
        raise ScopeError(f"dominio debe tener al menos dos etiquetas: {host!r}")
    norm = [_idna_label(label) for label in labels]
    if norm[-1].isdigit():
        raise ScopeError(f"TLD numérico no permitido: {host!r}")
    return ".".join(norm)


def _strict_ip(text: str) -> IPAddress:
    """Parsea una IP de forma estricta; rechaza notaciones ambiguas.

    ipaddress rechaza ceros a la izquierda, enteros y hex/octal, cubriendo
    las 'notaciones numéricas alternativas' que exige el spec.
    """
    try:
        return ipaddress.ip_address(text)
    except ValueError as exc:
        raise ScopeError(f"IP malformada o ambigua: {text!r}") from exc


def _split_host_port(host: str) -> str:
    """Extrae el host de un literal host[:puerto] o [IPv6][:puerto]."""
    host = host.strip()
    if not host:
        raise ScopeError("host vacío")
    if host.startswith("["):
        end = host.find("]")
        if end == -1:
            raise ScopeError("corchete IPv6 sin cerrar")
        inner = host[1:end]
        rest = host[end + 1 :]
        if rest:
            if not rest.startswith(":") or not rest[1:].isdigit():
                raise ScopeError(f"puerto inválido: {rest!r}")
        return inner
    # IPv6 sin corchetes (varios ':') -> no se le puede quitar puerto.
    if host.count(":") > 1:
        return host
    if host.count(":") == 1:
        h, _, port = host.partition(":")
        if not port.isdigit():
            raise ScopeError(f"puerto inválido: {port!r}")
        return h
    return host


def normalize_target(raw: str) -> Target:
    """Normaliza una entrada (host, IP o URL) a un Target. No toca la red."""
    if raw is None or not str(raw).strip():
        raise ScopeError("entrada vacía")
    s = str(raw).strip()

    if "://" in s:
        parsed = urlsplit(s)
        if parsed.username or parsed.password or "@" in parsed.netloc:
            raise ScopeError("credenciales en la URL no permitidas")
        try:
            host = parsed.hostname
        except ValueError as exc:
            raise ScopeError(f"host de URL inválido: {s!r}") from exc
        if not host:
            raise ScopeError("host ausente en la URL")
    else:
        if "@" in s:
            raise ScopeError("credenciales no permitidas")
        host = _split_host_port(s)

    host = host.strip().rstrip(".")
    if not host:
        raise ScopeError("host vacío tras normalizar")

    # Decisión IP vs dominio.
    if ":" in host:
        return Target("ip", _strict_ip(host))
    last_label = host.split(".")[-1]
    if last_label.isdigit():
        return Target("ip", _strict_ip(host))
    return Target("domain", _normalize_domain(host))


def parse_rule(raw: str) -> Rule:
    """Parsea una regla de scope a su forma normalizada."""
    if raw is None or not str(raw).strip():
        raise ScopeError("regla vacía")
    s = str(raw).strip().lower().rstrip(".")

    if s.startswith("*."):
        base = _normalize_domain(s[2:])
        return Rule("wildcard", base, raw)

    if "/" in s:
        try:
            net = ipaddress.ip_network(s, strict=False)
        except ValueError as exc:
            raise ScopeError(f"CIDR inválido: {s!r}") from exc
        return Rule("cidr", net, raw)

    last_label = s.split(".")[-1]
    if ":" in s or last_label.isdigit():
        return Rule("ip", _strict_ip(s), raw)

    return Rule("exact", _normalize_domain(s), raw)


def _matches(rule: Rule, target: Target) -> bool:
    """¿El destino coincide con la regla? (sin DNS)."""
    if target.kind == "ip":
        if rule.kind == "ip":
            return target.value == rule.value
        if rule.kind == "cidr":
            net = rule.value
            addr = target.value
            if net.version != addr.version:  # type: ignore[union-attr]
                return False
            return addr in net  # type: ignore[operator]
        return False

    # target.kind == 'domain'
    if rule.kind == "exact":
        return target.value == rule.value
    if rule.kind == "wildcard":
        base = str(rule.value)
        name = str(target.value)
        # Solo subdominios estrictos; el apex NO entra.
        return name.endswith("." + base) and name != base
    return False


class ScopeValidator:
    """Valida destinos contra reglas in-scope / out-of-scope (deny-by-default)."""

    def __init__(
        self,
        in_scope: object = (),
        out_of_scope: object = (),
        program: str | None = None,
        scope_version: str | None = None,
    ) -> None:
        self.program = program
        self.scope_version = scope_version
        self.in_rules: list[Rule] = [parse_rule(r) for r in in_scope]  # type: ignore[union-attr]
        self.out_rules: list[Rule] = [parse_rule(r) for r in out_of_scope]  # type: ignore[union-attr]

    def check(self, target: str) -> tuple[bool, str]:
        """Devuelve (autorizado, motivo) para auditoría. Nunca resuelve DNS."""
        try:
            t = normalize_target(target)
        except ScopeError as exc:
            return (False, f"denegado: entrada no normalizable ({exc})")

        for rule in self.out_rules:
            if _matches(rule, t):
                return (False, f"denegado: coincide out-of-scope {rule}")

        for rule in self.in_rules:
            if _matches(rule, t):
                return (True, f"permitido: coincide in-scope {rule}")

        return (False, "denegado por defecto: sin coincidencia in-scope")

    def is_in_scope(self, target: str) -> bool:
        """Firma estable para callers: True si el destino está autorizado."""
        return self.check(target)[0]
