"""Fuentes pasivas de subdominios: crt.sh (CT logs) y Wayback.

PASSIVE: solo fuentes públicas de terceros, nunca conexiones contra el
objetivo. El fetcher es inyectable para poder testear sin red y para aplicar
timeouts/límites en producción. El parseo es puro.
"""

from __future__ import annotations

import json
import urllib.request
from collections.abc import Callable
from typing import Any

from app.core.scope import ScopeError, normalize_target

Fetcher = Callable[[str], Any]


def _under_domain(host: str, domain: str) -> bool:
    domain = domain.strip().lower().rstrip(".")
    return host == domain or host.endswith("." + domain)


def _normalize_keep(raw: str, domain: str, out: set[str]) -> None:
    raw = raw.strip().lstrip("*.").lower()
    if not raw:
        return
    try:
        target = normalize_target(raw)
    except ScopeError:
        return
    if target.kind != "domain":
        return
    host = str(target)
    if _under_domain(host, domain):
        out.add(host)


def parse_crtsh(data: list[dict[str, Any]], domain: str) -> list[str]:
    """Extrae hostnames de la respuesta JSON de crt.sh."""
    out: set[str] = set()
    for row in data:
        name_value = row.get("name_value", "") or ""
        for line in str(name_value).splitlines():
            _normalize_keep(line, domain, out)
    return sorted(out)


def parse_wayback(rows: list[list[str]], domain: str) -> list[str]:
    """Extrae hostnames de la respuesta CDX de Wayback (lista de filas)."""
    out: set[str] = set()
    for i, row in enumerate(rows):
        if not row:
            continue
        if i == 0 and row[0] == "original":  # cabecera
            continue
        url = row[0]
        _normalize_keep(url, domain, out)
    return sorted(out)


def _default_fetcher(url: str) -> Any:
    req = urllib.request.Request(url, headers={"User-Agent": "BountyRadar/0.1 (+passive)"})
    with urllib.request.urlopen(req, timeout=20) as resp:  # noqa: S310  (https público)
        return json.loads(resp.read().decode("utf-8", errors="replace"))


class CrtShSource:
    name = "crt.sh"

    def __init__(self, fetcher: Fetcher | None = None) -> None:
        self._fetch = fetcher or _default_fetcher

    def hosts(self, domain: str) -> list[str]:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"
        data = self._fetch(url)
        return parse_crtsh(data if isinstance(data, list) else [], domain)


class WaybackSource:
    name = "wayback"

    def __init__(self, fetcher: Fetcher | None = None) -> None:
        self._fetch = fetcher or _default_fetcher

    def hosts(self, domain: str) -> list[str]:
        url = (
            "http://web.archive.org/cdx/search/cdx"
            f"?url=*.{domain}/*&output=json&fl=original&collapse=urlkey"
        )
        data = self._fetch(url)
        return parse_wayback(data if isinstance(data, list) else [], domain)
