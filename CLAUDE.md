# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Qué es

BountyRadar: plataforma local de automatización de bug bounty **autorizado**. Estado actual: **MVP en modo PASSIVE** (gestión de programas, scope, inventario de activos, recon pasivo, triaje y borradores de reporte). No ejecuta recon activo ni explotación; esos bloques van en hitos posteriores con gates de aprobación humana.

## Comandos

```bash
# Dependencias (núcleo = solo stdlib; dev y web aparte)
pip install -r requirements.txt fastapi uvicorn jinja2 sqlalchemy alembic

# Tests
pytest                                  # suite completa
pytest tests/test_scope.py              # un fichero
pytest tests/test_scope.py::test_exact_matches_itself   # un test
pytest -k wildcard                      # por patrón

# Lint (ruff debe quedar limpio en cada commit)
ruff check app tests
ruff check --fix app tests

# Migraciones (BOUNTYRADAR_DB_URL por defecto sqlite:///bountyradar.db)
export BOUNTYRADAR_DB_URL="sqlite:///bountyradar.db"
alembic upgrade head
alembic revision --autogenerate -m "mensaje"   # tras cambiar modelos

# Arrancar
uvicorn app.main:app --host 127.0.0.1 --port 8000   # dashboard en /, API en /docs
```

## Reglas del proyecto (no negociables)

- **Seguridad primero, deny-by-default.** El ScopeValidator y el PolicyEngine son el núcleo; no debilitar sus garantías ni cambiar las firmas estables `ScopeValidator.is_in_scope(target) -> bool` y `PolicyEngine.allowed(...) -> bool`.
- **La migración NO se aplica a ninguna BD sin confirmación explícita del usuario.** Autogenerar y testear sí; `alembic upgrade` contra una BD real, no.
- **Trabajo nuevo = su propio commit** (un componente/feature por commit, sin mezclar whitespace con lógica). Cada commit debe dejar `pytest` y `ruff` en verde.
- Nada de recon activo, explotación ni envío automático de reportes en el código. El triaje nunca marca `CONFIRMED`/`REPORTED` solo; eso es decisión humana.
- Las migraciones autogeneradas (`migrations/versions/`) están excluidas del lint a propósito.

## Arquitectura

Capas (dependen hacia abajo; `core` no depende de `db`/`api`):

- **`app/core/`** — lógica de seguridad pura, sin BD ni red:
  - `scope.py` ScopeValidator: normalización IDNA, wildcards (`*.x` no autoriza el apex), CIDR, anti-sufijo, anti-IP-ambigua. Comprobación **sintáctica**, nunca resuelve DNS.
  - `policy.py` PolicyEngine: modos PASSIVE→SAFE_ACTIVE→FULL_ACTIVE→EXPLOIT_HUNT, aprobaciones graduales, acciones prohibidas siempre denegadas.
  - `ratelimit.py` TokenBucket/RateLimitService/Budget: reloj **inyectable** (tests sin sleep).
  - `audit.py` AuditLogger: ALLOW/DENY con sink inyectable.
- **`app/db/`** — `models.py` (SQLAlchemy 2.x, enums `StrEnum`), `base.py` (Base + convención de nombres de constraints + `get_database_url`), `session.py` (dependencia FastAPI con commit/rollback).
- **`app/services/`** — dominio: `scope_import.py` (valida reglas con el parser de `core.scope`, sube `scope_version`), `inventory.py` (dedup por `(program, hostname)`, clasifica IN/OUT_OF_SCOPE con un ScopeValidator construido desde las reglas en BD), `triage.py` (dedup exacto por `dedup_key` y casi-dup por `location_key`; severidad y confianza separadas), `report.py` (Markdown + quality gate).
- **`app/recon/`** — `passive.py` (ingesta de hosts = revalidación de scope en frío, **sin red**; crea una Task PASSIVE), `sources.py` (adaptadores crt.sh/Wayback con **fetcher inyectable**; parseo puro).
- **`app/api/`** + **`app/main.py`** — esquemas Pydantic v2 y la app FastAPI; usa `SessionDep = Annotated[Session, Depends(get_session)]` para inyectar la sesión.

### Patrones clave al añadir código

- **Inyección para testear sin efectos**: reloj en rate limiting, fetcher en fuentes de recon, sink en auditoría. Mantener esto en componentes nuevos.
- **Dedup**: activos por hostname normalizado; hallazgos por firma semántica (`triage.dedup_key` / `location_key`), no por título.
- **Tests de migración** (`tests/test_migrations.py`): corren `upgrade head → downgrade base → upgrade head` sobre SQLite **temporal**, y verifican que no se toca ninguna BD real. Al añadir tablas/columnas, actualizar `EXPECTED_TABLES` / las aserciones de columnas.
- Tests de servicios/API usan SQLite en memoria; la API sobreescribe `get_session` con `app.dependency_overrides`.

## Git

Rama de trabajo: `claude/baseline-anchor-567-w90kmm` (también existe `claude/hitos-1-7` con el mismo contenido). No tocar `main`.
