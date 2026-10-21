# BountyRadar

Plataforma local de automatización de bug bounty **autorizado**. Estado actual:
**MVP en modo PASSIVE** (gestión de programas, importación de scope e inventario
de activos con clasificación deny-by-default). No ejecuta recon activo ni
explotación: eso corresponde a hitos posteriores y a los gates de aprobación
humana descritos en la especificación.

## Seguridad primero

- **ScopeValidator**: deny-by-default, normalización IDNA, anti-sufijo,
  anti-IP-ambigua. Comprobación puramente sintáctica (nunca resuelve DNS).
- **PolicyEngine**: modos PASSIVE → SAFE_ACTIVE → FULL_ACTIVE → EXPLOIT_HUNT,
  aprobaciones graduales, acciones prohibidas denegadas siempre.
- **RateLimitService / Budget**: límites global/host/programa y presupuestos.
- **AuditLogger**: registro auditable de ALLOW/DENY.

## Requisitos

- Python 3.11+

## Instalación

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
pip install fastapi uvicorn jinja2 sqlalchemy alembic
```

## Base de datos (migraciones)

```bash
export BOUNTYRADAR_DB_URL="sqlite:///bountyradar.db"
alembic upgrade head
```

> La migración solo se aplica cuando TÚ ejecutas este comando. El código nunca
> la aplica solo.

## Arrancar

```bash
uvicorn app.main:app --reload
```

- Dashboard: http://127.0.0.1:8000/
- API docs: http://127.0.0.1:8000/docs
- Salud: http://127.0.0.1:8000/health

## Tests

```bash
pytest          # suite completa
ruff check .    # lint
```

## Estructura

```
app/
  core/      ScopeValidator, PolicyEngine, RateLimit, AuditLogger
  db/        modelos SQLAlchemy, sesión, base declarativa
  services/  importación de scope, inventario de activos
  api/       esquemas Pydantic
  main.py    aplicación FastAPI + dashboard
migrations/  Alembic
tests/       suite pytest
```

## Hoja de ruta (pendiente)

Recon activo (SAFE_ACTIVE), adaptadores de herramientas, triaje, validación de
explotabilidad con PoCs y AUTOPILOT — todos con sus gates de aprobación humana.
