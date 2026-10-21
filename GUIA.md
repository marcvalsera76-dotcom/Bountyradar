# Guía rápida de BountyRadar

Guía práctica para usar BountyRadar desde el móvil (Termux) en modo PASSIVE.

## 1. Arrancar

En Termux, dentro de `~/bountyradar`:

```bash
export BOUNTYRADAR_DB_URL="sqlite:///bountyradar.db"
alembic upgrade head          # solo la primera vez (crea las tablas)
uvicorn app.main:app --host 127.0.0.1 --port 8001
```

**Deja esa sesión abierta** (no pulses Ctrl+C). Si da "address already in use", cambia el puerto (8002, 8003…).

## 2. Abrir la interfaz

En el navegador del móvil, barra de direcciones:

- **Dashboard (solo lectura):** `127.0.0.1:8001/`
- **API interactiva (para hacer cosas):** `127.0.0.1:8001/docs`

En `/docs`: pulsa un endpoint → **Try it out** → rellena → **Execute**.

## 3. Flujo de trabajo (modo pasivo)

El orden lógico es: **programa → scope → activos/recon → hallazgos → reporte**.

### a) Crear un programa
`POST /api/v1/programs`
```json
{"name":"Acme","platform":"HACKERONE","external_program_id":"acme"}
```
Plataformas válidas: `HACKERONE`, `BUGCROWD`, `INTIGRITI`, `PRIVATE`.

### b) Importar el scope
`POST /api/v1/programs/1/scope/import`
```json
{"in_scope":["*.acme.com"],"out_of_scope":["admin.acme.com"]}
```
Reglas válidas: dominio exacto (`acme.com`), comodín (`*.acme.com`), IP (`1.2.3.4`), CIDR (`10.0.0.0/8`). Las inválidas se rechazan solas.

### c) Añadir activos (hosts) y clasificarlos
`POST /api/v1/programs/1/recon/passive/import`
```json
{"hosts":["api.acme.com","admin.acme.com","shop.acme.com"],"source":"manual"}
```
Cada host sale clasificado IN_SCOPE / OUT_OF_SCOPE según el scope. Nunca toca la red.

### d) Registrar un hallazgo (triaje)
`POST /api/v1/programs/1/findings`
```json
{"host":"api.acme.com","vuln_type":"IDOR","title":"IDOR en /api/invoices",
 "path":"/api/invoices","evidence_pattern":"id=2 devuelve datos ajenos"}
```
El sistema deduplica, clasifica explotabilidad (HIGH/MEDIUM/LOW) y calcula confianza. Nunca lo marca confirmado solo.

### e) Ver el borrador de reporte
`GET /api/v1/findings/1/report`

Devuelve el Markdown. Si faltan campos (severidad, pasos, impacto, PoC), sale como **BORRADOR — No enviar** con la lista de lo que falta.

## 4. Con curl (alternativa a /docs)

Desde **otra** sesión de Termux (deja el server en la suya):

```bash
curl http://127.0.0.1:8001/health
curl -X POST http://127.0.0.1:8001/api/v1/programs \
 -H "Content-Type: application/json" \
 -d '{"name":"Acme","platform":"HACKERONE","external_program_id":"acme"}'
```

## Qué NO hace (a propósito)

No hace recon activo, ni escaneos, ni explotación, ni envía reportes. Todo eso
requiere hitos posteriores y aprobación humana explícita. BountyRadar hoy es:
scope seguro + inventario + recon pasivo + triaje + borrador de reporte.
