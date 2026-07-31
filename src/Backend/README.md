# Atrox Backend — Core API (FastAPI)

Backend asíncrono del framework Atrox. Implementa el núcleo de la API según **ADR-001** (Python + FastAPI + `asyncio`).

## Requisitos

- Python **3.10+**
- `pip`

## Arranque local

### 1. Entorno virtual (recomendado)

```bash
cd src/Backend
python -m venv .venv
```

**Windows (PowerShell):**
```powershell
.\.venv\Scripts\Activate.ps1
```

**Linux / macOS:**
```bash
source .venv/bin/activate
```

### 2. Instalar dependencias

```bash
pip install -e ".[dev]"
```

Alternativa con `requirements.txt`:

```bash
pip install -r requirements.txt
```

### 3. Configuración por variables de entorno

Copia el archivo de ejemplo y ajusta valores:

```bash
cp .env.example .env
```

| Variable | Descripción | Valor por defecto |
| :--- | :--- | :--- |
| `ATROX_APP_NAME` | Nombre del servicio | `Atrox API` |
| `ATROX_HOST` | Host de Uvicorn | `0.0.0.0` |
| `ATROX_PORT` | Puerto de Uvicorn | `8000` |
| `ATROX_ENV` | Entorno (`development` / `production`) | `development` |
| `ATROX_DEBUG` | Recarga automática en desarrollo | `false` |
| `ATROX_NMAP_PATH` | Ruta al binario de Nmap | `nmap` |
| `ATROX_NMAP_TIMEOUT_SECONDS` | Timeout máximo por escaneo | `300` |
| `ATROX_ENCRYPTION_MASTER_KEY` | Llave AES-256 (base64/hex, 32 bytes) — **solo env** | *(requerida para cifrado)* |

### 4. Iniciar el servidor (Uvicorn async)

**Opción A — script del paquete:**
```bash
atrox-api
```

**Opción B — módulo Python:**
```bash
python -m atrox
```

**Opción C — Uvicorn directo:**
```bash
uvicorn atrox.main:app --host 0.0.0.0 --port 8000 --reload
```

### 5. Verificar healthcheck

```bash
curl http://localhost:8000/health
```

Respuesta esperada (`200 OK`, `< 500 ms`):

```json
{
  "status": "ok",
  "service": "Atrox API",
  "environment": "development"
}
```

Documentación interactiva: [http://localhost:8000/docs](http://localhost:8000/docs)

### 6. Escaneo de descubrimiento (HU-002)

Requiere [Nmap](https://nmap.org/download.html) instalado y disponible en el `PATH`.

```bash
curl -X POST http://localhost:8000/api/discovery/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "scanme.nmap.org", "port_range": "22,80"}'
```

**PowerShell:**
```powershell
Invoke-RestMethod -Method POST -Uri http://localhost:8000/api/discovery/scan `
  -ContentType "application/json" `
  -Body '{"target":"scanme.nmap.org","port_range":"22,80"}'
```

Respuesta esperada (`200 OK`):

```json
{
  "target": "scanme.nmap.org",
  "port_range": "22,80",
  "status": "completed",
  "hosts": [
    {
      "address": "45.33.32.156",
      "status": "up",
      "ports": [
        {
          "port": 22,
          "protocol": "tcp",
          "service": "ssh",
          "version": "OpenSSH 6.6.1p1"
        }
      ]
    }
  ],
  "error": null
}
```

Estados posibles: `completed`, `unreachable`, `timeout`, `error`.

### 7. Cifrado en reposo (HU-007)

Reportes, credenciales y hallazgos sensibles se cifran con **AES-256-GCM** antes de persistirse.

#### Cómo activarlo (compañeros del equipo)

**1. Copia el archivo de entorno** (si aún no tienes `.env`):

```powershell
cd C:\Users\Usuario\atrox\src\Backend
copy .env.example .env
```

**2. Activa el entorno virtual y genera la llave:**

```powershell
cd C:\Users\Usuario\atrox\src\Backend
.\.venv\Scripts\Activate.ps1
python -c "from atrox.security.encryption import generate_master_key; print(generate_master_key())"
```

**3. Pega la llave en tu `.env`** (descomenta y completa):

```env
ATROX_ENCRYPTION_MASTER_KEY=pega_aqui_la_llave_generada
ATROX_ENCRYPTED_STORAGE_PATH=data/encrypted
```

**4. Reinicia el backend:**

```powershell
python -m atrox
```

> **Importante:** nunca subas el archivo `.env` ni la llave real a Git. Cada persona genera su propia llave local.

Documentación de rotación de llaves: [`docs/security/key_rotation.md`](docs/security/key_rotation.md)

**Integración (endpoints + jobs + persistencia):**

| Recurso | Endpoint | Qué cifra |
| :--- | :--- | :--- |
| Hallazgos | `POST/GET /api/findings` | description, evidence, poc, raw_output |
| Credenciales | `POST/GET /api/credentials` | password, secret, token, private_key |
| Reportes | `POST/GET /api/reports` | content, executive_summary, technical_details, body |

- Al completar un job `vulnscan`, los hallazgos se **persisten cifrados** y el `job.result` guarda findings cifrados.
- Al consultar `GET /api/jobs/{id}`, los findings se **descifran** para la respuesta autorizada.
- Los archivos en `data/encrypted/*.jsonl` nunca guardan esos campos en texto plano.

### 8. Log de auditoría inmutable (HU-008)

Cada escaneo y cambio de política queda registrado con **timestamp, usuario, acción y recurso**, firmado con **HMAC-SHA256**.

**Generar llave de firma** (nunca commitear):

```bash
python -c "from atrox.security.audit_signer import generate_signing_key; print(generate_signing_key())"
```

Configurar en `.env`:

```
ATROX_AUDIT_SIGNING_KEY=<valor-generado>
ATROX_AUDIT_RETENTION_DAYS=365
```

**Registrar evento (cambio de política):**

```powershell
Invoke-RestMethod -Method POST -Uri http://localhost:8000/api/audit/events `
  -ContentType "application/json" `
  -Body '{"user":"director.ti","action":"policy.updated","resource":"policy:scheduling","metadata":{"cron":"0 2 * * *"}}'
```

**Consultar logs por rango de fechas:**

```
GET /api/audit/logs?from=2026-06-01T00:00:00Z&to=2026-06-30T23:59:59Z&user=director.ti
```

**Verificar integridad (tamper detection):**

```
GET /api/audit/integrity
```

Los escaneos enviados vía `POST /api/jobs` se registran automáticamente como `scan.submitted`.

Documentación de retención: [`docs/security/audit_retention.md`](docs/security/audit_retention.md)

### 9. Orquestación IA con LangGraph (HU-013)

Grafo de estados que replica el razonamiento de un pentester:

```
analizar hallazgos → proponer acción → ejecutar herramienta → evaluar → (ciclo o parada)
```

Diagrama de flujo: [`docs/ai/pentest_orchestrator_flow.md`](../../docs/ai/pentest_orchestrator_flow.md)

```python
from atrox.ai.graph import run_pentest_orchestrator, MockDecider

result = run_pentest_orchestrator(
    findings=[{"id": "VULN-001", "severity": "critical", "name": "SQLi"}],
    target="lab.target.local",
    thread_id="demo-session",
    decider=MockDecider(stop_after_cycles=1),
)
print(result["stop_reason"], result["executed_tools"])
```

```bash
pytest tests/test_ai_graph.py -v
```

### 10. Análisis de vectores de ataque (HU-014)

Correlaciona hallazgos de Nuclei (HU-003) y propone cadenas de ataque priorizadas.

```powershell
Invoke-RestMethod -Method POST -Uri http://localhost:8000/api/ai/vectors/analyze `
  -ContentType "application/json" `
  -Body '{"findings":[{"template_id":"sqli-login-blind","name":"SQL Injection","severity":"critical","host":"http://lab.local","matched_at":"http://lab.local/login.php","tags":["sqli","web"],"ip":"192.168.1.10"},{"template_id":"mysql-default-credentials","name":"MySQL Default Creds","severity":"high","host":"mysql://192.168.1.10:3306","matched_at":"192.168.1.10:3306","tags":["mysql","database"],"ip":"192.168.1.10"}]}'
```

```bash
pytest tests/test_vector_analyzer.py -v
```

### 11. API REST unificada de escaneos (HU-009)

Fachada pública sobre la cola de HU-004: valida el payload y encola el trabajo automáticamente.

```powershell
Invoke-RestMethod -Method POST -Uri http://localhost:8000/api/scans `
  -ContentType "application/json" `
  -Body '{"target":"scanme.nmap.org","scan_type":"discovery","params":{"port_range":"22,80"}}'
```

Respuesta esperada (`202 Accepted`):

```json
{
  "scan_id": "b3f1...",
  "status": "pending"
}
```

`scan_id` es el mismo identificador que `job_id` en HU-004, por lo que el estado del escaneo puede consultarse con `GET /api/jobs/{scan_id}`.

El contrato queda publicado automáticamente en el schema OpenAPI (`GET /openapi.json`, UI en `/docs`) y validado por `tests/test_scans_contract.py` en CI.

```bash
pytest tests/test_scans_api.py tests/test_scans_contract.py -v
```

### 12. Consulta de resultados de escaneo (HU-010)

`GET /api/scans/{scan_id}` — vista de analista sobre el mismo `Job` de HU-004: progreso, activos descubiertos (`discovery`) o hallazgos paginados (`vulnscan`), filtrables por `severity` y `asset_status`. Coherente en cualquier estado: si el escaneo aún no terminó, `assets`/`findings` se devuelven vacíos en lugar de fallar.

```bash
curl "http://localhost:8000/api/scans/<scan_id>?page=1&page_size=20&severity=high"
```

Respuesta (ejemplo, escaneo `vulnscan` terminado):

```json
{
  "scan_id": "b3f1...",
  "scan_type": "vulnscan",
  "status": "done",
  "progress": 1.0,
  "target": "example.com",
  "assets": [],
  "findings": {
    "items": [{"template_id": "...", "severity": "high", "...": "..."}],
    "total": 42,
    "page": 1,
    "page_size": 20,
    "total_pages": 3
  },
  "error": null,
  "created_at": "...",
  "started_at": "...",
  "finished_at": "..."
}
```

Para escaneos `discovery`, `assets` trae los `HostFinding` descubiertos (filtrables por `asset_status=up|down`) y `findings` queda vacío.

```bash
pytest tests/test_scans_detail_api.py -v
```

### 13. Agente de generación de payloads contextualizados (HU-015)

`POST /api/ai/payloads/generate` — catálogo heurístico (sin LLM conectado, sin ejecución de red/subprocesos) que sugiere payloads adaptados a la categoría de vulnerabilidad (sqli/xss/rce/lfi/ssrf/default-login) y servicio inferidos de un `VulnFinding` de HU-003/HU-006, asociados a un `finding_id`. Revisión de seguridad documentada en [`docs/ADR/ADR-004 Seguridad_Agente_Generacion_Payloads.md`](../../docs/ADR/ADR-004%20Seguridad_Agente_Generacion_Payloads.md).

```bash
curl -X POST http://localhost:8000/api/ai/payloads/generate \
  -H "Content-Type: application/json" \
  -d '{
    "finding": {
      "template_id": "generic-sqli-detect",
      "name": "SQL Injection Detected",
      "severity": "high",
      "host": "http://example.com",
      "matched_at": "http://example.com/login?id=1",
      "tags": ["sqli", "injection"]
    }
  }'
```

Respuesta (ejemplo):

```json
{
  "finding_id": "generic-sqli-detect",
  "service": "http",
  "category": "sqli",
  "suggestions": [
    {"category": "sqli", "payload": "' OR '1'='1' -- -", "description": "Bypass de autenticación / condición siempre verdadera"}
  ],
  "disclaimer": "Uso exclusivo en entornos de laboratorio autorizados. ...",
  "generation_time_ms": 0.12,
  "within_sla": true
}
```

`disclaimer` siempre está presente en el contrato (no es opcional): el consumidor de la API no puede recibir payloads sin la advertencia de uso autorizado.

```bash
pytest tests/test_payload_generator.py tests/test_payloads_api.py tests/test_payloads_contract.py -v
```

### 14. Scoring de confianza para falsos positivos (HU-016)

`POST /api/ai/scoring/score` — score heurístico 0-100 por hallazgo (`VulnFinding` de HU-003/HU-006), con explicación breve de las señales usadas. Umbral configurable vía `ATROX_FP_SCORE_THRESHOLD` (default `40`), sobre-escribible por request (`threshold`). Bajo el umbral, el hallazgo se marca `probable_fp: true`. Evaluación con dataset TP/FP etiquetado y métrica de precisión medida (90.9%) documentadas en [`docs/ai/HU-016-scoring-evaluation.md`](../../docs/ai/HU-016-scoring-evaluation.md).

```bash
curl -X POST http://localhost:8000/api/ai/scoring/score \
  -H "Content-Type: application/json" \
  -d '{
    "finding": {
      "template_id": "tech-detect-nginx",
      "name": "Nginx Version Detection",
      "severity": "info",
      "host": "http://example.com",
      "matched_at": "http://example.com/",
      "tags": ["tech", "fingerprint"]
    }
  }'
```

Respuesta (ejemplo):

```json
{
  "finding_id": "tech-detect-nginx",
  "score": 0,
  "threshold": 40,
  "probable_fp": true,
  "explanation": "severidad info (base 20); tags de fingerprinting/informativos ['fingerprint', 'tech'] (-20); sin descripción de contexto (-10) -> score 0/100 (umbral 40)",
  "generation_time_ms": 0.01,
  "within_sla": true
}
```

```bash
pytest tests/test_scoring_rules.py tests/test_scoring_agent.py tests/test_scoring_api.py tests/test_scoring_contract.py tests/test_scoring_precision.py -v
```

## Pruebas

```bash
pytest tests/ -v -m "not integration"
```

Prueba de integración contra target de laboratorio (`scanme.nmap.org`):

```bash
pytest tests/test_nmap_integration.py -v -m integration
```

El smoke test valida que `GET /health` responde `200` en menos de 500 ms.

## Estructura

```
src/Backend/
├── atrox/
│   ├── api/
│   │   ├── health.py       # GET /health
│   │   └── discovery.py    # POST /api/discovery/scan
│   ├── scanner/
│   │   ├── nmap_wrapper.py
│   │   └── ...
│   ├── security/
│   │   ├── encryption.py       # AES-256-GCM
│   │   └── sensitive_fields.py # Campos sensibles
│   ├── config.py
│   ├── main.py
│   └── __main__.py
├── docs/security/
│   └── key_rotation.md
├── tests/
│   ├── test_encryption.py
│   └── ...
├── pyproject.toml
└── requirements.txt
```

## Trazabilidad

- **HU-001** — Bootstrap del núcleo FastAPI asíncrono
- **HU-002** — Descubrimiento de activos con wrapper Nmap (RF-001)
- **HU-007** — Cifrado AES-256-GCM de datos en reposo (RNF-001 · ADR-003)
- **HU-008** — Log de auditoría inmutable con firma criptográfica (RNF-003 · ADR-003)
- **HU-013** — Orquestación de agentes con LangGraph (RF-003 · ADR-002)
- **HU-014** — Agente de análisis de vectores de ataque (RF-003 · RNF-004)
- **HU-009** — API REST unificada de creación de escaneos, `POST /api/scans` (RF-001 · RF-002)
- **HU-010** — API REST de consulta de resultados, `GET /api/scans/{id}` (RF-001 · RF-002)
- **HU-015** — Agente de generación de payloads contextualizados, `POST /api/ai/payloads/generate` (RF-004 · RNF-004)
- **HU-016** — Scoring de confianza para falsos positivos, `POST /api/ai/scoring/score` (RF-005 · RNF-004)
- **ADR-001** — Lenguaje base y concurrencia
- **ADR-002** — Estrategia de integración IA
- **ADR-003** — Almacenamiento seguro de auditoría
