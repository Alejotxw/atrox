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

**Generar llave maestra** (nunca commitear el resultado):

```bash
python -c "from atrox.security.encryption import generate_master_key; print(generate_master_key())"
```

Exportar en el entorno:

```bash
export ATROX_ENCRYPTION_MASTER_KEY="<valor-generado>"
```

Uso programático:

```python
from atrox.security import SensitiveFieldEncryptor, get_encryption_service_from_settings

svc = get_encryption_service_from_settings()
encryptor = SensitiveFieldEncryptor(svc)

encrypted_finding = encryptor.encrypt_fields("finding", {
    "id": "VULN-001",
    "evidence": "PoC SQLi en /login.php",
})
```

Documentación de rotación de llaves: [`docs/security/key_rotation.md`](docs/security/key_rotation.md)

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
- **ADR-001** — Lenguaje base y concurrencia
- **ADR-002** — Estrategia de integración IA
- **ADR-003** — Almacenamiento seguro de auditoría
