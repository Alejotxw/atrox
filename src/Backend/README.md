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
│   │   ├── nmap_wrapper.py # Wrapper async de Nmap
│   │   ├── models.py
│   │   └── validators.py
│   ├── config.py
│   ├── main.py
│   └── __main__.py
├── tests/
│   ├── test_health.py
│   ├── test_nmap_wrapper.py
│   ├── test_discovery_api.py
│   └── test_nmap_integration.py
├── pyproject.toml
└── requirements.txt
```

## Trazabilidad

- **HU-001** — Bootstrap del núcleo FastAPI asíncrono
- **HU-002** — Descubrimiento de activos con wrapper Nmap (RF-001)
- **ADR-001** — Lenguaje base y concurrencia
