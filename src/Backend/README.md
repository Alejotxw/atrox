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

## Pruebas

```bash
pytest tests/ -v
```

El smoke test valida que `GET /health` responde `200` en menos de 500 ms.

## Estructura

```
src/Backend/
├── atrox/
│   ├── api/health.py   # Endpoint GET /health
│   ├── config.py       # Configuración centralizada (env)
│   ├── main.py         # Aplicación FastAPI
│   └── __main__.py     # Punto de entrada Uvicorn
├── tests/
│   └── test_health.py
├── pyproject.toml
└── requirements.txt
```

## Trazabilidad

- **HU-001** — Bootstrap del núcleo FastAPI asíncrono
- **ADR-001** — Lenguaje base y concurrencia
