# Design: Integración de Escaneo de Vulnerabilidades con Nuclei (HU-003)

## Technical Approach

Replicar el patrón ya probado de `NmapWrapper` (HU-002): clase async con runner inyectable, `_execute()` con `create_subprocess_exec` + `wait_for`, y manejo de excepciones mapeado a `ScanStatus`. La diferencia clave es el parser: Nuclei emite JSONL (`-jsonl`), un hallazgo por línea, en lugar de un único XML. El parser es defensivo: cada línea se procesa de forma independiente y los fallos se aíslan (skip + log WARNING) sin abortar el escaneo. Estructura plana en `atrox/scanner/`, sin sub-paquetes (YAGNI).

## Architecture Decisions

| # | Decisión | Elegido | Rechazado | Rationale |
|---|----------|---------|-----------|-----------|
| 1 | Seguridad de plantillas | `templates` = lista de NOMBRES; el wrapper antepone `nuclei_sandbox_templates` y valida que la ruta resuelta quede dentro del sandbox | Aceptar rutas FS arbitrarias | Evita path traversal vía API. La superficie de ataque queda confinada al sandbox de laboratorio |
| 2 | Organización del módulo | `nuclei_wrapper.py` plano junto a `nmap_wrapper.py` | Sub-paquete `scanner/nuclei/` | Coherente con HU-002. Refactor a sub-paquetes solo si crece |
| 3 | Type alias del runner | `NucleiRunner` separado de `NmapRunner` | Extraer `ScannerRunner` común | YAGNI. Con un 3er scanner se extrae. Firmas idénticas pero acopladas innecesariamente hoy |
| 4 | Manejo de errores | try/except en `scan()` → `ScanStatus` (reutilizado); JSONL malformado se omite + log | Status enum nuevo para vulnscan | Reutiliza contrato HU-002. `COMPLETED/TIMEOUT/ERROR` cubren los casos |
| 5 | Resiliencia del parser | Por línea: `json.loads` falla → skip+log; faltan campos requeridos (`template-id`, `info.name`, `info.severity`) → skip+log; severidad fuera del enum → `UNKNOWN` | Fallar todo el escaneo ante una línea inválida | Campos JSONL varían entre versiones de Nuclei (riesgo High del proposal) |

## Data Flow

    POST /api/vulnscan/scan
          │  VulnScanRequest (target, templates[], severities[], tags[])
          ▼
    get_nuclei_wrapper (Depends) ── Settings (nuclei_path, timeout, sandbox)
          │
          ▼
    NucleiWrapper.scan()
       1. resolver plantillas: nombre → sandbox/<nombre> (validar contención)
       2. construir args CLI (-jsonl -target -t ... -severity ... -tags ...)
       3. _execute() ──→ create_subprocess_exec | runner inyectado
       4. _parse_jsonl(stdout): por línea → VulnFinding (defaults defensivos)
       5. mapear status (excepción → ScanStatus)
          │
          ▼
    VulnScanResult (target, status, findings[], error?)

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `atrox/scanner/nuclei_wrapper.py` | Create | Wrapper async + `_execute` + `_parse_jsonl` + resolución de sandbox |
| `atrox/api/vulnscan.py` | Create | Router `POST /api/vulnscan/scan` + `get_nuclei_wrapper` |
| `atrox/scanner/models.py` | Modify | +`VulnSeverity`, `VulnFinding`, `VulnScanRequest`, `VulnScanResult` |
| `atrox/scanner/__init__.py` | Modify | Exporta `NucleiWrapper` |
| `atrox/config.py` | Modify | +`nuclei_path`, `nuclei_timeout_seconds`, `nuclei_sandbox_templates` |
| `atrox/main.py` | Modify | `include_router(vulnscan_router)` |
| `tests/test_nuclei_wrapper.py` | Create | Unit con mock runner |
| `tests/test_vulnscan_api.py` | Create | API con `dependency_overrides` |
| `tests/fixtures/nuclei_samples.py` | Create | Fixtures JSONL (válidos, malformados, severidad rara) |

## Interfaces / Contracts

```python
# scanner/nuclei_wrapper.py
NucleiRunner = Callable[[list[str]], Awaitable[tuple[int, str, str]]]

class NucleiWrapper:
    def __init__(self, nuclei_path="nuclei", timeout_seconds=600,
                 sandbox_templates="", runner: NucleiRunner | None = None): ...
    async def scan(self, target: str, templates: list[str] | None = None,
                   severities: list[str] | None = None,
                   tags: list[str] | None = None) -> VulnScanResult: ...

# scanner/models.py
class VulnSeverity(str, Enum):
    INFO="info"; LOW="low"; MEDIUM="medium"; HIGH="high"; CRITICAL="critical"; UNKNOWN="unknown"

class VulnFinding(BaseModel):
    template_id: str; name: str; severity: VulnSeverity
    matched_at: str = ""; description: str = ""; reference: list[str] = []

class VulnScanRequest(BaseModel):
    target: str               # reusa validate_target
    templates: list[str] = [] # NOMBRES, no rutas — validados contra sandbox
    severities: list[str] = []
    tags: list[str] = []

class VulnScanResult(BaseModel):
    target: str; status: ScanStatus
    findings: list[VulnFinding] = []; error: str | None = None
```

### Mapeo de campos JSONL → VulnFinding

| Nuclei JSONL | VulnFinding | Default si falta |
|--------------|-------------|------------------|
| `template-id` | `template_id` | skip (requerido) |
| `info.name` | `name` | skip (requerido) |
| `info.severity` | `severity` | `UNKNOWN` si fuera del enum |
| `matched-at` / `host` | `matched_at` | `""` |
| `info.description` | `description` | `""` |
| `info.reference` | `reference` | `[]` |

### Resolución de plantillas (sandbox)

```
nombre = "cve-2021-41773.yaml"
base   = Path(settings.nuclei_sandbox_templates).resolve()
ruta   = (base / nombre).resolve()
if not ruta.is_relative_to(base): raise ValueError  # bloquea ../traversal
```

Si `templates` está vacío y no hay sandbox configurado, el escaneo se rechaza con `ScanStatus.ERROR` (mensaje en español) para no ejecutar Nuclei sin restricción.

### Matriz de errores

| Excepción / condición | ScanStatus | error |
|-----------------------|-----------|-------|
| `FileNotFoundError` | `ERROR` | "Nuclei no encontrado. Instale Nuclei o configure ATROX_NUCLEI_PATH." |
| `asyncio.TimeoutError` | `TIMEOUT` | "El escaneo excedió el tiempo límite de {n}s" |
| Plantilla fuera del sandbox | `ERROR` | "Plantilla no permitida fuera del sandbox" |
| `Exception` genérica | `ERROR` | `str(exc)` |
| stdout vacío, sin findings | `COMPLETED` | `findings=[]` |
| findings parseados | `COMPLETED` | — |

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit | parser JSONL, sandbox, mapeo severidad, matriz errores | mock `NucleiRunner` + fixtures JSONL |
| API | `POST /api/vulnscan/scan` contrato y DI | `dependency_overrides[get_nuclei_wrapper]` |
| Integration | binario real | `@pytest.mark.integration` con skip si nuclei ausente |

## Configuration

| Setting | Env | Default |
|---------|-----|---------|
| `nuclei_path` | `ATROX_NUCLEI_PATH` | `"nuclei"` |
| `nuclei_timeout_seconds` | `ATROX_NUCLEI_TIMEOUT_SECONDS` | `600` |
| `nuclei_sandbox_templates` | `ATROX_NUCLEI_SANDBOX_TEMPLATES` | `""` |

## Migration / Rollout

No migration required. Cambio aditivo y aislado: revertir = quitar `include_router` en `main.py` y eliminar archivos nuevos.

## Open Questions

- [ ] ¿`severities`/`tags` deben validarse contra un set fijo, o pasar tal cual a Nuclei? (recomendación: pasar tal cual; Nuclei valida — bajo riesgo).
- [ ] ¿Rate-limit por defecto vía flag `-rate-limit`? (proposal lo menciona como Medium; decidir valor en tasks).
