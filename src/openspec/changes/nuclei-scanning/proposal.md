# Proposal: Integración de Escaneo de Vulnerabilidades con Nuclei (HU-003)

## Intent

El auditor de seguridad necesita ejecutar plantillas de vulnerabilidades sobre los servicios descubiertos por HU-002 (NmapWrapper) para detectar CVEs y configuraciones inseguras de forma automatizada. Hoy Atrox solo descubre activos y puertos; no evalúa exposiciones. Esta capacidad cierra el primer ciclo de auditoría: descubrir, luego evaluar.

## Scope

### In Scope
- `NucleiWrapper` async en `atrox/scanner/` con runner inyectable (mismo patrón que NmapWrapper).
- Parser JSONL defensivo de la salida de Nuclei (`-jsonl`), un hallazgo por línea.
- Modelos Pydantic: `VulnSeverity`, `VulnFinding`, `VulnScanRequest`, `VulnScanResult`.
- Endpoint independiente `POST /api/vulnscan/scan` con DI `get_nuclei_wrapper`.
- Soporte de sandbox de laboratorio vía plantillas mínimas locales.
- Configuración: `ATROX_NUCLEI_PATH`, `ATROX_NUCLEI_TIMEOUT_SECONDS`, `ATROX_NUCLEI_SANDBOX_TEMPLATES`.
- Tests unitarios (mock runner), de API (`dependency_overrides`) e integración (`@pytest.mark.integration`).

### Out of Scope
- Orquestación automática discovery→vulnscan en backend (el consumidor encadena las llamadas).
- Persistencia/historial de hallazgos en base de datos.
- UI o reporte exportable; gestión de plantillas remotas / actualización de templates.
- Priorización, deduplicación o correlación de hallazgos.

## Capabilities

### New Capabilities
- `vulnerability-scanning`: ejecución de plantillas Nuclei sobre un objetivo, parseo de hallazgos JSONL y exposición vía API REST con soporte de sandbox.

### Modified Capabilities
- None.

## Approach

Replicar el patrón consolidado de `NmapWrapper`: clase async con `runner: NucleiRunner | None` inyectable para tests, `_execute` con `asyncio.create_subprocess_exec` + `wait_for`, y manejo de `FileNotFoundError`/`TimeoutError`/`Exception` devolviendo `VulnScanResult` con `ScanStatus` reutilizado. El parser lee stdout línea a línea, ignora líneas vacías o no-JSON, y mapea cada objeto a `VulnFinding` con defaults defensivos porque los campos varían entre versiones de Nuclei. La severidad desconocida cae en `VulnSeverity.UNKNOWN`. Filtros opcionales (severidad, tags, plantillas) se traducen a flags CLI.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `atrox/scanner/nuclei_wrapper.py` | New | Wrapper async + parser JSONL |
| `atrox/api/vulnscan.py` | New | Router + `get_nuclei_wrapper` |
| `atrox/scanner/models.py` | Modified | +VulnSeverity, VulnFinding, VulnScanRequest, VulnScanResult |
| `atrox/scanner/__init__.py` | Modified | Exporta NucleiWrapper |
| `atrox/config.py` | Modified | +settings nuclei |
| `atrox/main.py` | Modified | Registra router vulnscan |
| `tests/test_nuclei_wrapper.py`, `tests/test_vulnscan_api.py`, `tests/fixtures/nuclei_samples.py` | New | Cobertura unit/API + fixtures JSONL |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Campos JSONL varían entre versiones de Nuclei | High | Parser con defaults defensivos; severidad fuera de enum → UNKNOWN |
| Binario Nuclei ausente en CI | High | Tests de integración con skip si no está instalado; unit con mock runner |
| Alto volumen de salida sin filtros | Medium | Defaults de rate-limit razonables; filtros de severidad/tags opcionales |
| Ejecución de plantillas arbitrarias (riesgo de seguridad) | Medium | Sandbox con plantillas mínimas locales vía `ATROX_NUCLEI_SANDBOX_TEMPLATES` |

## Rollback Plan

Cambio aditivo y aislado. Revertir = quitar el registro del router en `main.py` y eliminar los archivos nuevos; el rollback de los modelos y config es seguro porque ninguna capacidad existente los referencia. Un `git revert` del PR restaura el estado previo sin migraciones ni efectos colaterales.

## Dependencies

- Binario `nuclei` instalado en runtime (no requerido para unit/API tests).
- HU-002 (`NmapWrapper`) ya mergeada — provee la entrada de servicios descubiertos.

## Success Criteria

- [ ] Parser de salida Nuclei validado contra fixtures JSONL.
- [ ] `POST /api/vulnscan/scan` retorna `VulnScanResult` con hallazgos (ID, severidad, template, evidencia).
- [ ] Al menos un hallazgo de prueba reproducible en sandbox controlado.
- [ ] Tests unit/API verdes sin nuclei instalado; integración con skip condicional.
