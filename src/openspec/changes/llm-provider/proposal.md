# Proposal: Abstracción de Proveedor LLM (Cloud / Ollama) (HU-012)

## Intent

Los agentes de IA de Atrox (HU-013, HU-014, HU-015, HU-016) necesitan invocar un LLM para razonar sobre hallazgos, pero hoy la capa de decisión es 100% heurística y no existe ningún contrato para consumir un motor externo. ADR-002 exige soporte dual **Cloud (Gemini/OpenAI) vs. local (Ollama)** y la capacidad de cambiar de motor sin tocar la lógica de negocio. Esta historia introduce la capa de abstracción que lo hace posible: una interfaz común `generate(prompt, schema)`, selección de proveedor por configuración y respaldo documentado cuando el proveedor primario no responde.

## Scope

### In Scope
- Contrato común `LLMProvider.generate(prompt, schema)` async con `LLMResult` tipado y `LLMGenerationError` para fallos (red, HTTP, formato, esquema).
- Proveedores concretos: `GeminiProvider` (Cloud) y `OllamaProvider` (local), más `MockLLMProvider` para tests y desarrollo (default).
- `FallbackLLMProvider`: encadena proveedores y delega al primero que responda, registrando cada fallo.
- Fábrica `build_llm_provider(settings)` que arma la cadena primaria+respaldo según `ATROX_LLM_PROVIDER` y `ATROX_LLM_FALLBACK_PROVIDERS`.
- Configuración en `atrox/config.py` (prefijo `ATROX_`) y documentación en `.env.example`.
- Tests unitarios con red mockeada (`httpx.MockTransport`) y `MockLLMProvider` — el DoD se cumple sin llamadas reales.

### Out of Scope
- Conectar la capa a los agentes existentes (analyze/propose/evaluate, vectores, payloads, scoring): se hará en historias posteriores, que consumirán la capa vía `build_llm_provider`.
- Soporte de *streaming*, *embeddings* o *tool calling*.
- Proveedor OpenAI como implementación: la interfaz es compatible (misma forma de `generateContent`), pero el DoD exige *un* proveedor Cloud y *uno* local — Gemini + Ollama lo cumplen.
- UI de configuración de proveedores.

## Capabilities

### New Capabilities
- `llm-provider`: capa unificada para consumir LLMs Cloud/locales con contrato único, selección por configuración y respaldo automático.

### Modified Capabilities
- `ai-orchestration` (HU-013): la interfaz `PentestDecider` ya anticipa "LLM real o heurístico"; esta capa proveerá el motor real en una historia futura.

## Approach

Seguir el patrón ya consolidado de `NvdClient`: cliente HTTP async con `httpx.AsyncClient` **inyectable** (mismo argumento `http_client`) para mockear la red en tests unitarios. Cada proveedor implementa `generate(prompt, schema)` y lanza `LLMGenerationError` ante cualquier fallo (red, HTTP no-200, respuesta sin contenido, JSON inválido, clave ausente). `FallbackLLMProvider` captura ese error, registra con `logging.warning` y prueba el siguiente proveedor en la cadena. La fábrica lee la configuración y arma `[primario, *respaldo]`, omitiendo respaldos `mock` o duplicados. JSON Schema se pasa tal cual al proveedor (Gemini `responseSchema` / Ollama `format`), y el texto devuelto se parsea con un helper compartido que tolera fences markdown.

## Affected Areas

| Area | Impact | Description |
|------|--------|-------------|
| `atrox/ai/providers/` | New | Paquete con base, mock, gemini, ollama, fallback, factory |
| `atrox/ai/__init__.py` | Modified | Exporta la fábrica y el protocolo |
| `atrox/config.py` | Modified | +settings LLM (`llm_provider`, `llm_fallback_providers`, etc.) |
| `.env.example` | Modified | Documenta las variables LLM |
| `tests/test_llm_providers.py`, `tests/test_llm_factory.py` | New | Cobertura unitaria con red mockeada |
| `docs/ADR/ADR-005*` | New | Documenta decisión de abstracción y fallback |

## Risks

| Risk | Likelihood | Mitigation |
|------|------------|------------|
| Contratos REST distintos entre proveedores | Medium | Interfaz `generate(prompt, schema)` aísla la diferencia; cada proveedor encapsula su payload |
| Proveedor no responde (red caída, clave inválida, Ollama apagado) | High | `LLMGenerationError` + `FallbackLLMProvider` con logging; fallback documentado en ADR-005 |
| Respuesta del LLM no es JSON válido o viene en fences markdown | Medium | `parse_json_text` tolera fences; fallo → `LLMGenerationError` → respaldo |
| Clave de API Cloud ausente | Medium | `GeminiProvider.generate` falla con mensaje claro en runtime; no se rompe el arranque |
| Fábrica rompe ante configuración inválida | Medium | `ValueError` descriptivo en `build_single_provider`; tests de configuración |

## Rollback Plan

Cambio aditivo y aislado: el paquete `atrox/ai/providers/` no es importado por ninguna capacidad existente (los agentes siguen heurísticos). Revertir = eliminar el paquete, los settings LLM en `config.py` y las líneas de `.env.example`; `git revert` del PR restaura el estado sin migraciones ni efectos colaterales.

## Dependencies

- `httpx>=0.28.0` ya presente en `pyproject.toml`/`requirements.txt` (no se agregan dependencias).
- ADR-002 ya aprobado — define el soporte dual Cloud/local.
- Las historias HU-013..HU-016 ya definieron el patrón de agentes que consumirán esta capa.

## Success Criteria

- [ ] `generate(prompt, schema)` devuelve `LLMResult` parseado y validado como objeto JSON.
- [ ] `ATROX_LLM_PROVIDER=gemini|ollama|mock` selecciona el motor sin tocar código.
- [ ] Fallback documentado (ADR-005) y verificado con tests: proveedor primario caído → respaldo responde.
- [ ] Tests unitarios verdes con red mockeada (`httpx.MockTransport`) y `MockLLMProvider`; sin llamadas reales.
