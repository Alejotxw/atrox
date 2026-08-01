# Design: Abstracción de Proveedor LLM (Cloud / Ollama) (HU-012)

## Technical Approach

Replicar el patrón consolidado de `NvdClient` (HU-005): cliente HTTP async con `httpx.AsyncClient` inyectable (`http_client`) para mockear la red en tests con `httpx.MockTransport`. Cada proveedor implementa el protocolo `LLMProvider.generate(prompt, schema)` y traduce **todo** fallo a `LLMGenerationError` (red, HTTP no-200, sin contenido, JSON inválido, clave ausente) — así el `FallbackLLMProvider` puede encadenarlos sin conocer detalles de cada motor. El JSON Schema se pasa al proveedor tal cual (Gemini `responseSchema`, Ollama `format`); el texto devuelto se parsea con `parse_json_text`, que tolera fences markdown. No se agregan dependencias nuevas: `httpx` ya está en `pyproject.toml`.

## Architecture Decisions

| # | Decisión | Elegido | Rechazado | Rationale |
|---|----------|---------|-----------|-----------|
| 1 | Contrato | Protocol `LLMProvider` async + `LLMResult` (pydantic) + `LLMGenerationError` | Interfaz síncrona / `Any` crudo | Backend es asyncio (ADR-001); contrato tipado para validar estructura en la frontera |
| 2 | Mecanismo de red | `httpx.AsyncClient` inyectable por proveedor (mismo patrón que `NvdClient.http_client`) | SDKs oficiales (google-genai, openai) | Mantiene la dependencia única ya presente; tests con `MockTransport` sin red real; SDK local solo en historias que lo justifiquen |
| 3 | Clave Cloud ausente | `GeminiProvider.generate` lanza `LLMGenerationError` en runtime | `ValueError` en `__init__` | Un fallback Gemini sin clave no debe romper el arranque; la ausencia de clave se comporta como fallo de proveedor → entra el respaldo |
| 4 | Fallback | `FallbackLLMProvider` compone proveedores; logging.warning por fallo; propaga el último error | Retry con backoff sobre el mismo proveedor | El DoD pide respaldo entre motores; retry/intentos se delega a una capa futura (YAGNI) |
| 5 | Fábrica | `build_llm_provider(settings)` arma `[primario, *respaldo]`, omite `mock`/duplicados | Lectura ad-hoc de `os.environ` | Config centralizada en `Settings` (convención del repo); `mock` como respaldo ocultaría fallos reales |
| 6 | Parseo de JSON | `parse_json_text` compartido en `base.py`, tolera fences ```json | `json.loads` directo en cada proveedor | Gemini/Ollama a veces envuelven la salida en fences; fallo → `LLMGenerationError` → respaldo |
| 7 | Estructura de paquete | `atrox/ai/providers/` plano (base, mock, gemini, ollama, fallback, factory) | Un archivo `llm.py` monolítico | Coherente con `atrox/security/`, `atrox/threat_intel/`; separación clara por responsabilidad |

## Data Flow

```
build_llm_provider(settings)
  1. primario = build_single_provider(settings.llm_provider, settings)
  2. respaldos = [build_single_provider(n, settings)
                  for n in settings.llm_fallback_providers
                  if n != primario y n != "mock"]
  3. retorna primario (sin respaldo) o FallbackLLMProvider(chain)

generate(prompt, schema)
  FallbackLLMProvider.generate
    for provider in [primario, *respaldo]:
        try:    return await provider.generate(prompt, schema)      # LLMResult
        except LLMGenerationError as exc: logger.warning(...)        # siguiente

  GeminiProvider.generate
    POST {base}/models/{model}:generateContent
      body: contents[].parts[].text, generationConfig.responseSchema
      auth: x-goog-api-key
    → text = candidates[0].content.parts[0].text  → parse_json_text → LLMResult

  OllamaProvider.generate
    POST {base}/api/chat
      body: model, messages[], stream=false, format=schema, options.temperature=0
    → text = message.content → parse_json_text → LLMResult
```

## File Changes

| File | Action | Description |
|------|--------|-------------|
| `atrox/ai/providers/base.py` | Create | Protocol `LLMProvider`, `LLMResult`, `LLMGenerationError`, `parse_json_text` |
| `atrox/ai/providers/mock.py` | Create | `MockLLMProvider` determinista para tests/desarrollo |
| `atrox/ai/providers/gemini.py` | Create | `GeminiProvider` REST `generateContent` con cliente inyectable |
| `atrox/ai/providers/ollama.py` | Create | `OllamaProvider` `/api/chat` con cliente inyectable |
| `atrox/ai/providers/fallback.py` | Create | `FallbackLLMProvider` con cadena y logging |
| `atrox/ai/providers/factory.py` | Create | `build_llm_provider`, `build_single_provider` |
| `atrox/ai/providers/__init__.py` | Create | Exporta la API pública del paquete |
| `atrox/ai/__init__.py` | Modify | Exporta `build_llm_provider` y `LLMProvider` |
| `atrox/config.py` | Modify | +settings LLM (prefijo `ATROX_`) |
| `.env.example` | Modify | Documenta variables LLM |
| `tests/test_llm_providers.py` | Create | Unit providers/fallback con `MockTransport` |
| `tests/test_llm_factory.py` | Create | Unit fábrica y configuración |

## Interfaces / Contracts

```python
# ai/providers/base.py
class LLMGenerationError(Exception): ...

class LLMResult(BaseModel):
    provider: str
    model: str
    content: dict[str, Any]
    raw_text: str

class LLMProvider(Protocol):
    name: str
    model: str
    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult: ...

def parse_json_text(text: str) -> dict[str, Any]:
    """Parsea JSON tolerando fences ```json; lanza LLMGenerationError si no es objeto."""

# ai/providers/gemini.py
class GeminiProvider:
    name = "gemini"
    def __init__(self, *, api_key: str, model="gemini-2.0-flash",
                 base_url=GEMINI_BASE_URL, timeout_seconds=30,
                 http_client: httpx.AsyncClient | None = None) -> None: ...
    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult: ...

# ai/providers/ollama.py
class OllamaProvider:
    name = "ollama"
    def __init__(self, *, model="llama3", base_url="http://localhost:11434",
                 timeout_seconds=30, http_client: httpx.AsyncClient | None = None) -> None: ...
    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult: ...

# ai/providers/mock.py
class MockLLMProvider:
    name = "mock"
    def __init__(self, model="mock-model", content: dict[str, Any] | None = None) -> None: ...
    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult: ...

# ai/providers/fallback.py
class FallbackLLMProvider:
    def __init__(self, providers: Sequence[LLMProvider]) -> None: ...
    async def generate(self, prompt: str, schema: dict[str, Any]) -> LLMResult: ...

# ai/providers/factory.py
def build_single_provider(name: str, settings: Settings) -> LLMProvider: ...
def build_llm_provider(settings: Settings) -> LLMProvider: ...
```

### Payload Gemini (`generateContent`)

```json
{
  "contents": [{"parts": [{"text": "<prompt>"}]}],
  "generationConfig": {
    "responseMimeType": "application/json",
    "responseSchema": { "<schema>" },
    "temperature": 0
  }
}
```

Respuesta exitosa: `candidates[0].content.parts[0].text` → `parse_json_text`.

### Payload Ollama (`/api/chat`)

```json
{
  "model": "llama3",
  "messages": [{"role": "user", "content": "<prompt>"}],
  "stream": false,
  "format": { "<schema>" },
  "options": {"temperature": 0}
}
```

Respuesta exitosa: `message.content` → `parse_json_text`. Si `format` no se soporta en la versión instalada, Ollama responde HTTP 4xx → `LLMGenerationError` (el respaldo lo cubre).

### Matriz de errores

| Condición | Resultado |
|-----------|-----------|
| Red caída / DNS / conexión rechazada (`httpx.HTTPError`, `OSError`) | `LLMGenerationError` "Error de red al llamar a {proveedor}" |
| HTTP != 200 | `LLMGenerationError` "respondió HTTP {status}: {text[:300]}" |
| Respuesta sin candidatos/texto o sin `message.content` | `LLMGenerationError` "sin contenido" |
| Texto no parseable como objeto JSON | `LLMGenerationError` "no es JSON válido" |
| `api_key` ausente (Gemini) | `LLMGenerationError` "requiere ATROX_LLM_API_KEY" |
| Nombre de proveedor desconocido (fábrica) | `ValueError` listando válidos |
| `FallbackLLMProvider` sin proveedores | `ValueError` en construcción |

## Testing Strategy

| Layer | What | Approach |
|-------|------|----------|
| Unit (providers) | Gemini/Ollama éxito, fences, HTTP error, sin contenido, no-JSON, sin clave, sin candidatos | `httpx.MockTransport` inyectado como `http_client` |
| Unit (mock) | Contenido prefijado y default echo | `MockLLMProvider` directo |
| Unit (fallback) | Primario caído → respaldo; todos fallan; lista vacía | Proveedores `MockLLMProvider`/stubs que lanzan `LLMGenerationError` |
| Unit (factory) | mock default, gemini+ollama→Fallback, desconocido→ValueError, respaldo duplicado/mock omitido | `Settings` con atributos sobreescritos |
| Config | Defaults y override por entorno | `Settings(llm_provider="ollama", _env_file=None)` |

No se requieren llamadas reales: todo el DoD se cumple con red mockeada (`httpx.MockTransport`) y `MockLLMProvider`.

## Configuration

| Setting | Env | Default |
|---------|-----|---------|
| `llm_provider` | `ATROX_LLM_PROVIDER` | `"mock"` |
| `llm_model` | `ATROX_LLM_MODEL` | `None` (usa el default del proveedor) |
| `llm_api_key` | `ATROX_LLM_API_KEY` | `None` |
| `llm_timeout_seconds` | `ATROX_LLM_TIMEOUT_SECONDS` | `30` |
| `llm_gemini_model` | `ATROX_LLM_GEMINI_MODEL` | `"gemini-2.0-flash"` |
| `llm_ollama_base_url` | `ATROX_LLM_OLLAMA_BASE_URL` | `"http://localhost:11434"` |
| `llm_ollama_model` | `ATROX_LLM_OLLAMA_MODEL` | `"llama3"` |
| `llm_fallback_providers` | `ATROX_LLM_FALLBACK_PROVIDERS` | `[]` (JSON list, ej. `'["ollama"]'`) |

## Migration / Rollout

No migration required. Cambio aditivo y aislado: ningún módulo existente importa el paquete. El default `mock` garantiza que el comportamiento actual de la app no cambia hasta que una historia futura consume `build_llm_provider`.

## Open Questions

- [ ] ¿`parse_json_text` debe validar el resultado contra el JSON Schema pedido? (requiere dependencia `jsonschema`; recomendación: delegar la validación estricta a los agentes consumidores — YAGNI hoy).
- [ ] ¿`ATROX_LLM_API_KEY` reutiliza `GEMINI_API_KEY` estándar o se mantiene con prefijo `ATROX_`? (decisión: prefijo `ATROX_` por convención del repo; se puede mapear en despliegue).
