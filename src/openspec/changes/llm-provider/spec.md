# LLM Provider Abstraction Specification

## Purpose

Define la capa unificada para consumir LLMs en Atrox: contrato común `generate(prompt, schema)`, proveedores concretos (Gemini Cloud, Ollama local, Mock), selección por configuración y respaldo automático documentado cuando el proveedor no responde.

## Requirements

### Requirement: Interfaz común de generación

El sistema MUST exponer un contrato `LLMProvider` con método async `generate(prompt: str, schema: dict) -> LLMResult`, donde `schema` es un JSON Schema que el proveedor debe respetar y `LLMResult` contiene `provider`, `model`, `content` (objeto parseado) y `raw_text`. Cualquier fallo (red, HTTP, formato, esquema, clave ausente) MUST lanzar `LLMGenerationError`.

#### Scenario: Generación estructurada exitosa

- GIVEN un proveedor que responde con texto JSON válido para el esquema
- WHEN se invoca `generate(prompt, schema)`
- THEN se retorna un `LLMResult` con `content` parseado como objeto y `raw_text` con el texto crudo

#### Scenario: Respuesta en fences markdown

- GIVEN un proveedor que responde con el JSON envuelto en ```json ... ```
- WHEN se invoca `generate(prompt, schema)`
- THEN `content` se parsea correctamente ignorando los fences

#### Scenario: Proveedor no responde

- GIVEN un proveedor que lanza error de red o HTTP no-200
- WHEN se invoca `generate(prompt, schema)`
- THEN se lanza `LLMGenerationError` con mensaje descriptivo

#### Scenario: Respuesta sin contenido

- GIVEN un proveedor que responde 200 pero sin texto utilizable
- WHEN se invoca `generate(prompt, schema)`
- THEN se lanza `LLMGenerationError`

#### Scenario: Respuesta no-JSON

- GIVEN un proveedor que responde texto que no es un objeto JSON válido
- WHEN se invoca `generate(prompt, schema)`
- THEN se lanza `LLMGenerationError`

### Requirement: Proveedor Cloud (Gemini)

El sistema MUST incluir un proveedor Cloud `GeminiProvider` que llame a la REST API `generateContent` de Gemini con `responseMimeType=application/json` y `responseSchema=schema`. MUST aceptar `api_key`, `model`, `base_url`, `timeout_seconds` y `http_client` inyectable (patrón `NvdClient`).

#### Scenario: Llamada válida a Gemini

- GIVEN `api_key` configurada y un `http_client` que responde con `candidates[0].content.parts[0].text` en JSON
- WHEN se invoca `generate(prompt, schema)`
- THEN se retorna `LLMResult` con `provider == "gemini"`

#### Scenario: Gemini sin api_key

- GIVEN `api_key` vacía o ausente
- WHEN se invoca `generate(prompt, schema)`
- THEN se lanza `LLMGenerationError` indicando que falta `ATROX_LLM_API_KEY`

#### Scenario: Gemini sin candidatos

- GIVEN respuesta 200 sin campo `candidates`
- WHEN se invoca `generate(prompt, schema)`
- THEN se lanza `LLMGenerationError`

### Requirement: Proveedor local (Ollama)

El sistema MUST incluir un proveedor local `OllamaProvider` que llame a la API `/api/chat` de Ollama con `format=schema`, `stream=false` y `options.temperature=0`. MUST aceptar `model`, `base_url`, `timeout_seconds` y `http_client` inyectable. No envía datos a la nube.

#### Scenario: Llamada válida a Ollama

- GIVEN un `http_client` que responde con `message.content` en JSON
- WHEN se invoca `generate(prompt, schema)`
- THEN se retorna `LLMResult` con `provider == "ollama"`

#### Scenario: Payload correcto hacia Ollama

- GIVEN un `http_client` que captura el request
- WHEN se invoca `generate(prompt, schema)`
- THEN el body contiene `model`, `messages[0].content == prompt`, `stream == false` y `format == schema`

#### Scenario: Ollama responde sin contenido

- GIVEN respuesta 200 sin `message.content`
- WHEN se invoca `generate(prompt, schema)`
- THEN se lanza `LLMGenerationError`

### Requirement: Proveedor Mock para tests

El sistema MUST incluir un `MockLLMProvider` determinista sin red que devuelva `content` prefijado. MUST aceptar `content` opcional y `model`. Se usa como default de desarrollo (`ATROX_LLM_PROVIDER=mock`) y para los tests del DoD.

#### Scenario: Mock devuelve contenido prefijado

- GIVEN un `MockLLMProvider(content={"analysis": "ok"})`
- WHEN se invoca `generate("...", {...})`
- THEN se retorna `LLMResult` con `content == {"analysis": "ok"}` y `provider == "mock"`

#### Scenario: Mock con contenido por defecto

- GIVEN un `MockLLMProvider()` sin content
- WHEN se invoca `generate(prompt, schema)`
- THEN `content` contiene `"echo"` con el prompt

### Requirement: Fallback automático

El sistema MUST incluir `FallbackLLMProvider` que pruebe una secuencia de proveedores en orden y retorne el `LLMResult` del primero que tenga éxito. Debe registrar cada fallo con `logging.warning` y, si todos fallan, propagar `LLMGenerationError`.

#### Scenario: Primario caído, respaldo responde

- GIVEN un primario que lanza `LLMGenerationError` y un respaldo que responde
- WHEN se invoca `generate(prompt, schema)` sobre el fallback
- THEN se retorna el resultado del respaldo con su `provider`

#### Scenario: Todos los proveedores fallan

- GIVEN una cadena donde todos los proveedores lanzan `LLMGenerationError`
- WHEN se invoca `generate(prompt, schema)`
- THEN se propaga `LLMGenerationError`

#### Scenario: Fallback sin proveedores

- GIVEN un `FallbackLLMProvider()` construido con lista vacía
- THEN la construcción lanza `ValueError`

### Requirement: Selección por configuración

El sistema MUST seleccionar el proveedor primario vía `ATROX_LLM_PROVIDER` y el orden de respaldo vía `ATROX_LLM_FALLBACK_PROVIDERS` (lista JSON). `build_llm_provider(settings)` MUST retornar el proveedor único si no hay respaldo, o un `FallbackLLMProvider` con la cadena. Un nombre desconocido MUST lanzar `ValueError`.

#### Scenario: Proveedor mock por default

- GIVEN settings con `llm_provider == "mock"` y sin respaldos
- WHEN se invoca `build_llm_provider(settings)`
- THEN se retorna un `MockLLMProvider`

#### Scenario: Gemini con respaldo Ollama

- GIVEN settings con `llm_provider == "gemini"` y `llm_fallback_providers == ["ollama"]`
- WHEN se invoca `build_llm_provider(settings)`
- THEN se retorna un `FallbackLLMProvider` cuyos nombres son `gemini` y `ollama`

#### Scenario: Proveedor desconocido

- GIVEN settings con `llm_provider == "unknown"`
- WHEN se invoca `build_llm_provider(settings)`
- THEN se lanza `ValueError` con mensaje en español listando los válidos

#### Scenario: Respaldo mock o duplicado se omite

- GIVEN settings con `llm_provider == "gemini"` y `llm_fallback_providers == ["gemini", "mock", "ollama"]`
- WHEN se invoca `build_llm_provider(settings)`
- THEN la cadena resultante contiene solo `gemini` y `ollama`

### Requirement: Configuración centralizada

El sistema MUST registrar los settings LLM en `atrox/config.py::Settings` con prefijo `ATROX_`: `llm_provider` (default `"mock"`), `llm_model` (opcional), `llm_api_key`, `llm_timeout_seconds` (30), `llm_gemini_model` (`"gemini-2.0-flash"`), `llm_ollama_base_url` (`"http://localhost:11434"`), `llm_ollama_model` (`"llama3"`), `llm_fallback_providers` (lista, default `[]`).

#### Scenario: Defaults de configuración

- GIVEN settings por defecto
- WHEN se leen los atributos LLM
- THEN `llm_provider == "mock"`, `llm_timeout_seconds == 30`, `llm_fallback_providers == []`

#### Scenario: Override vía variable de entorno

- GIVEN `ATROX_LLM_PROVIDER=ollama` en el entorno
- WHEN se carga Settings
- THEN `llm_provider == "ollama"` y `llm_ollama_base_url == "http://localhost:11434"`
