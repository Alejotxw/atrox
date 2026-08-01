# ADR-005: Abstracción de Proveedor LLM y Fallback (HU-012)

* **Estado:** Aceptado
* **Fecha:** 1 de agosto de 2026
* **Impacto:** Medio (Infraestructura de IA)

## Contexto
ADR-002 define una arquitectura de agentes IA con soporte dual Cloud (Gemini Pro / OpenAI) y local (Ollama) para auditorías air-gapped. Los agentes de Atrox (HU-013..HU-016) son hoy heurísticos y no existe un contrato para consumir un LLM externo. Al conectar un motor, la lógica de negocio no debe depender del proveedor concreto: cambiar de Gemini a Ollama (o viceversa) debe ser una decisión de configuración, no un cambio de código. Además, un proveedor puede no responder (red caída, clave inválida, Ollama apagado), y el sistema debe degradar con gracia hacia otro motor.

## Decisión
Se introduce la capa `atrox/ai/providers/` con:

1. **Contrato único:** Protocol `LLMProvider.generate(prompt, schema)` async que retorna `LLMResult` tipado (`provider`, `model`, `content` parseado, `raw_text`) o lanza `LLMGenerationError`.
2. **Proveedores concretos:** `GeminiProvider` (Cloud, REST `generateContent` con `responseSchema`), `OllamaProvider` (local, `/api/chat` con `format=schema`) y `MockLLMProvider` (determinista, default de desarrollo/tests).
3. **Fallback:** `FallbackLLMProvider` prueba la cadena `[primario, *respaldo]` y usa el primero que responda, registrando cada fallo; si todos fallan, propaga `LLMGenerationError`.
4. **Selección por configuración:** `build_llm_provider(settings)` lee `ATROX_LLM_PROVIDER` y `ATROX_LLM_FALLBACK_PROVIDERS` (lista JSON). La lógica de negocio consume únicamente el contrato `LLMProvider`.

Los proveedores usan `httpx.AsyncClient` **inyectable** (patrón `NvdClient.http_client` de HU-005) para poder mockear la red en tests con `httpx.MockTransport`. No se agregan SDKs oficiales ni dependencias nuevas.

## Justificación Técnica
1. **Contrato único tipado:** el esquema se declara como JSON Schema y el resultado vuelve como objeto validado en la frontera; los agentes no parsean texto crudo ni conocen payloads REST.
2. **Fallback por error uniforme:** `LLMGenerationError` normaliza red, HTTP, formato y clave ausente, de modo que el respaldo se activa con una única semántica (igual que el `NvdClientError` de HU-005 no interrumpe la cola de escaneos).
3. **Clave ausente como fallo de runtime (no de arranque):** Gemini sin `ATROX_LLM_API_KEY` falla en `generate`, permitiendo que un Gemini configurado solo como respaldo no rompa el arranque de la app.
4. **Config centralizada:** settings en `atrox/config.py` con prefijo `ATROX_` (convención del repo); cambiar motor no toca código de negocio.

## Consecuencias
* **Positivas:** intercambio de motor por configuración; DoD satisfecho con tests de red mockeada y `MockLLMProvider`; base lista para las historias que conecten los agentes (HU-013..HU-016) al LLM real.
* **Negativas:** los proveedores Cloud agregan latencia de red (RNF-004 queda pendiente de medir en la integración real); el respaldo a Ollama requiere el demonio local corriendo; aún no hay validación estricta del resultado contra el JSON Schema pedido (se delega a los agentes consumidores).
* **Limitación:** el fallback actual es a nivel de proveedor; reintentos con backoff sobre el mismo motor y *circuit breakers* se evalúan en una capa futura.

## Trazabilidad Técnica
* **Requerimientos Relacionados:** RF-003, RF-004, RF-005, RNF-004.
* **ADR Relacionados:** ADR-002 (estrategia de integración IA).
* **Código:** `atrox/ai/providers/` (base, mock, gemini, ollama, fallback, factory), settings en `atrox/config.py`.
