# Tasks: Abstracción de Proveedor LLM (Cloud / Ollama) (HU-012)

## Review Workload Forecast

| Field | Value |
|-------|-------|
| Estimated changed lines | 430-480 |
| 400-line budget risk | High |
| Chained PRs recommended | Yes |
| Suggested split | PR 1 (base+mock+gemini+ollama+tests) -> PR 2 (fallback+factory+config+tests) -> PR 3 (docs) |
| Delivery strategy | ask-on-risk |
| Chain strategy | pending |

Decision needed before apply: Yes
Chained PRs recommended: Yes
Chain strategy: pending
400-line budget risk: High

### Suggested Work Units

| Unit | Goal | Likely PR | Notes |
|------|------|-----------|-------|
| 1 | base + mock + gemini + ollama + unit tests | PR 1 | Base: HU/012; standalone, no fallback needed |
| 2 | fallback + factory + config + tests | PR 2 | Base: PR 1 branch; depends on PR 1 |
| 3 | ADR-005 + .env.example + verify-report | PR 3 | Base: PR 2 branch; docs only |

## Phase 1: Foundation (base + mock) -- TDD

- [x] 1.1 RED: Add test stubs in `tests/test_llm_providers.py` importing LLMProvider, LLMResult, LLMGenerationError, MockLLMProvider -- tests fail (package missing). [Spec: Interfaz común, Mock]
- [x] 1.2 GREEN: Create `atrox/ai/providers/base.py` (LLMGenerationError, LLMResult, LLMProvider Protocol, parse_json_text) y `atrox/ai/providers/mock.py` (MockLLMProvider). [Spec: Interfaz común, Mock]
- [x] 1.3 Add package exports in `atrox/ai/providers/__init__.py`. [Spec: Interfaz común]

## Phase 2: Proveedores concretos (gemini + ollama) -- TDD

- [x] 2.1 RED: Write Gemini tests with `httpx.MockTransport`: success JSON, fences markdown, HTTP 500, no candidates, no api_key, non-JSON text. [Spec: Proveedor Cloud]
- [x] 2.2 GREEN: Create `atrox/ai/providers/gemini.py` (GeminiProvider con http_client inyectable). [Spec: Proveedor Cloud]
- [x] 2.3 RED: Write Ollama tests with `httpx.MockTransport`: success, request body (model/messages/stream/format), HTTP error, network error, no content. [Spec: Proveedor local]
- [x] 2.4 GREEN: Create `atrox/ai/providers/ollama.py` (OllamaProvider con http_client inyectable). [Spec: Proveedor local]

## Phase 3: Fallback + Factory + Config -- TDD

- [x] 3.1 RED: Write fallback tests: primary down → backup responds; all fail → LLMGenerationError; empty list → ValueError. [Spec: Fallback]
- [x] 3.2 GREEN: Create `atrox/ai/providers/fallback.py` (FallbackLLMProvider). [Spec: Fallback]
- [x] 3.3 RED: Write factory/config tests in `tests/test_llm_factory.py`: mock default, gemini+ollama→Fallback names, unknown→ValueError, duplicate/mock backup skipped, env override. [Spec: Selección por configuración, Configuración]
- [x] 3.4 GREEN: Create `atrox/ai/providers/factory.py` (build_single_provider, build_llm_provider); add LLM settings a `atrox/config.py`; export factory en `atrox/ai/__init__.py`. [Spec: Selección por configuración, Configuración]

## Phase 4: Documentación

- [x] 4.1 Add LLM variables to `.env.example` (con comentario de fallback). [Spec: Configuración]
- [x] 4.2 Create ADR-005 documenting the abstraction, provider selection, and fallback strategy. [Spec: Fallback]
- [ ] 4.3 Run `pytest tests/ -v -m "not integration"` and fill `verify-report.md`.
