# Evaluación del Validador Estructurado de Respuestas IA — HU-017

**Trazabilidad:** RF-003 · RF-004 · RF-005 · ADR-002
**Módulo:** `src/Backend/atrox/ai/schemas/`
**Tests:** `src/Backend/tests/test_llm_response_validator.py`, `test_validate_api.py`, `test_validate_contract.py`

---

## Qué valida y por qué

`POST /api/ai/validate` recibe la **respuesta cruda de un LLM** (`raw`) y un tipo de salida (`kind`). Valida esa respuesta contra el esquema Pydantic esperado **antes** de que cualquier dato llegue al motor de escaneo o a los reportes: si no cumple el esquema, se rechaza con un error controlado (`422`) y nunca fluye hacia aguas abajo.

El validador soporta los tres tipos de salida IA de la cadena (registrados en `atrox/ai/schemas/registry.py`, reutilizando los modelos de cada agente):

| `kind` | Esquema Pydantic | Origen |
| :--- | :--- | :--- |
| `vectors` | `VectorAnalysisResult` (RF-003) | `atrox/ai/agents/vectors/models.py` (HU-014) |
| `payloads` | `PayloadGenerationResult` (RF-004) | `atrox/ai/agents/payloads/models.py` (HU-015) |
| `scores` | `ConfidenceScoreResult` (RF-005) | `atrox/ai/agents/scoring/models.py` (HU-016) |

## Cómo valida (flujo `validator.py`)

1. **Extracción de JSON** (`extract_json_object`): acepta bloques markdown ```json, JSON plano o prosa con un objeto/arreglo JSON embebido; busca el primer JSON balanceado respetando cadenas de texto y anidación.
2. **Parseo**: `json.loads`; falla → `InvalidJSONError` (JSON malformado, respuesta vacía, prosa sin JSON).
3. **Validación del esquema**: `Model.model_validate`; falla → `SchemaRejectionError` (campo faltante, tipo incorrecto, valor fuera de rango — ej. `score` fuera de 0–100).
4. **Rechazo**: se registra en el log de rechazos (`rejections.py`), que mantiene un buffer en memoria siempre consultable y, si `ATROX_LLM_REJECTION_LOG_PATH` está configurado, persiste en JSONL append-only (mismo patrón que el log de auditoría HU-008).

## Reintento o error controlado

`LLMResponseValidator.validate(llm_invoke, kind=...)` encapsula la lógica de reintento:

- Si la respuesta es inválida, se registra el rechazo y se vuelve a invocar al LLM (`llm_invoke`) hasta `max_retries` veces (default `ATROX_LLM_VALIDATION_MAX_RETRIES`, sobre-escribible por llamada).
- Agotados los intentos, se lanza `ValidationRetriesExhaustedError` — **error controlado**, nunca un crash ni datos malformados hacia el motor de escaneo.
- Un `kind` no registrado lanza `UnknownOutputKindError` (respuesta `422`, sin registrar rechazo: no es una respuesta del LLM).

## Cobertura del validador en CI (DoD)

El job `backend-smoke` de `.github/workflows/ci.yml` (workflow real, en `.github/` en minúsculas) incluye un **paso dedicado** que ejecuta explícitamente los tres archivos de test del validador, además de correr la suite completa de unit tests:

```yaml
- name: Cobertura del validador de respuestas IA (HU-017)
  run: pytest tests/test_llm_response_validator.py tests/test_validate_api.py tests/test_validate_contract.py -v
```

Esto garantiza que cualquier cambio en el validador (o en los modelos que valida) rompe CI si no cumple las respuestas válidas e inválidas definidas.

## Tests

- **`test_llm_response_validator.py`** — núcleo del validador: registro de esquemas (3 kinds), respuestas **válidas** (fence markdown, JSON plano, prosa + JSON, las 3 kinds vía `validate`), respuestas **inválidas** (JSON malformado, vacío, prosa sin JSON, campo faltante, tipo incorrecto, valor fuera de rango), **reintento** (éxito tras primer rechazo, agotamiento con error controlado, sin retry por defecto, `kind` desconocido sin invocar al LLM) y **log de rechazos** (buffer en memoria, persistencia JSONL, truncado de `raw` para depuración).
- **`test_validate_api.py`** — `POST /api/ai/validate`: `200` con `valid: true` + datos validados; `422` con `InvalidJSONError`/`SchemaRejectionError`/`UnknownOutputKindError`; el rechazo se registra con su `rejection_id`.
- **`test_validate_contract.py`** — contrato OpenAPI: ruta documentada, request con `kind`/`raw` requeridos, envelope de respuesta (`valid`, `kind`, `data`, `error`, `detail`, `rejection_id`), respuesta `422` documentada.

```bash
cd src/Backend
pytest tests/test_llm_response_validator.py tests/test_validate_api.py tests/test_validate_contract.py -v
```

## Limitaciones conocidas

1. **Los agentes actuales son heurísticos** (HU-014/HU-015/HU-016), no hay LLM conectado todavía (verificado: ningún cliente `ChatOpenAI`/`ChatAnthropic` en `atrox/`). El validador es la capa de protección que se activará en cuanto se conecte un adaptador LLM real (ADR-002); hoy valida respuestas crudas de forma explícita vía API y sirve como infraestructura de prueba.
2. **Un JSON semánticamente válido pero engañoso** (datos plausibles pero incorrectos) no se detecta: Pydantic valida estructura y rangos, no el contenido. La validación de *calidad* del contenido queda para heurística (HU-016) o revisión humana.
3. **Extracción por primer JSON balanceado**: si la respuesta incluyera varios objetos JSON completos, solo se valida el primero.
4. **El log persistente es opt-in** (`ATROX_LLM_REJECTION_LOG_PATH`); sin él, los rechazos solo quedan en memoria y en el log estándar de la aplicación (`logging`, nivel ERROR).
