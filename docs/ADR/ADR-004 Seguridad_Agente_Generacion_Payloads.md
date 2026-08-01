# ADR-004: Revisión de Seguridad del Agente de Generación de Payloads (HU-015)

* **Estado:** Aceptado
* **Fecha:** 30 de julio de 2026
* **Impacto:** Alto (Seguridad — contenido dual-use)

## Contexto
HU-015 (`POST /api/ai/payloads/generate`) introduce un agente que sugiere *payloads* (cadenas de inyección SQL, XSS, RCE, LFI, SSRF, credenciales por defecto) asociados a un hallazgo de Nuclei. Este es contenido de doble uso por naturaleza: el mismo texto que acelera la validación autorizada en laboratorio es directamente utilizable para explotación no autorizada si el módulo se ejecuta o se expone fuera de su contexto previsto. La revisión cubre el diseño implementado en `atrox/ai/agents/payloads/` y `atrox/api/payloads.py`.

## Alcance de la revisión
1. **Capacidad de ejecución.** ¿El agente puede, directa o indirectamente, ejecutar los payloads que sugiere contra un objetivo?
2. **Origen del contenido.** ¿De dónde salen los payloads? ¿Hay riesgo de inyección de prompt o de contenido no controlado (relevante si en el futuro se conecta un LLM real, ver ADR-002)?
3. **Trazabilidad.** ¿Queda registro de quién solicitó payloads para qué hallazgo?
4. **Advertencia de uso.** ¿El consumidor de la API puede ignorar que el contenido es solo para entorno autorizado?
5. **Confidencialidad en reposo.** ¿Debe cifrarse este contenido si se persiste?

## Hallazgos y decisiones

### 1. Sin capacidad de ejecución (por diseño)
El agente (`generator.py`, `library.py`) es un catálogo heurístico en memoria: recibe un `VulnFinding`, infiere categoría/servicio por coincidencia de tags/nombre/`template_id`, y devuelve texto desde una tabla estática (`PAYLOAD_RULES`). No hay `subprocess`, `socket`, cliente HTTP, ni ningún mecanismo de red o de shell en el módulo. `test_payload_generator.py::TestPayloadAgentIsSandboxed` verifica esto de forma estática (AST) sobre cada archivo del agente, fallando la suite si alguien introduce un import con capacidad de ejecución (`subprocess`, `socket`, `os`, `requests`, `httpx`, `aiohttp`, `paramiko`). Esto es el "sandbox de prueba" exigido por el DoD: no es un entorno aislado en tiempo de ejecución (no hace falta, porque el módulo no ejecuta nada), sino una garantía verificada en cada corrida de tests de que el módulo nunca gana esa capacidad sin que el cambio se note.

### 2. Sin LLM conectado — no aplica (aún) superficie de prompt injection
A la fecha de esta revisión, ningún módulo del backend invoca un LLM real (se confirmó ausencia de `langchain-openai`, `langchain-anthropic`, `openai`, `anthropic` en `pyproject.toml` y de cualquier instanciación de cliente LLM en `atrox/`). El catálogo es estático y curado por el equipo, no generado dinámicamente a partir de texto no confiable (nombre/descripción del finding no se interpolan en los payloads devueltos, solo se usan para *matching* de categoría). Cuando ADR-002 se materialice con un LLM real, esta decisión debe revisarse: en ese punto, el `description`/`name` del finding (que proviene de plantillas de terceros vía Nuclei) pasaría a ser input no confiable hacia el LLM y requeriría sanitización explícita antes de esta fecha.

### 3. Trazabilidad vía log de auditoría existente
`POST /api/ai/payloads/generate` registra un evento `payload.generated` en el log de auditoría firmado de HU-008 (`atrox/security/audit_service.py`) cuando está configurado (`ATROX_AUDIT_SIGNING_KEY`), con `resource=finding:{finding_id}` y metadata de categoría/servicio — mismo patrón ya usado por `scan.submitted` (HU-004) y `scan.created` (HU-009). Si el audit log no está configurado, la generación de payloads igual funciona (no se degrada la disponibilidad por auditoría faltante), consistente con el resto de la API.

### 4. Advertencia obligatoria y no omitible
`PayloadGenerationResult.disclaimer` es un campo **siempre presente** en la respuesta (no opcional, no se puede desactivar vía parámetro), con el texto fijo `LAB_ONLY_DISCLAIMER` (`atrox/ai/agents/payloads/models.py`). `test_payloads_api.py::test_response_includes_authorized_lab_only_disclaimer` y el test de contrato OpenAPI (`test_payloads_contract.py`) verifican que el campo forma parte del esquema publicado, por lo que cualquier cliente que integre contra el contrato lo recibe siempre.

### 5. Confidencialidad en reposo — pendiente, documentado como deuda
Este agente es **stateless**: no persiste resultados (igual que el agente de vectores de HU-014). `ATROX_ENCRYPTION_MASTER_KEY` y `sensitive_fields.py` (ADR-003) protegen campos como `finding.poc`/`finding.evidence` cuando se persisten hallazgos, pero los payloads sugeridos por este endpoint no se escriben a `data/encrypted/*.jsonl` ni a ningún otro almacén hoy. **Decisión:** si una futura HU persiste el resultado de este agente (por ejemplo, para históricos de validación), la categoría `"finding"` de `SENSITIVE_FIELDS` (`atrox/security/sensitive_fields.py`) debe extenderse para cubrir el campo de payload antes de habilitar esa persistencia — no después.

## Consecuencias
* **Positivas:** Superficie de riesgo mínima (sin ejecución, sin red, sin estado); advertencia de uso autorizado imposible de omitir en el contrato; trazabilidad reutilizando la infraestructura de auditoría ya certificada en HU-008.
* **Negativas:** El catálogo es curado manualmente y limitado a categorías conocidas (`sqli`, `xss`, `rce`, `lfi`, `ssrf`, `default-login`); hallazgos fuera de catálogo devuelven una sugerencia genérica sin payload, requiriendo intervención manual del pentester — es una limitación aceptada a cambio de no fabricar contenido no verificado.

## Trazabilidad Técnica
* **Requerimientos Relacionados:** RF-004, RNF-004.
* **Historias de Usuario:** HU-015 (este módulo), depende de HU-003 (`VulnFinding`), reutiliza HU-008 (auditoría) y HU-009 (patrón de router).
