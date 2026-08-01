# Backlog Técnico — Atrox Framework

**Proyecto:** Framework de Pentesting Automatizado Asistido por Inteligencia Artificial  
**Rol:** Scrum Master / Ingeniero de Software Principal  
**Versión:** 1.0  
**Fecha:** 20 de junio de 2026

---

## 1. Propósito

Este documento inicializa el backlog técnico del framework **Atrox** con un catálogo cerrado de **24 historias de usuario funcionales**, validadas bajo la metodología **INVEST**. Cada ítem describe una funcionalidad **exclusiva y ejecutable** dentro del ciclo de desarrollo, trazable al alcance del producto: motor de escaneo base, capa de datos segura, orquestación con IA e interfaz operativa.

---

## 2. Hoja de Ruta Incremental (Sprints)

| Sprint | Épica | Historias | Objetivo incremental |
| :--- | :--- | :--- | :--- |
| **S1** | Núcleo de escaneo | HU-001 → HU-005 | Motor base operativo: descubrimiento, vulnerabilidades y concurrencia. |
| **S2** | Persistencia y seguridad | HU-006 → HU-008 | Almacenamiento cifrado, modelos de datos y auditoría inmutable. |
| **S3** | API de orquestación | HU-009 → HU-011 | Exposición REST y programación de escaneos recurrentes. |
| **S4** | Módulos de IA | HU-012 → HU-017 | Agentes LLM, análisis de vectores, payloads y filtrado de falsos positivos. |
| **S5** | Interfaz y reportes | HU-018 → HU-024 | Panel operativo, autenticación MFA y generación de reportes. |

---

## 3. Catálogo de Historias de Usuario

### Épica E1 — Motor de Escaneo Base

#### HU-001 — Bootstrap del núcleo FastAPI asíncrono
**Como** desarrollador del framework, **quiero** inicializar el backend con FastAPI y `asyncio`, **para** disponer de un punto de entrada no bloqueante que soporte escaneos concurrentes y futuras integraciones con IA.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S1 |
| **Trazabilidad** | ADR-001 · RNF-007 |
| **Criterios de aceptación** | 1) Existe endpoint `GET /health` que responde `200` en `< 500 ms`. 2) El servidor arranca con Uvicorn en modo async. 3) Existe configuración centralizada por variables de entorno. |
| **Definition of Done** | Proyecto Python empaquetado, CI ejecuta smoke test del healthcheck, documentación de arranque local. |

---

#### HU-002 — Descubrimiento de activos con wrapper Nmap
**Como** auditor de seguridad, **quiero** lanzar un escaneo de descubrimiento sobre una IP o dominio, **para** identificar puertos abiertos y servicios expuestos en el objetivo.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S1 |
| **Trazabilidad** | RF-001 · ADR-001 |
| **Criterios de aceptación** | 1) El módulo acepta objetivo (`IP` o `FQDN`) y rango de puertos. 2) Retorna JSON con puerto, protocolo, servicio y versión detectada. 3) Maneja timeout y objetivo inalcanzable sin caída del proceso. |
| **Definition of Done** | Tests unitarios con salida Nmap mockeada; integración probada contra target de laboratorio. |

---

#### HU-003 — Escaneo de vulnerabilidades con Nuclei
**Como** auditor de seguridad, **quiero** ejecutar plantillas de vulnerabilidades sobre los servicios descubiertos, **para** detectar CVEs y configuraciones inseguras de forma automatizada.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S1 |
| **Trazabilidad** | RF-002 |
| **Criterios de aceptación** | 1) Consume la salida de HU-002 como entrada. 2) Emite hallazgos con ID, severidad, template y evidencia. 3) Soporta ejecución en sandbox de laboratorio con plantillas mínimas. |
| **Definition of Done** | Parser de salida Nuclei validado; al menos un hallazgo de prueba reproducible en entorno controlado. |

---

#### HU-004 — Cola de trabajos de escaneo concurrente
**Como** operador del framework, **quiero** encolar múltiples trabajos de escaneo ejecutados en paralelo, **para** auditar varios objetivos sin bloquear la API principal.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S1 |
| **Trazabilidad** | ADR-001 · RNF-007 |
| **Criterios de aceptación** | 1) La cola acepta N trabajos con estado (`pending`, `running`, `done`, `failed`). 2) Tareas CPU-bound delegadas a `multiprocessing`. 3) Soporta al menos 10 escaneos simultáneos en entorno de prueba. |
| **Definition of Done** | Métricas de cola expuestas internamente; test de carga básico documentado. |

---

#### HU-005 — Sincronización diaria de base de amenazas (NVD)
**Como** administrador del sistema, **quiero** que el framework consuma la API NVD diariamente, **para** mantener actualizado el catálogo de CVEs usado en correlación de hallazgos.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Should |
| **Sprint** | S1 |
| **Trazabilidad** | RF-010 |
| **Criterios de aceptación** | 1) Job programado descarga e indexa CVEs nuevos/modificados. 2) Persiste `CVE-ID`, CVSS, descripción y fecha. 3) Registra errores de red sin interrumpir escaneos activos. |
| **Definition of Done** | Script/job ejecutable manualmente y vía scheduler; log de última sincronización consultable. |

---

### Épica E2 — Persistencia y Seguridad de Datos

#### HU-006 — Modelo de persistencia de escaneos y hallazgos
**Como** desarrollador, **quiero** persistir escaneos, activos y vulnerabilidades en base de datos relacional, **para** consultar histórico y alimentar módulos de IA y reportes.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S2 |
| **Trazabilidad** | RF-001 · RF-002 · RNF-008 |
| **Criterios de aceptación** | 1) Entidades: `Scan`, `Asset`, `Finding`, `Report`. 2) Relaciones y migraciones versionadas. 3) Consultas de hallazgos por escaneo en `< 3 s` con dataset de prueba. |
| **Definition of Done** | Migraciones aplicables en CI; repositorio de acceso a datos con tests de integración. |

---

#### HU-007 — Cifrado AES-256-GCM de datos en reposo
**Como** SysAdmin, **quiero** que reportes, credenciales y hallazgos sensibles se almacenen cifrados, **para** cumplir políticas de confidencialidad e integridad de la auditoría.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S2 |
| **Trazabilidad** | RNF-001 · ADR-003 |
| **Criterios de aceptación** | 1) Campos sensibles cifrados con AES-256-GCM vía `cryptography`. 2) Llave maestra solo por variable de entorno. 3) Test verifica imposibilidad de lectura sin llave válida. |
| **Definition of Done** | Documentación de rotación de llaves; ningún secreto en repositorio. |

---

#### HU-008 — Log de auditoría inmutable con firma criptográfica
**Como** Director de TI, **quiero** que cada escaneo y cambio de política quede registrado de forma inmutable, **para** disponer de trazabilidad forense ante incidentes.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S2 |
| **Trazabilidad** | RNF-003 · ADR-003 |
| **Criterios de aceptación** | 1) Cada evento registra timestamp, usuario, acción y recurso. 2) Entradas firmadas; alteración detectable en verificación. 3) API de consulta de logs filtrable por rango de fechas. |
| **Definition of Done** | Test de tamper detection; retención configurable documentada. |

---

### Épica E3 — API de Orquestación

#### HU-009 — API REST para lanzar escaneos
**Como** operador vía frontend o cliente externo, **quiero** crear un escaneo mediante `POST /api/scans`, **para** iniciar auditorías de forma programática.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S3 |
| **Trazabilidad** | RF-001 · RF-002 |
| **Criterios de aceptación** | 1) Payload valida objetivo y tipo de escaneo. 2) Retorna `scan_id` y estado inicial. 3) Encola trabajo en HU-004 automáticamente. |
| **Definition of Done** | Contrato OpenAPI publicado; tests de contrato en CI. |

---

#### HU-010 — API REST para consultar resultados de escaneo
**Como** analista, **quiero** consultar estado y hallazgos de un escaneo vía `GET /api/scans/{id}`, **para** monitorear progreso y revisar vulnerabilidades detectadas.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S3 |
| **Trazabilidad** | RF-001 · RF-002 |
| **Criterios de aceptación** | 1) Incluye progreso, activos descubiertos y lista paginada de hallazgos. 2) Filtrado por severidad y estado. 3) Respuesta coherente mientras el escaneo está en ejecución. |
| **Definition of Done** | Paginación testeada; tiempos de respuesta medidos en entorno de prueba. |

---

#### HU-011 — Programación de escaneos recurrentes (Cron)
**Como** SysAdmin, **quiero** configurar escaneos diarios, semanales o mensuales, **para** mantener visibilidad continua del estado de seguridad sin intervención manual.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Should |
| **Sprint** | S3 |
| **Trazabilidad** | RF-009 |
| **Criterios de aceptación** | 1) CRUD de reglas de scheduling con expresión cron o presets. 2) Ejecución automática crea escaneo vía HU-009. 3) Posibilidad de pausar/reanudar reglas. |
| **Definition of Done** | Al menos un escaneo recurrente demostrado en entorno de laboratorio. |

---

### Épica E4 — Módulos de Inteligencia Artificial

#### HU-012 — Abstracción de proveedor LLM (Cloud / Ollama)
**Como** arquitecto del sistema, **quiero** una capa que unifique Gemini, OpenAI y Ollama, **para** cambiar el motor de IA sin modificar la lógica de negocio.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S4 |
| **Trazabilidad** | ADR-002 |
| **Criterios de aceptación** | 1) Interfaz común `generate(prompt, schema)`. 2) Selección de proveedor por configuración. 3) Fallback documentado si el proveedor no responde. |
| **Definition of Done** | Tests con LLM mockeado; soporte mínimo de un proveedor Cloud y uno local. |

---

#### HU-013 — Orquestación de agentes con LangGraph
**Como** framework de pentesting, **quiero** definir un grafo de estados donde la IA decida el siguiente paso, **para** replicar el flujo de razonamiento de un pentester humano.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S4 |
| **Trazabilidad** | RF-003 · ADR-002 |
| **Criterios de aceptación** | 1) Grafo con nodos: analizar hallazgos → proponer acción → ejecutar herramienta → evaluar. 2) Estado persistido entre transiciones. 3) Ciclo terminable con condición de parada explícita. |
| **Definition of Done** | Diagrama de flujo en repo; test de recorrido completo con datos simulados. |

---

#### HU-014 — Agente de análisis de vectores de ataque
**Como** Red Team, **quiero** que la IA correlacione hallazgos del escaneo y proponga cadenas de ataque lógicas, **para** priorizar explotación según impacto real.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S4 |
| **Trazabilidad** | RF-003 |
| **Criterios de aceptación** | 1) Entrada: hallazgos de HU-003/HU-006. 2) Salida: lista ordenada de vectores con justificación. 3) Tiempo de respuesta `< 5 s` por lote de hasta 10 hallazgos (RNF-004). |
| **Definition of Done** | Caso de prueba con al menos 2 vectores encadenados validados manualmente. |

---

#### HU-015 — Agente de generación de payloads contextualizados
**Como** pentester, **quiero** que la IA sugiera payloads adaptados a la vulnerabilidad y servicio detectado, **para** acelerar la fase de validación controlada en laboratorio.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Should |
| **Sprint** | S4 |
| **Trazabilidad** | RF-004 |
| **Criterios de aceptación** | 1) Payloads asociados a un `finding_id`. 2) Incluye advertencia de uso exclusivo en entorno autorizado. 3) Salida estructurada JSON validada por esquema. |
| **Definition of Done** | Sandbox de prueba; revisión de seguridad del módulo documentada. |

---

#### HU-016 — Scoring de confianza para falsos positivos (IA)
**Como** analista SOC, **quiero** un score de confianza por hallazgo generado por heurística + IA, **para** filtrar ruido antes de escalar incidentes.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S4 |
| **Trazabilidad** | RF-005 |
| **Criterios de aceptación** | 1) Score numérico 0–100 por hallazgo. 2) Umbral configurable marca hallazgos como `probable_fp`. 3) Explicación breve del score disponible en API. |
| **Definition of Done** | Dataset de prueba con TP/FP etiquetados; métrica de precisión documentada. |

---

#### HU-017 — Validación estructurada de respuestas IA con Pydantic
**Como** desarrollador, **quiero** rechazar respuestas del LLM que no cumplan el esquema esperado, **para** evitar que datos malformados lleguen al motor de escaneo o a reportes.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S4 |
| **Trazabilidad** | ADR-002 |
| **Criterios de aceptación** | 1) Modelos Pydantic para vectores, payloads y scores. 2) Reintento o error controlado ante JSON inválido. 3) Log de rechazos para depuración. |
| **Definition of Done** | Tests con respuestas válidas e inválidas; cobertura del validador en CI. |

---

### Épica E5 — Interfaz, Autenticación y Reportes

#### HU-018 — Autenticación MFA para panel de administración
**Como** SysAdmin, **quiero** acceder al panel solo con credenciales + segundo factor, **para** proteger operaciones críticas del framework.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S5 |
| **Trazabilidad** | RNF-002 |
| **Criterios de aceptación** | 1) Login con usuario/contraseña + TOTP. 2) Sesiones con expiración configurable. 3) Rutas administrativas rechazan acceso sin MFA completado. |
| **Definition of Done** | Flujo E2E en frontend; política de bloqueo tras intentos fallidos. |

---

#### HU-019 — Dashboard web de métricas de seguridad
**Como** Director de TI, **quiero** visualizar KPIs agregados (activos, puertos, vulns críticas), **para** evaluar el riesgo global en un vistazo.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S5 |
| **Trazabilidad** | RNF-006 |
| **Criterios de aceptación** | 1) Render inicial del dashboard en `< 2 s` (conexión estándar). 2) Métricas consumen HU-010. 3) Actualización periódica sin recarga completa. |
| **Definition of Done** | Lighthouse básico documentado; responsive en viewport desktop. |

---

#### HU-020 — Consola en vivo de logs de escaneo
**Como** operador, **quiero** ver en tiempo real la salida del motor de escaneo en la UI, **para** diagnosticar bloqueos o errores durante la auditoría.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Should |
| **Sprint** | S5 |
| **Trazabilidad** | RF-001 · RF-002 |
| **Criterios de aceptación** | 1) Stream de eventos por WebSocket o SSE. 2) Líneas con timestamp, módulo y severidad. 3) Auto-scroll configurable. |
| **Definition of Done** | Demo con escaneo real/simulado; reconexión automática ante caída. |

---

#### HU-021 — Vista de gestión de hallazgos con filtros
**Como** analista, **quiero** listar, filtrar y ordenar vulnerabilidades detectadas, **para** priorizar remediación por severidad y confianza.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S5 |
| **Trazabilidad** | RF-002 · RF-005 |
| **Criterios de aceptación** | 1) Tabla con severidad, vector, score IA y estado. 2) Filtros por severidad, confianza y falso positivo. 3) Detalle expandible con evidencia del escaneo. |
| **Definition of Done** | Tests de componente; integración con API HU-010. |

---

#### HU-022 — Marcado manual de falsos positivos
**Como** SysAdmin, **quiero** marcar un hallazgo como falso positivo desde la UI, **para** retroalimentar el sistema y reducir ruido en futuros escaneos.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S5 |
| **Trazabilidad** | RF-006 |
| **Criterios de aceptación** | 1) Acción persiste estado `false_positive` con usuario y timestamp. 2) Hallazgo excluido de reportes por defecto. 3) Evento registrado en HU-008. |
| **Definition of Done** | Test E2E del flujo; dato disponible para reentrenamiento/heurística futura. |

---

#### HU-023 — Exportación de reporte ejecutivo en PDF
**Como** Director de TI, **quiero** exportar un reporte resumido en PDF, **para** comunicar impacto de negocio y criticidad a stakeholders no técnicos.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S5 |
| **Trazabilidad** | RF-007 · RNF-005 |
| **Criterios de aceptación** | 1) PDF generado en `< 10 s` para escaneo estándar. 2) Incluye resumen ejecutivo, heatmap de severidad y top riesgos. 3) Descarga desde UI autenticada. |
| **Definition of Done** | Plantilla versionada; test de generación en CI con snapshot. |

---

#### HU-024 — Exportación de reporte técnico con PoC y mitigación
**Como** SysAdmin, **quiero** exportar un reporte técnico detallado con evidencia y pasos de remediación, **para** ejecutar parches de forma precisa.

| Campo | Detalle |
| :--- | :--- |
| **Prioridad** | Must |
| **Sprint** | S5 |
| **Trazabilidad** | RF-008 · RNF-005 · ADR-003 |
| **Criterios de aceptación** | 1) Formato HTML/PDF con PoC, CVE, comandos y mitigación. 2) Datos sensibles respetan cifrado HU-007 al persistir. 3) Generación `< 10 s` (RNF-005). |
| **Definition of Done** | Ejemplo de reporte en `/docs/requeriments/ejemplos/` (opcional futuro); validación con caso real de laboratorio. |

---

> **Nota de cierre del catálogo:** Total **24 historias** (HU-001 → HU-024, sin duplicidad funcional). Cada HU es entregable de forma independiente dentro de su sprint, con dependencias explícitas solo hacia historias previas de la misma cadena de valor.

---

## 4. Matriz de Validación INVEST

Leyenda: **✅** Cumple · **⚠️** Cumple con condición (dependencia explícita documentada)

| ID | Historia | **I**ndependent | **N**egotiable | **V**aluable | **E**stimable | **S**mall | **T**estable |
| :--- | :--- | :---: | :---: | :---: | :---: | :---: | :---: |
| HU-001 | Bootstrap FastAPI async | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-002 | Wrapper Nmap | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-003 | Escaneo Nuclei | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-004 | Cola concurrente | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-005 | Sync NVD/CVE | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-006 | Persistencia hallazgos | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-007 | Cifrado AES-256-GCM | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-008 | Log auditoría inmutable | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-009 | API POST escaneos | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-010 | API GET resultados | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-011 | Scheduling Cron | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-012 | Abstracción LLM | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-013 | LangGraph agentes | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-014 | Análisis vectores IA | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-015 | Generación payloads | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-016 | Score falsos positivos | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-017 | Validación Pydantic | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-018 | MFA panel admin | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-019 | Dashboard métricas | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-020 | Consola logs en vivo | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-021 | Gestión hallazgos UI | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-022 | Marcado falsos positivos | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-023 | Reporte ejecutivo PDF | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |
| HU-024 | Reporte técnico PoC | ⚠️ | ✅ | ✅ | ✅ | ✅ | ✅ |

### Justificación INVEST (resumen por principio)

| Principio | Aplicación en el backlog |
| :--- | :--- |
| **Independent** | Historias base (HU-001, HU-005, HU-012, HU-018) no dependen de otras. Las marcadas ⚠️ tienen dependencia técnica explícita (ej. HU-003 requiere salida de HU-002) pero son entregables de sprint separables mediante mocks/stubs. |
| **Negotiable** | Criterios de aceptación definen el qué, no el cómo: tecnologías concretas (Nmap, Nuclei, LangGraph) son negociables manteniendo el valor. |
| **Valuable** | Cada HU aporta valor directo a auditor, SysAdmin o Director de TI; trazada a RF/RNF del SRS y ADRs del proyecto. |
| **Estimable** | Alcance acotado por criterios de aceptación medibles; apta para story points en planning poker. |
| **Small** | Cada ítem cabe en un sprint de 2 semanas con un equipo reducido; no hay épicas monolíticas. |
| **Testable** | Todo ítem incluye criterios verificables automática o manualmente (tiempos, endpoints, estados, formatos). |

---

## 5. Trazabilidad Técnica Consolidada

| HU | RF/RNF | ADR | Módulo ejecutable |
| :--- | :--- | :--- | :--- |
| HU-001 | RNF-007 | ADR-001 | `src/Backend/` — core API |
| HU-002 | RF-001 | ADR-001 | `src/Backend/scanner/nmap_wrapper` |
| HU-003 | RF-002 | — | `src/Backend/scanner/nuclei_wrapper` |
| HU-004 | RNF-007 | ADR-001 | `src/Backend/jobs/queue` |
| HU-005 | RF-010 | — | `src/Backend/threat_intel/nvd_sync` |
| HU-006 | RNF-008 | — | `src/Backend/models/` |
| HU-007 | RNF-001 | ADR-003 | `src/Backend/security/encryption` |
| HU-008 | RNF-003 | ADR-003 | `src/Backend/security/audit_log` |
| HU-009 | RF-001, RF-002 | — | `src/Backend/api/scans` |
| HU-010 | RF-001, RF-002 | — | `src/Backend/api/scans` |
| HU-011 | RF-009 | — | `src/Backend/scheduler/` |
| HU-012 | — | ADR-002 | `src/Backend/ai/providers/` |
| HU-013 | RF-003 | ADR-002 | `src/Backend/ai/graph/` |
| HU-014 | RF-003 | ADR-002 | `src/Backend/ai/agents/vectors` |
| HU-015 | RF-004 | ADR-002 | `src/Backend/ai/agents/payloads` |
| HU-016 | RF-005 | ADR-002 | `src/Backend/ai/scoring/` |
| HU-017 | — | ADR-002 | `src/Backend/ai/schemas/` |
| HU-018 | RNF-002 | — | `src/Backend/auth/` + `src/Frontend/` |
| HU-019 | RNF-006 | — | `src/Frontend/src/pages/Dashboard` |
| HU-020 | RF-001, RF-002 | — | `src/Frontend/src/components/ScanConsole` |
| HU-021 | RF-002, RF-005 | — | `src/Frontend/src/pages/Findings` |
| HU-022 | RF-006 | ADR-003 | `src/Frontend/` + `src/Backend/api/findings` |
| HU-023 | RF-007, RNF-005 | — | `src/Backend/reports/executive` |
| HU-024 | RF-008, RNF-005 | ADR-003 | `src/Backend/reports/technical` |

---

## 6. Referencias

- `README.md` — Visión del producto Atrox  
- `docs/SRS.md` — Requerimientos funcionales y no funcionales (RF/RNF)  
- `docs/Documentacion de Arquitectura.md` — Decisiones de arquitectura  
- `docs/ADR/` — Architecture Decision Records
