# ADR-002: Estrategia de Integración del LLM Orquestador

* **Estado:** Aceptado
* **Fecha:** 20 de junio de 2026
* **Impacto:** Alto (Inteligencia del Sistema)

## Contexto
La propuesta de valor del framework radica en automatizar el análisis posterior al escaneo clásico. El sistema debe interpretar vulnerabilidades complejas, sugerir cadenas lógicas de ataque (vectores) y discriminar falsos positivos de manera autónoma, requiriendo un motor de razonamiento avanzado y estructurado.

## Decisión
Se opta por una arquitectura basada en **Agentes de IA Orquestados**, utilizando el framework **LangChain / LangGraph** para el control de estados y flujos de trabajo cíclicos. El modelo principal de producción será consumido mediante **APIs en la nube (ej. Gemini Pro / OpenAI)** debido a su alta ventana de contexto y capacidad de razonamiento. No obstante, se integrará una abstracción mediante **Ollama** para permitir el despliegue opcional de modelos locales (ej. Llama 3) en entornos restringidos de auditoría privada.

## Justificación Técnica
1. **Arquitectura de Agentes y Control de Flujo:** LangGraph permite definir grafos de decisión donde la IA puede "decidir" ejecutar una herramienta de escaneo adicional si los datos iniciales son insuficientes, imitando las fases de un pentester humano.
2. **Manejo de Respuestas Estructuradas:** Herramientas como Pydantic integradas en LangChain aseguran que las respuestas del LLM (payloads, análisis de CVEs) sigan un esquema JSON estricto antes de interactuar con el motor del sistema.
3. **Flexibilidad Operativa (Cloud vs. Local):** El soporte dual mediante abstracciones garantiza que el framework pueda trabajar a máxima velocidad con modelos Cloud para Directores de TI que priorizan rapidez, pero retiene la capacidad de operar de forma 100% aislada (Air-Gapped) para infraestructuras críticas que no permiten la salida de datos.

## Consecuencias
* **Positivas:** Capacidad de adaptación frente a nuevos modelos de lenguaje, modularidad en las habilidades del agente y respuestas de IA altamente confiables y validadas.
* **Negativas:** Dependencia de la latencia de red en modo Cloud, posible variabilidad en los costos de consumo por volumen de tokens y requerimientos elevados de hardware si se ejecuta en modo local.

## Trazabilidad Técnica
* **Requerimientos Relacionados:** RF-003, RF-004, RF-005, RNF-004.