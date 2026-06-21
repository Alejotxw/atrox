# ADR-001: Selección del Lenguaje Base y Modelo de Concurrencia

* **Estado:** Aceptado
* **Fecha:** 20 de junio de 2026
* **Impacto:** Alto (Core del sistema)

## Contexto
El framework de pentesting automatizado requiere realizar múltiples tareas en paralelo: escaneos de red concurrentes (operaciones intensivas en I/O) y ejecución de scripts/herramientas criptográficas (operaciones intensivas en CPU). Adicionalmente, debe gestionar flujos de comunicación asíncronos con APIs de Inteligencia Artificial sin bloquear el hilo principal que atiende el panel de administración.

## Decisión
Se determina utilizar **Python** como lenguaje de programación base para el backend del framework, implementando el framework **FastAPI** y adoptando un modelo de **concurrencia asíncrona (`asyncio`)** para las operaciones I/O-bound. Para las tareas CPU-bound (como el procesamiento en crudo del motor de escaneo pesado), se delegará el procesamiento a un pool de subprocesos independientes (`multiprocessing`).

## Justificación Técnica
1. **Ecosistema de Ciberseguridad e IA:** Python posee las librerías nativas y de terceros más maduras tanto para tareas de seguridad (Scapy, Nmap wrappers) como para la integración con LLMs y procesamiento de datos.
2. **Eficiencia en Red (`asyncio`):** Las peticiones de escaneo y sondeo de puertos son altamente dependientes de tiempos de espera de red (I/O-bound). El asincronismo permite manejar miles de conexiones simultáneas bajo un solo hilo, evitando el sobrecosto de memoria que implicaría crear un hilo (Thread) por cada puerto o IP activa.
3. **Evasión del GIL (Global Interpreter Lock):** Dado que Python limita la ejecución multi-hilo real en CPU, el uso de `multiprocessing` para el procesamiento paralelo de vulnerabilidades garantiza el aprovechamiento de múltiples núcleos del VPS sin bloquear la API.

## Consecuencias
* **Positivas:** Alta escalabilidad horizontal en el motor de escaneo, consumo eficiente de memoria en el servidor y velocidad en las respuestas de la API de control.
* **Negativas:** Incremento en la complejidad del código debido a la gestión de funciones `async/await` y la necesidad estricta de evitar librerías síncronas bloqueantes dentro del flujo principal.

## Trazabilidad Técnica
* **Requerimientos Relacionados:** RF-001, RF-002, RNF-006, RNF-007.