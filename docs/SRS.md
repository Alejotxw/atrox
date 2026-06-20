# Especificación de Requerimientos de Software (SRS)
**Proyecto:** Framework de Pentesting Automatizado con Inteligencia Artificial (Atrox)

## 1. Requerimientos Funcionales (RF)

| ID | Nombre del Requerimiento | Descripción |
| :--- | :--- | :--- |
| **RF-001** | **Descubrimiento de Activos** | El motor de escaneo debe identificar puertos abiertos, servicios en ejecución y versiones de software en las IPs o dominios objetivo. |
| **RF-002** | **Escaneo de Vulnerabilidades** | El sistema debe ejecutar rutinas de escaneo automatizado para detectar vulnerabilidades conocidas (CVEs) y configuraciones deficientes. |
| **RF-003** | **Orquestación con IA: Análisis de Vectores** | El framework debe integrar un LLM para analizar los datos en crudo del escaneo y proponer cadenas de ataque o vectores de amenaza lógicos. |
| **RF-004** | **Generación Automatizada de Payloads** | La IA debe ser capaz de sugerir o generar *payloads* específicos adaptados a las vulnerabilidades descubiertas en el entorno objetivo. |
| **RF-005** | **Validación de Falsos Positivos (IA)** | El sistema debe utilizar heurística y modelos de IA para contrastar los hallazgos del escaneo, asignando un "Score de Confianza" para descartar falsos positivos. |
| **RF-006** | **Gestión Manual de Falsos Positivos** | Los SysAdmins deben poder marcar manualmente una vulnerabilidad reportada como "Falso Positivo", retroalimentando la base de datos para futuros escaneos. |
| **RF-007** | **Reportes Ejecutivos** | El sistema debe generar un reporte de alto nivel resumido, enfocado en el impacto de negocio y criticidad, diseñado para Directores de TI. |
| **RF-008** | **Reportes Técnicos y de Mitigación** | El sistema debe generar un reporte detallado con evidencia (PoC) y pasos exactos de remediación/parcheo, destinado a SysAdmins y equipos de soporte. |
| **RF-009** | **Programación de Escaneos (Scheduling)** | La plataforma debe permitir la configuración de escaneos recurrentes (diarios, semanales, mensuales) mediante tareas programadas (Cron jobs). |
| **RF-010** | **Actualización de Base de Amenazas** | El sistema debe consumir APIs externas (ej. NVD, VulnDB) diariamente para mantener la base de datos de firmas y CVEs actualizada. |

---

## 2. Requerimientos No Funcionales (RNF)

Los siguientes requerimientos establecen las métricas y restricciones de calidad que el framework debe cumplir, divididos por dimensiones críticas.

| ID | Categoría | Nombre del Requerimiento | Métrica / Criterio de Aceptación |
| :--- | :--- | :--- | :--- |
| **RNF-001** | **Seguridad** | Cifrado de Datos en Reposo | Todos los reportes, credenciales y datos de vulnerabilidades almacenados deben utilizar cifrado AES-256. |
| **RNF-002** | **Seguridad** | Autenticación y Autorización | Todo acceso al panel de gestión por parte de SysAdmins y Directores de TI debe exigir Autenticación Multifactor (MFA) obligatoria. |
| **RNF-003** | **Seguridad** | Trazabilidad de Auditoría | El 100% de los escaneos ejecutados y modificaciones a las políticas deben registrarse en un log inmutable con fecha, hora y usuario. |
| **RNF-004** | **Rendimiento** | Tiempo de Respuesta de IA | La orquestación del LLM para analizar una vulnerabilidad y devolver un contexto/mitigación debe completarse en `< 5 segundos` por petición. |
| **RNF-005** | **Rendimiento** | Generación de Reportes | La exportación de un reporte consolidado en formato PDF o HTML debe generarse en un tiempo máximo de `< 10 segundos`. |
| **RNF-006** | **Rendimiento** | Latencia de la Interfaz (UI) | El *dashboard* web debe cargar y renderizar las métricas iniciales de seguridad en `< 2 segundos` con una conexión estándar. |
| **RNF-007** | **Escalabilidad** | Ejecución Concurrente | El motor de escaneo debe soportar la ejecución de al menos `50 escaneos a objetivos diferentes de forma simultánea` sin degradar el rendimiento del nodo maestro. |
| **RNF-008** | **Escalabilidad** | Crecimiento de Datos | La arquitectura de la base de datos debe estar diseñada para soportar hasta `1 TB de datos históricos` de escaneos manteniendo consultas optimizadas bajo los 3 segundos. |
| **RNF-009** | **Disponibilidad** | Uptime del Dashboard | El panel de control e interfaz de orquestación debe garantizar una disponibilidad del `99.9%` mensual. |
| **RNF-010** | **Disponibilidad** | Objetivo de Tiempo de Recuperación (RTO) | Ante una caída crítica del servidor principal, el sistema debe poder ser restaurado y operativo (RTO) en `< 4 horas`. |