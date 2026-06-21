# ADR-003: Mecanismo de Almacenamiento Seguro de Datos de Auditoría

* **Estado:** Aceptado
* **Fecha:** 20 de junio de 2026
* **Impacto:** Crítico (Seguridad y Cumplimiento)

## Contexto
El sistema almacena datos de extrema confidencialidad, incluyendo exploits generados, inventario detallado de activos vulnerables, logs inmutables de las actividades de escaneo y credenciales temporales de acceso a los sistemas auditados. Comprometer esta base de datos transformaría el framework en un vector de ataque crítico para la infraestructura de los clientes.

## Decisión
Se decide implementar un mecanismo de **cifrado simétrico de datos en reposo utilizando el algoritmo AES-256-GCM** mediante la suite criptográfica de alto nivel `cryptography` en Python. Las llaves de cifrado maestras se manejarán estrictamente de forma externa al repositorio, inyectadas a través de variables de entorno seguras en el despliegue del contenedor. Los logs de auditoría operacional se registrarán con firmas criptográficas para garantizar su inmutabilidad.

## Justificación Técnica
1. **Seguridad y Autenticación:** El modo **GCM (Galois/Counter Mode)** de AES no solo cifra los datos (confidencialidad), sino que proporciona una etiqueta de autenticación que valida que la información no ha sido alterada ni manipulada maliciosamente en la base de datos (integridad).
2. **Cumplimiento de Estándares:** AES-256 es el estándar de oro en la industria de la seguridad y auditoría de TI, garantizando el cumplimiento de políticas de protección de datos rigurosas exigidas por los SysAdmins y Directores de TI.
3. **Rendimiento Criptográfico:** La librería seleccionada utiliza bindings de C optimizados (OpenSSL), minimizando la penalización en el tiempo de escritura/lectura de reportes y cumpliendo con el umbral requerido de rendimiento.

## Consecuencias
* **Positivas:** Blindaje de los hallazgos críticos contra accesos directos no autorizados a la base de datos y logs forenses confiables y legalmente válidos.
* **Negativas:** Complejidad añadida en la gestión, respaldo y rotación de las llaves de cifrado; la pérdida de la llave maestra resultará en la pérdida total e irrecuperable de los datos históricos.

## Trazabilidad Técnica
* **Requerimientos Relacionados:** RF-006, RF-008, RNF-001, RNF-002, RNF-003.