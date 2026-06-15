# Anexo: Transcripción de Entrevista de Validación del Framework

**Perfil del Entrevistado:** Desarrollador de Software (Full Stack)  
**Sector de la Industria:** Desarrollo de Aplicaciones y Soluciones Tecnológicas  
**Experiencia:** ~9 años en el área de ciberseguridad y desarrollo  
**Condición:** Anonimato solicitado / Autorización explícita otorgada para registro en el proyecto  

---

### Bloque 1: Perfil y Contexto Operativo

#### 1. ¿Cuál es su rol actual y cuántos años de experiencia tiene en el área de tecnologías de la información? ¿En qué tipo de entorno o industria trabaja principalmente?
Actualmente me desempeño en el área de desarrollo de software. Cuento con aproximadamente nueve años de experiencia en el sector tecnológico y trabajo principalmente con tecnologías del ecosistema de JavaScript/TypeScript (como NestJS/Next.js y React) y el entorno de .NET.

#### 2. ¿Cuáles considera que son los principales desafíos o problemas más frecuentes que enfrenta su equipo en temas de seguridad informática, detección de vulnerabilidades o protección de sistemas?
El principal desafío es que la seguridad suele quedar fuera de la planificación inicial de los proyectos. Comúnmente se tiende a confiar a ciegas en la experiencia del desarrollador, asumiendo que escribirá código seguro por defecto. Actualmente existe un vacío en los equipos: falta un rol o una persona dedicada exclusivamente a buscar vulnerabilidades, reportarlas y parcharlas en una etapa temprana del ciclo de vida del software; básicamente, es un aspecto que se suele ignorar.

---

### Bloque 2: Estado de la Automatización y Herramientas Actuales

#### 3. ¿Cómo describiría el nivel de automatización actual en las actividades relacionadas con la seguridad de infraestructura, aplicaciones o redes en su organización? ¿Qué herramientas o procesos utilizan para automatizar tareas repetitivas?
A nivel organizacional, la priorización en los proyectos reales es baja. En mi experiencia personal y de forma didáctica para autoformación, he implementado herramientas integradas en la suite de Bitbucket, específicamente **Snyk**. Esta herramienta analiza periódicamente el proyecto y genera reportes mensuales de las vulnerabilidades detectadas, pero no es una práctica estandarizada en el día a día del negocio.

#### 4. ¿Qué experiencia ha tenido con herramientas automatizadas de seguridad? ¿En qué aspectos le ha resultado más útil y cuáles han sido sus mayores frustraciones?
El desafío de implementar estas herramientas radica en los recursos y el tiempo. Dependiendo del presupuesto de la empresa, se puede optar por soluciones comerciales de pago o herramientas auto-hosteadas (Open Source). La mayor frustración es que la configuración inicial y el despliegue de estas plataformas suele demandar una gran cantidad de tiempo y esfuerzo técnico antes de empezar a ver resultados útiles.

---

### Bloque 3: Percepción de la Inteligencia Artificial en Ciberseguridad

#### 5. ¿Qué opinión tiene sobre el uso de inteligencia artificial aplicada a la seguridad informática? ¿En qué áreas cree que la IA podría generar mayor valor?
Es una excelente idea aplicar IA para el análisis de seguridad y vulnerabilidades corporativas. La inteligencia artificial tiene el potencial de aportar en todas y cada una de las fases de un security test (pentesting). No obstante, el gran riesgo a considerar son los permisos que se le otorgan y el entorno donde opera. Debe ser un entorno controlado, idealmente con datos de prueba y no de producción. La IA debería reportar riesgos altos, pero **no ejecutar la fase de explotación sin supervisión humana**; una explotación automatizada y autónoma podría corromper datos o tumbar servicios críticos, lo que causaría pérdidas severas o problemas legales.

#### 6. Si pudiera diseñar un framework inteligente que ayude a identificar y evaluar automáticamente riesgos y vulnerabilidades en sistemas y aplicaciones, ¿qué funcionalidades o capacidades le gustaría que incluyera?
Me gustaría que el framework incluyera tres capacidades principales:
* **Sugerencia automática de acciones de remediación:** Que además del reporte de vulnerabilidades, recomiende los pasos exactos a seguir.
* **Filtros de pruebas parametrizados por tiempo:** Que permita al usuario seleccionar qué vulnerabilidades probar o descartar según el tiempo disponible del equipo.
* **Componente didáctico integrado:** Que si la herramienta encuentra un fallo ya reportado formalmente, explique dentro de la misma interfaz de qué se trata, evitando que el desarrollador tenga que salir a buscar la documentación en fuentes externas.

#### 7. ¿Cuáles serían sus principales preocupaciones o riesgos al implementar un sistema que utilice inteligencia artificial para realizar evaluaciones automáticas de seguridad?
Mi mayor preocupación es la delimitación del alcance y el consentimiento. Como en cualquier auditoría real, se debe contar con autorización explícita de la empresa y configurar un rango de pruebas sumamente limitado y controlado, asegurando que la autonomía de la IA no ejecute acciones imprevistas que perjudiquen la continuidad del negocio.

---

### Bloque 4: Priorización e Integración Operativa

#### 8. ¿Qué tipo de pruebas o revisión de seguridad considera más importante o prioritarias para automatizar en su día a día? ¿Por qué?
Como desarrollador, la prioridad número uno es el **análisis de dependencias y librerías** (SCA); contar con un reporte que avise si los paquetes con los que construimos el software están desactualizados o contienen vulnerabilidades conocidas para aplicar parches inmediatamente. En segundo lugar, priorizaría el **escaneo automático de redes y puertos** para validar las configuraciones de los servidores.

#### 9. ¿Qué tipo de integración esperaría que tenga este tipo de framework con las herramientas y procesos que ya utilicen su trabajo?
Esperaría una integración híbrida y flexible. Lo ideal sería poder disparar los análisis de forma manual cuando se requiera, pero también tener la capacidad de programar tareas en segundo plano para que se ejecuten automáticamente al finalizar la jornada laboral, garantizando que el sistema trabaje de forma autónoma sin perder nunca la supervisión del equipo de TI.

#### 10. ¿Cómo mediría el éxito de un framework de este tipo? ¿Qué indicadores, mejoras o resultados serían más importantes para usted y para su organización?
El éxito se mediría a través de una visualización centralizada:
* **Dashboard de Control:** Un panel interactivo que registre el histórico de fallos y el estado de su resolución.
* **Métricas de Densidad de Defectos:** Indicadores claros que muestren cuántas vulnerabilidades van apareciendo a lo largo del ciclo de desarrollo y cuántas de ellas han sido parchadas exitosamente por el equipo.