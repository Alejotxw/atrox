# Anexo: Transcripción de Entrevista de Validación del Framework

**Perfil del Entrevistado:** Desarrollador de Software (Backend / Full Stack)  
**Sector de la Industria:** Desarrollo de Software a Medida y Plataformas SaaS  
**Experiencia:** ~6 años en ingeniería de software y arquitectura de aplicaciones  
**Condición:** Anonimato solicitado / Autorización explícita otorgada para registro en el proyecto  

---

### Bloque 1: Perfil y Contexto Operativo

#### 1. ¿Cuál es su rol actual y cuántos años de experiencia tiene en el área de tecnologías de la información? ¿En qué tipo de entornos o industrias trabaja principalmente?
Actualmente me desempeño como Desarrollador de Software Senior, enfocado principalmente en el desarrollo Backend y arquitectura de APIs. Tengo alrededor de 6 años de experiencia en la industria tecnológica. Trabajo principalmente en la creación de aplicaciones SaaS corporativas y plataformas de comercio electrónico (E-commerce) distribuidas en la nube.

#### 2. ¿Cuáles considera que son los principales desafíos o problemas más frecuentes que enfrenta su equipo en temas de seguridad informática, detección de vulnerabilidades o protección de sistemas?
Desde la perspectiva de desarrollo, el mayor desafío es el **conflicto entre la velocidad de entrega y la seguridad**. Vivimos bajo la presión de cumplir con fechas límite de *sprints* muy agresivas, lo que provoca que la seguridad a menudo se trate como un pensamiento tardío ("*afterthought*") o se asuma que las librerías de terceros ya son seguras por defecto. 

Otro gran problema es la falta de capacitación especializada en desarrollo seguro; sabemos programar lógica de negocio, pero identificar fallas sutiles como inyecciones indirectas o problemas de control de acceso a nivel de objeto (BOLA/IDOR) durante un *Code Review* manual es sumamente difícil.

---

### Bloque 2: Estado de la Automatización y Herramientas Actuales

#### 3. ¿Cómo describiría el nivel de automatización actual en las actividades relacionadas con la seguridad de infraestructura, aplicaciones o redes en su organización? ¿Qué herramientas o procesos utilizan para automatizar tareas repetitivas?
El nivel de automatización en nuestra organización es **moderado-alto en el pipeline de despliegue (CI/CD), pero básico en profundidad**. Tenemos automatizada la integración de linters y analizadores de dependencias. 

En cada *Pull Request*, herramientas automáticas revisan si estamos usando paquetes desactualizados. Sin embargo, no tenemos pruebas automatizadas que interactúen activamente con la aplicación en tiempo de ejecución (como un pentesting dinámico) antes de pasar a producción; eso sigue dependiendo de auditorías externas anuales o pruebas manuales esporádicas.

#### 4. ¿Qué experiencia ha tenido con herramientas automatizadas de seguridad? ¿En qué aspectos le ha resultado más útil y cuáles han sido sus mayores frustraciones?
Trabajo diariamente con herramientas como Dependabot, SonarQube y escáneres SAST integrados en GitHub/GitLab. 

Lo más útil es que te alertan instantáneamente en el repositorio si subes una credencial por error (detección de *secrets*) o si una librería de npm o NuGet tiene un CVE crítico conocido. 

Mi mayor frustración son los **falsos positivos en el análisis estático de código**. A veces la herramienta bloquea el pipeline de integración continua por una supuesta vulnerabilidad crítica en un fragmento de código que en realidad está sanitizado por el propio framework, obligándonos a perder horas justificando el hallazgo o modificando código limpio solo para "complacer" al escáner.

---

### Bloque 3: Percepción de la Inteligencia Artificial en Ciberseguridad

#### 5. ¿Qué opinión tiene sobre el uso de inteligencia artificial aplicada a la seguridad informática? ¿En qué áreas cree que la IA podría generar mayor valor?
Para los desarrolladores, la IA ya es parte del flujo de trabajo con asistentes de código, por lo que su uso en ciberseguridad nos parece un paso natural y muy valioso. El área donde la IA puede romper paradigmas es en el **análisis semántico y de contexto**. Los escáneres actuales solo buscan patrones de texto fijos; una IA puede entender la lógica del negocio detrás del código, identificar fallas de diseño lógicas (que las herramientas tradicionales ignoran) y, lo más importante, ayudarnos a escribir la corrección del código.

#### 6. Si pudiera diseñar un framework inteligente que ayude a identificar y evaluar automáticamente riesgos y vulnerabilidades en sistemas y aplicaciones, ¿qué funcionalidades o capacidades le gustaría que incluyera?
Como desarrollador, un framework ideal debería tener:
* **Generación Automática de Parches (Auto-Remediation):** Que no solo me diga dónde está el fallo, sino que cree un *Pull Request* sugerido con el código corregido usando las mejores prácticas de seguridad de nuestro propio stack tecnológico.
* **Explicaciones Didácticas y Contextuales:** Que explique el vector de ataque de forma clara dentro de nuestro entorno de desarrollo (IDE), detallando por qué esa línea específica de código es peligrosa.
* **Pruebas de Caja Negra Automatizadas post-despliegue:** Que sea capaz de simular ataques reales contra los *endpoints* que acabo de desplegar en el entorno de pruebas (Staging) para verificar si las validaciones que escribí realmente aguantan un ataque.

#### 7. ¿Cuáles lógicas serían sus principales preocupaciones o riesgos al implementar un sistema que utilice inteligencia artificial para realizar evaluaciones automáticas de seguridad?
Mi mayor preocupación son las **alucinaciones de la IA aplicadas a parches de código**. Si confiamos ciegamente en una solución de código propuesta por la IA para mitigar una vulnerabilidad, corremos el riesgo de que introduzca un *bug* funcional o, peor aún, una vulnerabilidad secundaria que rompa la estabilidad del sistema en producción. 

También está el factor rendimiento: si el framework ralentiza el pipeline de CI/CD o tarda horas analizando cada confirmación de código (*commit*), el equipo terminará desactivándolo para no retrasar las entregas.

---

### Bloque 4: Priorización e Integración Operativa

#### 8. ¿Qué tipo de pruebas o revisión de seguridad considera más importante o prioritarias para automatizar en su día a día? ¿Por qué?
Prioridad uno: **Seguridad en APIs y Autenticación/Autorización**. Las APIs son las que conectan nuestras bases de datos con el frontend y servicios externos; un error en la validación de tokens JWT o en la lógica de permisos puede exponer millones de registros. En segundo lugar, la **seguridad de la cadena de suministro de software (Software Supply Chain)**, asegurando que las dependencias de terceros que descargamos masivamente no contengan código malicioso inyectado.

#### 9. ¿Qué tipo de integración esperaría que tenga este tipo de framework con las herramientas y procesos que ya utilicen su trabajo?
La integración debe ser nativa en el flujo de trabajo del desarrollador. No queremos salir a una plataforma externa. Esperaría una **extensión para el IDE (como VS Code o JetBrains)** que resalte las vulnerabilidades mientras escribimos código, y una integración directa con **GitHub/GitLab** que comente directamente sobre las líneas de código afectadas en el *Pull Request*. Adicionalmente, que exporte los fallos confirmados como tareas técnicas en **Jira**.

#### 10. ¿Cómo mediría el éxito de un framework de este tipo? ¿Qué indicadores, mejoras o resultados serían más importantes para usted y para su organización?
Lo mediría a través del ciclo de vida del desarrollo seguro (DevSecOps):
1. **Defectos de Seguridad en Producción Evitados:** Reducción a cero de las vulnerabilidades críticas reportadas en producción por clientes o auditorías externas gracias a que fueron detectadas en desarrollo.
2. **Tiempo Medio de Remediación (MTTR):** Cuánto disminuye el tiempo que le toma a un desarrollador entender y corregir una vulnerabilidad una vez detectada.
3. **Tasa de Aceptación de Parches de IA:** Qué porcentaje de las soluciones automáticas sugeridas por el framework son correctas y aceptadas por los desarrolladores sin requerir modificaciones manuales significativas.