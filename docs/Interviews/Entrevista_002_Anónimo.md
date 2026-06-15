# Anexo: Transcripción de Entrevista de Validación del Framework

**Perfil del Entrevistado:** Director de TI  
**Sector de la Industria:** Servicios Financieros y Consultoría Tecnológica  
**Experiencia:** +20 años en Tecnologías de la Información  
**Condición:** Anonimato solicitado por políticas corporativas  

---

### Bloque 1: Perfil y Contexto Operativo

#### 1. ¿Cuál es su rol actual y cuántos años de experiencia tiene en el área de tecnologías de la información?
Cuento con algo más de 15 años de experiencia en el sector tecnológico, transitando desde roles técnicos en administración de redes y desarrollo de software hasta la gestión estratégica como Director de TI.

#### 2. ¿En qué tipo de entornos o industrias trabaja principalmente?
He desarrollado mi carrera principalmente en los sectores de servicios financieros avanzados, plataformas tecnológicas de alta concurrencia y consultoría corporativa.

#### 3. ¿Cuáles considera que son los principales desafíos o problemas más frecuentes que enfrenta su equipo en temas de seguridad informática, detección de vulnerabilidades o protección de sistemas?
El desafío número uno es la **fatiga de alertas** y la escasez de talento especializado. Recibimos miles de logs y reportes diarios, pero separar el ruido real de los falsos positivos consume demasiado tiempo. Además, el ritmo de despliegue del equipo de desarrollo es tan rápido que el equipo de seguridad tradicional se convierte en un cuello de botella. Proteger sistemas legados (legacy) sin afectar la disponibilidad del negocio es otro dolor de cabeza constante.

---

### Bloque 2: Estado de la Automatización y Herramientas Actuales

#### 4. ¿Cómo describiría el nivel de automatización actual en las actividades relacionadas con la seguridad de la infraestructura, aplicaciones o redes en su organización?
Yo lo calificaría como **moderado**. Automatizamos los análisis estáticos de código en el pipeline de despliegue y ejecutamos escaneos de vulnerabilidades perimetrales programados de forma mensual. Sin embargo, la fase de explotación, la correlación avanzada de fallos y las pruebas de penetración profundas siguen siendo procesos abrumadoramente manuales o dependientes de consultores externos trimestrales o anuales.

#### 5. ¿Qué herramientas o procesos utilizan para automatizar tareas repetitivas?
En el pipeline de CI/CD utilizamos herramientas clásicas de SAST/DAST (como SonarQube y escáneres integrados en el repositorio). Para la red, dependemos de las alertas nativas del SIEM, reglas automatizadas en los Firewalls/WAF y *scripts* internos en Python para auditorías de configuración rápidas.

#### 6. ¿Qué experiencias ha tenido con herramientas automatizadas de seguridad (escáneres de vulnerabilidades, herramientas de análisis de código, firewalls inteligentes, etc.)? ¿Qué aspectos le han resultado más útiles y cuáles han sido sus mayores frustraciones?
La experiencia es agridulce. Lo más útil es la **velocidad** para detectar fallos obvios o malas configuraciones básicas (como el OWASP Top 10 inicial) antes de que vayan a producción. 

La mayor frustración es la **falta de contexto de negocio**: un escáner tradicional te marca una vulnerabilidad "Crítica" en un servidor que está aislado y no tiene acceso a internet, haciéndonos perder tiempo valioso en mitigar algo que no representa un riesgo real inmediato, mientras ignora vectores combinados más sutiles.

---

### Bloque 3: Percepción de la Inteligencia Artificial en Ciberseguridad

#### 7. ¿Qué opinión tiene sobre el uso de Inteligencia Artificial aplicada a la seguridad informática? ¿En qué áreas cree que la IA podría generar mayor valor?
Es el paso inevitable y necesario. La IA es la única forma de contrarrestar los ataques automatizados que ya estamos sufriendo. Creo que su mayor valor no está en reemplazar al humano, sino en el **triaje contextual**: analizar logs masivos, entender la topología de la red de forma dinámica y priorizar las vulnerabilidades basándose en la probabilidad real de explotación.

#### 8. Si pudiera diseñar un framework inteligente que ayude a identificar y evaluar automáticamente riesgos y vulnerabilidades en sistemas y aplicaciones, ¿qué funcionalidades o capacidades le gustaría que incluyera?
Me gustaría que incluyera tres capacidades clave:
* **Validación segura de exploits:** Que no solo alerte de que la vulnerabilidad existe, sino que intente explotarla de forma controlada para demostrar que el vector es real, reduciendo drásticamente los falsos positivos.
* **Generación automática de reportes multinivel:** Que traduzca el hallazgo técnico en un lenguaje de riesgo financiero para la mesa directiva (C-Level), y a la vez entregue el código de remediación exacto para los desarrolladores.
* **Descubrimiento de activos en la sombra (Shadow IT):** Que mapee la infraestructura constantemente para encontrar endpoints, APIs o servidores que algún equipo interno levantó sin previa autorización de TI.

#### 9. ¿Cuáles lógicas serían sus principales preocupaciones o riesgos al implementar un sistema que utilice Inteligencia Artificial para realizar evaluaciones automáticas de seguridad?
Mi mayor miedo es el impacto en la **disponibilidad del entorno**. Un agente de IA mal calibrado o muy agresivo ejecutando pruebas automatizadas en producción podría tirar un servicio crítico del negocio (generando un DDoS autoinfligido). 

La segunda preocupación es la **privacidad y gobernanza de los datos**: ¿dónde se procesa la información de nuestras vulnerabilidades? Si el framework usa modelos comerciales externos, no puedo permitir que el mapa de debilidades de mi infraestructura se suba a una nube pública para entrenar modelos de terceros.

---

### Bloque 4: Priorización e Integración Operativa

#### 10. ¿Qué tipos de pruebas o revisiones de seguridad (redes, aplicaciones, servidores, APIs, etc.) considera más importantes o prioritarias para automatizar en su día a día? ¿Por qué?
Prioridad absoluta: **APIs y Aplicaciones Web**. ¿Por qué? Porque la infraestructura de servidores y redes suele ser más estática y predecible, pero nuestras aplicaciones y APIs cambian todos los días con cada despliegue que hacen los desarrolladores. Es el perímetro más expuesto, cambiante y propenso a errores humanos de lógica.

#### 11. ¿Qué tipo de integración esperaría que tenga este tipo de framework con las herramientas y procesos que ya utiliza en su trabajo (ej. sistemas de monitoreo, gestión de incidentes, desarrollo de software, etc.)?
Integración directa y transparente basada en APIs. Si el framework descubre algo, no quiero otra consola web aislada a la cual entrar. Necesito que abra un ticket automáticamente en **Jira** asignado al equipo correspondiente, envíe una alerta crítica a canales dedicados de **Slack/Teams** si el riesgo es alto, y alimente nuestro SIEM para correlacionar eventos históricos.

#### 12. ¿Cómo mediría el éxito de un framework de este tipo? ¿Qué indicadores, mejoras o resultados serían más importantes para usted y para su organización?
Lo mediría mediante tres indicadores clave de rendimiento (KPIs):
1. **Reducción del MTTR (Mean Time to Remediate):** Disminución del tiempo promedio que pasa desde que se introduce una vulnerabilidad hasta que se aplica el parche.
2. **Tasa de Falsos Positivos:** Que el indicador de efectividad mantenga los errores de diagnóstico por debajo del 5%.
3. **Eficiencia Operativa (Horas/Hombre):** Cuántas horas de ingeniería manual le ahorramos al equipo de ciberseguridad gracias al triaje inteligente del framework.