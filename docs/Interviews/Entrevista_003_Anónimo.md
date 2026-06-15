# Anexo: Transcripción de Entrevista de Validación del Framework

**Perfil del Entrevistado:** Especialista en Redes y Conectividad  
**Sector de la Industria:** Telecomunicaciones e Infraestructura de Datos Híbrida  
**Experiencia:** ~8 años en administración de redes, enrutamiento y seguridad perimetral  
**Condición:** Anonimato solicitado / Autorización explícita otorgada para registro en el proyecto  

---

### Bloque 1: Perfil y Contexto Operativo

#### 1. ¿Cuál es su rol actual y cuántos años de experiencia tiene en el área de tecnologías de la información? ¿En qué tipo de entorno o industria trabaja principalmente?
Actualmente me desempeño como Especialista en Redes e Infraestructura. Cuento con aproximadamente 8 años de experiencia enfocados en el diseño, implementación y aseguramiento de redes corporativas. Trabajo principalmente en entornos híbridos (On-Premise y Multi-Cloud) para empresas de telecomunicaciones y centros de datos que gestionan alta disponibilidad.

#### 2. ¿Cuáles considera que son los principales desafíos o problemas más frecuentes que enfrenta su equipo en temas de seguridad informática, detección de vulnerabilidades o protección de sistemas?
Desde la perspectiva de redes, nuestro mayor dolor de cabeza es el **Shadow IT** (dispositivos o servicios que los usuarios o desarrolladores conectan a la red sin autorización) y las **malas configuraciones en las políticas de los firewalls**. 

El tráfico interno (Este-Oeste) suele ser muy difícil de monitorear en tiempo real; si un atacante logra comprometer una sola máquina interna, la falta de una microsegmentación estricta facilita el movimiento lateral hacia servidores críticos. Además, programar ventanas de mantenimiento para parchar el firmware de routers y switches troncales sin afectar la operación del negocio es un desafío logístico constante.

---

### Bloque 2: Estado de la Automatización y Herramientas Actuales

#### 3. ¿Cómo describiría el nivel de automatización actual en las actividades relacionadas con la seguridad de infraestructura, aplicaciones o redes en su organización? ¿Qué herramientas o procesos utilizan para automatizar tareas repetitivas?
El nivel de automatización es **intermedio para aprovisionamiento, pero bajo para seguridad activa**. Utilizamos *scripts* en Python (con librerías como Netmiko o Nornir) y Ansible para automatizar despliegues de configuración masivos y auditorías de puertos abiertos. 

Sin embargo, las pruebas de penetración en la red y la verificación manual de si una regla de firewall es vulnerable o redundante siguen dependiendo de auditorías externas periódicas o de la revisión manual de tablas de enrutamiento por parte del equipo técnico.

#### 4. ¿Qué experiencia ha tenido con herramientas automatizadas de seguridad? ¿En qué aspectos le ha resultado más útil y cuáles han sido sus mayores frustraciones?
Trabajo constantemente con escáneres de red como Nmap (automatizado con *cronjobs*), OpenVAS y analizadores de tráfico como Wireshark. 

Lo más útil es la capacidad de lanzar barridos rápidos de ping y mapeos de servicios para identificar qué puertos están expuestos en una subred en cuestión de minutos. La mayor frustración es el **volumen de datos (ruido)**: capturar tráfico genera archivos `.pcap` masivos que toman horas analizar. Además, algunos escáneres de seguridad agresivos mal configurados tienden a saturar las tablas de ruteo o los buffers de los switches de capa 2 (Layer 2), provocando microcortes de conectividad que alertan falsamente a los sistemas de monitoreo.

---

### Bloque 3: Percepción de la Inteligencia Artificial en Ciberseguridad

#### 5. ¿Qué opinión tiene sobre el uso de inteligencia artificial aplicada a la seguridad informática? ¿En qué áreas cree que la IA podría generar mayor valor?
Considero que la IA es fundamental para la supervivencia de las redes modernas debido al volumen de tráfico actual. El área donde la IA genera un valor disruptivo es en el **análisis de comportamiento de tráfico (NetFlow/IPFIX)**. Una IA puede aprender el comportamiento base de la red y detectar anomalías en milisegundos: por ejemplo, si una base de datos empieza a enviar gigabytes de información a un destino externo inusual a las 3:00 AM, la IA puede identificar este patrón de exfiltración mucho antes que cualquier regla estática basada en firmas.

#### 6. Si pudiera diseñar un framework inteligente que ayude a identificar y evaluar automáticamente riesgos y vulnerabilidades en sistemas y aplicaciones, ¿qué funcionalidades o capacidades le gustaría que incluyera?
Para el ámbito de redes, un framework ideal debería contar con:
* **Mapeo Dinámico y Descubrimiento de Topologías:** Que auto-descubra la red de forma pasiva y dibuje el mapa de topología real, alertando inmediatamente cuando aparece un host o una interfaz de red nueva (Rogue Devices).
* **Auditoría Automatizada de Reglas de Firewall:** Que analice las listas de control de acceso (ACLs) y las políticas de seguridad para simular si un atacante externo podría saltar de una zona pública (DMZ) a una zona privada.
* **Inyección de Tráfico Canario (Smart Replay):** Capacidad de replicar ráfagas de tráfico de ataques conocidos de manera controlada para validar si nuestros sistemas IDS/IPS (Sistemas de Detección/Prevención de Intrusos) están reaccionando correctamente.

#### 7. ¿Cuáles serían sus principales preocupaciones o riesgos al implementar un sistema que utilice inteligencia artificial para realizar evaluaciones automáticas de seguridad?
Mi mayor temor es una **tormenta de difusión (Broadcast Storm) o una denegación de servicio (DoS) involuntaria**. Si la IA empieza a escanear puertos de manera autónoma, paralela y sin control de ancho de banda, puede saturar los enlaces WAN o colapsar el procesamiento de los dispositivos perimetrales. 

La otra preocupación es el aislamiento erróneo: si la IA decide bloquear proactivamente un puerto troncal (`Trunk Link`) de un switch pensando que es un ataque, podría dejar desconectada a una sucursal entera o a un piso de la empresa por un falso positivo.

---

### Bloque 4: Priorización e Integración Operativa

#### 8. ¿Qué tipo de pruebas o revisión de seguridad considera más importante o prioritarias para automatizar en su día a día? ¿Por qué?
La prioridad número uno es el **escaneo continuo de endpoints externos y gateways VPN**. Con el auge del trabajo remoto, los accesos VPN son el blanco favorito de los atacantes. En segundo lugar, automatizaría la **verificación del aislamiento de VLANs**; garantizar que la red de invitados o de desarrollo esté 100% aislada de la red de producción y que los protocolos de enrutamiento (como OSPF o BGP) tengan autenticación estricta para evitar el secuestro de rutas.

#### 9. ¿Qué tipo de integración esperaría que tenga este tipo de framework con las herramientas y procesos que ya utilicen su trabajo?
Debe integrarse de forma nativa con nuestras herramientas de monitoreo de red como **Zabbix, PRTG o SolarWinds**, enviando alertas mediante traps SNMP o Webhooks. Asimismo, es vital que se conecte directamente con el **Syslog centralizado o el SIEM** corporativo, para que los eventos de red descubiertos se correlacionen con los eventos de los servidores en una sola línea de tiempo.

#### 10. ¿Cómo mediría el éxito de un framework de este tipo? ¿Qué indicadores, mejoras o resultados serían más importantes para usted y para su organización?
Lo mediría bajo tres métricas de infraestructura:
1. **Tiempo de Detección de Activos No Autorizados:** Cuántos minutos le toma al framework detectar y alertar sobre un nuevo dispositivo conectado sin permisos.
2. **Porcentaje de Cobertura de la Red:** Qué porcentaje de los segmentos de red y subredes de la organización están siendo evaluados de forma continua.
3. **Reducción de Brechas por Desconfiguración:** Disminución en el número de puertos críticos e innecesarios que quedan abiertos por error tras un despliegue de infraestructura.