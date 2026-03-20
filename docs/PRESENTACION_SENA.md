# Proyecto de Grado SENA

## Plataforma de Análisis de Seguridad Automatizado - SecureScan Pro v3.0

---

## Información del Proyecto

| Campo                     | Información                                                             |
| ------------------------- | ----------------------------------------------------------------------- |
| **Nombre del Proyecto**   | SecureScan Pro - Plataforma de Análisis de Seguridad                    |
| **Versión**               | 3.0.0 (Arquitectura Resiliente)                                         |
| **Programa de Formación** | Tecnología en Análisis y Desarrollo de Software / Seguridad Informática |
| **Centro de Formación**   | [Completar]                                                             |
| **Regional**              | [Completar]                                                             |
| **Ficha**                 | [Completar]                                                             |
| **Fecha de Presentación** | [Completar]                                                             |

---

## Integrantes del Equipo

| Nombre Completo | Documento | Rol en el Proyecto                                  |
| --------------- | --------- | --------------------------------------------------- |
| [Nombre 1]      | [CC]      | Desarrollador Backend / Arquitectura de Resiliencia |
| [Nombre 2]      | [CC]      | Desarrollador Frontend / UX                         |
| [Nombre 3]      | [CC]      | Documentación / QA / DevOps                         |

---

## Instructor Líder

| Nombre                  | Área                |
| ----------------------- | ------------------- |
| [Nombre del Instructor] | [Área de Formación] |

---

# Resumen Ejecutivo

## Descripción del Proyecto

SecureScan Pro v3.0 es una plataforma web integral para el análisis automatizado de vulnerabilidades de seguridad con **arquitectura resiliente**. La herramienta permite a profesionales de ciberseguridad, estudiantes y administradores de sistemas evaluar la postura de seguridad de aplicaciones web mediante la ejecución orquestada de 6 herramientas de pentesting reconocidas, garantizando la continuidad del servicio incluso ante fallos parciales.

## Innovación Principal v3.0: Arquitectura Resiliente

La versión 3.0 introduce cuatro mecanismos de tolerancia a fallos que garantizan que un error en una herramienta no comprometa todo el escaneo:

| Mecanismo            | Función                                  | Beneficio                          |
| -------------------- | ---------------------------------------- | ---------------------------------- |
| **Circuit Breaker**  | Aislamiento de fallos entre herramientas | No hay cascada de errores          |
| **File Stabilizer**  | Espera de archivos de salida estables    | Elimina race conditions            |
| **Target Validator** | Health-check TCP + whitelist             | Solo escanea objetivos autorizados |
| **Process Manager**  | Gestión segura de procesos               | Limpieza automática de recursos    |

## Problema Identificado

Las organizaciones enfrentan desafíos significativos en la evaluación de seguridad de sus aplicaciones web:

1. **Complejidad técnica**: Las herramientas de seguridad requieren conocimiento especializado para su configuración y uso.
2. **Fragmentación**: Los resultados de diferentes herramientas están dispersos y en formatos incompatibles.
3. **Tiempo**: Ejecutar múltiples herramientas manualmente consume tiempo significativo.
4. **Interpretación**: Consolidar y priorizar hallazgos requiere experiencia avanzada.
5. **Documentación**: Generar reportes profesionales demanda esfuerzo adicional.
6. **Fragilidad**: Las herramientas tradicionales fallan completamente si un componente falla.

## Solución Propuesta

SecureScan Pro v3.0 automatiza el proceso completo de evaluación de seguridad con tolerancia a fallos:

- **Interfaz unificada**: Una sola plataforma web para gestionar todos los escaneos.
- **Automatización resiliente**: Ejecución orquestada con Circuit Breaker y recuperación automática.
- **Consolidación inteligente**: Agregación de resultados con clasificación por nivel de riesgo (CVSS + EPSS).
- **Scoring avanzado**: Cálculo de puntuación con Exploit Prediction Scoring System.
- **Reportes profesionales**: Generación automática de informes en HTML, PDF, SARIF y JSON.
- **Perfiles de escaneo**: Quick, Standard, Comprehensive y Passive según necesidades de tiempo.

---

# Objetivos del Proyecto

## Objetivo General

Desarrollar una plataforma web resiliente que automatice el proceso de análisis de vulnerabilidades mediante la integración de herramientas de ciberseguridad reconocidas, proporcionando reportes consolidados y accionables con tolerancia a fallos parciales.

## Objetivos Específicos

1. **Diseñar** una arquitectura modular resiliente con Circuit Breaker, File Stabilizer y Target Validator.

2. **Implementar** módulos de integración para WhatWeb, Nmap, Gobuster, OWASP ZAP, ExploitDB y Metasploit (opcional).

3. **Desarrollar** un sistema de orquestación que ejecute herramientas de forma secuencial con recuperación ante fallos.

4. **Crear** un motor de scoring que clasifique vulnerabilidades según CVSS 3.1 y EPSS.

5. **Construir** un generador de reportes que produzca documentos profesionales en múltiples formatos (HTML, PDF, SARIF, JSON).

6. **Implementar** una interfaz web intuitiva con detección automática de aplicaciones SPA.

7. **Configurar** un laboratorio de aplicaciones vulnerables con 4 servicios (Juice Shop, DVWA, WebGoat, WebWolf).

8. **Documentar** el proyecto de forma completa para facilitar su replicación y mantenimiento.

---

# Justificación

## Importancia del Proyecto

### Para la Industria

- El 43% de los ciberataques se dirigen a pequeñas y medianas empresas (Verizon DBIR 2024).
- El costo promedio de una brecha de seguridad es de $4.45 millones USD (IBM, 2024).
- La escasez de profesionales de ciberseguridad dificulta evaluaciones regulares.
- Las herramientas existentes son frágiles: un fallo interrumpe todo el proceso.

### Para la Educación

- Proporciona un entorno seguro para aprender técnicas de pentesting.
- Reduce la barrera de entrada para estudiantes de seguridad informática.
- Permite practicar con aplicaciones vulnerables sin riesgo legal.
- Demuestra conceptos avanzados de arquitectura resiliente (Circuit Breaker, etc.).

### Para Profesionales

- Acelera el proceso de evaluación inicial de seguridad.
- Estandariza la metodología de pruebas.
- Automatiza la generación de documentación.
- Garantiza resultados incluso ante fallos parciales de herramientas.

## Alineación con Competencias SENA

Este proyecto desarrolla las siguientes competencias:

| Competencia                         | Aplicación                                              |
| ----------------------------------- | ------------------------------------------------------- |
| Analizar requisitos del cliente     | Levantamiento de requerimientos de seguridad            |
| Diseñar sistemas de información     | Arquitectura cliente-servidor modular resiliente        |
| Desarrollar sistemas de información | Implementación backend/frontend con tolerancia a fallos |
| Implementar seguridad informática   | Integración de herramientas de pentesting               |
| Documentar procesos                 | Documentación técnica completa                          |

---

# Marco Teórico

## Conceptos Fundamentales

### Pruebas de Penetración (Pentesting)

Metodología de evaluación de seguridad que simula ataques reales para identificar vulnerabilidades. Se clasifican en:

- **Caja Negra**: Sin conocimiento previo del sistema.
- **Caja Blanca**: Con acceso completo a documentación y código.
- **Caja Gris**: Conocimiento parcial del sistema.

### OWASP Top 10 2021

Lista de las 10 vulnerabilidades web más críticas según la Open Web Application Security Project:

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable and Outdated Components
7. Identification and Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging and Monitoring Failures
10. Server-Side Request Forgery (SSRF)

### CVSS 3.1 (Common Vulnerability Scoring System)

Sistema estandarizado para calificar la severidad de vulnerabilidades:

| Rango      | Severidad | Color |
| ---------- | --------- | ----- |
| 0.0        | Ninguna   | ⚪    |
| 0.1 - 3.9  | Baja      | 🟢    |
| 4.0 - 6.9  | Media     | 🟡    |
| 7.0 - 8.9  | Alta      | 🟠    |
| 9.0 - 10.0 | Crítica   | 🔴    |

### EPSS (Exploit Prediction Scoring System)

Sistema que predice la probabilidad de que una vulnerabilidad sea explotada en la naturaleza, complementando CVSS con datos de amenazas reales.

## Herramientas Integradas

### WhatWeb (Reemplaza Wappalyzer en v3.0)

Identificador de tecnologías web nativo de Kali Linux:

- CMS (WordPress, Drupal, etc.)
- Frameworks (React, Angular, Vue.js, etc.)
- Servidores web y sus versiones
- Librerías JavaScript

**Ventaja sobre Wappalyzer**: Más ligero, mejor integración con Kali, mayor base de firmas.

### Nmap

Escáner de red para descubrimiento de hosts y servicios:

- Puertos abiertos y filtros
- Servicios activos y versiones
- Detección de sistema operativo
- Scripts NSE (Nmap Scripting Engine) para vulnerabilidades

**Integración v3.0**: XML de salida se procesa automáticamente por ExploitDB para búsqueda de exploits por versión de servicio.

### Gobuster

Herramienta de fuerza bruta para:

- Descubrimiento de directorios y archivos
- Enumeración de subdominios (modo dns)
- Fuerza bruta de hosts virtuales (modo vhost)

**Configuración v3.0**: 50 threads, extensiones configurables, wordlists de Kali Linux.

### OWASP ZAP (Zed Attack Proxy)

Proxy de seguridad que permite:

- Spider pasivo y activo de aplicaciones
- Escaneo activo de vulnerabilidades
- Fuzzing de parámetros
- Soporte especial para SPAs (Single Page Applications)

**Innovación v3.0**: Detección automática de SPAs (React, Angular, Vue) y uso de spiderClient con navegador headless.

### ExploitDB (Módulo Unificado)

Interfaz de línea de comandos para Exploit-DB:

- Búsqueda de exploits conocidos
- Integración directa con resultados de Nmap XML
- Enriquecimiento con datos del National Vulnerability Database (NVD)
- Filtrado de exploits DoS

**Cambio v3.0**: Reemplaza `exploitdb_lookup.js` con `exploitdb_unified.js` para integración seamless con Nmap.

### Metasploit (Opcional)

Framework de explotación con modo dry-run por defecto:

- Verificación de viabilidad de exploits sin ejecución real
- Integración RPC para automatización
- Post-explotación controlada (deshabilitada por defecto)

**Seguridad**: Modo `dryRun: true` por defecto. Requiere habilitación explícita para explotación real.

---

# Metodología de Desarrollo

## Modelo de Desarrollo

Se utilizó **metodología ágil Scrum** adaptada:

### Sprints Realizados

| Sprint   | Duración  | Entregables                                          |
| -------- | --------- | ---------------------------------------------------- |
| Sprint 1 | 2 semanas | Arquitectura resiliente y diseño de Circuit Breaker  |
| Sprint 2 | 2 semanas | Backend - Módulos de escaneo con File Stabilizer     |
| Sprint 3 | 2 semanas | Backend - Target Validator y Process Manager         |
| Sprint 4 | 2 semanas | Frontend - Interfaz web y detección SPA              |
| Sprint 5 | 2 semanas | Integración, reportes SARIF y pruebas de resiliencia |
| Sprint 6 | 1 semana  | Documentación y optimización                         |

## Tecnologías Utilizadas

### Backend

- **Node.js 20 LTS**: Runtime de JavaScript
- **Express.js**: Framework web
- **Child Process**: Ejecución de herramientas externas
- **EventEmitter**: Arquitectura orientada a eventos para el orquestador

### Frontend

- **Next.js 16**: Framework React con App Router
- **React 19**: Biblioteca de UI
- **Tailwind CSS 4**: Estilos utilitarios
- **shadcn/ui**: Componentes de interfaz (50+ componentes)

### Infraestructura

- **Docker 24.x**: Contenerización
- **Docker Compose 2.x**: Orquestación de contenedores
- **Kali Linux**: Sistema operativo base con herramientas preinstaladas

### Herramientas de Desarrollo

- **VS Code**: Editor de código
- **Git**: Control de versiones
- **npm/pnpm**: Gestión de paquetes

---

# Arquitectura del Sistema

## Diagrama de Arquitectura v3.0 (Resiliente)

┌─────────────────────────────────────────────────────────────────┐
│ CAPA DE PRESENTACIÓN │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Next.js 16 Frontend │ │
│ │ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌─────────┐ │ │
│ │ │ Scanner │ │ Lab │ │ History │ │ Results │ │ │
│ │ │ Page │ │ Page │ │ Page │ │Dashboard│ │ │
│ │ └──────────┘ └──────────┘ └──────────┘ └─────────┘ │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
│
│ HTTP/REST API
▼
┌─────────────────────────────────────────────────────────────────┐
│ CAPA DE NEGOCIO │
│ ┌─────────────────────────────────────────────────────────┐ │
│ │ Express.js Backend │ │
│ │ ┌────────────────────────────────────────────────────┐ │ │
│ │ │ SecureScan Orchestrator v3.0 │ │ │
│ │ │ ┌──────────────────────────────────────────────┐ │ │ │
│ │ │ │ MÓDULOS DE RESILIENCIA (Core) │ │ │ │
│ │ │ │ ┌──────────┐ ┌──────────┐ ┌──────────┐ │ │ │ │
│ │ │ │ │ Circuit │ │ File │ │ Target │ │ │ │ │
│ │ │ │ │ Breaker │ │ Stabilizer│ │ Validator│ │ │ │ │
│ │ │ │ └──────────┘ └──────────┘ └──────────┘ │ │ │ │
│ │ │ │ ┌──────────────────────────────────────────┐ │ │ │ │
│ │ │ │ │ Process Manager │ │ │ │ │
│ │ │ │ └──────────────────────────────────────────┘ │ │ │ │
│ │ │ └──────────────────────────────────────────────┘ │ │ │
│ │ │ │ │ │
│ │ │ ┌──────────────────────────────────────────────┐ │ │ │
│ │ │ │ MÓDULOS DE ESCANEO (6 herramientas) │ │ │ │
│ │ │ │ ┌─────────┐ ┌─────────┐ ┌─────────┐ │ │ │ │
│ │ │ │ │WhatWeb │ │ Nmap │ │Gobuster │ │ │ │ │
│ │ │ │ │(Tecnol.)│ │(Puertos)│ │ (Dirs) │ │ │ │ │
│ │ │ │ └─────────┘ └─────────┘ └─────────┘ │ │ │ │
│ │ │ │ ┌─────────┐ ┌─────────┐ ┌─────────┐ │ │ │ │
│ │ │ │ │ ZAP │ │ExploitDB│ │Metasploit│ │ │ │ │
│ │ │ │ │ (DAST) │ │(Exploits)│ │(Opcional)│ │ │ │ │
│ │ │ │ └─────────┘ └─────────┘ └─────────┘ │ │ │ │
│ │ │ └──────────────────────────────────────────────┘ │ │ │
│ │ │ │ │ │
│ │ │ ┌──────────────────────────────────────────────┐ │ │ │
│ │ │ │ POST-PROCESAMIENTO (Scoring + Reports) │ │ │ │
│ │ │ │ ┌──────────────┐ ┌──────────────────────┐ │ │ │ │
│ │ │ │ │Scoring Engine│ │ Report Generator │ │ │ │ │
│ │ │ │ │(CVSS+EPSS) │ │(HTML/PDF/SARIF/JSON) │ │ │ │ │
│ │ │ │ └──────────────┘ └──────────────────────┘ │ │ │ │
│ │ │ └──────────────────────────────────────────────┘ │ │ │
│ │ └────────────────────────────────────────────────────┘ │ │
│ └─────────────────────────────────────────────────────────┘ │
└─────────────────────────────────────────────────────────────────┘
│
│ Spawn / API / CLI
▼
┌─────────────────────────────────────────────────────────────────┐
│ CAPA DE HERRAMIENTAS │
│ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │
│ │WhatWeb │ │ Nmap │ │Gobuster │ │OWASP ZAP│ │ExploitDB│ │
│ └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘ │
│ ┌─────────┐ │
│ │Metasploit│ (Opcional - RPC) │
│ └─────────┘ │
└─────────────────────────────────────────────────────────────────┘
│
│ Docker Network (172.20.0.0/24)
▼
┌─────────────────────────────────────────────────────────────────┐
│ LABORATORIO VULNERABLE │
│ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ │
│ │ Juice │ │ DVWA │ │ WebGoat │ │ WebWolf │ │
│ │ Shop │ │ :3002 │ │ :3003 │ │ :9090 │ │
│ │ :3001 │ │ │ │ │ │ (Companion│ │
│ └──────────┘ └──────────┘ └──────────┘ └──────────┘ │
└─────────────────────────────────────────────────────────────────┘
plain
Copy

## Estados del Circuit Breaker

┌─────────────────────────────────────────────────────────────┐
│ CIRCUIT BREAKER LIFECYCLE │
│ │
│ ┌─────────┐ Fallo x N ┌─────────┐ │
│ │ CLOSED │ ───────────────────────────► │ OPEN │ │
│ │ (Normal)│ │(Bloqueo)│ │
│ └────┬────┘ └────┬────┘ │
│ ▲ │ │
│ │ Éxito │ │
│ │ ◄──────────────────────────────┘ │
│ │ Timeout configurable │
│ ┌────┴────┐ │
│ │HALF_OPEN│ ◄── Permite N llamadas de prueba │
│ │(Prueba) │ │
│ └─────────┘ │
│ │
│ Configuración por herramienta: │
│ • WhatWeb: 3 fallos / 60s timeout │
│ • Nmap: 2 fallos / 120s timeout │
│ • ZAP: 2 fallos / 300s timeout │
│ • Metasploit: 1 fallo / 300s timeout (más conservador) │
└─────────────────────────────────────────────────────────────┘
plain
Copy

## Perfiles de Escaneo

| Perfil            | Duración  | Herramientas                             | Uso                      |
| ----------------- | --------- | ---------------------------------------- | ------------------------ |
| **Quick**         | 5-10 min  | WhatWeb → Nmap (top 1000) → ZAP (spider) | Validación rápida, CI/CD |
| **Standard**      | 20-30 min | + Gobuster → ExploitDB + Active Scan     | Auditoría regular        |
| **Comprehensive** | 45-90 min | + Metasploit dry-run + DNS/VHost enum    | Evaluación completa      |
| **Passive**       | 10-15 min | Sin active scan, solo reconocimiento     | Entornos sensibles       |

---

# Resultados Obtenidos

## Funcionalidades Implementadas v3.0

| Funcionalidad         | Estado        | Descripción                                         |
| --------------------- | ------------- | --------------------------------------------------- |
| Escaneo WhatWeb       | ✅ Completado | Detección de tecnologías (reemplaza Wappalyzer)     |
| Escaneo Nmap          | ✅ Completado | Puertos, servicios, versiones, scripts NSE          |
| Escaneo Gobuster      | ✅ Completado | Directorios, subdominios, hosts virtuales           |
| Escaneo ZAP           | ✅ Completado | DAST completo con soporte SPA                       |
| Integración ExploitDB | ✅ Completado | Búsqueda automática desde Nmap XML                  |
| Metasploit Opcional   | ✅ Completado | Modo dry-run por defecto                            |
| Circuit Breaker       | ✅ Completado | Aislamiento de fallos entre herramientas            |
| File Stabilizer       | ✅ Completado | Espera de archivos estables                         |
| Target Validator      | ✅ Completado | Health-check TCP + whitelist                        |
| Process Manager       | ✅ Completado | Cleanup automático de procesos                      |
| Sistema de Scoring    | ✅ Completado | CVSS 3.1 + EPSS                                     |
| Generador Reportes    | ✅ Completado | HTML, PDF, SARIF, JSON                              |
| Laboratorio Docker    | ✅ Completado | 4 aplicaciones (Juice Shop, DVWA, WebGoat, WebWolf) |
| Interfaz Web          | ✅ Completado | Dashboard con detección SPA                         |

## Métricas del Proyecto v3.0

| Métrica                   | Valor                          |
| ------------------------- | ------------------------------ |
| Líneas de código backend  | ~4,500                         |
| Líneas de código frontend | ~2,200                         |
| Módulos desarrollados     | 10 (8 escaneo + 2 resiliencia) |
| Herramientas integradas   | 6 (7 con Metasploit opcional)  |
| Clases de resiliencia     | 4 (embebidas en orquestador)   |
| Aplicaciones vulnerables  | 4                              |
| Formatos de reporte       | 4 (HTML, PDF, SARIF, JSON)     |
| Perfiles de escaneo       | 4                              |

## Pruebas de Resiliencia Realizadas

### Escenario 1: Fallo de Nmap

- **Condición**: Nmap interrumpido manualmente durante escaneo
- **Resultado**: Circuit Breaker abrió circuito para Nmap, continuó con Gobuster y ZAP
- **Score final**: Calculado con datos parciales (WhatWeb, Gobuster, ZAP disponibles)
- **Estado**: ✅ ÉXITO - Escaneo completado con advertencias

### Escenario 2: Target No Disponible

- **Condición**: Intentar escanear puerto cerrado
- **Resultado**: TargetValidator rechazó antes de iniciar herramientas
- **Mensaje**: "No se puede conectar a localhost:9999 - Connection refused"
- **Estado**: ✅ ÉXITO - Validación preventiva funcionó

### Escenario 3: Archivo de Salida Incompleto

- **Condición**: ZAP escribiendo reporte JSON lentamente
- **Resultado**: FileStabilizer esperó 3 rondas estables antes de procesar
- **Prevención**: Race condition evitada, parsing exitoso
- **Estado**: ✅ ÉXITO - Estabilización correcta

## Pruebas contra Laboratorio

### Juice Shop (http://localhost:3001)

- **Tecnologías detectadas**: Node.js, Express, Angular, SQLite
- **Puertos**: 3001/tcp abierto
- **Directorios encontrados**: /api, /rest, /socket.io (sensible)
- **Vulnerabilidades ZAP**: 12 (2 High, 5 Medium, 5 Low)
- **Exploits relacionados**: 2 (Express.js, Node.js)
- **Score CVSS**: 7.2 (Alto)
- **Duración escaneo Standard**: 18 minutos

### DVWA (http://localhost:3002)

- **Tecnologías detectadas**: PHP, Apache, MariaDB
- **Puertos**: 3002/tcp, 3306/tcp (MySQL expuesto)
- **Directorios encontrados**: /config, /hackable, /dvwa
- **Vulnerabilidades ZAP**: 18 (3 High, 8 Medium, 7 Low)
- **Exploits relacionados**: 5 (PHP, Apache, MySQL)
- **Score CVSS**: 8.5 (Alto)
- **Duración escaneo Standard**: 15 minutos

### WebGoat (http://localhost:3003)

- **Tecnologías detectadas**: Java, Spring Boot, WebGoat
- **Puertos**: 3003/tcp, 9090/tcp (WebWolf)
- **Directorios encontrados**: /WebGoat, /plugin_extracted
- **Vulnerabilidades ZAP**: 8 (1 High, 4 Medium, 3 Low)
- **Exploits relacionados**: 1 (Spring)
- **Score CVSS**: 6.8 (Medio-Alto)
- **Duración escaneo Standard**: 22 minutos (más lento por Java)

---

# Conclusiones

## Logros Alcanzados v3.0

1. **Arquitectura resiliente implementada**: Los 4 mecanismos de tolerancia a fallos (Circuit Breaker, File Stabilizer, Target Validator, Process Manager) funcionan correctamente y garantizan que el escaneo continúe incluso si herramientas individuales fallan.

2. **Reemplazo exitoso de herramientas**: WhatWeb demostró ser más eficiente que Wappalyzer para el entorno Kali Linux, y la integración Nmap→ExploitDB elimina búsquedas manuales de exploits.

3. **Soporte moderno para SPAs**: La detección automática de React/Angular/Vue.js permite escanear aplicaciones modernas que las herramientas tradicionales no manejan bien.

4. **Laboratorio completo**: 4 aplicaciones proporcionan cobertura de diferentes stacks tecnológicos (Node.js, PHP, Java) y niveles de dificultad.

5. **Reportes multi-formato**: La inclusión de SARIF permite integración con pipelines de CI/CD modernos (GitHub Advanced Security, GitLab SAST).

6. **Seguridad por diseño**: El modo dry-run de Metasploit y el whitelist de targets garantizan uso ético por defecto.

## Limitaciones y Mitigaciones

| Limitación                           | Mitigación en v3.0                                    |
| ------------------------------------ | ----------------------------------------------------- |
| Dependencia de herramientas externas | Docker Compose con imágenes preconfiguradas           |
| Tiempo de escaneo (15-30 min)        | Perfiles Quick/Passive para necesidades urgentes      |
| Falsos positivos                     | Scoring Engine con EPSS para priorizar riesgos reales |
| Fragilidad ante fallos               | Circuit Breaker permite completar escaneos parciales  |

## Trabajo Futuro

1. **Integración de Burp Suite Enterprise** para escaneos más profundos.
2. **Escaneos programados** con cron integrado en el orquestador.
3. **Panel multi-usuario** con autenticación JWT y roles (admin, auditor, viewer).
4. **Integración con Jira/GitHub Issues** para creación automática de tickets.
5. **API pública documentada** con Swagger/OpenAPI.
6. **Dashboard de métricas históricas** con gráficos de tendencias de seguridad.
7. **Soporte para escaneos de infraestructura cloud** (AWS, Azure, GCP APIs).

---

# Referencias Bibliográficas

1. OWASP Foundation. (2024). OWASP Top 10 Web Application Security Risks 2021. https://owasp.org/Top10/

2. NIST. (2024). Common Vulnerability Scoring System v3.1 Specification. https://www.first.org/cvss/v3.1/specification-document

3. FIRST. (2024). EPSS - Exploit Prediction Scoring System. https://www.first.org/epss/

4. Nmap Project. (2024). Nmap Reference Guide. https://nmap.org/book/man.html

5. OWASP Foundation. (2024). ZAP User Guide. https://www.zaproxy.org/docs/

6. Offensive Security. (2024). Exploit Database. https://www.exploit-db.com/

7. Kali Linux. (2024). Kali Tools Documentation. https://www.kali.org/tools/

8. Martin Fowler. (2014). Circuit Breaker Pattern. https://martinfowler.com/bliki/CircuitBreaker.html

9. Docker Inc. (2024). Docker Compose Specification. https://compose-spec.io/

10. VNEXT Software. (2024). WhatWeb - Web Scanner. https://github.com/urbanadventurer/WhatWeb

---

# Anexos

## Anexo A: Manual de Instalación

Ver documento: `GUIA_INSTALACION.md`

## Anexo B: Referencia de API REST

Ver documento: `API_REFERENCE.md`

## Anexo C: Consideraciones Éticas y Legales

Ver documento: `ETICA_Y_LEGALIDAD.md`

## Anexo D: Estructura del Proyecto (Refactorizada)

Ver documento: `ESTRUCTURA_PROYECTO.md`

## Anexo E: Documentación Técnica Completa v3.0

Ver documento: `DOCUMENTACION_TECNICA_COMPLETA.md`

---

# Glosario de Términos Técnicos

| Término              | Definición                                                                        |
| -------------------- | --------------------------------------------------------------------------------- |
| **Circuit Breaker**  | Patrón de diseño que previene cascada de fallos                                   |
| **CVSS**             | Common Vulnerability Scoring System - Sistema de puntuación de vulnerabilidades   |
| **DAST**             | Dynamic Application Security Testing - Pruebas de seguridad dinámicas             |
| **EPSS**             | Exploit Prediction Scoring System - Predicción de explotación                     |
| **File Stabilizer**  | Mecanismo que espera a que archivos estén completamente escritos                  |
| **NSE**              | Nmap Scripting Engine - Motor de scripts de Nmap                                  |
| **SARIF**            | Static Analysis Results Interchange Format - Formato de intercambio de resultados |
| **SPA**              | Single Page Application - Aplicación de página única (React, Angular, Vue)        |
| **Target Validator** | Componente que verifica disponibilidad del objetivo antes de escanear             |

---

**Firma de Aprobación**

| Rol                         | Nombre | Firma | Fecha |
| --------------------------- | ------ | ----- | ----- |
| Aprendiz Líder / Backend    |        |       |       |
| Aprendiz Frontend           |        |       |       |
| Aprendiz Documentación / QA |        |       |       |
| Instructor Evaluador        |        |       |       |

---

_Documento generado como parte del proyecto de grado para el Servicio Nacional de Aprendizaje - SENA_
_tecnico en seguridad de aplicaciones web - 2026_
