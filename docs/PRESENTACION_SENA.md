# Proyecto de Grado SENA
## Plataforma de Analisis de Seguridad Automatizado - SecureScan Pro

---

## Informacion del Proyecto

| Campo | Informacion |
|-------|-------------|
| **Nombre del Proyecto** | SecureScan Pro - Plataforma de Analisis de Seguridad |
| **Programa de Formacion** | Tecnologia en Analisis y Desarrollo de Software / Seguridad Informatica |
| **Centro de Formacion** | [Completar] |
| **Regional** | [Completar] |
| **Ficha** | [Completar] |
| **Fecha de Presentacion** | [Completar] |

---

## Integrantes del Equipo

| Nombre Completo | Documento | Rol en el Proyecto |
|-----------------|-----------|-------------------|
| [Nombre 1] | [CC] | Desarrollador Backend / Lider |
| [Nombre 2] | [CC] | Desarrollador Frontend |
| [Nombre 3] | [CC] | Documentacion / QA |

---

## Instructor Lider

| Nombre | Area |
|--------|------|
| [Nombre del Instructor] | [Area de Formacion] |

---

# Resumen Ejecutivo

## Descripcion del Proyecto

SecureScan Pro es una plataforma web integral para el analisis automatizado de vulnerabilidades de seguridad. La herramienta permite a profesionales de ciberseguridad, estudiantes y administradores de sistemas evaluar la postura de seguridad de aplicaciones web mediante la ejecucion orquestada de multiples herramientas de pentesting reconocidas en la industria.

## Problema Identificado

Las organizaciones enfrentan desafios significativos en la evaluacion de seguridad de sus aplicaciones web:

1. **Complejidad tecnica**: Las herramientas de seguridad requieren conocimiento especializado para su configuracion y uso.
2. **Fragmentacion**: Los resultados de diferentes herramientas estan dispersos y en formatos incompatibles.
3. **Tiempo**: Ejecutar multiples herramientas manualmente consume tiempo significativo.
4. **Interpretacion**: Consolidar y priorizar hallazgos requiere experiencia avanzada.
5. **Documentacion**: Generar reportes profesionales demanda esfuerzo adicional.

## Solucion Propuesta

SecureScan Pro automatiza el proceso completo de evaluacion de seguridad:

- **Interfaz unificada**: Una sola plataforma web para gestionar todos los escaneos.
- **Automatizacion completa**: Ejecucion secuencial y orquestada de 6 herramientas de seguridad.
- **Consolidacion inteligente**: Agregacion de resultados con clasificacion por nivel de riesgo.
- **Scoring automatico**: Calculo de puntuacion de vulnerabilidad basado en CVSS.
- **Reportes profesionales**: Generacion automatica de informes tipo pentest.

---

# Objetivos del Proyecto

## Objetivo General

Desarrollar una plataforma web que automatice el proceso de analisis de vulnerabilidades mediante la integracion de herramientas de ciberseguridad reconocidas, proporcionando reportes consolidados y accionables.

## Objetivos Especificos

1. **Disenar** una arquitectura modular que permita la integracion flexible de herramientas de seguridad.

2. **Implementar** modulos de integracion para Nmap, Nikto, Gobuster, OWASP ZAP, Wappalyzer y Searchsploit.

3. **Desarrollar** un sistema de orquestacion que ejecute las herramientas de forma secuencial y controlada.

4. **Crear** un motor de scoring que clasifique vulnerabilidades segun su criticidad.

5. **Construir** un generador de reportes que produzca documentos profesionales en multiples formatos.

6. **Implementar** una interfaz web intuitiva para usuarios con diferentes niveles de experiencia.

7. **Configurar** un laboratorio de aplicaciones vulnerables para pruebas seguras y educacion.

8. **Documentar** el proyecto de forma completa para facilitar su replicacion y mantenimiento.

---

# Justificacion

## Importancia del Proyecto

### Para la Industria
- El 43% de los ciberataques se dirigen a pequenas y medianas empresas (Verizon DBIR 2024).
- El costo promedio de una brecha de seguridad es de $4.45 millones USD (IBM, 2024).
- La escasez de profesionales de ciberseguridad dificulta evaluaciones regulares.

### Para la Educacion
- Proporciona un entorno seguro para aprender tecnicas de pentesting.
- Reduce la barrera de entrada para estudiantes de seguridad informatica.
- Permite practicar con aplicaciones vulnerables sin riesgo legal.

### Para Profesionales
- Acelera el proceso de evaluacion inicial de seguridad.
- Estandariza la metodologia de pruebas.
- Automatiza la generacion de documentacion.

## Alineacion con Competencias SENA

Este proyecto desarrolla las siguientes competencias:

| Competencia | Aplicacion |
|-------------|------------|
| Analizar requisitos del cliente | Levantamiento de requerimientos de seguridad |
| Disenar sistemas de informacion | Arquitectura cliente-servidor modular |
| Desarrollar sistemas de informacion | Implementacion backend/frontend |
| Implementar seguridad informatica | Integracion de herramientas de pentesting |
| Documentar procesos | Documentacion tecnica completa |

---

# Marco Teorico

## Conceptos Fundamentales

### Pruebas de Penetracion (Pentesting)
Metodologia de evaluacion de seguridad que simula ataques reales para identificar vulnerabilidades. Se clasifican en:

- **Caja Negra**: Sin conocimiento previo del sistema.
- **Caja Blanca**: Con acceso completo a documentacion y codigo.
- **Caja Gris**: Conocimiento parcial del sistema.

### OWASP Top 10
Lista de las 10 vulnerabilidades web mas criticas segun la Open Web Application Security Project:

1. Broken Access Control
2. Cryptographic Failures
3. Injection
4. Insecure Design
5. Security Misconfiguration
6. Vulnerable Components
7. Authentication Failures
8. Software and Data Integrity Failures
9. Security Logging Failures
10. Server-Side Request Forgery

### CVSS (Common Vulnerability Scoring System)
Sistema estandarizado para calificar la severidad de vulnerabilidades:

| Rango | Severidad |
|-------|-----------|
| 0.0 | Ninguna |
| 0.1 - 3.9 | Baja |
| 4.0 - 6.9 | Media |
| 7.0 - 8.9 | Alta |
| 9.0 - 10.0 | Critica |

## Herramientas Integradas

### Nmap
Escaner de red para descubrimiento de hosts y servicios. Detecta:
- Puertos abiertos
- Servicios activos
- Versiones de software
- Sistema operativo

### Nikto
Escaner de vulnerabilidades web que verifica:
- Archivos peligrosos
- Versiones desactualizadas
- Configuraciones inseguras
- Mas de 6,700 items potencialmente peligrosos

### Gobuster
Herramienta de fuerza bruta para:
- Descubrimiento de directorios
- Enumeracion de subdominios
- Busqueda de archivos ocultos

### OWASP ZAP
Proxy de seguridad que permite:
- Escaneo pasivo automatico
- Escaneo activo de vulnerabilidades
- Fuzzing de parametros
- Spider de aplicaciones

### Wappalyzer
Identificador de tecnologias que detecta:
- CMS (WordPress, Drupal, etc.)
- Frameworks (React, Angular, etc.)
- Servidores web
- Librerias JavaScript

### Searchsploit
Interfaz de linea de comandos para Exploit-DB:
- Busqueda de exploits conocidos
- Base de datos de vulnerabilidades
- Integracion con Metasploit

---

# Metodologia de Desarrollo

## Modelo de Desarrollo

Se utilizo **metodologia agil Scrum** adaptada:

### Sprints Realizados

| Sprint | Duracion | Entregables |
|--------|----------|-------------|
| Sprint 1 | 2 semanas | Arquitectura y diseno |
| Sprint 2 | 2 semanas | Backend - Modulos de escaneo |
| Sprint 3 | 2 semanas | Frontend - Interfaz web |
| Sprint 4 | 2 semanas | Integracion y reportes |
| Sprint 5 | 1 semana | Documentacion y pruebas |

## Tecnologias Utilizadas

### Backend
- **Node.js 18+**: Runtime de JavaScript
- **Express.js**: Framework web
- **Child Process**: Ejecucion de herramientas externas

### Frontend
- **Next.js 16**: Framework React
- **Tailwind CSS**: Estilos utilitarios
- **shadcn/ui**: Componentes de interfaz

### Infraestructura
- **Docker**: Contenedorizacion
- **Docker Compose**: Orquestacion de contenedores
- **Kali Linux**: Sistema operativo base

### Herramientas de Desarrollo
- **VS Code**: Editor de codigo
- **Git**: Control de versiones
- **npm/pnpm**: Gestion de paquetes

---

# Arquitectura del Sistema

## Diagrama de Arquitectura

```
┌─────────────────────────────────────────────────────────────────┐
│                        CAPA DE PRESENTACION                      │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                    Next.js Frontend                      │    │
│  │  ┌──────────┐  ┌──────────┐  ┌──────────┐  ┌─────────┐ │    │
│  │  │  Scanner │  │   Lab    │  │ History  │  │ Results │ │    │
│  │  │   Page   │  │   Page   │  │   Page   │  │Dashboard│ │    │
│  │  └──────────┘  └──────────┘  └──────────┘  └─────────┘ │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ HTTP/REST API
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                        CAPA DE NEGOCIO                           │
│  ┌─────────────────────────────────────────────────────────┐    │
│  │                   Express.js Backend                     │    │
│  │  ┌────────────────────────────────────────────────────┐ │    │
│  │  │                   Orchestrator                      │ │    │
│  │  │  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐  │ │    │
│  │  │  │Wappalyzer│ │  Nmap   │ │Gobuster │ │  Nikto  │  │ │    │
│  │  │  └─────────┘ └─────────┘ └─────────┘ └─────────┘  │ │    │
│  │  │  ┌─────────┐ ┌─────────┐ ┌─────────────────────┐  │ │    │
│  │  │  │   ZAP   │ │Searchspl│ │   Scoring Engine    │  │ │    │
│  │  │  └─────────┘ └─────────┘ └─────────────────────┘  │ │    │
│  │  └────────────────────────────────────────────────────┘ │    │
│  │  ┌────────────────────────────────────────────────────┐ │    │
│  │  │              Report Generator                       │ │    │
│  │  └────────────────────────────────────────────────────┘ │    │
│  └─────────────────────────────────────────────────────────┘    │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Shell / API
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                      CAPA DE HERRAMIENTAS                        │
│  ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐   │
│  │  Nmap   │ │  Nikto  │ │Gobuster │ │OWASP ZAP│ │Searchspl│   │
│  └─────────┘ └─────────┘ └─────────┘ └─────────┘ └─────────┘   │
└─────────────────────────────────────────────────────────────────┘
                              │
                              │ Escaneo
                              ▼
┌─────────────────────────────────────────────────────────────────┐
│                    LABORATORIO VULNERABLE                        │
│  ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌──────────┐ ┌───────┐ │
│  │  Juice   │ │   DVWA   │ │ WebGoat  │ │  bWAPP   │ │Hackaz.│ │
│  │   Shop   │ │  :3002   │ │  :3003   │ │  :3004   │ │ :3005 │ │
│  │  :3001   │ │          │ │          │ │          │ │       │ │
│  └──────────┘ └──────────┘ └──────────┘ └──────────┘ └───────┘ │
└─────────────────────────────────────────────────────────────────┘
```

## Diagrama de Secuencia

```
Usuario          Frontend         Backend        Herramientas      Target
   │                │                │                │               │
   │ Ingresa URL    │                │                │               │
   │───────────────>│                │                │               │
   │                │ POST /api/scan │                │               │
   │                │───────────────>│                │               │
   │                │    Job ID      │                │               │
   │                │<───────────────│                │               │
   │                │                │                │               │
   │                │                │  Wappalyzer    │               │
   │                │                │───────────────>│ HTTP Request  │
   │                │                │                │──────────────>│
   │                │                │  Technologies  │               │
   │                │                │<───────────────│               │
   │                │                │                │               │
   │                │                │     Nmap       │               │
   │                │                │───────────────>│  Port Scan    │
   │                │                │                │──────────────>│
   │                │                │  Ports/Versions│               │
   │                │                │<───────────────│               │
   │                │                │                │               │
   │                │                │   Gobuster     │               │
   │                │                │───────────────>│  Dir Brute    │
   │                │                │                │──────────────>│
   │                │                │  Directories   │               │
   │                │                │<───────────────│               │
   │                │                │                │               │
   │                │                │     Nikto      │               │
   │                │                │───────────────>│  Web Scan     │
   │                │                │                │──────────────>│
   │                │                │ Vulnerabilities│               │
   │                │                │<───────────────│               │
   │                │                │                │               │
   │                │                │   OWASP ZAP    │               │
   │                │                │───────────────>│ Active Scan   │
   │                │                │                │──────────────>│
   │                │                │    Alerts      │               │
   │                │                │<───────────────│               │
   │                │                │                │               │
   │                │                │  Searchsploit  │               │
   │                │                │───────────────>│               │
   │                │                │    Exploits    │               │
   │                │                │<───────────────│               │
   │                │                │                │               │
   │                │                │ [Consolidate & Score]          │
   │                │                │ [Generate Report]              │
   │                │                │                │               │
   │                │ GET /status    │                │               │
   │                │───────────────>│                │               │
   │                │   Results      │                │               │
   │                │<───────────────│                │               │
   │   Resultados   │                │                │               │
   │<───────────────│                │                │               │
   │                │                │                │               │
```

---

# Resultados Obtenidos

## Funcionalidades Implementadas

| Funcionalidad | Estado | Descripcion |
|---------------|--------|-------------|
| Escaneo Nmap | Completado | Deteccion de puertos y servicios |
| Escaneo Nikto | Completado | Vulnerabilidades web |
| Escaneo Gobuster | Completado | Descubrimiento de directorios |
| Integracion ZAP | Completado | Escaneo activo de aplicaciones |
| Deteccion Wappalyzer | Completado | Identificacion de tecnologias |
| Busqueda Exploits | Completado | Integracion con Exploit-DB |
| Sistema de Scoring | Completado | Clasificacion por riesgo |
| Generador Reportes | Completado | HTML y Markdown |
| Laboratorio Docker | Completado | 5 aplicaciones vulnerables |
| Interfaz Web | Completado | Dashboard completo |

## Metricas del Proyecto

| Metrica | Valor |
|---------|-------|
| Lineas de codigo backend | ~3,500 |
| Lineas de codigo frontend | ~2,000 |
| Modulos desarrollados | 10 |
| Herramientas integradas | 6 |
| Aplicaciones vulnerables | 5 |
| Documentos generados | 6 |

## Pruebas Realizadas

### Pruebas contra Juice Shop
- **Puertos detectados**: 3001 (HTTP)
- **Tecnologias**: Node.js, Express, Angular
- **Vulnerabilidades encontradas**: 15
- **Exploits relacionados**: 3
- **Score final**: 7.2 (Alto)

### Pruebas contra DVWA
- **Puertos detectados**: 3002 (HTTP)
- **Tecnologias**: PHP, Apache, MySQL
- **Vulnerabilidades encontradas**: 23
- **Exploits relacionados**: 8
- **Score final**: 8.5 (Alto)

---

# Conclusiones

## Logros Alcanzados

1. **Automatizacion exitosa**: Se logro integrar 6 herramientas de seguridad en un flujo automatizado.

2. **Interfaz intuitiva**: La plataforma es accesible para usuarios con diferentes niveles de experiencia.

3. **Reportes profesionales**: Los informes generados cumplen con estandares de la industria.

4. **Ambiente seguro**: El laboratorio permite practicas sin riesgo legal.

5. **Documentacion completa**: El proyecto es replicable y mantenible.

## Limitaciones

1. **Dependencia de herramientas externas**: Requiere instalacion de multiples herramientas.

2. **Tiempo de escaneo**: Escaneos completos pueden tomar 15-30 minutos.

3. **Falsos positivos**: Algunas herramientas generan alertas que requieren validacion manual.

## Trabajo Futuro

1. Integracion de mas herramientas (Burp Suite, SQLMap).
2. Implementacion de escaneos programados.
3. Panel de administracion multi-usuario.
4. Integracion con sistemas de ticketing.
5. API publica documentada con Swagger.

---

# Referencias Bibliograficas

1. OWASP Foundation. (2024). OWASP Top 10 Web Application Security Risks. https://owasp.org/Top10/

2. NIST. (2024). Common Vulnerability Scoring System v3.1. https://nvd.nist.gov/vuln-metrics/cvss

3. Offensive Security. (2024). Exploit Database. https://www.exploit-db.com/

4. Gordon Lyon. (2024). Nmap Reference Guide. https://nmap.org/book/man.html

5. OWASP Foundation. (2024). ZAP User Guide. https://www.zaproxy.org/docs/

6. Kali Linux. (2024). Kali Tools. https://www.kali.org/tools/

---

# Anexos

## Anexo A: Manual de Usuario
Ver documento: `GUIA_INSTALACION.md`

## Anexo B: Referencia de API
Ver documento: `API_REFERENCE.md`

## Anexo C: Consideraciones Eticas
Ver documento: `ETICA_Y_LEGALIDAD.md`

## Anexo D: Estructura del Proyecto
Ver documento: `ESTRUCTURA_PROYECTO.md`

## Anexo E: Documentacion Tecnica Completa
Ver documento: `DOCUMENTACION_TECNICA_COMPLETA.md`

---

**Firma de Aprobacion**

| Rol | Nombre | Firma | Fecha |
|-----|--------|-------|-------|
| Aprendiz Lider | | | |
| Aprendiz 2 | | | |
| Aprendiz 3 | | | |
| Instructor | | | |

---

*Documento generado como parte del proyecto de grado para el Servicio Nacional de Aprendizaje - SENA*
