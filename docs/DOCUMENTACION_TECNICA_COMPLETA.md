# DOCUMENTACION TECNICA COMPLETA
# SecureScan Pro - Plataforma de Analisis de Seguridad Automatizada

---

## PORTADA

**Proyecto:** SecureScan Pro - Plataforma de Analisis de Seguridad  
**Version:** 1.0.0  
**Fecha:** Marzo 2026  
**Institucion:** SENA - Servicio Nacional de Aprendizaje  
**Programa:** Tecnologia en Analisis y Desarrollo de Sistemas de Informacion  
**Documento:** Documentacion Tecnica Final del Proyecto  

---

## TABLA DE CONTENIDOS

1. [Descripcion General del Proyecto](#1-descripcion-general-del-proyecto)
2. [Objetivo del Sistema](#2-objetivo-del-sistema)
3. [Problema que Resuelve](#3-problema-que-resuelve)
4. [Arquitectura Completa del Sistema](#4-arquitectura-completa-del-sistema)
5. [Diagrama de Funcionamiento](#5-diagrama-de-funcionamiento)
6. [Flujo de Ejecucion Paso a Paso](#6-flujo-de-ejecucion-paso-a-paso)
7. [Integracion Detallada de Cada Herramienta](#7-integracion-detallada-de-cada-herramienta)
8. [Automatizacion Completa del Escaneo](#8-automatizacion-completa-del-escaneo)
9. [Integracion con Exploit-DB](#9-integracion-con-exploit-db)
10. [Ejecucion de Herramientas desde el Backend](#10-ejecucion-de-herramientas-desde-el-backend)
11. [Interaccion Web-Backend (API REST)](#11-interaccion-web-backend-api-rest)
12. [Visualizacion de Resultados](#12-visualizacion-de-resultados)
13. [Calculo del Score de Vulnerabilidad](#13-calculo-del-score-de-vulnerabilidad)
14. [Generacion de Reporte Final](#14-generacion-de-reporte-final)
15. [Consideraciones Eticas y Legales](#15-consideraciones-eticas-y-legales)
16. [Estructura del Proyecto](#16-estructura-del-proyecto)
17. [Guia de Instalacion Completa](#17-guia-de-instalacion-completa)
18. [Laboratorio de Aplicaciones Vulnerables](#18-laboratorio-de-aplicaciones-vulnerables)
19. [Anexos](#19-anexos)

---

## 1. DESCRIPCION GENERAL DEL PROYECTO

### 1.1 Introduccion

SecureScan Pro es una plataforma web de analisis de seguridad que automatiza la ejecucion de herramientas de ciberseguridad profesionales desde una interfaz web intuitiva. El sistema permite a profesionales de seguridad, auditores y estudiantes realizar evaluaciones de vulnerabilidades de forma sistematica y profesional.

### 1.2 Caracteristicas Principales

- **Interfaz Web Moderna:** Dashboard intuitivo desarrollado con Next.js y React
- **Automatizacion Completa:** Orquestacion automatica de 6 herramientas de seguridad
- **Analisis en Tiempo Real:** Visualizacion del progreso y resultados en vivo
- **Reportes Profesionales:** Generacion de reportes tipo pentest en HTML, Markdown y PDF
- **Score de Vulnerabilidad:** Sistema de puntuacion que clasifica el nivel de riesgo
- **Laboratorio Integrado:** Entorno de practica con 5 aplicaciones vulnerables
- **API RESTful:** Backend escalable y documentado

### 1.3 Tecnologias Utilizadas

| Componente | Tecnologia |
|------------|------------|
| Frontend | Next.js 16, React 19, Tailwind CSS 4, shadcn/ui |
| Backend | Node.js 20+, Express.js |
| Base de Datos | Sistema de archivos JSON (escalable a PostgreSQL) |
| Contenedores | Docker, Docker Compose |
| Herramientas | Nmap, Nikto, Gobuster, OWASP ZAP, Wappalyzer, Searchsploit |
| Sistema Operativo | Kali Linux (recomendado) |

### 1.4 Requisitos del Sistema

**Hardware Minimo:**
- Procesador: 4 nucleos (Intel i5 o equivalente)
- RAM: 8 GB minimo (16 GB recomendado)
- Almacenamiento: 50 GB libres
- Red: Conexion a Internet

**Software Requerido:**
- Kali Linux 2024.x o superior
- Docker 24.x o superior
- Docker Compose 2.x o superior
- Node.js 20.x o superior
- npm 10.x o superior

---

## 2. OBJETIVO DEL SISTEMA

### 2.1 Objetivo General

Desarrollar una plataforma web automatizada que integre multiples herramientas de ciberseguridad para realizar evaluaciones de vulnerabilidades de forma sistematica, generando reportes profesionales que faciliten la identificacion y correccion de debilidades de seguridad.

### 2.2 Objetivos Especificos

1. **Automatizar** la ejecucion orquestada de herramientas de seguridad (Nmap, Nikto, Gobuster, ZAP, Wappalyzer, Searchsploit)

2. **Consolidar** los resultados de multiples herramientas en un formato unificado y comprensible

3. **Calcular** un score de vulnerabilidad basado en metodologias estandar (CVSS, OWASP)

4. **Generar** reportes profesionales descargables en multiples formatos

5. **Proporcionar** una interfaz web intuitiva para usuarios con diferentes niveles de experiencia

6. **Incluir** un laboratorio de practica con aplicaciones vulnerables para entrenamiento seguro

7. **Documentar** completamente el sistema para facilitar su replicacion y mantenimiento

### 2.3 Alcance del Proyecto

**Incluido:**
- Escaneo de aplicaciones web
- Deteccion de tecnologias
- Identificacion de puertos y servicios
- Descubrimiento de directorios
- Analisis de vulnerabilidades web
- Busqueda de exploits conocidos
- Generacion de reportes
- Laboratorio de practica

**Excluido:**
- Explotacion automatica de vulnerabilidades
- Ataques de fuerza bruta a credenciales
- Ingenieria social
- Analisis de codigo fuente
- Pruebas de denegacion de servicio

---

## 3. PROBLEMA QUE RESUELVE

### 3.1 Problematica Identificada

En el ambito de la ciberseguridad, los profesionales enfrentan varios desafios:

1. **Fragmentacion de Herramientas:** Cada herramienta de seguridad tiene su propia interfaz, parametros y formato de salida, lo que dificulta su uso conjunto.

2. **Curva de Aprendizaje:** Dominar multiples herramientas de linea de comandos requiere tiempo y experiencia significativa.

3. **Consolidacion Manual:** Combinar resultados de diferentes herramientas para generar un reporte unificado es un proceso tedioso y propenso a errores.

4. **Falta de Estandarizacion:** Sin un sistema de scoring consistente, es dificil priorizar hallazgos y comunicar riesgos a stakeholders no tecnicos.

5. **Entornos de Practica:** Configurar laboratorios de practica seguros requiere conocimiento tecnico avanzado.

### 3.2 Solucion Propuesta

SecureScan Pro aborda estos problemas mediante:

```
+------------------+     +-------------------+     +------------------+
|   PROBLEMA       | --> |    SOLUCION       | --> |   BENEFICIO      |
+------------------+     +-------------------+     +------------------+
| Fragmentacion    | --> | Orquestacion      | --> | Un solo punto    |
| de herramientas  |     | automatica        |     | de entrada       |
+------------------+     +-------------------+     +------------------+
| Curva de         | --> | Interfaz web      | --> | Uso inmediato    |
| aprendizaje      |     | intuitiva         |     | sin capacitacion |
+------------------+     +-------------------+     +------------------+
| Consolidacion    | --> | Parser unificado  | --> | Resultados       |
| manual           |     | automatico        |     | integrados       |
+------------------+     +-------------------+     +------------------+
| Sin scoring      | --> | Motor de scoring  | --> | Priorizacion     |
| estandar         |     | basado en CVSS    |     | clara            |
+------------------+     +-------------------+     +------------------+
| Laboratorios     | --> | Docker Compose    | --> | Lab listo en     |
| complejos        |     | con 5 apps        |     | un comando       |
+------------------+     +-------------------+     +------------------+
```

### 3.3 Beneficiarios

- **Estudiantes de Ciberseguridad:** Aprenden con herramientas reales en entorno seguro
- **Profesionales de TI:** Realizan auditorias rapidas de sus sistemas
- **Pentesters Junior:** Aceleran su flujo de trabajo con automatizacion
- **Instituciones Educativas:** Usan la plataforma para practicas y evaluaciones

---

## 4. ARQUITECTURA COMPLETA DEL SISTEMA

### 4.1 Diagrama de Arquitectura General

```
+============================================================================+
|                        SECURESCAN PRO - ARQUITECTURA                       |
+============================================================================+

                              +------------------+
                              |     USUARIO      |
                              |    (Navegador)   |
                              +--------+---------+
                                       |
                                       | HTTPS
                                       v
+------------------------------------------------------------------------------+
|                              CAPA DE PRESENTACION                            |
|  +------------------------------------------------------------------------+  |
|  |                         FRONTEND (Next.js 16)                          |  |
|  |  +------------------+  +------------------+  +------------------+      |  |
|  |  |   Landing Page   |  |  Scanner Page    |  |   Lab Manager    |      |  |
|  |  +------------------+  +------------------+  +------------------+      |  |
|  |  +------------------+  +------------------+  +------------------+      |  |
|  |  |   History Page   |  |  Results View    |  |  Report Download |      |  |
|  |  +------------------+  +------------------+  +------------------+      |  |
|  +------------------------------------------------------------------------+  |
+------------------------------------------------------------------------------+
                                       |
                                       | API REST (JSON)
                                       v
+------------------------------------------------------------------------------+
|                              CAPA DE APLICACION                              |
|  +------------------------------------------------------------------------+  |
|  |                       BACKEND (Node.js + Express)                      |  |
|  |                                                                        |  |
|  |  +------------------------+    +-----------------------------+         |  |
|  |  |     API Controllers    |    |     Job Queue Manager       |         |  |
|  |  |  - POST /api/scan      |    |  - Cola de trabajos         |         |  |
|  |  |  - GET /api/scan/:id   |    |  - Gestion de concurrencia  |         |  |
|  |  |  - GET /api/report     |    |  - Timeouts y reintentos    |         |  |
|  |  +------------------------+    +-----------------------------+         |  |
|  |                                                                        |  |
|  |  +------------------------------------------------------------------+  |  |
|  |  |                      ORCHESTRATOR MODULE                         |  |  |
|  |  |  Coordina la ejecucion secuencial de todas las herramientas     |  |  |
|  |  +------------------------------------------------------------------+  |  |
|  |                                                                        |  |
|  |  +-------------+ +-------------+ +-------------+ +-------------+       |  |
|  |  | Wappalyzer  | |    Nmap     | |  Gobuster   | |   Nikto     |       |  |
|  |  |   Module    | |   Module    | |   Module    | |   Module    |       |  |
|  |  +-------------+ +-------------+ +-------------+ +-------------+       |  |
|  |  +-------------+ +-------------+ +-------------+ +-------------+       |  |
|  |  |  ZAP Module | | ExploitDB   | |  Scoring    | |   Report    |       |  |
|  |  |             | |   Module    | |   Engine    | |  Generator  |       |  |
|  |  +-------------+ +-------------+ +-------------+ +-------------+       |  |
|  +------------------------------------------------------------------------+  |
+------------------------------------------------------------------------------+
                                       |
                                       | Spawn/Exec
                                       v
+------------------------------------------------------------------------------+
|                            CAPA DE HERRAMIENTAS                              |
|  +------------------------------------------------------------------------+  |
|  |                    SISTEMA OPERATIVO (Kali Linux)                      |  |
|  |                                                                        |  |
|  |  +-------------+ +-------------+ +-------------+ +-------------+       |  |
|  |  |    Nmap     | |   Nikto     | |  Gobuster   | |  OWASP ZAP  |       |  |
|  |  |   CLI       | |    CLI      | |    CLI      | |   Daemon    |       |  |
|  |  +-------------+ +-------------+ +-------------+ +-------------+       |  |
|  |  +-------------+ +-------------+                                       |  |
|  |  | Wappalyzer  | | Searchsploit|                                       |  |
|  |  |    CLI      | |    CLI      |                                       |  |
|  |  +-------------+ +-------------+                                       |  |
|  +------------------------------------------------------------------------+  |
+------------------------------------------------------------------------------+
                                       |
                                       | Docker Network
                                       v
+------------------------------------------------------------------------------+
|                           LABORATORIO VULNERABLE                             |
|  +------------------------------------------------------------------------+  |
|  |                         DOCKER COMPOSE                                 |  |
|  |                                                                        |  |
|  |  +-------------+ +-------------+ +-------------+ +-------------+       |  |
|  |  | Juice Shop  | |    DVWA     | |  WebGoat    | |   bWAPP     |       |  |
|  |  | Port: 3001  | | Port: 3002  | | Port: 3003  | | Port: 3004  |       |  |
|  |  +-------------+ +-------------+ +-------------+ +-------------+       |  |
|  |  +-------------+                                                       |  |
|  |  |  Hackazon   |                                                       |  |
|  |  | Port: 3005  |                                                       |  |
|  |  +-------------+                                                       |  |
|  +------------------------------------------------------------------------+  |
+------------------------------------------------------------------------------+

+------------------------------------------------------------------------------+
|                           CAPA DE PERSISTENCIA                               |
|  +------------------------------------------------------------------------+  |
|  |  +------------------+  +------------------+  +------------------+      |  |
|  |  |   /reports/      |  |   /data/jobs/    |  |    /logs/        |      |  |
|  |  | Reportes JSON,   |  |  Estado de jobs  |  |  Logs del        |      |  |
|  |  | HTML, Markdown   |  |  y resultados    |  |  sistema         |      |  |
|  |  +------------------+  +------------------+  +------------------+      |  |
|  +------------------------------------------------------------------------+  |
+------------------------------------------------------------------------------+
```

### 4.2 Componentes Principales

#### 4.2.1 Frontend (Next.js 16)

El frontend es una aplicacion de pagina unica (SPA) con renderizado del lado del servidor (SSR):

| Pagina | Ruta | Descripcion |
|--------|------|-------------|
| Landing | `/` | Pagina principal con informacion del proyecto |
| Scanner | `/scanner` | Interfaz para iniciar escaneos |
| Lab | `/lab` | Gestion del laboratorio vulnerable |
| History | `/history` | Historial de escaneos realizados |

#### 4.2.2 Backend (Node.js + Express)

El backend maneja toda la logica de negocio:

```javascript
// Estructura de modulos del backend
backend/
├── server.js           // Punto de entrada y configuracion Express
├── modules/
│   ├── orchestrator.js     // Coordinador de herramientas
│   ├── nmap_scanner.js     // Wrapper para Nmap
│   ├── nikto_scanner.js    // Wrapper para Nikto
│   ├── gobuster_scanner.js // Wrapper para Gobuster
│   ├── zap_scanner.js      // Wrapper para OWASP ZAP
│   ├── wappalyzer_detector.js // Wrapper para Wappalyzer
│   ├── exploitdb_lookup.js // Wrapper para Searchsploit
│   ├── scoring_engine.js   // Motor de calculo de score
│   └── report_generator.js // Generador de reportes
└── utils/
    └── logger.js           // Sistema de logging
```

#### 4.2.3 Herramientas de Seguridad

Cada herramienta tiene un proposito especifico:

| Herramienta | Funcion | Output |
|-------------|---------|--------|
| Wappalyzer | Detecta tecnologias web | JSON con tecnologias |
| Nmap | Escanea puertos y servicios | XML con puertos/versiones |
| Gobuster | Descubre directorios | Lista de rutas encontradas |
| Nikto | Encuentra vulnerabilidades web | JSON con hallazgos |
| OWASP ZAP | Escaneo de aplicacion web | JSON con alertas |
| Searchsploit | Busca exploits conocidos | JSON con exploits |

---

## 5. DIAGRAMA DE FUNCIONAMIENTO

### 5.1 Diagrama de Secuencia Principal

```
+--------+     +----------+     +------------+     +-----------+
| Usuario|     | Frontend |     |  Backend   |     |Herramienta|
+---+----+     +----+-----+     +-----+------+     +-----+-----+
    |               |                 |                  |
    | 1. Ingresa URL|                 |                  |
    |-------------->|                 |                  |
    |               |                 |                  |
    |               | 2. POST /api/scan                  |
    |               |---------------->|                  |
    |               |                 |                  |
    |               | 3. Return jobId |                  |
    |               |<----------------|                  |
    |               |                 |                  |
    | 4. Muestra ID |                 |                  |
    |<--------------|                 |                  |
    |               |                 |                  |
    |               |                 | 5. Spawn Wappalyzer
    |               |                 |----------------->|
    |               |                 |                  |
    |               |                 | 6. Return techs  |
    |               |                 |<-----------------|
    |               |                 |                  |
    |               |                 | 7. Spawn Nmap    |
    |               |                 |----------------->|
    |               |                 |                  |
    |               |                 | 8. Return ports  |
    |               |                 |<-----------------|
    |               |                 |                  |
    |               |                 | [... Gobuster, Nikto, ZAP ...]
    |               |                 |                  |
    |               |                 | 9. Spawn Searchsploit
    |               |                 |----------------->|
    |               |                 |                  |
    |               |                 | 10. Return exploits
    |               |                 |<-----------------|
    |               |                 |                  |
    |               | 11. GET /api/scan/:id/status       |
    |               |---------------->|                  |
    |               |                 |                  |
    |               | 12. Return progress                |
    |               |<----------------|                  |
    |               |                 |                  |
    | 13. Update UI |                 |                  |
    |<--------------|                 |                  |
    |               |                 |                  |
    |               |                 | 14. Calculate Score
    |               |                 |--------+         |
    |               |                 |        |         |
    |               |                 |<-------+         |
    |               |                 |                  |
    |               |                 | 15. Generate Report
    |               |                 |--------+         |
    |               |                 |        |         |
    |               |                 |<-------+         |
    |               |                 |                  |
    |               | 16. GET /api/scan/:id/report       |
    |               |---------------->|                  |
    |               |                 |                  |
    |               | 17. Return report                  |
    |               |<----------------|                  |
    |               |                 |                  |
    | 18. Download  |                 |                  |
    |<--------------|                 |                  |
    |               |                 |                  |
+---+----+     +----+-----+     +-----+------+     +-----+-----+
```

### 5.2 Diagrama de Estados del Escaneo

```
                    +-------------+
                    |   CREATED   |
                    +------+------+
                           |
                           | iniciar escaneo
                           v
                    +------+------+
                    |   RUNNING   |<---------+
                    +------+------+          |
                           |                 |
           +---------------+---------------+ |
           |               |               | |
           v               v               v |
    +------+------+ +------+------+ +------+-+----+
    | WAPPALYZER  | |    NMAP     | |  GOBUSTER   |
    +------+------+ +------+------+ +------+------+
           |               |               |
           +---------------+---------------+
                           |
                           v
    +------+------+ +------+------+ +------+------+
    |    NIKTO    | |     ZAP     | | SEARCHSPLOIT|
    +------+------+ +------+------+ +------+------+
           |               |               |
           +---------------+---------------+
                           |
                           v
                    +------+------+
                    |  ANALYZING  |
                    +------+------+
                           |
                           | calcular score
                           v
                    +------+------+
                    |  REPORTING  |
                    +------+------+
                           |
                           | generar reporte
                           v
                    +------+------+
                    |  COMPLETED  |
                    +-------------+
                           
        (En caso de error en cualquier etapa)
                           |
                           v
                    +------+------+
                    |   FAILED    |
                    +-------------+
```

---

## 6. FLUJO DE EJECUCION PASO A PASO

### 6.1 Paso 1: Ingreso de URL

El usuario ingresa la URL objetivo en la interfaz web:

```
┌──────────────────────────────────────────────────────────────────┐
│  SecureScan Pro - Nuevo Escaneo                                  │
├──────────────────────────────────────────────────────────────────┤
│                                                                  │
│  URL o Dominio Objetivo:                                         │
│  ┌────────────────────────────────────────────────────────────┐  │
│  │ http://localhost:3001                                      │  │
│  └────────────────────────────────────────────────────────────┘  │
│                                                                  │
│  Opciones de Escaneo:                                            │
│  [x] Deteccion de tecnologias (Wappalyzer)                      │
│  [x] Escaneo de puertos (Nmap)                                  │
│  [x] Descubrimiento de directorios (Gobuster)                   │
│  [x] Vulnerabilidades web (Nikto)                               │
│  [x] Escaneo de aplicacion (OWASP ZAP)                          │
│  [x] Busqueda de exploits (Searchsploit)                        │
│                                                                  │
│  Modo de escaneo:                                                │
│  ( ) Rapido (5-10 min)                                          │
│  (x) Normal (15-30 min)                                         │
│  ( ) Profundo (30-60 min)                                       │
│                                                                  │
│                    [ Iniciar Escaneo ]                           │
│                                                                  │
└──────────────────────────────────────────────────────────────────┘
```

### 6.2 Paso 2: Validacion y Creacion del Job

El backend valida la entrada y crea un trabajo:

```javascript
// Validacion de URL
const validateTarget = (url) => {
  // Lista blanca para laboratorio
  const whitelist = [
    'localhost',
    '127.0.0.1',
    '192.168.',
    '10.',
    '172.16.'
  ];
  
  const urlObj = new URL(url);
  const isWhitelisted = whitelist.some(
    prefix => urlObj.hostname.startsWith(prefix)
  );
  
  if (!isWhitelisted) {
    throw new Error('Solo se permiten objetivos locales o en redes privadas');
  }
  
  return true;
};

// Creacion del job
const createScanJob = (target, options) => {
  const jobId = generateUUID();
  const job = {
    id: jobId,
    target: target,
    options: options,
    status: 'created',
    progress: 0,
    steps: [],
    results: {},
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };
  
  // Guardar en memoria/archivo
  jobs.set(jobId, job);
  
  return job;
};
```

### 6.3 Paso 3: Ejecucion de Wappalyzer

Primera herramienta en ejecutarse para detectar tecnologias:

```bash
# Comando ejecutado
wappalyzer http://localhost:3001 --pretty

# Salida ejemplo
{
  "urls": {
    "http://localhost:3001/": {
      "status": 200
    }
  },
  "technologies": [
    {
      "slug": "express",
      "name": "Express",
      "confidence": 100,
      "version": "4.18.2",
      "categories": [
        {
          "id": 18,
          "name": "Web frameworks"
        }
      ]
    },
    {
      "slug": "nodejs",
      "name": "Node.js",
      "confidence": 100,
      "categories": [
        {
          "id": 27,
          "name": "Programming languages"
        }
      ]
    }
  ]
}
```

### 6.4 Paso 4: Ejecucion de Nmap

Escaneo de puertos y deteccion de versiones:

```bash
# Comando ejecutado
nmap -sV -sC -oX /tmp/nmap_result.xml localhost -p 3001-3005

# Salida parseada
{
  "host": {
    "address": "127.0.0.1",
    "hostnames": ["localhost"],
    "status": "up"
  },
  "ports": [
    {
      "port": 3001,
      "protocol": "tcp",
      "state": "open",
      "service": {
        "name": "http",
        "product": "Node.js Express framework",
        "version": "4.18.2"
      }
    },
    {
      "port": 3002,
      "protocol": "tcp",
      "state": "open",
      "service": {
        "name": "http",
        "product": "Apache",
        "version": "2.4.56"
      }
    }
  ]
}
```

### 6.5 Paso 5: Ejecucion de Gobuster

Descubrimiento de directorios y archivos:

```bash
# Comando ejecutado
gobuster dir -u http://localhost:3001 -w /usr/share/wordlists/dirb/common.txt \
  -x php,html,js,txt -o /tmp/gobuster_result.txt -q

# Salida
/admin                (Status: 200) [Size: 1234]
/api                  (Status: 301) [Size: 178]
/login                (Status: 200) [Size: 2456]
/uploads              (Status: 403) [Size: 287]
/config.js            (Status: 200) [Size: 456]
/robots.txt           (Status: 200) [Size: 89]
/.git                 (Status: 403) [Size: 287]
```

### 6.6 Paso 6: Ejecucion de Nikto

Analisis de vulnerabilidades del servidor web:

```bash
# Comando ejecutado
nikto -h http://localhost:3001 -Format json -output /tmp/nikto_result.json

# Salida parseada
{
  "host": "localhost",
  "port": "3001",
  "vulnerabilities": [
    {
      "id": "000544",
      "osvdb": "877",
      "method": "GET",
      "url": "/",
      "message": "The X-Content-Type-Options header is not set",
      "severity": "medium"
    },
    {
      "id": "000291",
      "osvdb": "0",
      "method": "GET",
      "url": "/admin",
      "message": "Admin login page found",
      "severity": "info"
    }
  ]
}
```

### 6.7 Paso 7: Ejecucion de OWASP ZAP

Escaneo completo de la aplicacion web:

```bash
# Iniciar ZAP en modo daemon (si no esta corriendo)
zap.sh -daemon -port 8080 -config api.key=12345

# Escaneo via API
curl "http://localhost:8080/JSON/spider/action/scan/?apikey=12345&url=http://localhost:3001"
curl "http://localhost:8080/JSON/ascan/action/scan/?apikey=12345&url=http://localhost:3001"

# Obtener alertas
curl "http://localhost:8080/JSON/core/view/alerts/?apikey=12345&baseurl=http://localhost:3001"

# Salida parseada
{
  "alerts": [
    {
      "name": "Cross-Site Scripting (Reflected)",
      "risk": "High",
      "confidence": "Medium",
      "cweid": "79",
      "wascid": "8",
      "description": "Cross-site Scripting (XSS) is an attack technique...",
      "solution": "Phase: Architecture and Design...",
      "instances": [
        {
          "uri": "http://localhost:3001/search",
          "method": "GET",
          "param": "q",
          "evidence": "<script>alert(1)</script>"
        }
      ]
    }
  ]
}
```

### 6.8 Paso 8: Ejecucion de Searchsploit

Busqueda de exploits basada en versiones detectadas:

```bash
# Comandos ejecutados (basados en versiones de Nmap)
searchsploit --json "Node.js Express 4.18"
searchsploit --json "Apache 2.4.56"

# Salida combinada
{
  "searches": [
    {
      "query": "Apache 2.4",
      "results": [
        {
          "title": "Apache 2.4.49 - Path Traversal",
          "edb_id": "50383",
          "date": "2021-10-05",
          "type": "webapps",
          "platform": "multiple",
          "path": "/usr/share/exploitdb/exploits/multiple/webapps/50383.py"
        }
      ]
    }
  ]
}
```

### 6.9 Paso 9: Calculo del Score

El motor de scoring procesa todos los hallazgos:

```javascript
// Ejemplo de calculo
const calculateScore = (findings) => {
  const weights = {
    critical: 25,
    high: 15,
    medium: 8,
    low: 3,
    info: 1
  };
  
  let totalPenalty = 0;
  
  findings.forEach(finding => {
    totalPenalty += weights[finding.severity] || 0;
  });
  
  const normalizationFactor = Math.max(1, findings.length / 10);
  const score = Math.max(0, 100 - (totalPenalty / normalizationFactor));
  
  return Math.round(score);
};

// Ejemplo de resultado
// Hallazgos: 2 criticos, 5 altos, 10 medios, 8 bajos, 15 info
// Penalty: (2*25) + (5*15) + (10*8) + (8*3) + (15*1) = 50 + 75 + 80 + 24 + 15 = 244
// Normalization: max(1, 40/10) = 4
// Score: 100 - (244/4) = 100 - 61 = 39/100 (Deficiente)
```

### 6.10 Paso 10: Generacion del Reporte

El sistema genera reportes en multiples formatos:

```javascript
// Generacion de reporte HTML
const generateHTMLReport = (scanResults) => {
  const template = fs.readFileSync('templates/report.html', 'utf8');
  
  const data = {
    scanId: scanResults.id,
    target: scanResults.target,
    date: new Date().toISOString(),
    score: scanResults.score,
    riskLevel: getRiskLevel(scanResults.score),
    findings: scanResults.findings,
    // ... mas datos
  };
  
  // Renderizar con motor de plantillas
  const html = Mustache.render(template, data);
  
  // Guardar archivo
  const reportPath = `reports/${scanResults.id}/report.html`;
  fs.writeFileSync(reportPath, html);
  
  return reportPath;
};
```

---

## 7. INTEGRACION DETALLADA DE CADA HERRAMIENTA

### 7.1 Wappalyzer

**Proposito:** Detectar tecnologias utilizadas en el sitio web objetivo.

**Instalacion:**
```bash
# Opcion 1: Via npm
sudo npm install -g wappalyzer

# Opcion 2: Clonar repositorio
git clone https://github.com/wappalyzer/wappalyzer.git
cd wappalyzer
npm install
npm link
```

**Uso desde el backend:**
```javascript
// backend/modules/wappalyzer_detector.js
const { execSync, spawn } = require('child_process');

class WappalyzerDetector {
  constructor(options = {}) {
    this.timeout = options.timeout || 60000;
  }

  async detect(targetUrl) {
    return new Promise((resolve, reject) => {
      const args = [targetUrl, '--pretty'];
      const process = spawn('wappalyzer', args);
      
      let stdout = '';
      let stderr = '';
      
      process.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      process.on('close', (code) => {
        if (code === 0) {
          try {
            const result = JSON.parse(stdout);
            resolve(this.parseResults(result));
          } catch (e) {
            reject(new Error('Error parsing Wappalyzer output'));
          }
        } else {
          reject(new Error(`Wappalyzer failed: ${stderr}`));
        }
      });
      
      // Timeout
      setTimeout(() => {
        process.kill();
        reject(new Error('Wappalyzer timeout'));
      }, this.timeout);
    });
  }

  parseResults(rawResult) {
    const technologies = [];
    
    if (rawResult.technologies) {
      rawResult.technologies.forEach(tech => {
        technologies.push({
          name: tech.name,
          version: tech.version || 'Unknown',
          confidence: tech.confidence,
          categories: tech.categories.map(c => c.name),
          website: tech.website
        });
      });
    }
    
    return {
      url: Object.keys(rawResult.urls)[0],
      technologies: technologies,
      timestamp: new Date().toISOString()
    };
  }
}

module.exports = WappalyzerDetector;
```

### 7.2 Nmap

**Proposito:** Escanear puertos abiertos y detectar versiones de servicios.

**Instalacion:**
```bash
sudo apt update
sudo apt install -y nmap
```

**Uso desde el backend:**
```javascript
// backend/modules/nmap_scanner.js
const { spawn } = require('child_process');
const xml2js = require('xml2js');
const fs = require('fs');
const path = require('path');

class NmapScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 300000; // 5 minutos
    this.outputDir = options.outputDir || '/tmp';
  }

  async scan(target, scanType = 'normal') {
    const outputFile = path.join(this.outputDir, `nmap_${Date.now()}.xml`);
    
    // Configurar argumentos segun tipo de escaneo
    const args = this.buildArgs(target, scanType, outputFile);
    
    return new Promise((resolve, reject) => {
      const process = spawn('nmap', args);
      
      let stderr = '';
      
      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      process.on('close', async (code) => {
        if (code === 0 && fs.existsSync(outputFile)) {
          try {
            const xmlContent = fs.readFileSync(outputFile, 'utf8');
            const result = await this.parseXML(xmlContent);
            
            // Limpiar archivo temporal
            fs.unlinkSync(outputFile);
            
            resolve(result);
          } catch (e) {
            reject(new Error('Error parsing Nmap output'));
          }
        } else {
          reject(new Error(`Nmap failed: ${stderr}`));
        }
      });
      
      setTimeout(() => {
        process.kill();
        reject(new Error('Nmap timeout'));
      }, this.timeout);
    });
  }

  buildArgs(target, scanType, outputFile) {
    const baseArgs = ['-oX', outputFile];
    
    switch (scanType) {
      case 'quick':
        return [...baseArgs, '-T4', '-F', target];
      case 'normal':
        return [...baseArgs, '-sV', '-sC', '-T3', target];
      case 'deep':
        return [...baseArgs, '-sV', '-sC', '-A', '-T2', '-p-', target];
      default:
        return [...baseArgs, '-sV', target];
    }
  }

  async parseXML(xmlContent) {
    const parser = new xml2js.Parser();
    const result = await parser.parseStringPromise(xmlContent);
    
    const hosts = [];
    
    if (result.nmaprun && result.nmaprun.host) {
      result.nmaprun.host.forEach(host => {
        const hostData = {
          address: host.address?.[0]?.$.addr,
          hostnames: host.hostnames?.[0]?.hostname?.map(h => h.$.name) || [],
          status: host.status?.[0]?.$.state,
          ports: []
        };
        
        if (host.ports?.[0]?.port) {
          host.ports[0].port.forEach(port => {
            hostData.ports.push({
              port: parseInt(port.$.portid),
              protocol: port.$.protocol,
              state: port.state?.[0]?.$.state,
              service: {
                name: port.service?.[0]?.$.name,
                product: port.service?.[0]?.$.product,
                version: port.service?.[0]?.$.version,
                extrainfo: port.service?.[0]?.$.extrainfo
              },
              scripts: port.script?.map(s => ({
                id: s.$.id,
                output: s.$.output
              })) || []
            });
          });
        }
        
        hosts.push(hostData);
      });
    }
    
    return {
      hosts: hosts,
      scanInfo: {
        type: result.nmaprun?.scaninfo?.[0]?.$.type,
        protocol: result.nmaprun?.scaninfo?.[0]?.$.protocol,
        startTime: result.nmaprun?.$?.startstr,
        endTime: result.nmaprun?.runstats?.[0]?.finished?.[0]?.$.timestr
      }
    };
  }
}

module.exports = NmapScanner;
```

### 7.3 Gobuster

**Proposito:** Descubrir directorios y archivos ocultos mediante fuerza bruta.

**Instalacion:**
```bash
sudo apt install -y gobuster
```

**Uso desde el backend:**
```javascript
// backend/modules/gobuster_scanner.js
const { spawn } = require('child_process');

class GobusterScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 600000; // 10 minutos
    this.wordlist = options.wordlist || '/usr/share/wordlists/dirb/common.txt';
    this.threads = options.threads || 10;
  }

  async scan(targetUrl, extensions = ['php', 'html', 'js', 'txt']) {
    return new Promise((resolve, reject) => {
      const args = [
        'dir',
        '-u', targetUrl,
        '-w', this.wordlist,
        '-x', extensions.join(','),
        '-t', this.threads.toString(),
        '-q', // Quiet mode
        '--no-color'
      ];
      
      const process = spawn('gobuster', args);
      
      let stdout = '';
      let stderr = '';
      
      process.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      process.on('close', (code) => {
        // Gobuster retorna codigo diferente de 0 a veces sin error real
        const results = this.parseResults(stdout);
        resolve(results);
      });
      
      setTimeout(() => {
        process.kill();
        // Retornar resultados parciales
        resolve(this.parseResults(stdout));
      }, this.timeout);
    });
  }

  parseResults(output) {
    const lines = output.split('\n').filter(line => line.trim());
    const directories = [];
    
    lines.forEach(line => {
      // Formato: /path (Status: XXX) [Size: XXXX]
      const match = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)\s+\[Size:\s*(\d+)\]/);
      
      if (match) {
        const path = match[1];
        const status = parseInt(match[2]);
        const size = parseInt(match[3]);
        
        directories.push({
          path: path,
          statusCode: status,
          size: size,
          risk: this.assessRisk(path, status),
          type: this.determineType(path)
        });
      }
    });
    
    return {
      directories: directories,
      summary: {
        total: directories.length,
        byStatus: this.groupByStatus(directories),
        highRisk: directories.filter(d => d.risk === 'high').length
      }
    };
  }

  assessRisk(path, status) {
    const highRiskPaths = [
      '/admin', '/administrator', '/wp-admin', '/phpmyadmin',
      '/config', '/.git', '/.env', '/backup', '/db', '/database',
      '/uploads', '/private', '/secret', '/debug', '/test'
    ];
    
    const lowPath = path.toLowerCase();
    
    if (highRiskPaths.some(hp => lowPath.includes(hp))) {
      return 'high';
    }
    
    if (status === 200 || status === 301) {
      return 'medium';
    }
    
    return 'low';
  }

  determineType(path) {
    if (path.includes('.')) {
      const ext = path.split('.').pop().toLowerCase();
      const types = {
        'php': 'script',
        'html': 'page',
        'htm': 'page',
        'js': 'script',
        'css': 'style',
        'txt': 'text',
        'json': 'data',
        'xml': 'data',
        'sql': 'database',
        'bak': 'backup',
        'zip': 'archive',
        'tar': 'archive',
        'gz': 'archive'
      };
      return types[ext] || 'file';
    }
    return 'directory';
  }

  groupByStatus(directories) {
    const groups = {};
    directories.forEach(d => {
      groups[d.statusCode] = (groups[d.statusCode] || 0) + 1;
    });
    return groups;
  }
}

module.exports = GobusterScanner;
```

### 7.4 Nikto

**Proposito:** Escanear vulnerabilidades conocidas en servidores web.

**Instalacion:**
```bash
sudo apt install -y nikto
```

**Uso desde el backend:**
```javascript
// backend/modules/nikto_scanner.js
const { spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

class NiktoScanner {
  constructor(options = {}) {
    this.timeout = options.timeout || 900000; // 15 minutos
    this.outputDir = options.outputDir || '/tmp';
  }

  async scan(targetUrl, options = {}) {
    const outputFile = path.join(this.outputDir, `nikto_${Date.now()}.json`);
    
    return new Promise((resolve, reject) => {
      const args = [
        '-h', targetUrl,
        '-Format', 'json',
        '-output', outputFile,
        '-Tuning', options.tuning || '123456789abc'
      ];
      
      if (options.ssl) {
        args.push('-ssl');
      }
      
      const process = spawn('nikto', args);
      
      let stderr = '';
      
      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      process.on('close', (code) => {
        if (fs.existsSync(outputFile)) {
          try {
            const content = fs.readFileSync(outputFile, 'utf8');
            const result = this.parseResults(content);
            fs.unlinkSync(outputFile);
            resolve(result);
          } catch (e) {
            reject(new Error('Error parsing Nikto output'));
          }
        } else {
          reject(new Error(`Nikto failed: ${stderr}`));
        }
      });
      
      setTimeout(() => {
        process.kill();
        if (fs.existsSync(outputFile)) {
          const content = fs.readFileSync(outputFile, 'utf8');
          resolve(this.parseResults(content));
        } else {
          resolve({ vulnerabilities: [], partial: true });
        }
      }, this.timeout);
    });
  }

  parseResults(jsonContent) {
    let data;
    try {
      data = JSON.parse(jsonContent);
    } catch {
      // Nikto a veces genera JSON invalido
      return { vulnerabilities: [], parseError: true };
    }
    
    const vulnerabilities = [];
    
    if (data.vulnerabilities) {
      data.vulnerabilities.forEach(vuln => {
        vulnerabilities.push({
          id: vuln.id || 'N/A',
          osvdbId: vuln.OSVDB || '0',
          method: vuln.method || 'GET',
          url: vuln.url || '/',
          message: vuln.msg || vuln.message,
          severity: this.mapSeverity(vuln),
          references: this.extractReferences(vuln)
        });
      });
    }
    
    return {
      host: data.host,
      port: data.port,
      vulnerabilities: vulnerabilities,
      summary: {
        total: vulnerabilities.length,
        bySeverity: this.groupBySeverity(vulnerabilities)
      },
      scanTime: data.elapsed || 'Unknown'
    };
  }

  mapSeverity(vuln) {
    // Mapear basado en OSVDB y contenido
    const msg = (vuln.msg || vuln.message || '').toLowerCase();
    
    if (msg.includes('critical') || msg.includes('remote code') || msg.includes('sql injection')) {
      return 'critical';
    }
    if (msg.includes('xss') || msg.includes('injection') || msg.includes('bypass')) {
      return 'high';
    }
    if (msg.includes('disclosure') || msg.includes('directory listing') || msg.includes('version')) {
      return 'medium';
    }
    if (msg.includes('header') || msg.includes('cookie') || msg.includes('missing')) {
      return 'low';
    }
    
    return 'info';
  }

  extractReferences(vuln) {
    const refs = [];
    
    if (vuln.OSVDB && vuln.OSVDB !== '0') {
      refs.push(`https://osvdb.org/show/osvdb/${vuln.OSVDB}`);
    }
    
    // Extraer CVEs del mensaje
    const cveMatch = (vuln.msg || '').match(/CVE-\d{4}-\d+/gi);
    if (cveMatch) {
      cveMatch.forEach(cve => {
        refs.push(`https://cve.mitre.org/cgi-bin/cvename.cgi?name=${cve}`);
      });
    }
    
    return refs;
  }

  groupBySeverity(vulnerabilities) {
    const groups = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    vulnerabilities.forEach(v => {
      groups[v.severity] = (groups[v.severity] || 0) + 1;
    });
    return groups;
  }
}

module.exports = NiktoScanner;
```

### 7.5 OWASP ZAP

**Proposito:** Escaneo completo de aplicaciones web (spider + escaneo activo).

**Instalacion:**
```bash
sudo apt install -y zaproxy
```

**Uso desde el backend:**
```javascript
// backend/modules/zap_scanner.js
const axios = require('axios');

class ZAPScanner {
  constructor(options = {}) {
    this.apiUrl = options.apiUrl || 'http://localhost:8080';
    this.apiKey = options.apiKey || '';
    this.timeout = options.timeout || 1800000; // 30 minutos
  }

  async isRunning() {
    try {
      await axios.get(`${this.apiUrl}/JSON/core/view/version/`, {
        params: { apikey: this.apiKey },
        timeout: 5000
      });
      return true;
    } catch {
      return false;
    }
  }

  async scan(targetUrl, options = {}) {
    // Verificar que ZAP esta corriendo
    const running = await this.isRunning();
    if (!running) {
      throw new Error('OWASP ZAP no esta corriendo. Ejecute: zap.sh -daemon -port 8080');
    }
    
    const results = {
      spider: null,
      activeScan: null,
      alerts: [],
      timestamp: new Date().toISOString()
    };
    
    try {
      // 1. Spider
      if (options.spider !== false) {
        results.spider = await this.runSpider(targetUrl);
      }
      
      // 2. Ajax Spider (opcional)
      if (options.ajaxSpider) {
        await this.runAjaxSpider(targetUrl);
      }
      
      // 3. Active Scan
      if (options.activeScan !== false) {
        results.activeScan = await this.runActiveScan(targetUrl);
      }
      
      // 4. Obtener alertas
      results.alerts = await this.getAlerts(targetUrl);
      
      return this.formatResults(results);
    } catch (error) {
      throw new Error(`ZAP scan failed: ${error.message}`);
    }
  }

  async runSpider(targetUrl) {
    // Iniciar spider
    const startResponse = await axios.get(`${this.apiUrl}/JSON/spider/action/scan/`, {
      params: {
        apikey: this.apiKey,
        url: targetUrl,
        maxChildren: 10,
        recurse: true
      }
    });
    
    const scanId = startResponse.data.scan;
    
    // Esperar a que termine
    await this.waitForScan('spider', scanId);
    
    // Obtener resultados
    const resultsResponse = await axios.get(`${this.apiUrl}/JSON/spider/view/results/`, {
      params: { apikey: this.apiKey, scanId: scanId }
    });
    
    return {
      scanId: scanId,
      urlsFound: resultsResponse.data.results?.length || 0
    };
  }

  async runActiveScan(targetUrl) {
    // Iniciar escaneo activo
    const startResponse = await axios.get(`${this.apiUrl}/JSON/ascan/action/scan/`, {
      params: {
        apikey: this.apiKey,
        url: targetUrl,
        recurse: true,
        scanPolicyName: 'Default Policy'
      }
    });
    
    const scanId = startResponse.data.scan;
    
    // Esperar a que termine
    await this.waitForScan('ascan', scanId);
    
    return { scanId: scanId };
  }

  async waitForScan(scanType, scanId) {
    const endpoint = scanType === 'spider' ? 'spider' : 'ascan';
    const maxWait = this.timeout;
    const interval = 5000;
    let waited = 0;
    
    while (waited < maxWait) {
      const statusResponse = await axios.get(
        `${this.apiUrl}/JSON/${endpoint}/view/status/`,
        { params: { apikey: this.apiKey, scanId: scanId } }
      );
      
      const progress = parseInt(statusResponse.data.status);
      
      if (progress >= 100) {
        return;
      }
      
      await new Promise(resolve => setTimeout(resolve, interval));
      waited += interval;
    }
    
    throw new Error(`${scanType} timeout`);
  }

  async getAlerts(targetUrl) {
    const response = await axios.get(`${this.apiUrl}/JSON/alert/view/alerts/`, {
      params: {
        apikey: this.apiKey,
        baseurl: targetUrl,
        start: 0,
        count: 1000
      }
    });
    
    return response.data.alerts || [];
  }

  formatResults(results) {
    const alerts = results.alerts.map(alert => ({
      name: alert.name,
      risk: alert.risk,
      confidence: alert.confidence,
      description: alert.description,
      solution: alert.solution,
      reference: alert.reference,
      cweid: alert.cweid,
      wascid: alert.wascid,
      instances: [{
        uri: alert.url,
        method: alert.method,
        param: alert.param,
        evidence: alert.evidence
      }],
      severity: this.mapRiskToSeverity(alert.risk)
    }));
    
    // Agrupar alertas duplicadas
    const groupedAlerts = this.groupAlerts(alerts);
    
    return {
      spider: results.spider,
      activeScan: results.activeScan,
      alerts: groupedAlerts,
      summary: {
        total: groupedAlerts.length,
        byRisk: this.countByRisk(groupedAlerts)
      }
    };
  }

  mapRiskToSeverity(risk) {
    const mapping = {
      'High': 'high',
      'Medium': 'medium',
      'Low': 'low',
      'Informational': 'info'
    };
    return mapping[risk] || 'info';
  }

  groupAlerts(alerts) {
    const groups = {};
    
    alerts.forEach(alert => {
      const key = `${alert.name}-${alert.cweid}`;
      
      if (!groups[key]) {
        groups[key] = { ...alert, instances: [] };
      }
      
      groups[key].instances.push(...alert.instances);
    });
    
    return Object.values(groups);
  }

  countByRisk(alerts) {
    const counts = { high: 0, medium: 0, low: 0, info: 0 };
    alerts.forEach(a => {
      counts[a.severity] = (counts[a.severity] || 0) + 1;
    });
    return counts;
  }
}

module.exports = ZAPScanner;
```

### 7.6 Searchsploit (Exploit-DB)

**Proposito:** Buscar exploits conocidos para las versiones detectadas.

**Instalacion:**
```bash
sudo apt install -y exploitdb

# Actualizar base de datos
searchsploit -u
```

**Uso desde el backend:**
```javascript
// backend/modules/exploitdb_lookup.js
const { execSync, spawn } = require('child_process');

class ExploitDBLookup {
  constructor(options = {}) {
    this.timeout = options.timeout || 30000;
  }

  async search(queries) {
    const results = {
      searches: [],
      exploits: [],
      timestamp: new Date().toISOString()
    };
    
    for (const query of queries) {
      try {
        const searchResult = await this.executeSearch(query);
        results.searches.push({
          query: query,
          resultsCount: searchResult.length
        });
        results.exploits.push(...searchResult);
      } catch (error) {
        results.searches.push({
          query: query,
          error: error.message
        });
      }
    }
    
    // Eliminar duplicados
    results.exploits = this.deduplicateExploits(results.exploits);
    
    return results;
  }

  async searchFromNmapResults(nmapResults) {
    const queries = [];
    
    // Extraer software y versiones de Nmap
    if (nmapResults.hosts) {
      nmapResults.hosts.forEach(host => {
        host.ports?.forEach(port => {
          const service = port.service;
          
          if (service?.product) {
            // Busqueda con producto y version
            if (service.version) {
              queries.push(`${service.product} ${service.version}`);
            }
            // Busqueda solo con producto
            queries.push(service.product);
          }
          
          // Busqueda por nombre de servicio
          if (service?.name && service.name !== 'unknown') {
            queries.push(service.name);
          }
        });
      });
    }
    
    // Eliminar duplicados y limitar
    const uniqueQueries = [...new Set(queries)].slice(0, 20);
    
    return this.search(uniqueQueries);
  }

  executeSearch(query) {
    return new Promise((resolve, reject) => {
      const args = ['--json', query];
      const process = spawn('searchsploit', args);
      
      let stdout = '';
      let stderr = '';
      
      process.stdout.on('data', (data) => {
        stdout += data.toString();
      });
      
      process.stderr.on('data', (data) => {
        stderr += data.toString();
      });
      
      process.on('close', (code) => {
        try {
          const result = JSON.parse(stdout);
          const exploits = this.parseSearchResults(result, query);
          resolve(exploits);
        } catch {
          // Searchsploit puede no retornar JSON valido si no hay resultados
          resolve([]);
        }
      });
      
      setTimeout(() => {
        process.kill();
        resolve([]);
      }, this.timeout);
    });
  }

  parseSearchResults(result, query) {
    const exploits = [];
    
    if (result.RESULTS_EXPLOIT) {
      result.RESULTS_EXPLOIT.forEach(exp => {
        exploits.push({
          title: exp.Title,
          edbId: exp['EDB-ID'],
          date: exp.Date,
          type: exp.Type,
          platform: exp.Platform,
          path: exp.Path,
          relatedQuery: query,
          severity: this.assessExploitSeverity(exp),
          url: `https://www.exploit-db.com/exploits/${exp['EDB-ID']}`
        });
      });
    }
    
    return exploits;
  }

  assessExploitSeverity(exploit) {
    const title = (exploit.Title || '').toLowerCase();
    const type = (exploit.Type || '').toLowerCase();
    
    // Remote Code Execution
    if (title.includes('remote code execution') || title.includes('rce')) {
      return 'critical';
    }
    
    // SQL Injection, Authentication Bypass
    if (title.includes('sql injection') || title.includes('auth bypass')) {
      return 'critical';
    }
    
    // Local File Inclusion, Remote File Inclusion
    if (title.includes('file inclusion') || title.includes('lfi') || title.includes('rfi')) {
      return 'high';
    }
    
    // XSS
    if (title.includes('xss') || title.includes('cross-site scripting')) {
      return 'medium';
    }
    
    // Denial of Service
    if (title.includes('denial of service') || title.includes('dos')) {
      return 'medium';
    }
    
    // Information Disclosure
    if (title.includes('disclosure') || title.includes('information leak')) {
      return 'low';
    }
    
    return 'info';
  }

  deduplicateExploits(exploits) {
    const seen = new Set();
    return exploits.filter(exp => {
      const key = exp.edbId;
      if (seen.has(key)) {
        return false;
      }
      seen.add(key);
      return true;
    });
  }

  async updateDatabase() {
    return new Promise((resolve, reject) => {
      const process = spawn('searchsploit', ['-u']);
      
      process.on('close', (code) => {
        if (code === 0) {
          resolve({ success: true, message: 'Database updated' });
        } else {
          reject(new Error('Failed to update database'));
        }
      });
    });
  }
}

module.exports = ExploitDBLookup;
```

---

## 8. AUTOMATIZACION COMPLETA DEL ESCANEO

### 8.1 Modulo Orquestador

El orquestador coordina la ejecucion secuencial de todas las herramientas:

```javascript
// backend/modules/orchestrator.js
const WappalyzerDetector = require('./wappalyzer_detector');
const NmapScanner = require('./nmap_scanner');
const GobusterScanner = require('./gobuster_scanner');
const NiktoScanner = require('./nikto_scanner');
const ZAPScanner = require('./zap_scanner');
const ExploitDBLookup = require('./exploitdb_lookup');
const ScoringEngine = require('./scoring_engine');
const ReportGenerator = require('./report_generator');
const logger = require('../utils/logger');

class ScanOrchestrator {
  constructor(options = {}) {
    this.wappalyzer = new WappalyzerDetector(options.wappalyzer);
    this.nmap = new NmapScanner(options.nmap);
    this.gobuster = new GobusterScanner(options.gobuster);
    this.nikto = new NiktoScanner(options.nikto);
    this.zap = new ZAPScanner(options.zap);
    this.exploitdb = new ExploitDBLookup(options.exploitdb);
    this.scoring = new ScoringEngine();
    this.reportGenerator = new ReportGenerator(options.reports);
    
    this.jobs = new Map();
  }

  async runFullScan(target, options = {}) {
    const jobId = this.generateJobId();
    
    const job = {
      id: jobId,
      target: target,
      status: 'running',
      progress: 0,
      currentStep: '',
      steps: [],
      results: {},
      errors: [],
      startTime: new Date().toISOString(),
      endTime: null
    };
    
    this.jobs.set(jobId, job);
    
    // Ejecutar escaneo en background
    this.executeScan(job, options).catch(error => {
      job.status = 'failed';
      job.errors.push(error.message);
      logger.error(`Scan ${jobId} failed:`, error);
    });
    
    return jobId;
  }

  async executeScan(job, options) {
    const steps = [
      { name: 'wappalyzer', label: 'Detectando tecnologias', weight: 10 },
      { name: 'nmap', label: 'Escaneando puertos', weight: 20 },
      { name: 'gobuster', label: 'Descubriendo directorios', weight: 15 },
      { name: 'nikto', label: 'Analizando vulnerabilidades', weight: 20 },
      { name: 'zap', label: 'Escaneando aplicacion', weight: 25 },
      { name: 'exploitdb', label: 'Buscando exploits', weight: 5 },
      { name: 'scoring', label: 'Calculando score', weight: 3 },
      { name: 'report', label: 'Generando reporte', weight: 2 }
    ];
    
    let completedWeight = 0;
    
    for (const step of steps) {
      if (options.skip?.includes(step.name)) {
        completedWeight += step.weight;
        continue;
      }
      
      job.currentStep = step.label;
      job.steps.push({ name: step.name, status: 'running', startTime: new Date().toISOString() });
      
      try {
        logger.info(`Starting step: ${step.name}`);
        
        switch (step.name) {
          case 'wappalyzer':
            job.results.wappalyzer = await this.wappalyzer.detect(job.target);
            break;
            
          case 'nmap':
            job.results.nmap = await this.nmap.scan(
              new URL(job.target).hostname,
              options.scanType || 'normal'
            );
            break;
            
          case 'gobuster':
            job.results.gobuster = await this.gobuster.scan(job.target);
            break;
            
          case 'nikto':
            job.results.nikto = await this.nikto.scan(job.target);
            break;
            
          case 'zap':
            job.results.zap = await this.zap.scan(job.target, {
              spider: options.zapSpider !== false,
              activeScan: options.zapActiveScan !== false
            });
            break;
            
          case 'exploitdb':
            if (job.results.nmap) {
              job.results.exploitdb = await this.exploitdb.searchFromNmapResults(
                job.results.nmap
              );
            }
            break;
            
          case 'scoring':
            job.results.score = this.scoring.calculate(job.results);
            break;
            
          case 'report':
            job.results.report = await this.reportGenerator.generate(job);
            break;
        }
        
        const stepIndex = job.steps.findIndex(s => s.name === step.name);
        job.steps[stepIndex].status = 'completed';
        job.steps[stepIndex].endTime = new Date().toISOString();
        
        completedWeight += step.weight;
        job.progress = Math.round((completedWeight / 100) * 100);
        
      } catch (error) {
        logger.error(`Step ${step.name} failed:`, error);
        
        const stepIndex = job.steps.findIndex(s => s.name === step.name);
        job.steps[stepIndex].status = 'failed';
        job.steps[stepIndex].error = error.message;
        job.errors.push(`${step.name}: ${error.message}`);
        
        // Continuar con los siguientes pasos
        completedWeight += step.weight;
        job.progress = Math.round((completedWeight / 100) * 100);
      }
    }
    
    job.status = job.errors.length > 0 ? 'completed_with_errors' : 'completed';
    job.endTime = new Date().toISOString();
    job.currentStep = 'Completado';
    job.progress = 100;
    
    logger.info(`Scan ${job.id} completed`);
    
    return job;
  }

  getJob(jobId) {
    return this.jobs.get(jobId);
  }

  generateJobId() {
    return `scan_${Date.now()}_${Math.random().toString(36).substr(2, 9)}`;
  }
}

module.exports = ScanOrchestrator;
```

### 8.2 Script Bash de Escaneo Completo

```bash
#!/bin/bash
# tools/run_all_scans.sh
# Script para ejecutar todos los escaneos de forma secuencial

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Configuracion
TARGET="${1:-http://localhost:3001}"
OUTPUT_DIR="${2:-./reports/$(date +%Y%m%d_%H%M%S)}"
WORDLIST="${WORDLIST:-/usr/share/wordlists/dirb/common.txt}"

# Crear directorio de salida
mkdir -p "$OUTPUT_DIR"

echo -e "${BLUE}================================================${NC}"
echo -e "${BLUE}    SecureScan Pro - Escaneo Automatizado${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "Objetivo: ${GREEN}$TARGET${NC}"
echo -e "Salida: ${GREEN}$OUTPUT_DIR${NC}"
echo -e "${BLUE}================================================${NC}"

# Funcion para logging
log() {
    echo -e "${GREEN}[$(date +%H:%M:%S)]${NC} $1"
}

error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Extraer host y puerto de la URL
extract_host() {
    echo "$1" | sed -E 's|https?://([^:/]+).*|\1|'
}

extract_port() {
    local port=$(echo "$1" | sed -E 's|https?://[^:/]+:?([0-9]*)/.*|\1|')
    if [ -z "$port" ]; then
        if [[ "$1" == https://* ]]; then
            echo "443"
        else
            echo "80"
        fi
    else
        echo "$port"
    fi
}

HOST=$(extract_host "$TARGET")
PORT=$(extract_port "$TARGET")

# 1. Wappalyzer
log "Paso 1/6: Ejecutando Wappalyzer..."
if command -v wappalyzer &> /dev/null; then
    wappalyzer "$TARGET" --pretty > "$OUTPUT_DIR/wappalyzer.json" 2>/dev/null || \
        warning "Wappalyzer fallo o no encontro tecnologias"
    log "Wappalyzer completado"
else
    warning "Wappalyzer no instalado. Saltando..."
fi

# 2. Nmap
log "Paso 2/6: Ejecutando Nmap..."
nmap -sV -sC -oX "$OUTPUT_DIR/nmap.xml" -oN "$OUTPUT_DIR/nmap.txt" "$HOST" -p "$PORT" 2>/dev/null || \
    error "Nmap fallo"
log "Nmap completado"

# 3. Gobuster
log "Paso 3/6: Ejecutando Gobuster..."
if [ -f "$WORDLIST" ]; then
    gobuster dir -u "$TARGET" -w "$WORDLIST" -x php,html,js,txt -q \
        -o "$OUTPUT_DIR/gobuster.txt" 2>/dev/null || \
        warning "Gobuster termino con errores"
    log "Gobuster completado"
else
    warning "Wordlist no encontrada: $WORDLIST"
fi

# 4. Nikto
log "Paso 4/6: Ejecutando Nikto..."
nikto -h "$TARGET" -Format json -output "$OUTPUT_DIR/nikto.json" 2>/dev/null || \
    warning "Nikto termino con errores"
log "Nikto completado"

# 5. OWASP ZAP (modo baseline)
log "Paso 5/6: Ejecutando OWASP ZAP..."
if command -v zap-baseline.py &> /dev/null; then
    zap-baseline.py -t "$TARGET" -J "$OUTPUT_DIR/zap.json" -r "$OUTPUT_DIR/zap.html" 2>/dev/null || \
        warning "ZAP termino con alertas"
    log "ZAP completado"
elif pgrep -f "zap.sh" > /dev/null; then
    log "ZAP daemon detectado. Usando API..."
    # Usar curl para llamar a la API de ZAP
    ZAP_API="http://localhost:8080"
    curl -s "${ZAP_API}/JSON/spider/action/scan/?url=${TARGET}" > /dev/null
    sleep 30
    curl -s "${ZAP_API}/JSON/alert/view/alerts/?baseurl=${TARGET}" > "$OUTPUT_DIR/zap.json"
    log "ZAP completado via API"
else
    warning "OWASP ZAP no disponible. Saltando..."
fi

# 6. Searchsploit
log "Paso 6/6: Ejecutando Searchsploit..."

# Extraer versiones de Nmap para buscar
SEARCH_TERMS=""
if [ -f "$OUTPUT_DIR/nmap.txt" ]; then
    SEARCH_TERMS=$(grep -oP '(?<=product: )[^\n]+|(?<=version: )[^\n]+' "$OUTPUT_DIR/nmap.xml" 2>/dev/null | \
        head -10 | sort -u)
fi

if [ -n "$SEARCH_TERMS" ]; then
    echo '{"searches": [' > "$OUTPUT_DIR/searchsploit.json"
    first=true
    
    while IFS= read -r term; do
        if [ -n "$term" ]; then
            if [ "$first" = true ]; then
                first=false
            else
                echo "," >> "$OUTPUT_DIR/searchsploit.json"
            fi
            
            log "  Buscando: $term"
            result=$(searchsploit --json "$term" 2>/dev/null || echo '{"RESULTS_EXPLOIT": []}')
            echo "{\"query\": \"$term\", \"results\": $result}" >> "$OUTPUT_DIR/searchsploit.json"
        fi
    done <<< "$SEARCH_TERMS"
    
    echo ']}'  >> "$OUTPUT_DIR/searchsploit.json"
    log "Searchsploit completado"
else
    warning "No se encontraron versiones para buscar en Exploit-DB"
    echo '{"searches": []}' > "$OUTPUT_DIR/searchsploit.json"
fi

# Resumen
echo -e "\n${BLUE}================================================${NC}"
echo -e "${GREEN}    Escaneo Completado${NC}"
echo -e "${BLUE}================================================${NC}"
echo -e "Archivos generados en: ${GREEN}$OUTPUT_DIR${NC}"
echo ""
ls -la "$OUTPUT_DIR"
echo ""
echo -e "Para procesar los resultados, ejecute:"
echo -e "  ${YELLOW}node tools/parse_results.js $OUTPUT_DIR${NC}"
echo -e "${BLUE}================================================${NC}"
```

---

## 9. INTEGRACION CON EXPLOIT-DB

### 9.1 Instalacion de Searchsploit

```bash
# Instalar exploit-db
sudo apt update
sudo apt install -y exploitdb

# Verificar instalacion
searchsploit --version

# Actualizar base de datos
searchsploit -u

# Verificar ubicacion de la base de datos
ls -la /usr/share/exploitdb/
```

### 9.2 Uso Basico de Searchsploit

```bash
# Busqueda simple
searchsploit apache 2.4

# Busqueda con JSON output
searchsploit --json apache 2.4

# Busqueda exacta
searchsploit -e "Apache 2.4.49"

# Copiar exploit a directorio actual
searchsploit -m 50383

# Ver detalles de un exploit
searchsploit -x 50383
```

### 9.3 Integracion Automatizada

La integracion automatica sigue este flujo:

```
+-------------+     +-------------+     +---------------+     +-------------+
|    NMAP     | --> |   Parser    | --> |  Searchsploit | --> |   Results   |
| (versiones) |     | (extraer)   |     |   (buscar)    |     |   (JSON)    |
+-------------+     +-------------+     +---------------+     +-------------+

Ejemplo de flujo:

1. Nmap detecta: Apache/2.4.49 (Ubuntu)
2. Parser extrae: ["Apache 2.4.49", "Apache 2.4", "Apache"]
3. Searchsploit busca cada termino
4. Resultados consolidados con severidad asignada
```

### 9.4 Ejemplo de Salida Integrada

```json
{
  "searches": [
    {
      "query": "Apache 2.4.49",
      "resultsCount": 3
    },
    {
      "query": "Node.js",
      "resultsCount": 15
    }
  ],
  "exploits": [
    {
      "title": "Apache HTTP Server 2.4.49 - Path Traversal & Remote Code Execution",
      "edbId": "50383",
      "date": "2021-10-05",
      "type": "webapps",
      "platform": "multiple",
      "path": "/usr/share/exploitdb/exploits/multiple/webapps/50383.py",
      "relatedQuery": "Apache 2.4.49",
      "severity": "critical",
      "url": "https://www.exploit-db.com/exploits/50383"
    }
  ],
  "summary": {
    "totalExploits": 18,
    "bySeverity": {
      "critical": 2,
      "high": 5,
      "medium": 8,
      "low": 3
    }
  }
}
```

---

## 10. EJECUCION DE HERRAMIENTAS DESDE EL BACKEND

### 10.1 Patron de Ejecucion

Todas las herramientas siguen el mismo patron de ejecucion:

```javascript
// Patron generico de ejecucion de herramienta
const { spawn } = require('child_process');

async function executeCommand(command, args, options = {}) {
  return new Promise((resolve, reject) => {
    const process = spawn(command, args, {
      timeout: options.timeout || 60000,
      env: { ...process.env, ...options.env }
    });
    
    let stdout = '';
    let stderr = '';
    
    process.stdout.on('data', (data) => {
      stdout += data.toString();
      if (options.onProgress) {
        options.onProgress(data.toString());
      }
    });
    
    process.stderr.on('data', (data) => {
      stderr += data.toString();
    });
    
    process.on('close', (code) => {
      if (code === 0 || options.ignoreExitCode) {
        resolve({ stdout, stderr, code });
      } else {
        reject(new Error(`Command failed with code ${code}: ${stderr}`));
      }
    });
    
    process.on('error', (error) => {
      reject(error);
    });
    
    // Timeout handler
    if (options.timeout) {
      setTimeout(() => {
        process.kill('SIGTERM');
        reject(new Error('Command timeout'));
      }, options.timeout);
    }
  });
}
```

### 10.2 Ejemplos de Endpoints

```javascript
// server.js - Endpoints principales

const express = require('express');
const ScanOrchestrator = require('./modules/orchestrator');

const app = express();
const orchestrator = new ScanOrchestrator();

app.use(express.json());

// Iniciar nuevo escaneo
app.post('/api/scan', async (req, res) => {
  try {
    const { target, options } = req.body;
    
    // Validar target
    if (!target) {
      return res.status(400).json({ error: 'Target URL required' });
    }
    
    // Validar que sea URL local/privada
    const url = new URL(target);
    const allowedHosts = ['localhost', '127.0.0.1'];
    const privateRanges = ['192.168.', '10.', '172.16.'];
    
    const isAllowed = allowedHosts.includes(url.hostname) ||
      privateRanges.some(range => url.hostname.startsWith(range));
    
    if (!isAllowed) {
      return res.status(403).json({ 
        error: 'Only local/private targets allowed' 
      });
    }
    
    // Iniciar escaneo
    const jobId = await orchestrator.runFullScan(target, options);
    
    res.json({ 
      success: true, 
      jobId: jobId,
      message: 'Scan started successfully'
    });
    
  } catch (error) {
    res.status(500).json({ error: error.message });
  }
});

// Obtener estado del escaneo
app.get('/api/scan/:id/status', (req, res) => {
  const job = orchestrator.getJob(req.params.id);
  
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }
  
  res.json({
    id: job.id,
    status: job.status,
    progress: job.progress,
    currentStep: job.currentStep,
    steps: job.steps,
    errors: job.errors
  });
});

// Obtener resultados completos
app.get('/api/scan/:id/results', (req, res) => {
  const job = orchestrator.getJob(req.params.id);
  
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }
  
  if (job.status === 'running') {
    return res.status(202).json({ 
      message: 'Scan still in progress',
      progress: job.progress
    });
  }
  
  res.json(job.results);
});

// Descargar reporte
app.get('/api/scan/:id/report', (req, res) => {
  const job = orchestrator.getJob(req.params.id);
  const format = req.query.format || 'html';
  
  if (!job) {
    return res.status(404).json({ error: 'Job not found' });
  }
  
  if (!job.results?.report) {
    return res.status(404).json({ error: 'Report not generated yet' });
  }
  
  const reportPath = job.results.report[format];
  
  if (!reportPath) {
    return res.status(400).json({ 
      error: `Format ${format} not available` 
    });
  }
  
  res.download(reportPath);
});

// Listar aplicaciones del laboratorio
app.get('/api/lab/apps', async (req, res) => {
  const apps = [
    { name: 'Juice Shop', port: 3001, url: 'http://localhost:3001' },
    { name: 'DVWA', port: 3002, url: 'http://localhost:3002' },
    { name: 'WebGoat', port: 3003, url: 'http://localhost:3003' },
    { name: 'bWAPP', port: 3004, url: 'http://localhost:3004' },
    { name: 'Hackazon', port: 3005, url: 'http://localhost:3005' }
  ];
  
  // Verificar estado de cada app
  for (const app of apps) {
    try {
      const response = await fetch(app.url, { 
        method: 'HEAD', 
        timeout: 5000 
      });
      app.status = response.ok ? 'running' : 'error';
    } catch {
      app.status = 'stopped';
    }
  }
  
  res.json(apps);
});

app.listen(4000, () => {
  console.log('SecureScan Pro Backend running on port 4000');
});
```

---

## 11. INTERACCION WEB-BACKEND (API REST)

### 11.1 Especificacion de la API

| Endpoint | Metodo | Descripcion | Request Body | Response |
|----------|--------|-------------|--------------|----------|
| `/api/scan` | POST | Iniciar escaneo | `{target, options}` | `{jobId}` |
| `/api/scan/:id/status` | GET | Estado del escaneo | - | `{status, progress, steps}` |
| `/api/scan/:id/results` | GET | Resultados completos | - | `{results}` |
| `/api/scan/:id/report` | GET | Descargar reporte | `?format=html\|md\|pdf` | File |
| `/api/lab/apps` | GET | Listar apps del lab | - | `[{app}]` |
| `/api/lab/status` | GET | Estado del laboratorio | - | `{running, apps}` |

### 11.2 Ejemplos de Llamadas API

```javascript
// Ejemplo: Iniciar escaneo desde el frontend
async function startScan(targetUrl, options = {}) {
  const response = await fetch('/api/scan', {
    method: 'POST',
    headers: {
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      target: targetUrl,
      options: {
        scanType: 'normal',
        tools: ['wappalyzer', 'nmap', 'gobuster', 'nikto', 'zap', 'exploitdb']
      }
    })
  });
  
  if (!response.ok) {
    throw new Error('Failed to start scan');
  }
  
  return response.json();
}

// Ejemplo: Polling del estado
async function pollScanStatus(jobId, onProgress) {
  const pollInterval = 2000; // 2 segundos
  
  return new Promise((resolve, reject) => {
    const poll = async () => {
      try {
        const response = await fetch(`/api/scan/${jobId}/status`);
        const data = await response.json();
        
        onProgress(data);
        
        if (data.status === 'completed' || data.status === 'failed') {
          resolve(data);
        } else {
          setTimeout(poll, pollInterval);
        }
      } catch (error) {
        reject(error);
      }
    };
    
    poll();
  });
}

// Ejemplo: Descargar reporte
async function downloadReport(jobId, format = 'html') {
  const response = await fetch(`/api/scan/${jobId}/report?format=${format}`);
  
  if (!response.ok) {
    throw new Error('Failed to download report');
  }
  
  const blob = await response.blob();
  const url = window.URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = `security_report_${jobId}.${format}`;
  a.click();
  window.URL.revokeObjectURL(url);
}
```

---

## 12. VISUALIZACION DE RESULTADOS

### 12.1 Componentes de la Interfaz

La interfaz web muestra los resultados de forma organizada:

```
+=========================================================================+
|  SecureScan Pro - Resultados del Escaneo                                |
+=========================================================================+

+-------------------------------------------------------------------------+
| RESUMEN EJECUTIVO                                                       |
+-------------------------------------------------------------------------+
|                                                                         |
|  Score de Seguridad: [============================------] 72/100        |
|  Nivel de Riesgo: MODERADO                                              |
|                                                                         |
|  +---------------+  +---------------+  +---------------+                |
|  | 2 CRITICOS    |  | 5 ALTOS       |  | 12 MEDIOS     |                |
|  | (Rojo)        |  | (Naranja)     |  | (Amarillo)    |                |
|  +---------------+  +---------------+  +---------------+                |
|                                                                         |
+-------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
| TECNOLOGIAS DETECTADAS                                                  |
+-------------------------------------------------------------------------+
|  +-------------+  +-------------+  +-------------+  +-------------+     |
|  | Express.js  |  | Node.js     |  | Angular     |  | MongoDB     |     |
|  | v4.18.2     |  | v18.x       |  | v15.x       |  | v6.x        |     |
|  +-------------+  +-------------+  +-------------+  +-------------+     |
+-------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
| PUERTOS Y SERVICIOS                                                     |
+-------------------------------------------------------------------------+
|  Puerto | Estado | Servicio | Version            | Riesgo               |
|  -------|--------|----------|--------------------|---------             |
|  3001   | Abierto| HTTP     | Node.js Express    | Medio                |
|  3002   | Abierto| HTTP     | Apache 2.4.56      | Bajo                 |
|  22     | Abierto| SSH      | OpenSSH 8.9        | Info                 |
+-------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
| VULNERABILIDADES ENCONTRADAS                                            |
+-------------------------------------------------------------------------+
|                                                                         |
|  [CRITICO] Cross-Site Scripting (XSS) Reflejado                        |
|  Ubicacion: /search?q=                                                  |
|  CWE-79 | OWASP A7:2017                                                |
|  [Ver detalles] [Ver solucion]                                         |
|  ----------------------------------------------------------------      |
|  [ALTO] SQL Injection                                                  |
|  Ubicacion: /api/users?id=                                             |
|  CWE-89 | OWASP A1:2017                                                |
|  [Ver detalles] [Ver solucion]                                         |
|                                                                         |
+-------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
| EXPLOITS RELACIONADOS                                                   |
+-------------------------------------------------------------------------+
|  +-------------------------------------------------------------------+ |
|  | Apache 2.4.49 - Path Traversal RCE                     [CRITICO]  | |
|  | EDB-ID: 50383 | Tipo: webapps | Plataforma: multiple              | |
|  | [Copiar exploit] [Ver en Exploit-DB]                              | |
|  +-------------------------------------------------------------------+ |
+-------------------------------------------------------------------------+

+-------------------------------------------------------------------------+
|  [Descargar Reporte HTML]  [Descargar Reporte PDF]  [Nuevo Escaneo]    |
+-------------------------------------------------------------------------+
```

### 12.2 Codigo del Dashboard de Resultados

El componente `ResultsDashboard` renderiza todos los resultados de forma interactiva, con tabs para cada seccion, graficos de distribucion de vulnerabilidades, y opciones para filtrar y exportar.

---

## 13. CALCULO DEL SCORE DE VULNERABILIDAD

### 13.1 Metodologia de Scoring

El sistema utiliza una formula ponderada basada en la severidad de los hallazgos:

```
Score = 100 - (Penalizacion_Total / Factor_Normalizacion)

Donde:
  Penalizacion_Total = Sum(Cantidad_por_severidad * Peso_severidad)
  Factor_Normalizacion = max(1, Total_Hallazgos / 10)
```

### 13.2 Pesos por Severidad

| Severidad | Peso | Justificacion |
|-----------|------|---------------|
| Critico | 25 | Impacto severo, explotacion inmediata posible |
| Alto | 15 | Impacto significativo, requiere atencion urgente |
| Medio | 8 | Impacto moderado, debe corregirse |
| Bajo | 3 | Impacto menor, corregir cuando sea posible |
| Informativo | 1 | Sin impacto directo, mejores practicas |

### 13.3 Implementacion del Motor de Scoring

```javascript
// backend/modules/scoring_engine.js

class ScoringEngine {
  constructor() {
    this.weights = {
      critical: 25,
      high: 15,
      medium: 8,
      low: 3,
      info: 1
    };
  }

  calculate(scanResults) {
    // Consolidar todos los hallazgos de todas las herramientas
    const allFindings = this.consolidateFindings(scanResults);
    
    // Contar por severidad
    const counts = this.countBySeverity(allFindings);
    
    // Calcular penalizacion
    let totalPenalty = 0;
    for (const [severity, count] of Object.entries(counts)) {
      totalPenalty += count * (this.weights[severity] || 0);
    }
    
    // Factor de normalizacion
    const totalFindings = Object.values(counts).reduce((a, b) => a + b, 0);
    const normalizationFactor = Math.max(1, totalFindings / 10);
    
    // Score final
    const rawScore = 100 - (totalPenalty / normalizationFactor);
    const score = Math.max(0, Math.min(100, Math.round(rawScore)));
    
    return {
      score: score,
      riskLevel: this.getRiskLevel(score),
      breakdown: {
        counts: counts,
        totalPenalty: totalPenalty,
        normalizationFactor: normalizationFactor
      },
      findings: allFindings
    };
  }

  consolidateFindings(results) {
    const findings = [];
    
    // Nikto
    if (results.nikto?.vulnerabilities) {
      results.nikto.vulnerabilities.forEach(v => {
        findings.push({
          source: 'nikto',
          severity: v.severity,
          title: v.message,
          url: v.url,
          id: v.id
        });
      });
    }
    
    // ZAP
    if (results.zap?.alerts) {
      results.zap.alerts.forEach(a => {
        findings.push({
          source: 'zap',
          severity: a.severity,
          title: a.name,
          description: a.description,
          cweid: a.cweid
        });
      });
    }
    
    // Gobuster (directorios de alto riesgo)
    if (results.gobuster?.directories) {
      results.gobuster.directories
        .filter(d => d.risk === 'high')
        .forEach(d => {
          findings.push({
            source: 'gobuster',
            severity: 'medium',
            title: `Directorio sensible expuesto: ${d.path}`,
            path: d.path
          });
        });
    }
    
    // Searchsploit
    if (results.exploitdb?.exploits) {
      results.exploitdb.exploits.forEach(e => {
        findings.push({
          source: 'exploitdb',
          severity: e.severity,
          title: `Exploit disponible: ${e.title}`,
          edbId: e.edbId
        });
      });
    }
    
    return findings;
  }

  countBySeverity(findings) {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    findings.forEach(f => {
      counts[f.severity] = (counts[f.severity] || 0) + 1;
    });
    return counts;
  }

  getRiskLevel(score) {
    if (score >= 90) return { level: 'excellent', label: 'Excelente', color: '#22c55e' };
    if (score >= 70) return { level: 'good', label: 'Bueno', color: '#84cc16' };
    if (score >= 50) return { level: 'moderate', label: 'Moderado', color: '#eab308' };
    if (score >= 30) return { level: 'poor', label: 'Deficiente', color: '#f97316' };
    return { level: 'critical', label: 'Critico', color: '#ef4444' };
  }
}

module.exports = ScoringEngine;
```

### 13.4 Interpretacion del Score

| Rango | Nivel | Descripcion | Accion Recomendada |
|-------|-------|-------------|-------------------|
| 90-100 | Excelente | Sistema con seguridad optima | Mantener monitoreo |
| 70-89 | Bueno | Vulnerabilidades menores | Corregir en proxima iteracion |
| 50-69 | Moderado | Requiere atencion | Planificar correccion |
| 30-49 | Deficiente | Riesgo significativo | Correccion prioritaria |
| 0-29 | Critico | Sistema en riesgo | Accion inmediata requerida |

---

## 14. GENERACION DE REPORTE FINAL

### 14.1 Estructura del Reporte

El reporte generado incluye las siguientes secciones:

1. **Portada y Metadatos**
   - ID del escaneo
   - Objetivo
   - Fecha y duracion

2. **Resumen Ejecutivo**
   - Score de vulnerabilidad
   - Distribucion de hallazgos
   - Principales riesgos

3. **Tecnologias Detectadas**
   - Lista de tecnologias
   - Versiones identificadas
   - Categorias

4. **Puertos y Servicios**
   - Tabla de puertos abiertos
   - Versiones de servicios
   - Scripts NSE ejecutados

5. **Directorios Descubiertos**
   - Lista de rutas encontradas
   - Clasificacion por riesgo

6. **Vulnerabilidades Web**
   - Hallazgos de Nikto
   - Alertas de ZAP
   - Severidad y remediacion

7. **Exploits Relacionados**
   - Lista de exploits encontrados
   - Links a Exploit-DB

8. **Recomendaciones**
   - Priorizadas por severidad
   - Acciones especificas

9. **Anexos**
   - Comandos ejecutados
   - Archivos raw

### 14.2 Formatos Disponibles

- **HTML:** Reporte interactivo con estilos profesionales
- **Markdown:** Compatible con GitHub/GitLab
- **PDF:** Para impresion y distribucion formal

---

## 15. CONSIDERACIONES ETICAS Y LEGALES

### 15.1 Marco Legal

**IMPORTANTE: AVISO LEGAL**

El uso de herramientas de seguridad informatica esta regulado por leyes nacionales e internacionales. En Colombia aplican:

- **Ley 1273 de 2009:** Delitos informaticos
- **Ley 1581 de 2012:** Proteccion de datos personales
- **Codigo Penal Colombiano:** Articulos sobre acceso abusivo

**Consecuencias del uso no autorizado:**
- Multas economicas significativas
- Penas de prision (1-8 anos segun el delito)
- Responsabilidad civil por danos

### 15.2 Requisitos de Autorizacion

Antes de realizar cualquier escaneo, DEBE obtener:

1. **Autorizacion escrita** del propietario del sistema
2. **Alcance definido** (URLs, IPs, horarios permitidos)
3. **Contacto de emergencia** en caso de incidentes
4. **Acuerdo de confidencialidad** para los resultados

### 15.3 Ejemplo de Carta de Autorizacion

```
AUTORIZACION PARA PRUEBAS DE SEGURIDAD

Yo, [Nombre del Propietario], con identificacion [CC/NIT], 
en calidad de [Cargo] de [Empresa], autorizo a [Nombre del Tester] 
para realizar pruebas de seguridad sobre los siguientes sistemas:

Sistemas autorizados:
- [URL/IP 1]
- [URL/IP 2]

Periodo autorizado: [Fecha inicio] a [Fecha fin]
Horario permitido: [Horario]

Alcance:
- [x] Escaneo de puertos
- [x] Deteccion de vulnerabilidades
- [x] Pruebas de aplicacion web
- [ ] Pruebas de ingenieria social
- [ ] Pruebas de denegacion de servicio

Queda expresamente PROHIBIDO:
- Acceder a datos de usuarios reales
- Modificar o eliminar informacion
- Compartir hallazgos con terceros

Firma del propietario: ____________________
Fecha: ____________________
```

### 15.4 Buenas Practicas

1. **Solo usar en laboratorio local** durante el aprendizaje
2. **Documentar todas las acciones** realizadas
3. **No explotar vulnerabilidades** encontradas
4. **Reportar hallazgos** al propietario responsablemente
5. **Mantener confidencialidad** de los resultados

---

## 16. ESTRUCTURA DEL PROYECTO

### 16.1 Arbol Completo de Carpetas

```
securescan-pro/
├── README.md
├── LICENSE
├── .gitignore
├── .env.example
│
├── docker-compose.yml          # Laboratorio de apps vulnerables
├── setup_lab.sh                # Script de configuracion del lab
│
├── docs/
│   ├── DOCUMENTACION_TECNICA_COMPLETA.md
│   ├── GUIA_INSTALACION.md
│   ├── API_REFERENCE.md
│   └── diagrams/
│       ├── arquitectura.png
│       └── secuencia.png
│
├── backend/
│   ├── package.json
│   ├── server.js               # Punto de entrada Express
│   │
│   ├── modules/
│   │   ├── orchestrator.js     # Coordinador de escaneos
│   │   ├── nmap_scanner.js     # Modulo Nmap
│   │   ├── nikto_scanner.js    # Modulo Nikto
│   │   ├── gobuster_scanner.js # Modulo Gobuster
│   │   ├── zap_scanner.js      # Modulo OWASP ZAP
│   │   ├── wappalyzer_detector.js # Modulo Wappalyzer
│   │   ├── exploitdb_lookup.js # Modulo Searchsploit
│   │   ├── scoring_engine.js   # Motor de scoring
│   │   └── report_generator.js # Generador de reportes
│   │
│   ├── utils/
│   │   └── logger.js           # Sistema de logging
│   │
│   └── templates/
│       ├── report.html         # Plantilla HTML
│       └── report.md           # Plantilla Markdown
│
├── app/                        # Frontend Next.js
│   ├── layout.tsx
│   ├── page.tsx                # Landing page
│   ├── globals.css
│   │
│   ├── scanner/
│   │   └── page.tsx            # Pagina de escaneo
│   │
│   ├── lab/
│   │   └── page.tsx            # Gestion del laboratorio
│   │
│   └── history/
│       └── page.tsx            # Historial de escaneos
│
├── components/
│   ├── header.tsx
│   ├── scan-form.tsx
│   ├── scan-progress.tsx
│   └── results-dashboard.tsx
│
├── lib/
│   ├── utils.ts
│   └── scan-context.tsx
│
├── tools/
│   ├── install_tools.sh        # Instalador de herramientas
│   ├── run_all_scans.sh        # Script de escaneo completo
│   └── parse_results.js        # Parser de resultados
│
├── reports/                    # Directorio de reportes generados
│   └── .gitkeep
│
└── wordlists/
    └── .gitkeep                # Wordlists personalizadas
```

---

## 17. GUIA DE INSTALACION COMPLETA

### 17.1 Requisitos Previos

#### Instalar Kali Linux

1. Descargar ISO desde: https://www.kali.org/get-kali/
2. Crear USB booteable o maquina virtual
3. Seguir el asistente de instalacion
4. Actualizar el sistema:

```bash
sudo apt update && sudo apt full-upgrade -y
```

#### Instalar Docker

```bash
# Instalar Docker
sudo apt install -y docker.io

# Instalar Docker Compose
sudo apt install -y docker-compose

# Agregar usuario al grupo docker
sudo usermod -aG docker $USER

# IMPORTANTE: Cerrar sesion y volver a entrar
# o ejecutar: newgrp docker

# Verificar instalacion
docker --version
docker-compose --version
```

#### Instalar VS Code

```bash
# Descargar e instalar
sudo apt install -y curl gpg
curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft.gpg] https://packages.microsoft.com/repos/vscode stable main" | sudo tee /etc/apt/sources.list.d/vscode.list
sudo apt update
sudo apt install -y code

# Extensiones recomendadas
code --install-extension esbenp.prettier-vscode
code --install-extension dbaeumer.vscode-eslint
code --install-extension bradlc.vscode-tailwindcss
```

### 17.2 Instalar Herramientas de Seguridad

```bash
# Actualizar repositorios
sudo apt update

# Instalar todas las herramientas necesarias
sudo apt install -y \
    nmap \
    nikto \
    gobuster \
    zaproxy \
    exploitdb \
    nodejs \
    npm

# Instalar Wappalyzer CLI
sudo npm install -g wappalyzer

# Actualizar base de datos de exploits
searchsploit -u

# Verificar instalaciones
nmap --version
nikto -Version
gobuster version
searchsploit --version
node --version
npm --version
```

### 17.3 Clonar y Configurar el Proyecto

```bash
# Clonar repositorio
git clone https://github.com/tu-usuario/securescan-pro.git
cd securescan-pro

# Instalar dependencias del backend
cd backend
npm install
cd ..

# Instalar dependencias del frontend
npm install

# Copiar archivo de configuracion
cp .env.example .env
```

### 17.4 Levantar el Laboratorio

```bash
# Dar permisos de ejecucion al script
chmod +x setup_lab.sh

# Ejecutar el script de configuracion
./setup_lab.sh

# Esperar a que todas las aplicaciones esten listas
# El script mostrara el estado de cada aplicacion
```

### 17.5 Iniciar la Aplicacion

```bash
# Terminal 1: Iniciar backend
cd backend
npm run dev

# Terminal 2: Iniciar frontend
npm run dev

# Abrir en navegador
# Frontend: http://localhost:3000
# Backend API: http://localhost:4000
```

### 17.6 Verificar Instalacion

1. Abrir http://localhost:3000 en el navegador
2. Ir a la seccion "Laboratorio"
3. Verificar que todas las apps muestren estado "Running"
4. Iniciar un escaneo de prueba contra http://localhost:3001

---

## 18. LABORATORIO DE APLICACIONES VULNERABLES

### 18.1 Aplicaciones Incluidas

| Aplicacion | Puerto | Descripcion | Dificultad |
|------------|--------|-------------|------------|
| Juice Shop | 3001 | Tienda e-commerce moderna con OWASP Top 10 | Media-Alta |
| DVWA | 3002 | Aplicacion clasica de practica | Baja-Media |
| WebGoat | 3003 | Tutoriales interactivos de OWASP | Guiada |
| bWAPP | 3004 | 100+ bugs de seguridad | Variada |
| Hackazon | 3005 | E-commerce realista | Media |

### 18.2 Docker Compose

El archivo `docker-compose.yml` incluido levanta todas las aplicaciones:

```yaml
version: '3.8'

services:
  juice-shop:
    image: bkimminich/juice-shop
    container_name: juice-shop
    ports:
      - "3001:3000"
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "wget", "-q", "--spider", "http://localhost:3000"]
      interval: 30s
      timeout: 10s
      retries: 3

  dvwa:
    image: vulnerables/web-dvwa
    container_name: dvwa
    ports:
      - "3002:80"
    restart: unless-stopped
    environment:
      - MYSQL_ALLOW_EMPTY_PASSWORD=yes

  webgoat:
    image: webgoat/webgoat
    container_name: webgoat
    ports:
      - "3003:8080"
      - "9090:9090"
    restart: unless-stopped

  bwapp:
    image: raesene/bwapp
    container_name: bwapp
    ports:
      - "3004:80"
    restart: unless-stopped

  hackazon:
    image: ianwijaya/hackazon
    container_name: hackazon
    ports:
      - "3005:80"
    restart: unless-stopped

networks:
  default:
    name: vuln-lab-network
```

### 18.3 Comandos Utiles

```bash
# Ver estado de los contenedores
docker-compose ps

# Ver logs de una aplicacion
docker-compose logs juice-shop

# Reiniciar una aplicacion
docker-compose restart dvwa

# Detener todo el laboratorio
docker-compose down

# Detener y eliminar volumenes
docker-compose down --volumes --remove-orphans

# Actualizar imagenes
docker-compose pull
docker-compose up -d
```

---

## 19. ANEXOS

### 19.1 Referencias y Recursos

**Documentacion Oficial:**
- Nmap: https://nmap.org/book/
- Nikto: https://github.com/sullo/nikto/wiki
- Gobuster: https://github.com/OJ/gobuster
- OWASP ZAP: https://www.zaproxy.org/docs/
- Exploit-DB: https://www.exploit-db.com/

**Estandares y Metodologias:**
- OWASP Testing Guide: https://owasp.org/www-project-web-security-testing-guide/
- PTES: http://www.pentest-standard.org/
- CVSS: https://www.first.org/cvss/

**Aplicaciones Vulnerables:**
- OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
- DVWA: https://dvwa.co.uk/
- WebGoat: https://owasp.org/www-project-webgoat/

### 19.2 Glosario de Terminos

| Termino | Definicion |
|---------|------------|
| CVE | Common Vulnerabilities and Exposures - Identificador unico de vulnerabilidades |
| CVSS | Common Vulnerability Scoring System - Sistema de puntuacion de vulnerabilidades |
| CWE | Common Weakness Enumeration - Catalogo de debilidades de software |
| XSS | Cross-Site Scripting - Inyeccion de scripts maliciosos |
| SQLi | SQL Injection - Inyeccion de comandos SQL |
| RCE | Remote Code Execution - Ejecucion remota de codigo |
| LFI | Local File Inclusion - Inclusion de archivos locales |
| OWASP | Open Web Application Security Project |
| Pentest | Prueba de penetracion |

### 19.3 Contacto y Soporte

Para dudas o problemas con el proyecto:
- Crear issue en el repositorio de GitHub
- Consultar la documentacion oficial de cada herramienta
- Recursos de la comunidad OWASP

---

**Documento generado para proyecto academico SENA**  
**SecureScan Pro v1.0 - Plataforma de Analisis de Seguridad**  
**Marzo 2026**
