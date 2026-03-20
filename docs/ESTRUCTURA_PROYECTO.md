# Estructura del Proyecto SecureScan Pro v3.0

## Arbol Completo de Directorios

securescan-pro/
│
├── docker-compose.yml # Configuracion del laboratorio vulnerable
├── setup*lab.sh # Script de instalacion del laboratorio
├── package.json # Dependencias del proyecto principal
├── README.md # Documentacion general del proyecto
│
├── backend/ # API REST y logica del servidor
│ ├── package.json # Dependencias del backend
│ ├── server.js # Servidor Express principal
│ │
│ ├── modules/ # Modulos de escaneo
│ │ ├── orchestrator.js # Orquestador principal v3.0 (con resiliencia)
│ │ ├── whatweb_detector.js # Deteccion de tecnologias (reemplaza Wappalyzer)
│ │ ├── nmap_scanner.js # Escaner de puertos y servicios
│ │ ├── gobuster_scanner.js # Descubrimiento de directorios
│ │ ├── zap_scanner.js # OWASP ZAP integration
│ │ ├── exploitdb_unified.js # Busqueda de exploits (integrado con Nmap)
│ │ ├── metasploit_integration.js # Explotacion controlada (opcional, dry-run)
│ │ ├── scoring_engine.js # Motor de puntuacion CVSS + EPSS
│ │ └── report_generator.js # Generador de reportes multi-formato
│ │
│ ├── templates/ # Plantillas de reportes
│ │ └── report.html # Plantilla HTML (unico formato de plantilla)
│ │
│ └── utils/ # Utilidades
│ └── logger.js # Sistema de logging
│
├── app/ # Frontend Next.js (App Router)
│ ├── layout.tsx # Layout principal
│ ├── page.tsx # Pagina de inicio
│ ├── globals.css # Estilos globales
│ │
│ ├── scanner/ # Modulo de escaneo
│ │ └── page.tsx # Interfaz de escaneo
│ │
│ ├── lab/ # Modulo del laboratorio
│ │ └── page.tsx # Estado del laboratorio
│ │
│ └── history/ # Historial de escaneos
│ └── page.tsx # Lista de escaneos anteriores
│
├── components/ # Componentes React
│ ├── header.tsx # Cabecera de navegacion
│ ├── scan-form.tsx # Formulario de escaneo
│ ├── scan-progress.tsx # Progreso del escaneo
│ ├── results-dashboard.tsx # Dashboard de resultados
│ ├── theme-provider.tsx # Proveedor de tema
│ └── ui/ # Componentes shadcn/ui
│
├── lib/ # Librerias y contextos
│ ├── utils.ts # Utilidades generales
│ └── scan-context.tsx # Contexto de escaneo
│
├── tools/ # Scripts de automatizacion (VACIO - obsoleto)
│ # Carpeta vacia - funcionalidad migrada al orchestrator.js
│
├── reports/ # Reportes generados (gitignore)
│ └── [timestamp]/ # Carpeta por escaneo
│ ├── whatweb_output.json
│ ├── nmap_output.xml
│ ├── nmap_output.txt
│ ├── gobuster_output.txt
│ ├── zap_scan*[id].json
│ ├── exploitdb\_[timestamp].json
│ ├── report.html
│ ├── report.pdf
│ ├── report.sarif
│ └── report.json
│
├── wordlists/ # Diccionarios para Gobuster
│ └── common.txt # Lista de directorios comunes
│
├── docs/ # Documentacion
│ ├── DOCUMENTACION_TECNICA_COMPLETA.md
│ ├── GUIA_INSTALACION.md
│ ├── API_REFERENCE.md
│ ├── ETICA_Y_LEGALIDAD.md
│ ├── ESTRUCTURA_PROYECTO.md
│ └── PRESENTACION_SENA.md
│
└── scripts/ # Scripts de utilidad
└── start-backend.js # Script de inicio del backend
plain
Copy

## Descripcion de Cada Componente

### 1. Raiz del Proyecto

| Archivo              | Descripcion                                                                                |
| -------------------- | ------------------------------------------------------------------------------------------ |
| `docker-compose.yml` | Define los 4 contenedores de aplicaciones vulnerables (Juice Shop, DVWA, WebGoat, WebWolf) |
| `setup_lab.sh`       | Script bash para levantar el laboratorio con un comando                                    |
| `package.json`       | Metadatos y scripts del proyecto principal                                                 |
| `README.md`          | Documentacion general y guia rapida de uso                                                 |

### 2. Backend (`/backend`)

#### Archivo Principal

- **server.js**: Servidor Express con endpoints REST para:
  - Iniciar escaneos (`POST /api/scan`)
  - Consultar estado (`GET /api/scan/:id/status`)
  - Obtener resultados (`GET /api/scan/:id/results`)
  - Descargar reportes (`GET /api/scan/:id/report`)
  - Estado del laboratorio (`GET /api/lab/apps`)
  - Verificar salud del sistema (`GET /health`)
  - Estado de herramientas (`GET /tools/status`)

#### Modulos de Escaneo (`/backend/modules`)

| Modulo                      | Herramienta | Funcion                                                                                                   | Resiliencia                                                                                                                                |
| --------------------------- | ----------- | --------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `orchestrator.js`           | -           | Coordina la ejecucion secuencial con Circuit Breaker, File Stabilizer, Target Validator y Process Manager | Circuit Breaker por herramienta, File Stabilizer para archivos de salida, Target Validator para health-check, Process Manager para cleanup |
| `whatweb_detector.js`       | WhatWeb     | Deteccion de tecnologias web (reemplaza Wappalyzer)                                                       | Circuit Breaker: 3 fallos / 60s timeout                                                                                                    |
| `nmap_scanner.js`           | Nmap        | Escaneo de puertos, servicios, versiones y vulnerabilidades                                               | Circuit Breaker: 2 fallos / 120s timeout                                                                                                   |
| `gobuster_scanner.js`       | Gobuster    | Descubrimiento de directorios, subdominios y hosts virtuales                                              | Circuit Breaker: 3 fallos / 60s timeout                                                                                                    |
| `zap_scanner.js`            | OWASP ZAP   | Escaneo DAST completo con soporte SPA                                                                     | Circuit Breaker: 2 fallos / 300s timeout                                                                                                   |
| `exploitdb_unified.js`      | ExploitDB   | Busqueda de exploits conocidos con integracion Nmap XML                                                   | Circuit Breaker: 3 fallos / 60s timeout                                                                                                    |
| `metasploit_integration.js` | Metasploit  | Verificacion de exploits en modo dry-run (opcional)                                                       | Circuit Breaker: 1 fallo / 300s timeout, deshabilitado por defecto                                                                         |
| `scoring_engine.js`         | -           | Calcula puntuacion de riesgo con CVSS 3.1 + EPSS                                                          | -                                                                                                                                          |
| `report_generator.js`       | -           | Genera reportes en HTML, PDF, SARIF, JSON                                                                 | -                                                                                                                                          |

#### Caracteristicas de Resiliencia (v3.0)

El orchestrator.js incluye 4 mecanismos de tolerancia a fallos:

| Clase             | Funcion                                  | Implementacion                                                 |
| ----------------- | ---------------------------------------- | -------------------------------------------------------------- |
| `CircuitBreaker`  | Aislamiento de fallos entre herramientas | Estados: CLOSED, OPEN, HALF_OPEN. Configurable por herramienta |
| `FileStabilizer`  | Espera archivos de salida estables       | 3 rondas consecutivas sin cambios de tamaño/mtime              |
| `TargetValidator` | Health-check TCP + whitelist             | Verifica conexion antes de escanear, valida scope permitido    |
| `ProcessManager`  | Gestion segura de procesos               | Registro de PIDs, cleanup SIGTERM/SIGINT, timeout forzado      |

#### Plantillas (`/backend/templates`)

- **report.html**: Plantilla profesional para reportes HTML (unico formato de plantilla, PDF/SARIF/JSON se generan via codigo)

### 3. Frontend (`/app`)

#### Paginas

| Ruta       | Archivo            | Descripcion                                             |
| ---------- | ------------------ | ------------------------------------------------------- |
| `/`        | `page.tsx`         | Landing page con informacion del proyecto               |
| `/scanner` | `scanner/page.tsx` | Interfaz principal de escaneo con formulario y progreso |
| `/lab`     | `lab/page.tsx`     | Estado y control del laboratorio (4 apps)               |
| `/history` | `history/page.tsx` | Historial de escaneos anteriores                        |

#### Componentes (`/components`)

| Componente              | Funcion                                                    |
| ----------------------- | ---------------------------------------------------------- |
| `header.tsx`            | Navegacion principal                                       |
| `scan-form.tsx`         | Formulario para ingresar URL objetivo y seleccionar perfil |
| `scan-progress.tsx`     | Barra de progreso en tiempo real con fases del escaneo     |
| `results-dashboard.tsx` | Visualizacion de resultados con score y vulnerabilidades   |
| `theme-provider.tsx`    | Gestion de tema claro/oscuro                               |

### 4. Scripts de Automatizacion (`/tools`)

> **NOTA v3.0**: Esta carpeta esta **VACIA**. La funcionalidad de los scripts legacy ha sido migrada al orchestrator.js:
>
> - `run_all_scans.sh` → Reemplazado por `scanSequence` en el orchestrator
> - `install_tools.sh` → Obsoleto, herramientas se gestionan via docker-compose o apt
> - `parse_results.js` → Reemplazado por `FileStabilizer` nativo

### 5. Documentacion (`/docs`)

| Documento                           | Contenido                                                                                   |
| ----------------------------------- | ------------------------------------------------------------------------------------------- |
| `DOCUMENTACION_TECNICA_COMPLETA.md` | Documento principal con arquitectura resiliente, stack tecnologico, modulos de resiliencia  |
| `GUIA_INSTALACION.md`               | Guia paso a paso para principiantes (Kali Linux, Docker, herramientas)                      |
| `API_REFERENCE.md`                  | Referencia completa de la API REST con endpoints, parametros, respuestas y codigos de error |
| `ETICA_Y_LEGALIDAD.md`              | Consideraciones eticas, marco legal colombiano, mecanismos de seguridad tecnicos            |
| `ESTRUCTURA_PROYECTO.md`            | Este documento - estructura de archivos y directorios                                       |
| `PRESENTACION_SENA.md`              | Documento de presentacion del proyecto de grado                                             |

## Flujo de Datos

Usuario (Frontend)
│
▼
┌──────────────────┐
│ POST /api/scan │
│ { target: URL } │
└────────┬─────────┘
│
▼
┌──────────────────┐
│ Orchestrator │
│ (orchestrator │
│ .js) │
│ │
│ Resiliencia: │
│ - TargetValidator (health-check)
│ - CircuitBreaker (por herramienta)
│ - FileStabilizer (archivos estables)
│ - ProcessManager (cleanup)
└────────┬─────────┘
│
├─────────────────────────────────────────────┐
│ │
▼ ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ WhatWeb │ │ Nmap │ │ Gobuster │
│ (tecnologias) │ │ (puertos/vers.) │ │ (directorios) │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
│ │ │
└────────────────────┼────────────────────┘
│
┌────────────────────┼────────────────────┐
│ │ │
▼ ▼ ▼
┌─────────────────┐ ┌─────────────────┐ ┌─────────────────┐
│ OWASP ZAP │ │ ExploitDB │ │ Metasploit │
│ (escaneo DAST) │ │ (busca exploits)│ │ (dry-run opt.) │
│ │ │ (integra Nmap) │ │ │
└────────┬────────┘ └────────┬────────┘ └────────┬────────┘
│ │ │
└────────────────────┼────────────────────┘
│
▼
┌─────────────────┐
│ Scoring Engine │
│ (CVSS + EPSS) │
└────────┬────────┘
│
▼
┌─────────────────┐
│ Report Generator│
│(HTML/PDF/SARIF/ │
│ JSON) │
└────────┬────────┘
│
▼
┌─────────────────┐
│ /reports/ │
│ [timestamp]/ │
└─────────────────┘
plain
Copy

## Variables de Entorno

Crear archivo `.env` en la raiz:

```env
# Configuracion del servidor
PORT=3000
NODE_ENV=development

# Timeouts de herramientas (segundos)
NMAP_TIMEOUT=600
ZAP_TIMEOUT=1800
GOBUSTER_TIMEOUT=300
WHATWEB_TIMEOUT=60
EXPLOITDB_TIMEOUT=120
METASPLOIT_TIMEOUT=600

# Configuracion de ZAP
ZAP_API_KEY=your-zap-api-key
ZAP_PORT=8080

# Configuracion de Metasploit (opcional)
MSF_RPC_PASSWORD=secure-password
MSF_RPC_PORT=55553

# Whitelist de objetivos permitidos (separados por coma)
ALLOWED_TARGETS=localhost:3001,localhost:3002,localhost:3003,localhost:9090,127.0.0.1

# Directorios
REPORTS_DIR=./reports
TEMP_DIR=./temp
LOGS_DIR=./logs
WORDLISTS_DIR=./wordlists

# Perfil de escaneo por defecto
DEFAULT_SCAN_PROFILE=standard

# Seguridad
MAX_SCAN_DURATION=3600
MAX_CONCURRENT_SCANS=1
Puertos Utilizados
Table
Puerto	Servicio	Descripcion
3000	Frontend Next.js	Aplicacion web principal
4000	Backend API	Servidor Express (configurable via PORT)
3001	Juice Shop	Laboratorio vulnerable - Node.js/Express
3002	DVWA	Laboratorio vulnerable - PHP/Apache
3003	WebGoat	Laboratorio vulnerable - Java/Spring
9090	WebWolf	Companion de WebGoat - email interception
8080	OWASP ZAP API	API del daemon ZAP (configurable)
55553	Metasploit RPC	Puerto RPC de Metasploit (opcional)
NOTA: Los puertos 3004 (bWAPP) y 3005 (Hackazon) NO ESTAN INCLUIDOS en esta version.
Archivos Ignorados (.gitignore)
gitignore
Copy
# Dependencias
node_modules/
.pnpm-store/

# Reportes generados
reports/
temp/
logs/

# Variables de entorno
.env
.env.local
.env.*.local

# Logs
*.log
logs/

# Sistema
.DS_Store
Thumbs.db

# IDE
.vscode/
.idea/

# Build
.next/
dist/
build/
out/

# Coverage
coverage/
.nyc_output/

# Docker
.docker/
Comandos Rapidos
bash
Copy
# Levantar laboratorio
./setup_lab.sh
# o manualmente:
docker-compose up -d

# Verificar estado del laboratorio
docker-compose ps

# Instalar dependencias backend
cd backend && npm install

# Iniciar backend (Terminal 1)
cd backend && npm run dev

# Iniciar frontend (Terminal 2)
npm run dev

# Destruir laboratorio
docker-compose down --volumes --remove-orphans

# Ver logs de un servicio
docker-compose logs juice-shop

# Actualizar base de datos de exploits
sudo searchsploit -u
Notas de Desarrollo
Agregar Nueva Herramienta
Crear modulo en /backend/modules/nueva_herramienta.js
Implementar interface estandar:
JavaScript
Copy
class NuevaHerramienta {
  async scan(target, outputDir, options) { ... }
  async parse(outputFile) { ... }
}
module.exports = NuevaHerramienta;
Registrar en orchestrator.js:
Agregar a scanSequence
Crear Circuit Breaker en constructor
Implementar metodo runNuevaHerramienta()
Agregar scoring en scoring_engine.js si aplica
Documentar en API_REFERENCE.md
Agregar Nueva App Vulnerable
Agregar servicio en docker-compose.yml (puerto 3006+)
Actualizar allowedTargets en orchestrator.js
Agregar healthcheck en docker-compose.yml
Agregar card en /app/lab/page.tsx
Documentar en GUIA_INSTALACION.md y PRESENTACION_SENA.md
Version: 3.0.0 (Resiliente)
Ultima actualizacion: Marzo 2026
Autor: Proyecto SENA - Analisis de Seguridad
Cambios v3.0:
Reemplazado Wappalyzer por WhatWeb
Eliminado Nikto (no implementado)
Eliminados bWAPP y Hackazon del laboratorio
Agregados mecanismos de resiliencia (Circuit Breaker, File Stabilizer, Target Validator, Process Manager)
Eliminados scripts obsoletos de /tools/
Eliminada plantilla report.md (formatos via codigo)
Integracion Nmap->ExploitDB unificada
```
