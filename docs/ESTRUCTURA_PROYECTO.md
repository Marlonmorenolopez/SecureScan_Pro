# Estructura del Proyecto SecureScan Pro

## Arbol Completo de Directorios

```
securescan-pro/
│
├── docker-compose.yml              # Configuracion del laboratorio vulnerable
├── setup_lab.sh                    # Script de instalacion del laboratorio
├── package.json                    # Dependencias del proyecto principal
│
├── backend/                        # API REST y logica del servidor
│   ├── package.json               # Dependencias del backend
│   ├── server.js                  # Servidor Express principal
│   │
│   ├── modules/                   # Modulos de escaneo
│   │   ├── nmap_scanner.js       # Escaner de puertos y servicios
│   │   ├── nikto_scanner.js      # Escaner de vulnerabilidades web
│   │   ├── gobuster_scanner.js   # Descubrimiento de directorios
│   │   ├── zap_scanner.js        # OWASP ZAP integration
│   │   ├── wappalyzer_detector.js # Deteccion de tecnologias
│   │   ├── exploitdb_lookup.js   # Busqueda de exploits
│   │   ├── orchestrator.js       # Orquestador de escaneos
│   │   ├── scoring_engine.js     # Motor de puntuacion
│   │   └── report_generator.js   # Generador de reportes
│   │
│   ├── templates/                 # Plantillas de reportes
│   │   ├── report.html           # Plantilla HTML
│   │   └── report.md             # Plantilla Markdown
│   │
│   └── utils/                     # Utilidades
│       └── logger.js             # Sistema de logging
│
├── app/                           # Frontend Next.js (App Router)
│   ├── layout.tsx                # Layout principal
│   ├── page.tsx                  # Pagina de inicio
│   ├── globals.css               # Estilos globales
│   │
│   ├── scanner/                  # Modulo de escaneo
│   │   └── page.tsx             # Interfaz de escaneo
│   │
│   ├── lab/                      # Modulo del laboratorio
│   │   └── page.tsx             # Estado del laboratorio
│   │
│   └── history/                  # Historial de escaneos
│       └── page.tsx             # Lista de escaneos anteriores
│
├── components/                    # Componentes React
│   ├── header.tsx                # Cabecera de navegacion
│   ├── scan-form.tsx             # Formulario de escaneo
│   ├── scan-progress.tsx         # Progreso del escaneo
│   ├── results-dashboard.tsx     # Dashboard de resultados
│   └── ui/                       # Componentes shadcn/ui
│
├── lib/                          # Librerias y contextos
│   ├── utils.ts                  # Utilidades generales
│   └── scan-context.tsx          # Contexto de escaneo
│
├── tools/                        # Scripts de automatizacion
│   ├── run_all_scans.sh         # Ejecutar todos los escaneos
│   ├── install_tools.sh         # Instalar herramientas
│   └── parse_results.js         # Parsear resultados
│
├── reports/                      # Reportes generados (gitignore)
│   └── [timestamp]/             # Carpeta por escaneo
│       ├── nmap_output.xml
│       ├── nikto_output.json
│       ├── gobuster_output.txt
│       ├── zap_output.json
│       ├── wappalyzer_output.json
│       ├── exploits_output.json
│       ├── consolidated.json
│       ├── report.html
│       └── report.md
│
├── wordlists/                    # Diccionarios para Gobuster
│   └── common.txt               # Lista de directorios comunes
│
└── docs/                         # Documentacion
    ├── DOCUMENTACION_TECNICA_COMPLETA.md
    ├── GUIA_INSTALACION.md
    ├── API_REFERENCE.md
    ├── ETICA_Y_LEGALIDAD.md
    ├── ESTRUCTURA_PROYECTO.md
    └── diagramas/
        ├── arquitectura.png
        └── secuencia.png
```

## Descripcion de Cada Componente

### 1. Raiz del Proyecto

| Archivo | Descripcion |
|---------|-------------|
| `docker-compose.yml` | Define los 5 contenedores de aplicaciones vulnerables |
| `setup_lab.sh` | Script bash para levantar el laboratorio con un comando |
| `package.json` | Metadatos y scripts del proyecto principal |

### 2. Backend (`/backend`)

#### Archivo Principal
- **server.js**: Servidor Express con endpoints REST para:
  - Iniciar escaneos (`POST /api/scan`)
  - Consultar estado (`GET /api/scan/:id/status`)
  - Descargar reportes (`GET /api/scan/:id/report`)
  - Estado del laboratorio (`GET /api/lab/status`)

#### Modulos de Escaneo (`/backend/modules`)

| Modulo | Herramienta | Funcion |
|--------|-------------|---------|
| `nmap_scanner.js` | Nmap | Escaneo de puertos, servicios y versiones |
| `nikto_scanner.js` | Nikto | Vulnerabilidades de servidor web |
| `gobuster_scanner.js` | Gobuster | Descubrimiento de directorios |
| `zap_scanner.js` | OWASP ZAP | Escaneo de aplicaciones web |
| `wappalyzer_detector.js` | Wappalyzer | Deteccion de tecnologias |
| `exploitdb_lookup.js` | Searchsploit | Busqueda de exploits conocidos |
| `orchestrator.js` | - | Coordina la ejecucion secuencial |
| `scoring_engine.js` | - | Calcula puntuacion de riesgo |
| `report_generator.js` | - | Genera reportes HTML/MD/PDF |

#### Plantillas (`/backend/templates`)
- **report.html**: Plantilla profesional para reportes HTML
- **report.md**: Plantilla Markdown para documentacion

### 3. Frontend (`/app`)

#### Paginas

| Ruta | Archivo | Descripcion |
|------|---------|-------------|
| `/` | `page.tsx` | Landing page con informacion del proyecto |
| `/scanner` | `scanner/page.tsx` | Interfaz principal de escaneo |
| `/lab` | `lab/page.tsx` | Estado y control del laboratorio |
| `/history` | `history/page.tsx` | Historial de escaneos |

#### Componentes (`/components`)

| Componente | Funcion |
|------------|---------|
| `header.tsx` | Navegacion principal |
| `scan-form.tsx` | Formulario para ingresar URL objetivo |
| `scan-progress.tsx` | Barra de progreso en tiempo real |
| `results-dashboard.tsx` | Visualizacion de resultados |

### 4. Scripts de Automatizacion (`/tools`)

| Script | Lenguaje | Funcion |
|--------|----------|---------|
| `run_all_scans.sh` | Bash | Ejecuta todas las herramientas en secuencia |
| `install_tools.sh` | Bash | Instala todas las dependencias |
| `parse_results.js` | Node.js | Parsea y consolida resultados |

### 5. Documentacion (`/docs`)

| Documento | Contenido |
|-----------|-----------|
| `DOCUMENTACION_TECNICA_COMPLETA.md` | Documento principal para SENA |
| `GUIA_INSTALACION.md` | Guia paso a paso para principiantes |
| `API_REFERENCE.md` | Referencia de la API REST |
| `ETICA_Y_LEGALIDAD.md` | Consideraciones eticas y legales |
| `ESTRUCTURA_PROYECTO.md` | Este documento |

## Flujo de Datos

```
Usuario (Frontend)
       │
       ▼
┌──────────────────┐
│  POST /api/scan  │
│  { target: URL } │
└────────┬─────────┘
         │
         ▼
┌──────────────────┐
│   Orchestrator   │
│   (orchestrator  │
│      .js)        │
└────────┬─────────┘
         │
         ├─────────────────────────────────────────────┐
         │                                             │
         ▼                                             ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│   Wappalyzer    │  │      Nmap       │  │    Gobuster     │
│   (tecnologias) │  │ (puertos/vers.) │  │  (directorios)  │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
         ┌────────────────────┼────────────────────┐
         │                    │                    │
         ▼                    ▼                    ▼
┌─────────────────┐  ┌─────────────────┐  ┌─────────────────┐
│      Nikto      │  │    OWASP ZAP    │  │   Searchsploit  │
│ (vulns. web)    │  │ (escaneo activo)│  │    (exploits)   │
└────────┬────────┘  └────────┬────────┘  └────────┬────────┘
         │                    │                    │
         └────────────────────┼────────────────────┘
                              │
                              ▼
                    ┌─────────────────┐
                    │  Scoring Engine │
                    │ (clasificacion) │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │ Report Generator│
                    │ (HTML/MD/PDF)   │
                    └────────┬────────┘
                             │
                             ▼
                    ┌─────────────────┐
                    │   /reports/     │
                    │  [timestamp]/   │
                    └─────────────────┘
```

## Variables de Entorno

Crear archivo `.env` en la raiz:

```env
# Configuracion del servidor
PORT=3000
NODE_ENV=development

# Timeouts de herramientas (segundos)
NMAP_TIMEOUT=300
NIKTO_TIMEOUT=600
GOBUSTER_TIMEOUT=300
ZAP_TIMEOUT=900
WAPPALYZER_TIMEOUT=60

# Configuracion de ZAP
ZAP_API_KEY=your-zap-api-key
ZAP_PORT=8080

# Whitelist de objetivos permitidos
ALLOWED_TARGETS=localhost,127.0.0.1,192.168.1.0/24

# Directorio de reportes
REPORTS_DIR=./reports

# Directorio de wordlists
WORDLISTS_DIR=./wordlists
```

## Puertos Utilizados

| Puerto | Servicio |
|--------|----------|
| 3000 | Backend API |
| 3001 | Juice Shop |
| 3002 | DVWA |
| 3003 | WebGoat |
| 3004 | bWAPP |
| 3005 | Hackazon |
| 8080 | OWASP ZAP (daemon) |

## Archivos Ignorados (`.gitignore`)

```gitignore
# Dependencias
node_modules/
.pnpm-store/

# Reportes generados
reports/

# Variables de entorno
.env
.env.local

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
```

## Comandos Rapidos

```bash
# Levantar laboratorio
./setup_lab.sh

# Instalar herramientas
./tools/install_tools.sh

# Iniciar backend
cd backend && npm run dev

# Iniciar frontend
npm run dev

# Ejecutar escaneo manual
./tools/run_all_scans.sh http://localhost:3001

# Destruir laboratorio
docker-compose down --volumes --remove-orphans
```

## Notas de Desarrollo

### Agregar Nueva Herramienta

1. Crear modulo en `/backend/modules/nueva_herramienta.js`
2. Implementar interface estandar:
   ```javascript
   module.exports = {
     scan: async (target, options) => { ... },
     parse: (output) => { ... },
     name: 'nueva_herramienta'
   };
   ```
3. Registrar en `orchestrator.js`
4. Agregar scoring en `scoring_engine.js`

### Agregar Nueva App Vulnerable

1. Agregar servicio en `docker-compose.yml`
2. Actualizar `setup_lab.sh` con healthcheck
3. Agregar card en `/app/lab/page.tsx`

---

**Version**: 1.0.0  
**Ultima actualizacion**: Marzo 2026  
**Autor**: Proyecto SENA - Analisis de Seguridad
