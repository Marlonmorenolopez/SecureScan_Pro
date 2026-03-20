DOCUMENTACIÓN TÉCNICA - SecureScan Pro v3.0
Plataforma de Análisis de Seguridad Automatizada con Arquitectura Resiliente
Versión: 3.0.0 (Resiliente)
Fecha: Marzo 2026
Institución: SENA - Servicio Nacional de Aprendizaje
TABLA DE CONTENIDOS
Visión General del Sistema
Arquitectura Resiliente
Módulos de Infraestructura
Herramientas de Seguridad Integradas
Flujo de Orquestación
Laboratorio Vulnerable
API REST
Instalación y Despliegue
Consideraciones de Seguridad

1. VISIÓN GENERAL DEL SISTEMA
   1.1 Propósito
   SecureScan Pro v3.0 es una plataforma de análisis de seguridad automatizada diseñada con arquitectura resiliente que permite realizar evaluaciones de vulnerabilidades de forma sistemática, tolerante a fallos y escalable. El sistema integra múltiples herramientas de ciberseguridad profesionales bajo un orquestador centralizado que garantiza la continuidad del escaneo incluso cuando componentes individuales fallan.
   1.2 Diferenciales Clave v3.0
   Table
   Característica Descripción Beneficio
   Circuit Breaker Aislamiento de fallos entre herramientas No hay cascada de errores
   File Stabilizer Espera de archivos estables Elimina race conditions
   Target Validator Health-check TCP + whitelist Solo escanea objetivos autorizados
   Perfiles de Escaneo Quick, Standard, Comprehensive, Passive Adaptable a necesidades de tiempo
   Detección SPA Automática (React, Angular, Vue) Escaneo moderno de aplicaciones
   Integración Nmap→ExploitDB Búsqueda automática de exploits Enriquecimiento de datos
   1.3 Stack Tecnológico
   plain
   Copy
   ┌─────────────────────────────────────────────────────────────┐
   │ CAPA DE PRESENTACIÓN │
   │ Next.js 16 + React 19 + Tailwind CSS 4 │
   ├─────────────────────────────────────────────────────────────┤
   │ CAPA DE APLICACIÓN │
   │ Node.js 20 LTS + Express.js │
   │ SecureScanOrchestrator v3.0 (EventEmitter) │
   ├─────────────────────────────────────────────────────────────┤
   │ CAPA DE RESILIENCIA │
   │ CircuitBreaker │ FileStabilizer │ TargetValidator │
   ├─────────────────────────────────────────────────────────────┤
   │ CAPA DE HERRAMIENTAS │
   │ WhatWeb │ Nmap │ Gobuster │ ZAP │ ExploitDB │ Metasploit │
   ├─────────────────────────────────────────────────────────────┤
   │ CAPA DE INFRAESTRUCTURA │
   │ Docker Compose + Kali Linux │
   └─────────────────────────────────────────────────────────────┘
2. ARQUITECTURA RESILIENTE
   2.1 Diagrama de Componentes
   plain
   Copy
   ┌─────────────────────────────────────────────────────────────┐
   │ CLIENTE │
   │ (Navegador Web) │
   └────────────────────┬──────────────────────────────────────────┘
   │
   ▼ HTTPS
   ┌─────────────────────────────────────────────────────────────┐
   │ FRONTEND (Next.js) │
   │ ┌─────────────┐ ┌─────────────┐ ┌─────────────────────┐ │
   │ │ Landing │ │ Scanner │ │ Lab Dashboard │ │
   │ │ Page │ │ Page │ │ (Estado en vivo) │ │
   │ └─────────────┘ └─────────────┘ └─────────────────────┘ │
   └────────────────────┬──────────────────────────────────────────┘
   │ API REST (/api/scan, /api/lab/apps)
   ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ BACKEND (Node.js + Express) │
   │ │
   │ ┌─────────────────────────────────────────────────────────┐ │
   │ │ ORQUESTADOR CENTRAL v3.0 │ │
   │ │ EventEmitter │ Configuración │ Gestión de Estado │ │
   │ └─────────────────────────────────────────────────────────┘ │
   │ │
   │ ┌─────────────────────────────────────────────────────────┐ │
   │ │ MÓDULOS DE RESILIENCIA (Core) │ │
   │ │ │ │
   │ │ ┌──────────────┐ ┌──────────────┐ ┌──────────────┐│ │
   │ │ │ Circuit │ │ File │ │ Target ││ │
   │ │ │ Breaker │ │ Stabilizer │ │ Validator ││ │
   │ │ │ │ │ │ │ ││ │
   │ │ │ • CLOSED │ │ • Espera │ │ • Health TCP ││ │
   │ │ │ • OPEN │ │ estabilidad│ │ • Whitelist ││ │
   │ │ │ • HALF_OPEN │ │ • 3 rondas │ │ • Scope ││ │
   │ │ └──────────────┘ └──────────────┘ └──────────────┘│ │
   │ │ │ │
   │ │ ┌──────────────────────────────────────────────────┐ │ │
   │ │ │ ProcessManager │ │ │
   │ │ │ • Registro de PIDs │ • Cleanup SIGTERM/SIGINT │ │ │
   │ │ └──────────────────────────────────────────────────┘ │ │
   │ └─────────────────────────────────────────────────────────┘ │
   │ │
   │ ┌─────────────────────────────────────────────────────────┐ │
   │ │ MÓDULOS DE ESCANEO (Tools) │ │
   │ │ │ │
   │ │ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │ │
   │ │ │WhatWeb │ │ Nmap │ │Gobuster │ │ ZAP │ │ │
   │ │ │(Tecnol.)│ │(Puertos)│ │ (Dirs) │ │ (DAST) │ │ │
   │ │ └─────────┘ └─────────┘ └─────────┘ └─────────┘ │ │
   │ │ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │ │
   │ │ │ExploitDB│ │Metasploit│ │ Scoring │ │ Report │ │ │
   │ │ │(Exploits)│ │ (Opcional)│ │ Engine │ │Generator│ │ │
   │ │ └─────────┘ └─────────┘ └─────────┘ └─────────┘ │ │
   │ └─────────────────────────────────────────────────────────┘ │
   └────────────────────┬──────────────────────────────────────────┘
   │ Spawn / API / CLI
   ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ HERRAMIENTAS DEL SISTEMA │
   │ ┌─────────┐ ┌─────────┐ ┌─────────┐ ┌─────────┐ │
   │ │WhatWeb │ │ Nmap │ │Gobuster │ │OWASP ZAP│ │
   │ └─────────┘ └─────────┘ └─────────┘ └─────────┘ │
   │ ┌─────────┐ ┌─────────┐ │
   │ │ExploitDB│ │Metasploit│ (RPC) │
   │ └─────────┘ └─────────┘ │
   └────────────────────┬──────────────────────────────────────────┘
   │ Docker Network (172.20.0.0/24)
   ▼
   ┌─────────────────────────────────────────────────────────────┐
   │ LABORATORIO VULNERABLE │
   │ ┌─────────────┐ ┌─────────────┐ ┌─────────────┐ │
   │ │ Juice Shop │ │ DVWA │ │ WebGoat │ │
   │ │ :3001 │ │ :3002 │ │ :3003 │ │
   │ │ Node.js │ │ PHP │ │ Java │ │
   │ └─────────────┘ └─────────────┘ └─────────────┘ │
   │ ┌─────────────┐ │
   │ │ WebWolf │ ← Companion de WebGoat (phishing/email) │
   │ │ :9090 │ │
   │ └─────────────┘ │
   └─────────────────────────────────────────────────────────────┘
   2.2 Estados del Circuit Breaker
   plain
   Copy
   ┌─────────────────────────────────────────────────────────────┐
   │ CIRCUIT BREAKER LIFECYCLE │
   │ │
   │ ┌─────────┐ Fallo x3 ┌─────────┐ │
   │ │ CLOSED │ ─────────────────────────► │ OPEN │ │
   │ │ (Normal)│ │(Bloqueo)│ │
   │ └────┬────┘ └────┬────┘ │
   │ ▲ │ │
   │ │ Éxito x1 │ │
   │ │ ◄──────────────────────────────┘ │
   │ │ Timeout 60s │
   │ │ │
   │ ┌────┴────┐ │
   │ │HALF_OPEN│ ◄── Permite 1 llamada de prueba │
   │ │(Prueba) │ │
   │ └─────────┘ │
   │ │
   │ Transición OPEN → HALF_OPEN: Después de resetTimeout │
   │ Transición HALF_OPEN → CLOSED: Después de halfOpenMaxCalls │
   │ Transición a OPEN: Después de failureThreshold fallos │
   └─────────────────────────────────────────────────────────────┘
3. MÓDULOS DE INFRAESTRUCTURA
   3.1 Circuit Breaker
   Propósito: Prevenir que fallos en una herramienta afecten todo el escaneo.
   Implementación:
   JavaScript
   Copy
   class CircuitBreaker extends EventEmitter {
   constructor(name, options = {}) {
   this.failureThreshold = options.failureThreshold || 3;
   this.resetTimeout = options.resetTimeout || 60000;
   this.halfOpenMaxCalls = options.halfOpenMaxCalls || 1;
   this.state = 'CLOSED'; // CLOSED | OPEN | HALF_OPEN
   }
   }
   Configuración por Herramienta:
   Table
   Herramienta failureThreshold resetTimeout Justificación
   WhatWeb 3 60s Ligero, puede reintentar
   Nmap 2 120s Pesado, más conservador
   Gobuster 3 60s Estable generalmente
   ZAP 2 300s Daemon crítico, más timeout
   Metasploit 1 300s Opcional, muy pesado
   3.2 File Stabilizer
   Propósito: Eliminar race conditions esperando que archivos de salida estén completamente escritos.
   Algoritmo:
   JavaScript
   Copy
   async waitForStable(filePath, timeout = 30000) {
   // 1. Verificar que archivo existe
   // 2. Esperar 3 rondas consecutivas donde:
   // - Tamaño no cambie
   // - mtime no cambie
   // 3. Máximo 60 intentos (30s) o timeout personalizado
   }
   Uso en el Orquestador:
   Después de WhatWeb: Espera whatweb_output.json
   Después de Nmap: Espera nmap_output.xml y nmap_output.txt
   Después de Gobuster: Espera resultados de directorios
   Después de ZAP: Espera reporte JSON
   3.3 Target Validator
   Propósito: Garantizar que solo se escaneen objetivos autorizados.
   Validaciones:
   Scope Check: Target debe estar en allowedTargets
   Health Check: Conexión TCP exitosa antes de escanear
   Whitelist Configurada:
   JavaScript
   Copy
   allowedTargets: [
   'localhost:3001', // Juice Shop
   'localhost:3002', // DVWA
   'localhost:3003', // WebGoat
   '127.0.0.1:3001',
   '127.0.0.1:3002',
   '127.0.0.1:3003',
   '172.20.0.0/24' // Red Docker interna
   ]
   3.4 Process Manager
   Propósito: Gestión segura de procesos hijos con cleanup automático.
   Características:
   Registro de PIDs activos
   Señal SIGTERM graceful (5s timeout)
   SIGKILL forzado si persiste
   Cleanup automático en señales del sistema (SIGTERM, SIGINT)
4. HERRAMIENTAS DE SEGURIDAD INTEGRADAS
   4.1 WhatWeb (Reemplaza Wappalyzer)
   Cambio v3.0: Wappalyzer fue reemplazado por WhatWeb nativo de Kali Linux.
   Ventajas:
   Más ligero (no requiere Node.js/npm adicional)
   Mayor base de firmas en Kali
   Mejor integración con el ecosistema
   Comando Ejecutado:
   bash
   Copy
   whatweb <target> -- aggression=3 --log-json=/tmp/whatweb_output.json
   Output:
   JSON
   Copy
   {
   "target": "http://localhost:3001",
   "technologies": [
   {"name": "Express", "version": "4.18.2", "category": "Web Framework"},
   {"name": "Node.js", "version": "18.x", "category": "Platform"}
   ]
   }
   4.2 Nmap
   Propósito: Descubrimiento de puertos, servicios, versiones y vulnerabilidades.
   Perfiles de Timing:
   Table
   Perfil Timing Puertos Scripts Duración Est.
   Quick T4 top 1000 safe ~2 min
   Standard T4 all vuln,vulners,safe ~10 min
   Deep T2 all vuln,vulners,exploit ~30 min
   Integración ExploitDB: El XML de Nmap se pasa automáticamente a ExploitDB para búsqueda de exploits por versión de servicio.
   4.3 Gobuster
   Propósito: Fuerza bruta de directorios, archivos, subdominios y hosts virtuales.
   Modos Soportados:
   dir: Directorios y archivos
   dns: Subdominios
   vhost: Hosts virtuales (comprehensive scan)
   Configuración:
   JavaScript
   Copy
   {
   threads: 50,
   extensions: 'php,html,txt,bak,zip,sql,env,config,xml,json',
   wordlistDir: '/usr/share/wordlists'
   }
   4.4 OWASP ZAP
   Propósito: Escaneo DAST completo (Spider + Active Scan).
   Detección Automática SPA:
   JavaScript
   Copy
   const isSPA = this.technologies?.some(t =>
   ['React', 'Angular', 'Vue.js', 'SPA'].includes(t.name)
   );

const spiderType = isSPA ? 'spiderClient' : 'traditional';
Configuración:
JavaScript
Copy
{
spider: {
type: 'spiderClient', // Para SPAs modernas
maxDuration: 15, // minutos
browser: 'firefox-headless'
},
activeScan: {
enabled: true,
policy: 'Default',
maxScanDuration: 30 // minutos
}
}
4.5 ExploitDB (Módulo Unificado)
Cambio v3.0: exploitdb_lookup.js fue reemplazado por exploitdb_unified.js con integración directa a Nmap.
Dos Modos de Operación:
Modo Nmap XML (Preferido):
JavaScript
Copy
// Extrae automáticamente servicios y versiones del XML de Nmap
await ExploitDB.searchFromNmap(nmapXmlFile, outputDir);
Modo Fallback (Tecnologías):
JavaScript
Copy
// Si no hay Nmap, busca por tecnologías de WhatWeb
for (const tech of technologies) {
await ExploitDB.search(`${tech.name} ${tech.version}`);
}
Enriquecimiento NVD:
JavaScript
Copy
{
enrichWithNVD: true, // Agrega datos del National Vulnerability Database
maxResults: 10,
excludeTerms: 'dos' // Excluye exploits de denegación de servicio
}
4.6 Metasploit (Opcional)
Estado: Deshabilitado por defecto (enabled: false)
Modo Dry-Run:
Cuando está habilitado, por defecto opera en modo dryRun: true, lo que significa que solo verifica la viabilidad de exploits sin ejecutarlos realmente.
Configuración:
JavaScript
Copy
{
enabled: false,
dryRun: true, // Solo verificación
minRanking: 'good', // Mínimo ranking de exploit (excellent, great, good, normal)
maxSessions: 3, // Máximo de sesiones paralelas
postExploitation: {
enabled: false,
autoRun: false
}
}
4.7 Scoring Engine
Motor de Cálculo de Riesgo:
Fórmula:
plain
Copy
Score = 100 - (Penalización_Total / Factor_Normalización)

Donde:
Penalización_Total = Σ(Cantidad_severidad × Peso_severidad)
Factor_Normalización = max(1, Total_Hallazgos / 10)
Pesos CVSS 3.1:
Table
Severidad Peso Color
Critical 25 🔴 #ef4444
High 15 🟠 #f97316
Medium 8 🟡 #eab308
Low 3 🟢 #22c55e
Info 1 ⚪ #6b7280
Integración EPSS:
JavaScript
Copy
{
useEPSS: true, // Exploit Prediction Scoring System
// Probabilidad de explotación en la naturaleza
}
4.8 Report Generator
Formatos Soportados:
Table
Formato Extensión Uso
HTML .html Reporte interactivo para clientes
PDF .pdf Documento formal para archivos
SARIF .sarif Integración CI/CD (GitHub/GitLab)
JSON .json Procesamiento programático
Secciones Configurables:
JavaScript
Copy
sections: {
executiveSummary: true, // Resumen para directivos
methodology: true, // Metodología utilizada
findings: true, // Hallazgos detallados
riskAssessment: true, // Evaluación de riesgo
remediationPlan: true // Plan de remediación
} 5. FLUJO DE ORQUESTACIÓN
5.1 Diagrama de Secuencia
plain
Copy
Usuario Frontend Backend Orquestador Herramientas
│ │ │ │ │
│─Ingresa URL───►│ │ │ │
│ │─POST /api/scan►│ │ │
│ │ │─run()────────────►│ │
│ │ │ │─validateTarget() │
│ │ │ │◄─OK───────────────│
│ │ │ │ │
│ │◄─jobId─────────│ │─whatweb()───────►│
│◄─ID mostrado───│ │ │◄─JSON────────────│
│ │ │ │─waitStable() │
│ │ │ │ │
│ │─GET /status────►│ │─nmap()──────────►│
│◄─Progress 15%──│◄───────────────│ │◄─XML─────────────│
│ │ │ │─waitStable() │
│ │ │ │─exploitdb()─────►│
│◄─Progress 35%──│◄───────────────│ │◄─exploits────────│
│ │ │ │ │
│ │─GET /status────►│ │─gobuster()──────►│
│◄─Progress 55%──│◄───────────────│ │◄─dirs───────────│
│ │ │ │ │
│ │ │ │─zap()───────────►│
│◄─Progress 80%──│◄───────────────│ │◄─alerts─────────│
│ │ │ │─waitStable() │
│ │ │ │ │
│ │ │ │─scoring() │
│◄─Progress 95%──│◄───────────────│ │◄─score──────────│
│ │ │ │─reporting() │
│ │ │ │◄─HTML/PDF────────►│
│ │ │ │ │
│ │─GET /report────►│ │ │
│◄─Download──────│◄───────────────│◄─────────────────│◄─────────────────│
5.2 Perfiles de Escaneo Predefinidos
JavaScript
Copy
// Uso: SecureScanOrchestrator.scanWithProfile(target, 'quick')

┌─────────────┬─────────────────────────────────────────────────────────────┐
│ QUICK │ 5-10 minutos │
├─────────────┼─────────────────────────────────────────────────────────────┤
│ Secuencia │ whatweb → nmap (top 1000) → zap (spider only) → scoring │
│ Nmap │ topPorts: 1000, scripts: 'safe' │
│ ZAP │ activeScan: false │
│ Use case │ Validación rápida, CI/CD pipeline │
└─────────────┴─────────────────────────────────────────────────────────────┘

┌─────────────┬─────────────────────────────────────────────────────────────┐
│ STANDARD │ 20-30 minutos (DEFAULT) │
├─────────────┼─────────────────────────────────────────────────────────────┤
│ Secuencia │ whatweb → nmap (all ports) → gobuster → zap → exploitdb │
│ Nmap │ topPorts: 'all', scripts: 'vuln,vulners,safe' │
│ ZAP │ activeScan: true, maxDuration: 30min │
│ Use case │ Auditoría de seguridad regular │
└─────────────┴─────────────────────────────────────────────────────────────┘

┌─────────────┬─────────────────────────────────────────────────────────────┐
│COMPREHENSIVE│ 45-90 minutos │
├─────────────┼─────────────────────────────────────────────────────────────┤
│ Secuencia │ + metasploit (dry-run) + dns/vhost enumeration │
│ Nmap │ topPorts: 'all', scripts: 'vuln,vulners,exploit' │
│ Gobuster │ modes: ['dir', 'dns', 'vhost'] │
│ Metasploit │ dryRun: true (verificación de exploits) │
│ Use case │ Auditoría profunda, evaluación de riesgo completa │
└─────────────┴─────────────────────────────────────────────────────────────┘

┌─────────────┬─────────────────────────────────────────────────────────────┐
│ PASSIVE │ 10-15 minutos │
├─────────────┼─────────────────────────────────────────────────────────────┤
│ Secuencia │ whatweb → nmap (safe scripts) → gobuster → exploitdb │
│ Nmap │ scripts: 'safe' only │
│ ZAP │ activeScan: false (solo spider pasivo) │
│ Use case │ Entornos sensibles, mínimo impacto │
└─────────────┴─────────────────────────────────────────────────────────────┘ 6. LABORATORIO VULNERABLE
6.1 Arquitectura Docker Compose
Red Interna: 172.20.0.0/24
yaml
Copy
networks:
securescan-lab:
driver: bridge
ipam:
config: - subnet: 172.20.0.0/24
6.2 Servicios Incluidos
Table
Servicio Puerto Stack Propósito Dificultad
Juice Shop 3001 Node.js, Express, Angular, SQLite OWASP Top 10 2021 moderno, API REST/GraphQL, Gamificación ⭐⭐⭐ Principiante-Avanzado
DVWA 3002 PHP, Apache, MariaDB Clásico educativo, niveles ajustables (Low/Medium/High/Impossible) ⭐ Principiante
WebGoat 3003 Java, Spring Boot Tutoriales interactivos con explicaciones paso a paso ⭐⭐ Principiante-Intermedio
WebWolf 9090 Java, Spring Boot Companion de WebGoat para interceptar emails y requests ⭐⭐ Intermedio
6.3 Configuraciones de Seguridad Reducida
Juice Shop:
yaml
Copy
environment:

- NODE_ENV=unsafe # Deshabilita protecciones
- CHALLENGE_SOLVED_WEBHOOK=false
- CTF_KEY=securescan-ctf-key
  DVWA:
  yaml
  Copy
  environment:
- SECURITY_LEVEL=low # Nivel más básico
- PHPIDS_ENABLED=false # Deshabilita IDS
- RECAPTCHA_PUBLIC_KEY= # Sin CAPTCHA
  WebGoat:
  yaml
  Copy
  environment:
- WEBGOAT_SECURITY_XFRAMEOPTIONS=false # Permite iframes
  6.4 Health Checks
  Todos los servicios incluyen healthchecks configurados:
  yaml
  Copy
  healthcheck:
  test: ["CMD", "wget", "--quiet", "--tries=1", "--spider", "http://localhost:3000"]
  interval: 30s
  timeout: 10s
  retries: 3
  start_period: 40s # Tiempo de arranque inicial
  6.5 Volúmenes Persistentes
  yaml
  Copy
  volumes:
  juice-shop-data: # Persiste progreso de desafíos
  dvwa-db-data: # Persiste base de datos
  webgoat-data: # Persiste progreso de lecciones

7. API REST
   7.1 Especificación de Endpoints
   Table
   Endpoint Método Descripción Request Response
   /api/scan POST Iniciar escaneo {target, options} {jobId, status}
   /api/scan/:id/status GET Estado del escaneo - {progress, currentStep, phases}
   /api/scan/:id/results GET Resultados completos - {phases, summary, findings}
   /api/scan/:id/report GET Descargar reporte ?format=html|pdf|sarif|json File
   /api/lab/apps GET Estado del laboratorio - [{name, port, status, health}]
   7.2 Ejemplos de Uso
   Iniciar Escaneo:
   bash
   Copy
   curl -X POST http://localhost:4000/api/scan \
    -H "Content-Type: application/json" \
    -d '{
   "target": "http://localhost:3001",
   "options": {
   "profile": "standard",
   "failFast": false
   }
   }'
   Respuesta:
   JSON
   Copy
   {
   "success": true,
   "jobId": "scan_1712345678901_abc123xyz",
   "status": "created",
   "message": "Scan started successfully",
   "estimatedDuration": "20-30 minutes"
   }
   Consultar Estado:
   bash
   Copy
   curl http://localhost:4000/api/scan/scan_1712345678901_abc123xyz/status
   Respuesta:
   JSON
   Copy
   {
   "id": "scan_1712345678901_abc123xyz",
   "status": "running",
   "progress": 65,
   "currentStep": "Escaneando aplicación (ZAP)",
   "phases": [
   {"name": "whatweb", "status": "completed", "duration": "45s"},
   {"name": "nmap", "status": "completed", "duration": "180s"},
   {"name": "gobuster", "status": "completed", "duration": "120s"},
   {"name": "zap", "status": "running", "startedAt": "2026-03-19T22:45:00Z"},
   {"name": "exploitdb", "status": "pending"},
   {"name": "scoring", "status": "pending"},
   {"name": "reporting", "status": "pending"}
   ],
   "circuitBreakers": {
   "nmap": {"state": "CLOSED", "failures": 0},
   "zap": {"state": "CLOSED", "failures": 0}
   }
   }
8. INSTALACIÓN Y DESPLIEGUE
   8.1 Requisitos del Sistema
   Hardware Mínimo:
   CPU: 4 núcleos (Intel i5/AMD Ryzen 5 o superior)
   RAM: 8 GB mínimo (16 GB recomendado para escaneos comprehensive)
   Almacenamiento: 50 GB libres (SSD recomendado)
   Red: Conexión a Internet para actualizaciones de bases de datos
   Software Base:
   Kali Linux 2024.x o Ubuntu 22.04 LTS
   Docker 24.x + Docker Compose 2.x
   Node.js 20 LTS
   npm 10.x
   8.2 Instalación de Dependencias
   bash
   Copy

# 1. Actualizar sistema

sudo apt update && sudo apt full-upgrade -y

# 2. Instalar Docker

sudo apt install -y docker.io docker-compose-plugin
sudo usermod -aG docker $USER
newgrp docker

# 3. Instalar Node.js 20

curl -fsSL https://deb.nodesource.com/setup_20.x | sudo -E bash -
sudo apt install -y nodejs

# 4. Instalar herramientas de seguridad

sudo apt install -y \
 whatweb \
 nmap \
 gobuster \
 zaproxy \
 exploitdb \
 metasploit-framework

# 5. Actualizar bases de datos

sudo searchsploit -u
8.3 Estructura de Archivos del Proyecto
plain
Copy
securescan-pro/
├── docker-compose.yml # Laboratorio vulnerable
├── README.md
├── .env.example
│
├── backend/
│ ├── server.js # Entry point Express
│ ├── package.json
│ │
│ ├── modules/
│ │ ├── orchestrator.js # ORQUESTADOR PRINCIPAL v3.0
│ │ ├── whatweb_detector.js # Detección de tecnologías
│ │ ├── nmap_scanner.js # Escaneo de puertos/servicios
│ │ ├── gobuster_scanner.js # Fuerza bruta de directorios
│ │ ├── zap_scanner.js # Escaneo DAST
│ │ ├── exploitdb_unified.js # Búsqueda de exploits (unificado)
│ │ ├── metasploit_integration.js # Explotación opcional
│ │ ├── scoring_engine.js # Cálculo de riesgo CVSS+EPSS
│ │ └── report_generator.js # Generación de reportes
│ │
│ └── utils/
│ └── logger.js # Sistema de logging
│
├── app/ # Frontend Next.js 16
│ ├── layout.tsx
│ ├── page.tsx
│ ├── scanner/
│ │ └── page.tsx
│ ├── lab/
│ │ └── page.tsx
│ └── history/
│ └── page.tsx
│
├── components/ # Componentes React
│ ├── scan-form.tsx
│ ├── scan-progress.tsx
│ └── results-dashboard.tsx
│
├── reports/ # Output de reportes generados
└── temp/ # Archivos temporales de escaneo
8.4 Inicio del Sistema
bash
Copy

# 1. Clonar repositorio

git clone https://github.com/sena/securescan-pro.git
cd securescan-pro

# 2. Configurar variables de entorno

cp .env.example .env

# Editar .env con configuraciones locales

# 3. Iniciar laboratorio vulnerable

docker-compose up -d

# 4. Verificar estado del laboratorio (30-60 segundos)

docker-compose ps

# Debe mostrar: juice-shop, dvwa, webgoat, webwolf como "healthy"

# 5. Instalar dependencias del backend

cd backend
npm install

# 6. Iniciar backend (Terminal 1)

npm run dev

# API disponible en http://localhost:4000

# 7. Iniciar frontend (Terminal 2)

cd ..
npm install
npm run dev

# Aplicación disponible en http://localhost:3000

8.5 Verificación Post-Instalación
bash
Copy

# Verificar herramientas del sistema

whatweb --version
nmap --version
gobuster version
searchsploit --version

# Verificar laboratorio

curl http://localhost:3001 # Juice Shop
curl http://localhost:3002/login.php # DVWA
curl http://localhost:3003/WebGoat # WebGoat
curl http://localhost:9090 # WebWolf

# Verificar API del backend

curl http://localhost:4000/api/lab/apps 9. CONSIDERACIONES DE SEGURIDAD
9.1 Alcance Permitido
El sistema está hardcodeado para solo operar en:
localhost:_
127.0.0.1:_
172.20.0.0/24 (red Docker del laboratorio)
Cualquier intento de escanear fuera de estos rangos será rechazado por el TargetValidator antes de iniciar cualquier herramienta.
9.2 Modo Dry-Run de Metasploit
Aunque Metasploit está incluido, por defecto opera en modo dryRun: true, lo que significa:
✅ Verifica la existencia de exploits
✅ Comprueba compatibilidad con el target
❌ NO ejecuta exploits reales
❌ NO establece sesiones Meterpreter
Para habilitar explotación real (solo en entornos aislados):
JavaScript
Copy
// backend/config/scan-profiles.js
metasploit: {
enabled: true,
dryRun: false, // ⚠️ PELIGROSO: Solo en laboratorios aislados
requireConfirmation: true // Requiere confirmación manual
}
9.3 Límites de Recursos
El orquestador incluye límites para prevenir consumo excesivo:
JavaScript
Copy
// Timeouts máximos por herramienta
whatweb: 60s
nmap: 600s (10 min)
gobuster: 300s (5 min)
zap: 1800s (30 min)
metasploit: 600s (10 min)

// Máximo duración total de escaneo
safety.maxScanDuration: 3600s (1 hora)
9.4 Buenas Prácticas
Nunca modificar allowedTargets para incluir IPs públicas sin autorización legal escrita
Usar siempre dryRun: true en Metasploit a menos que sea un laboratorio completamente aislado
Revisar reportes antes de compartirlos - pueden contener datos sensibles del target
Mantener herramientas actualizadas - sudo apt update && sudo searchsploit -u semanalmente
Integración Wappalyzer, Nikto, Nmap, Gobuster, ZAP, Searchsploit
Documentación Técnica SecureScan Pro v3.0
© 2026 SENA - Servicio Nacional de Aprendizaje
Tecnico en seguridad de aplicaciones web