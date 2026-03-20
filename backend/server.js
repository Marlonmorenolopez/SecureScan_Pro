/**
 * ============================================================================
 * SECURITYSCAN PRO - SERVIDOR PRINCIPAL (CORREGIDO - v1.1)
 * ============================================================================
 * API REST para automatización de herramientas de seguridad
 * Proyecto SENA - Plataforma de Análisis de Seguridad
 * 
 * CAMBIOS DE SEGURIDAD:
 * - Validación estricta de alcance (scope) con whitelist
 * - Sanitización de input para prevenir inyección
 * - Rate limiting por IP de origen
 * - Separación de validación de formato vs validación de alcance
 * ============================================================================
 */

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const { v4: uuidv4 } = require('uuid');
const path = require('path');
const fs = require('fs');
const net = require('net');
const { URL } = require('url');

// Importar módulos de escaneo
const NmapScanner = require('./modules/nmap_scanner');
const NiktoScanner = require('./modules/nikto_scanner');
const GobusterScanner = require('./modules/gobuster_scanner');
const ZapScanner = require('./modules/zap_scanner');
const WappalyzerDetector = require('./modules/wappalyzer_detector');
const ExploitDBLookup = require('./modules/exploitdb_lookup');
const Orchestrator = require('./modules/orchestrator');
const ReportGenerator = require('./modules/report_generator');
const ScoringEngine = require('./modules/scoring_engine');
const Logger = require('./utils/logger');

const app = express();
const PORT = process.env.PORT || 5000;

// ============================================================================
// CONFIGURACIÓN DE SEGURIDAD - SCOPE Y ALCANCE
// ============================================================================

/**
 * Lista blanca de targets permitidos (laboratorios Docker locales)
 * Formato: hostname:puerto o IP:puerto
 */
const ALLOWED_TARGETS = Object.freeze([
  // Juice Shop
  'localhost:3001',
  '127.0.0.1:3001',
  '172.20.0.2:3000',  // IP interna Docker (si aplica)
  
  // DVWA
  'localhost:3002',
  '127.0.0.1:3002',
  '172.20.0.3:80',
  
  // WebGoat
  'localhost:3003',
  '127.0.0.1:3003',
  '172.20.0.4:8080',
  
  // WebWolf (companion)
  'localhost:9090',
  '127.0.0.1:9090',
]);

/**
 * Rangos IP privados permitidos (CIDR notation)
 * Solo para entornos de laboratorio controlados
 */
const ALLOWED_IP_RANGES = Object.freeze([
  '127.0.0.1/32',      // Loopback
  '::1/128',           // IPv6 loopback
  '172.20.0.0/24',     // Docker network del laboratorio
]);

/**
 * Caracteres permitidos en hostname/IP (whitelist estricta)
 * Bloquea: ; | & $ ` \n \r < > ( ) { } [ ] # ! * ? ~ = + % @
 */
const SAFE_TARGET_PATTERN = /^[a-zA-Z0-9.\-:]+$/;

/**
 * Patrón para validar formato de IP
 */
const IPV4_PATTERN = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;

/**
 * Patrón para validar hostname (sin caracteres especiales)
 */
const HOSTNAME_PATTERN = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;

// ============================================================================
// MIDDLEWARE DE SEGURIDAD
// ============================================================================

// Helmet para headers de seguridad
app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      styleSrc: ["'self'", "'unsafe-inline'"],
      scriptSrc: ["'self'"],
      imgSrc: ["'self'", "data:", "blob:"],
    },
  },
  hsts: {
    maxAge: 31536000,
    includeSubDomains: true,
    preload: true
  }
}));

// CORS - Solo permitir orígenes autorizados
const corsOptions = {
  origin: process.env.ALLOWED_ORIGINS?.split(',') || ['http://localhost:3000', 'http://localhost:5173'],
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization'],
  credentials: true
};
app.use(cors(corsOptions));

// Rate limiting - Por IP de origen (no global)
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutos
  max: 100, // Máximo 100 requests por ventana por IP
  keyGenerator: (req) => {
    // Usar IP real del cliente (considerando proxies)
    return req.ip || req.connection.remoteAddress || 'unknown';
  },
  handler: (req, res) => {
    Logger.warn(`Rate limit exceeded for IP: ${req.ip}`);
    res.status(429).json({
      error: 'Demasiadas solicitudes desde esta IP, intente de nuevo más tarde',
      code: 'RATE_LIMIT_EXCEEDED',
      retryAfter: Math.ceil(limiter.windowMs / 1000)
    });
  },
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

// Parser JSON con límites estrictos
app.use(express.json({ 
  limit: '10mb',
  strict: true, // Solo aceptar arrays y objetos
  verify: (req, res, buf) => {
    // Verificar que no haya JSON malicioso
    try {
      JSON.parse(buf);
    } catch (e) {
      res.status(400).json({ error: 'JSON inválido' });
      throw new Error('Invalid JSON');
    }
  }
}));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Servir archivos estáticos de reportes (con restricciones)
app.use('/reports', express.static(path.join(__dirname, 'outputs', 'reports'), {
  dotfiles: 'deny',
  index: false,
  maxAge: '1d'
}));

// ============================================================================
// ALMACÉN DE ESCANEOS EN MEMORIA
// ============================================================================

const scans = new Map();

// ============================================================================
// FUNCIONES DE VALIDACIÓN DE SEGURIDAD
// ============================================================================

/**
 * Verifica si una IP está dentro de un rango CIDR
 * @param {string} ip - Dirección IP a verificar
 * @param {string} cidr - Rango en notación CIDR (ej: "192.168.1.0/24")
 * @returns {boolean}
 */
function isIpInCidr(ip, cidr) {
  const [range, bits = 32] = cidr.split('/');
  const mask = parseInt(bits, 10);
  
  const ipLong = ipToLong(ip);
  const rangeLong = ipToLong(range);
  const maskLong = -1 << (32 - mask);
  
  return (ipLong & maskLong) === (rangeLong & maskLong);
}

/**
 * Convierte IP a número entero
 * @param {string} ip 
 * @returns {number}
 */
function ipToLong(ip) {
  return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet, 10), 0) >>> 0;
}

/**
 * Extrae hostname y puerto de un target de forma segura
 * @param {string} target 
 * @returns {{hostname: string, port: string|null, isValid: boolean, error: string|null}}
 */
function parseTarget(target) {
  // Verificar que no sea null/undefined
  if (!target || typeof target !== 'string') {
    return { hostname: null, port: null, isValid: false, error: 'Target es requerido' };
  }

  // Trim y eliminar espacios
  const cleanTarget = target.trim();
  
  if (cleanTarget.length === 0) {
    return { hostname: null, port: null, isValid: false, error: 'Target no puede estar vacío' };
  }

  // Verificar longitud máxima (prevenir DoS)
  if (cleanTarget.length > 253) {
    return { hostname: null, port: null, isValid: false, error: 'Target excede longitud máxima' };
  }

  // Verificar caracteres peligrosos (inyección de comandos)
  const dangerousChars = /[;|&$`\\n\r<>\(\)\{\}\[\]#!\*\?~=%@]/;
  if (dangerousChars.test(cleanTarget)) {
    return { 
      hostname: null, 
      port: null, 
      isValid: false, 
      error: 'Target contiene caracteres no permitidos' 
    };
  }

  // Intentar parsear como URL
  let url;
  try {
    // Agregar protocolo si no existe para poder parsear
    const urlString = cleanTarget.startsWith('http') ? cleanTarget : `http://${cleanTarget}`;
    url = new URL(urlString);
  } catch (e) {
    // No es una URL válida, intentar parsear como host:puerto
    const parts = cleanTarget.split(':');
    if (parts.length === 2) {
      const [hostname, port] = parts;
      return validateHostPort(hostname, port);
    }
    // Solo hostname
    return validateHostPort(cleanTarget, null);
  }

  // Extraer hostname y puerto de URL
  const hostname = url.hostname;
  const port = url.port || (url.protocol === 'https:' ? '443' : '80');
  
  return validateHostPort(hostname, port);
}

/**
 * Valida hostname y puerto por separado
 * @param {string} hostname 
 * @param {string|null} port 
 * @returns {{hostname: string, port: string|null, isValid: boolean, error: string|null}}
 */
function validateHostPort(hostname, port) {
  // Validar hostname
  if (!hostname || hostname.length === 0) {
    return { hostname: null, port: null, isValid: false, error: 'Hostname requerido' };
  }

  // Verificar que hostname solo contenga caracteres seguros
  if (!SAFE_TARGET_PATTERN.test(hostname)) {
    return { 
      hostname: null, 
      port: null, 
      isValid: false, 
      error: 'Hostname contiene caracteres no permitidos' 
    };
  }

  // Validar formato de IP o hostname
  const isIP = IPV4_PATTERN.test(hostname);
  const isHostname = HOSTNAME_PATTERN.test(hostname);

  if (!isIP && !isHostname) {
    return { 
      hostname: null, 
      port: null, 
      isValid: false, 
      error: 'Formato de hostname/IP inválido' 
    };
  }

  // Validar puerto si se proporciona
  if (port !== null) {
    const portNum = parseInt(port, 10);
    if (isNaN(portNum) || portNum < 1 || portNum > 65535) {
      return { 
        hostname: null, 
        port: null, 
        isValid: false, 
        error: 'Puerto debe estar entre 1 y 65535' 
      };
    }
  }

  return { 
    hostname, 
    port, 
    isValid: true, 
    error: null 
  };
}

/**
 * Verifica si un target está en la lista blanca de alcance permitido
 * @param {string} hostname 
 * @param {string|null} port 
 * @returns {{allowed: boolean, reason: string|null}}
 */
function isTargetInScope(hostname, port) {
  // Construir representación canónica
  const targetWithPort = port ? `${hostname}:${port}` : hostname;
  const targetWithoutPort = hostname;

  // Verificar en lista blanca exacta
  if (ALLOWED_TARGETS.includes(targetWithPort) || ALLOWED_TARGETS.includes(targetWithoutPort)) {
    return { allowed: true, reason: null };
  }

  // Verificar si es IP en rango permitido
  if (IPV4_PATTERN.test(hostname)) {
    const inAllowedRange = ALLOWED_IP_RANGES.some(range => {
      try {
        return isIpInCidr(hostname, range);
      } catch {
        return false;
      }
    });

    if (!inAllowedRange) {
      return { 
        allowed: false, 
        reason: `IP ${hostname} no está en rangos permitidos para laboratorio` 
      };
    }

    // IP está en rango permitido, verificar puerto
    if (port) {
      const allowedPorts = ['3001', '3002', '3003', '9090', '80', '8080'];
      if (!allowedPorts.includes(port)) {
        return { 
          allowed: false, 
          reason: `Puerto ${port} no está en lista de puertos de laboratorio permitidos` 
        };
      }
    }

    return { allowed: true, reason: null };
  }

  // Verificar si se permiten targets externos (modo no seguro)
  if (process.env.ALLOW_EXTERNAL_TARGETS === 'true') {
    Logger.warn(`Target externo permitido (ALLOW_EXTERNAL_TARGETS=true): ${targetWithPort}`);
    return { allowed: true, reason: 'EXTERNAL_TARGET_WARNING' };
  }

  return { 
    allowed: false, 
    reason: `Target ${targetWithPort} no está en lista de laboratorios permitidos` 
  };
}

// ============================================================================
// MIDDLEWARE DE VALIDACIÓN DE TARGET
// ============================================================================

const validateTarget = (req, res, next) => {
  const { target } = req.body;
  
  // Paso 1: Parsear y validar formato
  const parsed = parseTarget(target);
  
  if (!parsed.isValid) {
    Logger.warn(`Validación de formato fallida para target: ${target} - ${parsed.error}`);
    return res.status(400).json({
      error: 'Target inválido',
      code: 'INVALID_TARGET_FORMAT',
      details: parsed.error,
      received: target
    });
  }

  // Paso 2: Verificar alcance (scope)
  const scopeCheck = isTargetInScope(parsed.hostname, parsed.port);
  
  if (!scopeCheck.allowed) {
    Logger.warn(`Target fuera de alcance: ${target} - ${scopeCheck.reason}`);
    return res.status(403).json({
      error: 'Target no permitido',
      code: 'TARGET_OUT_OF_SCOPE',
      details: scopeCheck.reason,
      allowedTargets: ALLOWED_TARGETS,
      hint: 'Solo se permiten laboratorios Docker locales (Juice Shop, DVWA, WebGoat)'
    });
  }

  // Paso 3: Advertencia si es target externo
  if (scopeCheck.reason === 'EXTERNAL_TARGET_WARNING') {
    // Continuar pero loggear advertencia
    Logger.warn(`Escaneo contra target externo: ${target}`);
  }

  // Paso 4: Sanitizar y guardar en request para uso posterior
  req.sanitizedTarget = {
    original: target,
    hostname: parsed.hostname,
    port: parsed.port,
    canonical: parsed.port ? `${parsed.hostname}:${parsed.port}` : parsed.hostname,
    url: parsed.port ? `http://${parsed.hostname}:${parsed.port}` : `http://${parsed.hostname}`
  };

  Logger.info(`Target validado: ${req.sanitizedTarget.canonical}`);
  next();
};

// ============================================================================
// RUTAS API
// ============================================================================

/**
 * GET /api/health
 * Verificar estado del servidor
 */
app.get('/api/health', (req, res) => {
  res.json({
    status: 'healthy',
    timestamp: new Date().toISOString(),
    version: '1.1.0-security',
    scope: {
      allowedTargets: ALLOWED_TARGETS,
      externalTargetsAllowed: process.env.ALLOW_EXTERNAL_TARGETS === 'true'
    },
    services: {
      nmap: 'available',
      nikto: 'available',
      gobuster: 'available',
      zap: 'available',
      wappalyzer: 'available',
      searchsploit: 'available'
    }
  });
});

/**
 * GET /api/lab/status
 * Verificar estado del laboratorio Docker
 */
app.get('/api/lab/status', async (req, res) => {
  try {
    const { exec } = require('child_process');
    const util = require('util');
    const execPromise = util.promisify(exec);

    const labApps = [
      { name: 'Juice Shop', port: 3001, url: 'http://localhost:3001' },
      { name: 'DVWA', port: 3002, url: 'http://localhost:3002' },
      { name: 'WebGoat', port: 3003, url: 'http://localhost:3003' },
      { name: 'bWAPP', port: 3004, url: 'http://localhost:3004' },
      { name: 'Hackazon', port: 3005, url: 'http://localhost:3005' },
      { name: 'Mutillidae', port: 3006, url: 'http://localhost:3006' }
    ];

    const status = await Promise.all(labApps.map(async (app) => {
      try {
        const { stdout } = await execPromise(`curl -s -o /dev/null -w "%{http_code}" --max-time 3 ${app.url}`);
        const httpCode = stdout.trim();
        return {
          ...app,
          status: ['200', '301', '302', '401', '403'].includes(httpCode) ? 'running' : 'stopped',
          httpCode
        };
      } catch {
        return { ...app, status: 'stopped', httpCode: null };
      }
    }));

    const runningCount = status.filter(s => s.status === 'running').length;

    res.json({
      labStatus: runningCount > 0 ? 'running' : 'stopped',
      runningApps: runningCount,
      totalApps: labApps.length,
      apps: status
    });
  } catch (error) {
    Logger.error('Error checking lab status:', error);
    res.status(500).json({ error: 'Error verificando estado del laboratorio' });
  }
});

/**
 * POST /api/scan
 * Iniciar un nuevo escaneo
 */
app.post('/api/scan', validateTarget, async (req, res) => {
  try {
    // Usar target sanitizado
    const target = req.sanitizedTarget.url;
    const { options = {} } = req.body;
    const scanId = uuidv4();
    const timestamp = Date.now();

    // Crear directorio para este escaneo
    const outputDir = path.join(__dirname, 'outputs', 'scans', `${scanId}`);
    fs.mkdirSync(outputDir, { recursive: true });

    // Inicializar estado del escaneo
    const scanData = {
      id: scanId,
      target: req.sanitizedTarget.canonical, // Guardar canonical, no el original
      targetHostname: req.sanitizedTarget.hostname,
      targetPort: req.sanitizedTarget.port,
      options: {
        runWappalyzer: options.runWappalyzer !== false,
        runNmap: options.runNmap !== false,
        runGobuster: options.runGobuster !== false,
        runNikto: options.runNikto !== false,
        runZap: options.runZap !== false,
        runSearchsploit: options.runSearchsploit !== false,
        nmapPorts: options.nmapPorts || '1-1000',
        gobusterWordlist: options.gobusterWordlist || '/usr/share/wordlists/dirb/common.txt',
        zapMode: options.zapMode || 'baseline' // baseline, full, api
      },
      status: 'queued',
      progress: 0,
      currentTool: null,
      startedAt: new Date().toISOString(),
      completedAt: null,
      outputDir,
      results: {},
      vulnerabilities: [],
      score: null,
      error: null
    };

    scans.set(scanId, scanData);

    Logger.info(`Nuevo escaneo iniciado: ${scanId} -> ${req.sanitizedTarget.canonical}`);

    // Iniciar escaneo en background
    runScan(scanId).catch(error => {
      Logger.error(`Error en escaneo ${scanId}:`, error);
      const scan = scans.get(scanId);
      if (scan) {
        scan.status = 'error';
        scan.error = error.message;
      }
    });

    res.status(202).json({
      message: 'Escaneo iniciado correctamente',
      scanId,
      target: req.sanitizedTarget.canonical,
      options: scanData.options,
      statusUrl: `/api/scan/${scanId}/status`,
      reportUrl: `/api/scan/${scanId}/report`
    });

  } catch (error) {
    Logger.error('Error iniciando escaneo:', error);
    res.status(500).json({
      error: 'Error al iniciar el escaneo',
      details: error.message
    });
  }
});

/**
 * GET /api/scan/:id/status
 * Obtener estado de un escaneo
 */
app.get('/api/scan/:id/status', (req, res) => {
  const { id } = req.params;
  const scan = scans.get(id);

  if (!scan) {
    return res.status(404).json({
      error: 'Escaneo no encontrado',
      code: 'SCAN_NOT_FOUND'
    });
  }

  res.json({
    id: scan.id,
    target: scan.target,
    status: scan.status,
    progress: scan.progress,
    currentTool: scan.currentTool,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    error: scan.error,
    toolsCompleted: Object.keys(scan.results),
    vulnerabilitiesFound: scan.vulnerabilities.length,
    score: scan.score
  });
});

/**
 * GET /api/scan/:id/results
 * Obtener resultados detallados de un escaneo
 */
app.get('/api/scan/:id/results', (req, res) => {
  const { id } = req.params;
  const scan = scans.get(id);

  if (!scan) {
    return res.status(404).json({
      error: 'Escaneo no encontrado',
      code: 'SCAN_NOT_FOUND'
    });
  }

  if (scan.status !== 'completed' && scan.status !== 'error') {
    return res.json({
      message: 'Escaneo aún en progreso',
      status: scan.status,
      progress: scan.progress,
      partialResults: scan.results
    });
  }

  res.json({
    id: scan.id,
    target: scan.target,
    status: scan.status,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    results: scan.results,
    vulnerabilities: scan.vulnerabilities,
    score: scan.score,
    summary: generateSummary(scan)
  });
});

/**
 * GET /api/scan/:id/report
 * Descargar reporte del escaneo
 */
app.get('/api/scan/:id/report', async (req, res) => {
  const { id } = req.params;
  const { format = 'html' } = req.query;
  const scan = scans.get(id);

  if (!scan) {
    return res.status(404).json({
      error: 'Escaneo no encontrado',
      code: 'SCAN_NOT_FOUND'
    });
  }

  if (scan.status !== 'completed') {
    return res.status(400).json({
      error: 'El escaneo no ha terminado',
      status: scan.status,
      progress: scan.progress
    });
  }

  try {
    const reportPath = await ReportGenerator.generate(scan, format);
    
    const contentTypes = {
      'html': 'text/html',
      'pdf': 'application/pdf',
      'json': 'application/json',
      'md': 'text/markdown'
    };

    res.setHeader('Content-Type', contentTypes[format] || 'text/html');
    res.setHeader('Content-Disposition', `attachment; filename="security-report-${id}.${format}"`);
    res.sendFile(reportPath);

  } catch (error) {
    Logger.error('Error generando reporte:', error);
    res.status(500).json({
      error: 'Error generando el reporte',
      details: error.message
    });
  }
});

/**
 * GET /api/scans
 * Listar todos los escaneos
 */
app.get('/api/scans', (req, res) => {
  const { status, limit = 50 } = req.query;
  
  let scanList = Array.from(scans.values()).map(scan => ({
    id: scan.id,
    target: scan.target,
    status: scan.status,
    progress: scan.progress,
    startedAt: scan.startedAt,
    completedAt: scan.completedAt,
    vulnerabilitiesFound: scan.vulnerabilities.length,
    score: scan.score
  }));

  if (status) {
    scanList = scanList.filter(s => s.status === status);
  }

  scanList = scanList.slice(0, parseInt(limit));

  res.json({
    total: scanList.length,
    scans: scanList
  });
});

/**
 * DELETE /api/scan/:id
 * Eliminar un escaneo
 */
app.delete('/api/scan/:id', (req, res) => {
  const { id } = req.params;
  
  if (!scans.has(id)) {
    return res.status(404).json({
      error: 'Escaneo no encontrado',
      code: 'SCAN_NOT_FOUND'
    });
  }

  scans.delete(id);
  Logger.info(`Escaneo eliminado: ${id}`);

  res.json({
    message: 'Escaneo eliminado correctamente',
    id
  });
});

// ============================================================================
// FUNCIÓN PRINCIPAL DE ESCANEO
// ============================================================================

async function runScan(scanId) {
  const scan = scans.get(scanId);
  if (!scan) return;

  scan.status = 'running';
  const orchestrator = new Orchestrator(scan);

  try {
    // 1. Wappalyzer - Detección de tecnologías
    if (scan.options.runWappalyzer) {
      scan.currentTool = 'wappalyzer';
      scan.progress = 10;
      Logger.info(`[${scanId}] Ejecutando Wappalyzer...`);
      
      scan.results.wappalyzer = await WappalyzerDetector.scan(scan.target, scan.outputDir);
      Logger.info(`[${scanId}] Wappalyzer completado`);
    }

    // 2. Nmap - Escaneo de puertos
    if (scan.options.runNmap) {
      scan.currentTool = 'nmap';
      scan.progress = 25;
      Logger.info(`[${scanId}] Ejecutando Nmap...`);
      
      scan.results.nmap = await NmapScanner.scan(scan.target, scan.outputDir, {
        ports: scan.options.nmapPorts
      });
      Logger.info(`[${scanId}] Nmap completado`);
    }

    // 3. Gobuster - Descubrimiento de directorios
    if (scan.options.runGobuster) {
      scan.currentTool = 'gobuster';
      scan.progress = 40;
      Logger.info(`[${scanId}] Ejecutando Gobuster...`);
      
      scan.results.gobuster = await GobusterScanner.scan(scan.target, scan.outputDir, {
        wordlist: scan.options.gobusterWordlist
      });
      Logger.info(`[${scanId}] Gobuster completado`);
    }

    // 4. Nikto - Análisis de vulnerabilidades web
    if (scan.options.runNikto) {
      scan.currentTool = 'nikto';
      scan.progress = 55;
      Logger.info(`[${scanId}] Ejecutando Nikto...`);
      
      scan.results.nikto = await NiktoScanner.scan(scan.target, scan.outputDir);
      Logger.info(`[${scanId}] Nikto completado`);
    }

    // 5. OWASP ZAP - Escaneo de aplicaciones web
    if (scan.options.runZap) {
      scan.currentTool = 'zap';
      scan.progress = 70;
      Logger.info(`[${scanId}] Ejecutando OWASP ZAP (${scan.options.zapMode})...`);
      
      scan.results.zap = await ZapScanner.scan(scan.target, scan.outputDir, {
        mode: scan.options.zapMode
      });
      Logger.info(`[${scanId}] OWASP ZAP completado`);
    }

    // 6. Searchsploit - Búsqueda de exploits
    if (scan.options.runSearchsploit && scan.results.nmap) {
      scan.currentTool = 'searchsploit';
      scan.progress = 85;
      Logger.info(`[${scanId}] Ejecutando Searchsploit...`);
      
      const versions = orchestrator.extractVersionsFromNmap(scan.results.nmap);
      scan.results.searchsploit = await ExploitDBLookup.search(versions, scan.outputDir);
      Logger.info(`[${scanId}] Searchsploit completado`);
    }

    // 7. Consolidar resultados y calcular score
    scan.currentTool = 'scoring';
    scan.progress = 95;
    Logger.info(`[${scanId}] Calculando score de vulnerabilidad...`);

    const scoringEngine = new ScoringEngine();
    const { vulnerabilities, score } = scoringEngine.calculate(scan.results);
    
    scan.vulnerabilities = vulnerabilities;
    scan.score = score;

    // Escaneo completado
    scan.status = 'completed';
    scan.progress = 100;
    scan.currentTool = null;
    scan.completedAt = new Date().toISOString();

    Logger.info(`[${scanId}] Escaneo completado. Score: ${score.overall}/100`);

  } catch (error) {
    scan.status = 'error';
    scan.error = error.message;
    scan.currentTool = null;
    Logger.error(`[${scanId}] Error en escaneo:`, error);
    throw error;
  }
}

// ============================================================================
// UTILIDADES
// ============================================================================

function generateSummary(scan) {
  const vulnBySeverity = {
    critical: scan.vulnerabilities.filter(v => v.severity === 'critical').length,
    high: scan.vulnerabilities.filter(v => v.severity === 'high').length,
    medium: scan.vulnerabilities.filter(v => v.severity === 'medium').length,
    low: scan.vulnerabilities.filter(v => v.severity === 'low').length,
    info: scan.vulnerabilities.filter(v => v.severity === 'info').length
  };

  return {
    totalVulnerabilities: scan.vulnerabilities.length,
    bySeverity: vulnBySeverity,
    toolsRun: Object.keys(scan.results).length,
    scanDuration: scan.completedAt ? 
      Math.round((new Date(scan.completedAt) - new Date(scan.startedAt)) / 1000) + 's' : null,
    overallScore: scan.score?.overall,
    riskLevel: scan.score?.riskLevel
  };
}

// ============================================================================
// MANEJO DE ERRORES
// ============================================================================

app.use((err, req, res, next) => {
  Logger.error('Error no manejado:', err);
  res.status(500).json({
    error: 'Error interno del servidor',
    code: 'INTERNAL_ERROR'
  });
});

// 404 Handler
app.use((req, res) => {
  res.status(404).json({
    error: 'Endpoint no encontrado',
    code: 'NOT_FOUND'
  });
});

// ============================================================================
// INICIAR SERVIDOR
// ============================================================================

app.listen(PORT, () => {
  console.log('');
  console.log('╔══════════════════════════════════════════════════════════════════╗');
  console.log('║           SECURITYSCAN PRO - BACKEND API (v1.1 SECURE)           ║');
  console.log('╠══════════════════════════════════════════════════════════════════╣');
  console.log(`║  Servidor corriendo en: http://localhost:${PORT}                    ║`);
  console.log('║  Documentación API:     http://localhost:' + PORT + '/api/health          ║');
  console.log('║  Modo: LABORATORIO CONTROLADO (scope restringido)                ║');
  console.log('╚══════════════════════════════════════════════════════════════════╝');
  console.log('');
  Logger.info(`Servidor iniciado en puerto ${PORT}`);
  Logger.info(`Targets permitidos: ${ALLOWED_TARGETS.join(', ')}`);
});

module.exports = app;
