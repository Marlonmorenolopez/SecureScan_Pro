/**
 * ============================================================================
 * SECURITYSCAN PRO - ORCHESTRATOR v3.0 (RESILIENTE)
 * ============================================================================
 * Motor de orquestación centralizado con:
 * - Circuit Breaker para tolerancia a fallos
 * - Validación de targets (health-check TCP)
 * - Espera de archivos estables (race condition fix)
 * - Timeouts granulares y cleanup de procesos

 * -Verifica que no haya errores de sintaxis:
bash
Copy
node -c /backend/orchestrator.js
* -Instala dependencias faltantes (si aún no lo has hecho):
bash
Copy
npm install xml2js axios
 * ============================================================================
 */

const path = require('path');
const fs = require('fs');
const net = require('net');
const EventEmitter = require('events');
const { promisify } = require('util');
const Logger = require('./utils/logger');

// Importar módulos mejorados
const WhatWebDetector = require('./modules/whatweb_detector');
const NmapScanner = require('./modules/nmap_scanner');
const GobusterScanner = require('./modules/gobuster_scanner');
const ZAPScanner = require('./modules/zap_scanner');
const ExploitDB = require('./modules/exploitdb_unified');
const MetasploitIntegration = require('./modules/metasploit_integration');
const ScoringEngine = require('./modules/scoring_engine');
const ReportGenerator = require('./modules/report_generator');

// ============================================================================
// UTILIDADES DE RESILIENCIA
// ============================================================================

/**
 * Circuit Breaker - Previene cascada de fallos
 * Estados: CLOSED (normal) -> OPEN (fallo) -> HALF_OPEN (recuperación)
 */
class CircuitBreaker extends EventEmitter {
  constructor(name, options = {}) {
    super();
    this.name = name;
    this.failureThreshold = options.failureThreshold || 3;
    this.resetTimeout = options.resetTimeout || 60000; // 1 minuto
    this.halfOpenMaxCalls = options.halfOpenMaxCalls || 1;
    
    this.state = 'CLOSED'; // CLOSED, OPEN, HALF_OPEN
    this.failures = 0;
    this.successes = 0;
    this.lastFailureTime = null;
    this.halfOpenCalls = 0;
    
    Logger.info(`[CIRCUIT-BREAKER] ${name} inicializado (estado: CLOSED)`);
  }

  async execute(fn, ...args) {
    if (this.state === 'OPEN') {
      if (Date.now() - this.lastFailureTime > this.resetTimeout) {
        this.transitionTo('HALF_OPEN');
      } else {
        throw new Error(`Circuit Breaker "${this.name}" está ABIERTO - servicio temporalmente no disponible`);
      }
    }

    if (this.state === 'HALF_OPEN' && this.halfOpenCalls >= this.halfOpenMaxCalls) {
      throw new Error(`Circuit Breaker "${this.name}" en HALF_OPEN - límite de llamadas alcanzado`);
    }

    if (this.state === 'HALF_OPEN') {
      this.halfOpenCalls++;
    }

    try {
      const result = await fn(...args);
      this.onSuccess();
      return result;
    } catch (error) {
      this.onFailure();
      throw error;
    }
  }

  onSuccess() {
    this.failures = 0;
    
    if (this.state === 'HALF_OPEN') {
      this.successes++;
      if (this.successes >= this.halfOpenMaxCalls) {
        this.transitionTo('CLOSED');
        Logger.info(`[CIRCUIT-BREAKER] ${this.name} cerrado nuevamente - servicio recuperado`);
      }
    }
  }

  onFailure() {
    this.failures++;
    this.lastFailureTime = Date.now();
    
    if (this.failures >= this.failureThreshold) {
      this.transitionTo('OPEN');
      Logger.error(`[CIRCUIT-BREAKER] ${this.name} ABIERTO tras ${this.failures} fallos consecutivos`);
    }
  }

  transitionTo(newState) {
    const oldState = this.state;
    this.state = newState;
    this.emit('stateChange', { name: this.name, from: oldState, to: newState });
    
    if (newState === 'CLOSED') {
      this.failures = 0;
      this.successes = 0;
      this.halfOpenCalls = 0;
    } else if (newState === 'HALF_OPEN') {
      this.halfOpenCalls = 0;
      this.successes = 0;
    }
  }

  getState() {
    return {
      name: this.name,
      state: this.state,
      failures: this.failures,
      successes: this.successes,
      lastFailure: this.lastFailureTime
    };
  }
}

/**
 * FileStabilizer - Espera a que archivos de salida estén completos
 * Resuelve race condition en generación de reportes
 */
class FileStabilizer {
  constructor(options = {}) {
    this.checkInterval = options.checkInterval || 500; // ms
    this.maxAttempts = options.maxAttempts || 60; // 30 segundos max
    this.stabilityRounds = options.stabilityRounds || 3; // Rounds consecutivas estables
  }

  async waitForStable(filePath, timeout = 30000) {
    const startTime = Date.now();
    let attempts = 0;
    let stableRounds = 0;
    let lastSize = -1;
    let lastMtime = -1;

    Logger.info(`[FILE-STABILIZER] Esperando estabilización de: ${filePath}`);

    while (attempts < this.maxAttempts) {
      // Verificar timeout global
      if (Date.now() - startTime > timeout) {
        throw new Error(`Timeout esperando estabilización de ${filePath}`);
      }

      // Verificar que archivo existe
      if (!fs.existsSync(filePath)) {
        await this.sleep(this.checkInterval);
        attempts++;
        continue;
      }

      const stats = fs.statSync(filePath);
      const currentSize = stats.size;
      const currentMtime = stats.mtimeMs;

      // Verificar que no esté vacío
      if (currentSize === 0) {
        await this.sleep(this.checkInterval);
        attempts++;
        continue;
      }

      // Verificar estabilidad (tamaño y mtime no cambian)
      if (currentSize === lastSize && currentMtime === lastMtime) {
        stableRounds++;
        
        if (stableRounds >= this.stabilityRounds) {
          Logger.info(`[FILE-STABILIZER] Archivo estable después de ${attempts} intentos: ${filePath}`);
          return {
            path: filePath,
            size: currentSize,
            stabilizedAt: new Date().toISOString(),
            attempts
          };
        }
      } else {
        // Reset contador de rounds estables si hubo cambio
        stableRounds = 0;
      }

      lastSize = currentSize;
      lastMtime = currentMtime;
      
      await this.sleep(this.checkInterval);
      attempts++;
    }

    throw new Error(`Archivo ${filePath} no se estabilizó después de ${this.maxAttempts} intentos`);
  }

  async waitForMultiple(filePaths, timeout = 30000) {
    const results = await Promise.allSettled(
      filePaths.map(fp => this.waitForStable(fp, timeout))
    );

    const successful = results.filter(r => r.status === 'fulfilled').map(r => r.value);
    const failed = results.filter(r => r.status === 'rejected').map(r => r.reason.message);

    if (failed.length > 0) {
      Logger.warn(`[FILE-STABILIZER] Algunos archivos no se estabilizaron: ${failed.join(', ')}`);
    }

    return { successful, failed };
  }

  sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }
}

/**
 * TargetValidator - Health-check TCP antes de escanear
 */
class TargetValidator {
  constructor(options = {}) {
    this.connectTimeout = options.connectTimeout || 5000;
    this.allowedTargets = options.allowedTargets || [];
  }

  /**
   * Valida que el target esté en la lista de permitidos
   */
  validateScope(target) {
    if (this.allowedTargets.length === 0) {
      return true; // Modo permisivo si no hay whitelist
    }

    const normalized = target.replace(/^https?:\/\//, '').split('/')[0];
    
    const isAllowed = this.allowedTargets.some(allowed => {
      if (normalized === allowed) return true;
      if (normalized.startsWith(allowed)) return true;
      return false;
    });

    if (!isAllowed) {
      throw new Error(`Target "${target}" fuera de alcance permitido. Permitidos: ${this.allowedTargets.join(', ')}`);
    }

    return true;
  }

  /**
   * Health-check TCP para verificar que el laboratorio responde
   */
  async healthCheck(target) {
    const url = new URL(target.startsWith('http') ? target : `http://${target}`);
    const hostname = url.hostname;
    const port = parseInt(url.port) || (url.protocol === 'https:' ? 443 : 80);

    // Primero validar scope
    this.validateScope(target);

    // Luego health-check TCP
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      
      socket.setTimeout(this.connectTimeout);
      
      socket.on('connect', () => {
        socket.destroy();
        Logger.info(`[TARGET-VALIDATOR] Health-check OK: ${hostname}:${port}`);
        resolve({
          target,
          hostname,
          port,
          reachable: true,
          checkedAt: new Date().toISOString()
        });
      });
      
      socket.on('error', (err) => {
        socket.destroy();
        reject(new Error(`No se puede conectar a ${hostname}:${port} - ${err.message}`));
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error(`Timeout conectando a ${hostname}:${port}`));
      });
      
      socket.connect(port, hostname);
    });
  }

  /**
   * Valida múltiples targets (para escaneos con múltiples endpoints)
   */
  async validateMultiple(targets) {
    const results = await Promise.allSettled(
      targets.map(t => this.healthCheck(t))
    );

    const reachable = results
      .filter(r => r.status === 'fulfilled')
      .map(r => r.value);
    
    const unreachable = results
      .filter(r => r.status === 'rejected')
      .map(r => ({ error: r.reason.message }));

    return { reachable, unreachable };
  }
}

/**
 * ProcessManager - Gestión segura de procesos con timeouts y cleanup
 */
class ProcessManager {
  constructor() {
    this.activeProcesses = new Map();
  }

  register(pid, metadata = {}) {
    this.activeProcesses.set(pid, {
      pid,
      startTime: Date.now(),
      ...metadata
    });
    Logger.debug(`[PROCESS-MANAGER] Proceso registrado: ${pid}`);
  }

  unregister(pid) {
    this.activeProcesses.delete(pid);
    Logger.debug(`[PROCESS-MANAGER] Proceso completado: ${pid}`);
  }

  async cleanup() {
    Logger.info(`[PROCESS-MANAGER] Limpiando ${this.activeProcesses.size} procesos activos`);
    
    for (const [pid, metadata] of this.activeProcesses) {
      try {
        process.kill(pid, 'SIGTERM');
        Logger.info(`[PROCESS-MANAGER] Señal SIGTERM enviada a ${pid}`);
        
        // Esperar 5 segundos y forzar SIGKILL si persiste
        await new Promise(resolve => setTimeout(resolve, 5000));
        
        try {
          process.kill(pid, 0); // Verificar si existe
          process.kill(pid, 'SIGKILL');
          Logger.warn(`[PROCESS-MANAGER] SIGKILL enviado a ${pid}`);
        } catch {
          // Proceso ya terminado
        }
      } catch (error) {
        Logger.error(`[PROCESS-MANAGER] Error limpiando ${pid}:`, error);
      }
    }
    
    this.activeProcesses.clear();
  }

  getActiveCount() {
    return this.activeProcesses.size;
  }
}

// ============================================================================
// ORQUESTADOR PRINCIPAL
// ============================================================================

class SecureScanOrchestrator extends EventEmitter {
  /**
   * Configuración por defecto del orquestador
   */
  static get DEFAULT_CONFIG() {
    return {
      // Directorios
      outputDir: './reports',
      tempDir: './temp',
      logsDir: './logs',
      
      // Secuencia de escaneo
      scanSequence: [
        'whatweb',      // 1. Detección de tecnologías
        'nmap',         // 2. Escaneo de puertos y servicios
        'gobuster',     // 3. Descubrimiento de directorios/subdominios
        'zap',          // 4. Escaneo DAST completo
        'exploitdb',    // 5. Búsqueda de exploits
        'metasploit',   // 6. Explotación controlada (opcional)
        'scoring',      // 7. Cálculo de riesgos
        'reporting'     // 8. Generación de reportes
      ],
      
      // Targets permitidos (laboratorios)
      allowedTargets: [
        'localhost:3001',    // Juice Shop
        'localhost:3002',    // DVWA
        'localhost:3003',    // WebGoat
        '127.0.0.1:3001',
        '127.0.0.1:3002',
        '127.0.0.1:3003',
        '172.20.0.0/24'      // Red Docker interna
      ],
      
      // Configuración por herramienta
      tools: {
        whatweb: {
          enabled: true,
          aggression: 3,
          timeout: 60,
          circuitBreaker: { failureThreshold: 3, resetTimeout: 60000 }
        },
        
        nmap: {
          enabled: true,
          timing: 'T4',
          versionIntensity: 7,
          scripts: 'vuln,vulners,safe',
          osDetection: true,
          traceroute: true,
          topPorts: 'all',
          timeout: 600,
          circuitBreaker: { failureThreshold: 2, resetTimeout: 120000 }
        },
        
        gobuster: {
          enabled: true,
          modes: ['dir', 'dns'],
          threads: 50,
          wordlistDir: '/usr/share/wordlists',
          extensions: 'php,html,txt,bak,zip,sql,env,config,xml,json',
          timeout: 300,
          circuitBreaker: { failureThreshold: 3, resetTimeout: 60000 }
        },
        
        zap: {
          enabled: true,
          spider: {
            type: 'spiderClient',
            maxDuration: 15
          },
          activeScan: {
            enabled: true,
            policy: 'Default',
            maxScanDuration: 30
          },
          authentication: { enabled: false },
          timeout: 1800,
          circuitBreaker: { failureThreshold: 2, resetTimeout: 300000 }
        },
        
        exploitdb: {
          enabled: true,
          enrichWithNVD: true,
          maxResults: 10,
          excludeTerms: 'dos',
          mirror: false,
          timeout: 120,
          circuitBreaker: { failureThreshold: 3, resetTimeout: 60000 }
        },
        
        metasploit: {
          enabled: false,
          dryRun: true,
          minRanking: 'good',
          maxSessions: 3,
          postExploitation: { enabled: false, autoRun: false },
          timeout: 600,
          circuitBreaker: { failureThreshold: 1, resetTimeout: 300000 }
        },
        
        scoring: {
          enabled: true,
          cvssVersion: '3.1',
          useEPSS: true,
          calculateTemporal: true,
          calculateEnvironmental: true
        },
        
        reporting: {
          enabled: true,
          formats: ['html', 'pdf', 'sarif', 'json'],
          template: 'default',
          sections: {
            executiveSummary: true,
            methodology: true,
            findings: true,
            riskAssessment: true,
            remediationPlan: true
          }
        }
      },
      
      // Opciones de seguridad
      safety: {
        requireConfirmation: true,
        maxScanDuration: 3600
      },
      
      // Opciones de resiliencia
      resilience: {
        fileStabilizer: {
          checkInterval: 500,
          maxAttempts: 60,
          stabilityRounds: 3
        },
        targetValidator: {
          connectTimeout: 5000
        },
        processManager: {
          enabled: true
        }
      }
    };
  }

  /**
   * Constructor
   */
  constructor(config = {}) {
    super();
    this.config = this.mergeConfig(SecureScanOrchestrator.DEFAULT_CONFIG, config);
    this.results = {};
    this.startTime = null;
    this.endTime = null;
    
    // Inicializar componentes de resiliencia
    this.fileStabilizer = new FileStabilizer(this.config.resilience.fileStabilizer);
    this.targetValidator = new TargetValidator({
      allowedTargets: this.config.allowedTargets,
      ...this.config.resilience.targetValidator
    });
    this.processManager = new ProcessManager();
    
    // Circuit breakers por herramienta
    this.circuitBreakers = {};
    for (const [tool, toolConfig] of Object.entries(this.config.tools)) {
      if (toolConfig.circuitBreaker) {
        this.circuitBreakers[tool] = new CircuitBreaker(tool, toolConfig.circuitBreaker);
      }
    }
    
    // Asegurar directorios existen
    this.ensureDirectories();
    
    // Manejar señales de terminación
    this.setupGracefulShutdown();
  }

  setupGracefulShutdown() {
    const shutdown = async (signal) => {
      Logger.info(`[ORCHESTRATOR] Recibida señal ${signal}, iniciando shutdown graceful...`);
      await this.processManager.cleanup();
      process.exit(0);
    };

    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  }

  /**
   * Ejecutar escaneo completo con validaciones de resiliencia
   */
  async run(target, options = {}) {
    this.startTime = Date.now();
    this.emit('scan:start', { target, timestamp: new Date().toISOString() });
    
    Logger.info(`[ORCHESTRATOR] Iniciando escaneo completo contra: ${target}`);
    Logger.info(`[ORCHESTRATOR] Secuencia: ${this.config.scanSequence.join(' -> ')}`);

    try {
      // 1. VALIDACIÓN DE TARGET (Health-check)
      Logger.info(`[ORCHESTRATOR] Validando target: ${target}`);
      const validation = await this.targetValidator.healthCheck(target);
      this.emit('target:validated', validation);
      
      // 2. EJECUCIÓN SECUENCIAL CON CIRCUIT BREAKER
      for (const phase of this.config.scanSequence) {
        if (!this.shouldRun(phase)) {
          Logger.info(`[ORCHESTRATOR] Fase ${phase} omitida (deshabilitada)`);
          continue;
        }

        this.emit('phase:start', { phase });
        const startPhase = Date.now();

        try {
          // Usar Circuit Breaker si existe para esta fase
          const breaker = this.circuitBreakers[phase];
          
          if (breaker) {
            this.results[phase] = await breaker.execute(
              () => this.runPhase(phase, target)
            );
          } else {
            this.results[phase] = await this.runPhase(phase, target);
          }

          const duration = ((Date.now() - startPhase) / 1000).toFixed(2);
          Logger.info(`[ORCHESTRATOR] Fase ${phase} completada en ${duration}s`);
          
          this.emit('phase:complete', { phase, results: this.results[phase], duration });

        } catch (error) {
          Logger.error(`[ORCHESTRATOR] Fase ${phase} falló:`, error.message);
          this.emit('phase:error', { phase, error: error.message });
          
          // Continuar con siguiente fase (fail-fast opcional)
          if (options.failFast) {
            throw error;
          }
        }
      }

      this.endTime = Date.now();
      const duration = ((this.endTime - this.startTime) / 1000).toFixed(2);
      
      Logger.info(`[ORCHESTRATOR] Escaneo completado en ${duration}s`);

      const finalResults = {
        target,
        duration,
        timestamp: new Date().toISOString(),
        phases: this.results,
        summary: this.generateSummary(),
        validation,
        circuitBreakers: Object.fromEntries(
          Object.entries(this.circuitBreakers).map(([k, v]) => [k, v.getState()])
        )
      };

      this.emit('scan:complete', finalResults);
      return finalResults;

    } catch (error) {
      Logger.error('[ORCHESTRATOR] Error en escaneo:', error);
      this.emit('scan:error', { error: error.message });
      throw error;
    }
  }

  /**
   * Ejecutar fase individual
   */
  async runPhase(phase, target) {
    switch (phase) {
      case 'whatweb':
        return await this.runWhatWeb(target);
      case 'nmap':
        return await this.runNmap(target);
      case 'gobuster':
        return await this.runGobuster(target);
      case 'zap':
        return await this.runZAP(target);
      case 'exploitdb':
        return await this.runExploitDB();
      case 'metasploit':
        return await this.runMetasploit(target);
      case 'scoring':
        return await this.runScoring();
      case 'reporting':
        return await this.runReporting(target);
      default:
        throw new Error(`Fase desconocida: ${phase}`);
    }
  }

  // ============================================================================
  // MÉTODOS DE EJECUCIÓN POR FASE (con espera de archivos estables)
  // ============================================================================

  async runWhatWeb(target) {
    const config = this.config.tools.whatweb;
    const outputDir = path.join(this.config.tempDir, 'whatweb');
    
    Logger.info('[ORCHESTRATOR] Ejecutando WhatWeb...');
    
    const results = await WhatWebDetector.scan(target, outputDir, {
      aggression: config.aggression,
      timeout: config.timeout
    });

    // Esperar archivo de salida estable
    const outputFile = path.join(outputDir, 'whatweb_output.json');
    await this.fileStabilizer.waitForStable(outputFile, 10000);

    this.technologies = results.technologies.map(t => ({
      name: t.name,
      version: t.version,
      category: t.category
    }));

    return results;
  }

  async runNmap(target) {
    const config = this.config.tools.nmap;
    const outputDir = path.join(this.config.tempDir, 'nmap');
    
    Logger.info('[ORCHESTRATOR] Ejecutando Nmap...');
    
    const results = await NmapScanner.scan(target, outputDir, {
      timing: config.timing,
      versionIntensity: config.versionIntensity,
      scripts: config.scripts,
      osDetection: config.osDetection,
      traceroute: config.traceroute,
      topPorts: config.topPorts,
      maxRetries: 6,
      hostTimeout: '30m'
    });

    // Esperar archivos de salida estables
    const filesToWait = [
      path.join(outputDir, 'nmap_output.xml'),
      path.join(outputDir, 'nmap_output.txt')
    ];
    await this.fileStabilizer.waitForMultiple(filesToWait, 60000);

    this.nmapResults = results;
    this.nmapXmlFile = results.outputFiles?.xml;

    return results;
  }

  async runGobuster(target) {
    const config = this.config.tools.gobuster;
    const outputDir = path.join(this.config.tempDir, 'gobuster');
    const results = {};

    Logger.info('[ORCHESTRATOR] Ejecutando Gobuster...');

    if (config.modes.includes('dir')) {
      Logger.info('[ORCHESTRATOR] Gobuster: Modo DIR');
      results.dir = await GobusterScanner.deepDirScan(target, outputDir, {
        threads: config.threads,
        extensions: config.extensions
      });
      
      const dirOutput = path.join(outputDir, `gobuster_dir_${Date.now()}.txt`);
      if (fs.existsSync(dirOutput)) {
        await this.fileStabilizer.waitForStable(dirOutput, 30000);
      }
    }

    if (config.modes.includes('dns') && !target.match(/^\d/)) {
      Logger.info('[ORCHESTRATOR] Gobuster: Modo DNS');
      const domain = target.replace(/^https?:\/\//, '').split('/')[0];
      results.dns = await GobusterScanner.subdomainScan(domain, outputDir);
    }

    this.discoveredUrls = this.extractUrlsFromGobuster(results);
    return results;
  }

  async runZAP(target) {
    const config = this.config.tools.zap;
    const outputDir = path.join(this.config.tempDir, 'zap');
    
    Logger.info('[ORCHESTRATOR] Ejecutando ZAP...');

    const isSPA = this.technologies?.some(t => 
      ['React', 'Angular', 'Vue.js', 'SPA'].includes(t.name)
    );

    const spiderType = isSPA ? 'spiderClient' : config.spider.type;

    const results = await ZAPScanner.scan(target, outputDir, {
      spider: {
        type: spiderType,
        maxDuration: config.spider.maxDuration,
        browser: isSPA ? 'firefox-headless' : undefined
      },
      activeScan: config.activeScan,
      authentication: config.authentication,
      reporting: { formats: ['json'], riskThreshold: 'Informational' }
    });

    // Esperar reporte JSON estable
    const zapReport = path.join(outputDir, `zap_scan_${results.scanId}.json`);
    await this.fileStabilizer.waitForStable(zapReport, 120000);

    this.zapFindings = results.alerts.map(alert => ({
      tool: 'zap',
      title: alert.name,
      severity: alert.risk,
      description: alert.description,
      solution: alert.solution,
      cweId: alert.cweId,
      wascId: alert.wascId,
      evidence: alert.instances?.map(i => i.uri).join(', ')
    }));

    return results;
  }

  async runExploitDB() {
    const config = this.config.tools.exploitdb;
    const outputDir = path.join(this.config.tempDir, 'exploitdb');
    
    Logger.info('[ORCHESTRATOR] Ejecutando ExploitDB...');

    if (this.nmapXmlFile && fs.existsSync(this.nmapXmlFile)) {
      Logger.info('[ORCHESTRATOR] ExploitDB: Integración con Nmap XML');
      
      const results = await ExploitDB.searchFromNmap(this.nmapXmlFile, outputDir, {
        enrichWithNVD: config.enrichWithNVD,
        maxResults: config.maxResults,
        excludeTerms: config.excludeTerms,
        mirror: config.mirror
      });

      // Esperar archivo de salida
      const edbOutput = path.join(outputDir, `exploitdb_${Date.now()}.json`);
      if (fs.existsSync(edbOutput)) {
        await this.fileStabilizer.waitForStable(edbOutput, 30000);
      }

      return results;
    }

    // Fallback: búsqueda por tecnologías
    const results = [];
    for (const tech of this.technologies?.slice(0, 5) || []) {
      const searchQuery = tech.version ? `${tech.name} ${tech.version}` : tech.name;
      const techResults = await ExploitDB.search(searchQuery, outputDir, {
        maxResults: 3,
        enrichWithNVD: config.enrichWithNVD,
        excludeTerms: config.excludeTerms
      });
      results.push({ technology: tech.name, version: tech.version, exploits: techResults.exploits });
    }

    return { services: results };
  }

  async runMetasploit(target) {
    const config = this.config.tools.metasploit;
    
    if (!config.enabled) {
      Logger.info('[ORCHESTRATOR] Metasploit deshabilitado');
      return { enabled: false };
    }

    Logger.info('[ORCHESTRATOR] Inicializando Metasploit...');

    const msf = new MetasploitIntegration({
      workspace: { name: `SecureScan-${Date.now()}` },
      exploitation: {
        dryRun: config.dryRun,
        minRanking: config.minRanking,
        maxSessions: config.maxSessions
      },
      postExploitation: config.postExploitation
    });

    await msf.initialize();

    if (this.nmapXmlFile) {
      await msf.importNmapResults(this.nmapXmlFile);
    }

    const exploitables = this.prepareExploitables();
    const results = await msf.autoExploitFromFindings(exploitables, {
      minCvss: 7.0,
      dryRun: config.dryRun
    });

    await msf.shutdown();

    return {
      enabled: true,
      dryRun: config.dryRun,
      attempts: results.length,
      successful: results.filter(r => r.success).length,
      sessions: results.filter(r => r.sessionId).map(r => r.sessionId),
      details: results
    };
  }

  async runScoring() {
    const config = this.config.tools.scoring;
    
    Logger.info('[ORCHESTRATOR] Ejecutando Scoring Engine...');

    const engine = new ScoringEngine({
      cvssVersion: config.cvssVersion,
      useEPSS: config.useEPSS,
      calculateTemporal: config.calculateTemporal,
      calculateEnvironmental: config.calculateEnvironmental
    });

    this.addFindingsToEngine(engine);
    const results = await engine.runScoring();
    this.scoredResults = results;

    return results;
  }

  async runReporting(target) {
    const config = this.config.tools.reporting;
    
    Logger.info('[ORCHESTRATOR] Generando reportes...');

    const generator = new ReportGenerator({
      reportInfo: {
        title: 'SecureScan Pro - Security Assessment Report',
        client: target,
        date: new Date().toISOString().split('T')[0],
        classification: 'Confidential'
      },
      output: { dir: this.config.outputDir, format: 'html' },
      sections: config.sections
    });

    const results = [];
    for (const format of config.formats) {
      Logger.info(`[ORCHESTRATOR] Generando reporte ${format.toUpperCase()}...`);
      
      const report = await generator.generate({
        target,
        findings: this.scoredResults?.results || [],
        startTime: this.startTime,
        endTime: this.endTime,
        phases: this.results
      }, { format });

      results.push({ format, path: report.path, size: report.size });
    }

    return { formats: results, summary: this.scoredResults?.summary };
  }

  // ============================================================================
  // MÉTODOS AUXILIARES
  // ============================================================================

  shouldRun(phase) {
    return this.config.scanSequence.includes(phase) && 
           this.config.tools[phase]?.enabled !== false;
  }

  ensureDirectories() {
    [this.config.outputDir, this.config.tempDir, this.config.logsDir]
      .forEach(dir => {
        if (!fs.existsSync(dir)) {
          fs.mkdirSync(dir, { recursive: true });
        }
      });
  }

  mergeConfig(defaultConfig, userConfig) {
    const merged = JSON.parse(JSON.stringify(defaultConfig)); // Deep clone
    
    for (const key in userConfig) {
      if (typeof userConfig[key] === 'object' && !Array.isArray(userConfig[key]) && 
          key !== 'resilience' && key !== 'tools') {
        merged[key] = { ...merged[key], ...userConfig[key] };
      } else {
        merged[key] = userConfig[key];
      }
    }
    
    return merged;
  }

  extractUrlsFromGobuster(gobusterResults) {
    const urls = [];
    if (gobusterResults.dir?.found) {
      urls.push(...gobusterResults.dir.found.map(f => f.url));
    }
    return urls;
  }

  prepareExploitables() {
    const exploitables = [];

    if (this.results.exploitdb?.services) {
      for (const service of this.results.exploitdb.services) {
        if (service.exploits?.length > 0) {
          exploitables.push({
            target: service.target,
            service: service.service,
            exploits: service.exploits,
            cvss: Math.max(...service.exploits.map(e => e.cvss || 0))
          });
        }
      }
    }

    if (this.zapFindings) {
      for (const finding of this.zapFindings.filter(f => ['High', 'Critical'].includes(f.severity))) {
        exploitables.push({
          target: finding.instances?.[0]?.uri,
          vulnerability: finding.title,
          severity: finding.severity,
          type: 'web'
        });
      }
    }

    return exploitables;
  }

  addFindingsToEngine(engine) {
    if (this.results.whatweb?.technologies) {
      for (const tech of this.results.whatweb.technologies) {
        engine.addFinding({
          tool: 'whatweb',
          category: 'technology_detection',
          title: `Detected ${tech.name} ${tech.version || ''}`,
          description: `Technology detected: ${tech.name} (${tech.category})`,
          severity: 'Info',
          target: this.results.whatweb.url
        });
      }
    }

    if (this.results.nmap?.vulnerabilities) {
      for (const vuln of this.results.nmap.vulnerabilities) {
        engine.addFinding({
          tool: 'nmap',
          category: vuln.type || 'vulnerability',
          title: vuln.description?.substring(0, 100),
          description: vuln.description,
          severity: this.mapNmapSeverity(vuln.severity),
          cvss: vuln.cvss,
          cve: vuln.cves?.[0],
          target: `${vuln.host}:${vuln.port}`
        });
      }
    }

    if (this.zapFindings) {
      for (const finding of this.zapFindings) {
        engine.addFinding({ ...finding, tool: 'zap' });
      }
    }

    if (this.results.gobuster?.dir?.found) {
      const sensitive = this.results.gobuster.dir.found.filter(f => f.sensitive);
      for (const item of sensitive) {
        engine.addFinding({
          tool: 'gobuster',
          category: 'information_disclosure',
          title: `Sensitive file/directory exposed: ${item.url}`,
          description: `Potentially sensitive resource found: ${item.url}`,
          severity: item.risk === 'high' ? 'High' : 'Medium',
          target: item.url
        });
      }
    }
  }

  mapNmapSeverity(severity) {
    const mapping = {
      'critical': 'Critical',
      'high': 'High',
      'medium': 'Medium',
      'low': 'Low',
      'info': 'Info'
    };
    return mapping[severity?.toLowerCase()] || 'Info';
  }

  generateSummary() {
    const scoring = this.scoredResults;
    
    return {
      totalFindings: scoring?.totalScored || 0,
      critical: scoring?.stats?.bySeverity?.critical || 0,
      high: scoring?.stats?.bySeverity?.high || 0,
      medium: scoring?.stats?.bySeverity?.medium || 0,
      low: scoring?.stats?.bySeverity?.low || 0,
      overallRisk: scoring?.summary?.overallRisk || 'Unknown',
      topRisks: scoring?.summary?.topRisks?.slice(0, 5) || [],
      phasesCompleted: Object.keys(this.results).length,
      reportLocation: this.config.outputDir,
      circuitBreakerStates: Object.fromEntries(
        Object.entries(this.circuitBreakers).map(([k, v]) => [k, v.getState()])
      )
    };
  }

  // ============================================================================
  // MÉTODOS ESTÁTICOS DE CONVENIENCIA
  // ============================================================================

  static async quickScan(target, options = {}) {
    const orchestrator = new SecureScanOrchestrator(options);
    return orchestrator.run(target);
  }

  static async scanWithProfile(target, profile, options = {}) {
    const profiles = {
      quick: {
        scanSequence: ['whatweb', 'nmap', 'zap', 'scoring', 'reporting'],
        tools: {
          nmap: { topPorts: 1000, scripts: 'safe' },
          zap: { activeScan: { enabled: false } }
        }
      },
      standard: {
        scanSequence: ['whatweb', 'nmap', 'gobuster', 'zap', 'exploitdb', 'scoring', 'reporting']
      },
      comprehensive: {
        scanSequence: ['whatweb', 'nmap', 'gobuster', 'zap', 'exploitdb', 'metasploit', 'scoring', 'reporting'],
        tools: {
          nmap: { topPorts: 'all', scripts: 'vuln,vulners,exploit' },
          gobuster: { modes: ['dir', 'dns', 'vhost'] },
          metasploit: { enabled: true, dryRun: false }
        }
      },
      passive: {
        scanSequence: ['whatweb', 'nmap', 'gobuster', 'exploitdb', 'scoring', 'reporting'],
        tools: {
          nmap: { scripts: 'safe' },
          zap: { activeScan: { enabled: false } }
        }
      }
    };

    const config = profiles[profile] || profiles.standard;
    const orchestrator = new SecureScanOrchestrator({ ...config, ...options });
    return orchestrator.run(target);
  }
}

// Exportar clases adicionales para testing
module.exports = SecureScanOrchestrator;
module.exports.CircuitBreaker = CircuitBreaker;
module.exports.FileStabilizer = FileStabilizer;
module.exports.TargetValidator = TargetValidator;
module.exports.ProcessManager = ProcessManager;
