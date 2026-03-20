/**
 * ============================================================================
 * SECURITYSCAN PRO - MÓDULO GOBUSTER MEJORADO (CORREGIDO - RCE PREVENIDO)
 * ============================================================================
 * Descubrimiento de directorios, subdominios, virtual hosts y cloud storage
 * 
 * MEJORAS DE SEGURIDAD:
 * - Reemplazo de exec() por execFile() para prevenir inyección de comandos
 * - Validación estricta de URLs, dominios y todos los parámetros de entrada
 * - Eliminación de concatenación de strings en comandos
 * ============================================================================
 */

const { execFile } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const Logger = require('../utils/logger');

const execFilePromise = util.promisify(execFile);

class GobusterScanner {
  /**
   * Modos de operación soportados
   */
  static MODES = {
    DIR: 'dir',
    DNS: 'dns',
    VHOST: 'vhost',
    FUZZ: 'fuzz',
    S3: 's3',
    GCS: 'gcs',
    TFTP: 'tftp'
  };

  /**
   * Validación estricta de target según modo
   */
  static validateTarget(target, mode) {
    if (!target || typeof target !== 'string') {
      throw new Error('Target es requerido y debe ser string');
    }

    const trimmed = target.trim();

    // Whitelist base de caracteres seguros
    const safePattern = /^[a-zA-Z0-9.\-:_/]+$/;
    
    if (!safePattern.test(trimmed)) {
      throw new Error(`Target contiene caracteres no permitidos: ${trimmed}`);
    }

    // Bloquear patrones peligrosos
    const dangerousPatterns = [
      /;.*$/m, /\|/g, /&/g, /`/g, /\$/g, /\(/g, /\)/g, /</g, />/g, 
      /\\/g, /\{\}/g, /\[\]/g, /[\n\r]/g, /\0/g
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(trimmed)) {
        throw new Error(`Target contiene caracteres de shell peligrosos: ${trimmed}`);
      }
    }

    // Validación específica por modo
    switch (mode) {
      case 'dir':
      case 'vhost':
      case 'fuzz':
        // Debe ser URL válida o IP con path opcional
        if (!this.isValidUrlOrIp(trimmed)) {
          throw new Error(`Target inválido para modo ${mode}: debe ser URL o IP válida`);
        }
        break;
        
      case 'dns':
        // Debe ser dominio válido
        if (!this.isValidDomain(trimmed)) {
          throw new Error(`Target inválido para modo DNS: debe ser dominio válido`);
        }
        break;
        
      case 's3':
      case 'gcs':
      case 'tftp':
        // Bucket names tienen restricciones específicas
        if (!/^[a-z0-9.\-]{3,63}$/.test(trimmed)) {
          throw new Error(`Bucket name inválido: ${trimmed}`);
        }
        break;
    }

    if (trimmed.length > 253) {
      throw new Error('Target excede longitud máxima permitida (253 caracteres)');
    }

    return trimmed;
  }

  /**
   * Validar si es URL o IP válida
   */
  static isValidUrlOrIp(str) {
    // Patrón para URL básica o IP
    const urlPattern = /^(https?:\/\/)?([\da-z.\-]+)(:\d+)?(\/.*)?$/i;
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}(:\d+)?(\/.*)?$/;
    const ipv6Pattern = /^([0-9a-fA-F:]+)(:\d+)?(\/.*)?$/;
    
    return urlPattern.test(str) || ipv4Pattern.test(str) || ipv6Pattern.test(str);
  }

  /**
   * Validar nombre de dominio
   */
  static isValidDomain(str) {
    // Remover protocolo si existe
    const domain = str.replace(/^https?:\/\//, '').split('/')[0];
    // Validar formato de dominio
    const domainPattern = /^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?)*$/;
    return domainPattern.test(domain) && domain.length <= 253;
  }

  /**
   * Validación de opciones de escaneo
   */
  static validateOptions(options) {
    const validated = {};

    // Validar modo
    if (options.mode) {
      const validModes = Object.values(this.MODES);
      if (!validModes.includes(options.mode)) {
        throw new Error(`Modo inválido: ${options.mode}. Modos válidos: ${validModes.join(', ')}`);
      }
      validated.mode = options.mode;
    } else {
      validated.mode = 'dir';
    }

    // Validar threads: número entre 1 y 200
    if (options.threads !== undefined) {
      const threads = parseInt(options.threads, 10);
      if (isNaN(threads) || threads < 1 || threads > 200) {
        throw new Error('Threads debe ser número entre 1 y 200');
      }
      validated.threads = threads;
    } else {
      validated.threads = 50;
    }

    // Validar timeout: número positivo
    if (options.timeout !== undefined) {
      const timeout = parseInt(options.timeout, 10);
      if (isNaN(timeout) || timeout <= 0 || timeout > 300) {
        throw new Error('Timeout debe ser número positivo (máx 300 segundos)');
      }
      validated.timeout = timeout;
    } else {
      validated.timeout = 10;
    }

    // Validar wordlist: path seguro
    if (options.wordlist) {
      const wordlist = String(options.wordlist);
      // Solo permitir paths absolutos en directorios conocidos
      const allowedPrefixes = [
        '/usr/share/wordlists/',
        '/opt/',
        '/tmp/',
        './wordlists/'
      ];
      
      const isAllowed = allowedPrefixes.some(prefix => wordlist.startsWith(prefix));
      if (!isAllowed) {
        throw new Error(`Wordlist path no permitido: ${wordlist}. Use directorios autorizados.`);
      }
      
      // Validar que no contenga traversal
      if (wordlist.includes('..') || wordlist.includes('~')) {
        throw new Error('Wordlist path contiene caracteres de traversal');
      }
      
      validated.wordlist = wordlist;
    } else {
      validated.wordlist = '/usr/share/wordlists/dirb/common.txt';
    }

    // Validar wordlistOffset
    if (options.wordlistOffset !== undefined) {
      const offset = parseInt(options.wordlistOffset, 10);
      if (isNaN(offset) || offset < 0 || offset > 10000000) {
        throw new Error('wordlistOffset debe ser número positivo razonable');
      }
      validated.wordlistOffset = offset;
    } else {
      validated.wordlistOffset = 0;
    }

    // Validar status codes: solo números, comas y guiones
    if (options.statusCodes) {
      const codes = String(options.statusCodes);
      if (!/^[0-9,\-]+$/.test(codes)) {
        throw new Error('statusCodes contiene caracteres inválidos');
      }
      validated.statusCodes = codes;
    } else {
      validated.statusCodes = '200,204,301,302,307,401,403,405,500';
    }

    // Validar extensions: solo letras, números y comas
    if (options.extensions) {
      const ext = String(options.extensions);
      if (!/^[a-zA-Z0-9,]+$/.test(ext)) {
        throw new Error('extensions contiene caracteres inválidos');
      }
      validated.extensions = ext;
    }

    // Validar method: solo letras mayúsculas
    if (options.method) {
      const method = String(options.method).toUpperCase();
      if (!/^[A-Z]+$/.test(method) || method.length > 10) {
        throw new Error('Método HTTP inválido');
      }
      validated.method = method;
    } else {
      validated.method = 'GET';
    }

    // Validar userAgent: longitud razonable, sin caracteres de control
    if (options.userAgent) {
      const ua = String(options.userAgent);
      if (ua.length > 500 || /[\x00-\x1F\x7F]/.test(ua)) {
        throw new Error('User-Agent inválido');
      }
      validated.userAgent = ua;
    } else {
      validated.userAgent = 'gobuster/3.6';
    }

    // Flags booleanos
    validated.randomAgent = options.randomAgent === true;
    validated.followRedirects = options.followRedirects === true;
    validated.expanded = options.expanded !== false;
    validated.noProgress = options.noProgress !== false;
    validated.quiet = options.quiet === true;
    validated.debug = options.debug === true;
    validated.skipSSL = options.skipSSL === true;

    // Validar proxy: URL básica
    if (options.proxy) {
      const proxy = String(options.proxy);
      const proxyPattern = /^https?:\/\/[a-zA-Z0-9.\-]+(:\d+)?$/;
      if (!proxyPattern.test(proxy)) {
        throw new Error('Formato de proxy inválido');
      }
      validated.proxy = proxy;
    }

    // Opciones específicas por modo
    validated.dirOptions = {
      force: options.dirOptions?.force === true
    };

    validated.dnsOptions = {
      showIPs: options.dnsOptions?.showIPs === true,
      showCNAME: options.dnsOptions?.showCNAME !== false,
      wildcard: options.dnsOptions?.wildcard === true,
      noFQDN: options.dnsOptions?.noFQDN === true
    };

    if (options.dnsOptions?.resolver) {
      const resolver = String(options.dnsOptions.resolver);
      if (!this.isValidIp(resolver)) {
        throw new Error('DNS resolver inválido');
      }
      validated.dnsOptions.resolver = resolver;
    }

    validated.vhostOptions = {
      appendDomain: options.vhostOptions?.appendDomain !== false
    };

    if (options.vhostOptions?.excludeHostLength !== undefined) {
      const len = parseInt(options.vhostOptions.excludeHostLength, 10);
      if (!isNaN(len) && len >= 0) {
        validated.vhostOptions.excludeHostLength = len;
      }
    }

    validated.fuzzOptions = {
      data: options.fuzzOptions?.data
    };

    validated.cloudOptions = {
      maxFiles: options.cloudOptions?.maxFiles || 100
    };

    return validated;
  }

  /**
   * Validar dirección IP
   */
  static isValidIp(ip) {
    const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
    const ipv6Pattern = /^[0-9a-fA-F:]+$/;
    return ipv4Pattern.test(ip) || ipv6Pattern.test(ip);
  }

  /**
   * Configuración por defecto optimizada
   */
  static get DEFAULT_CONFIG() {
    return {
      mode: 'dir',
      threads: 50,
      timeout: 10,
      wordlist: '/usr/share/wordlists/dirb/common.txt',
      wordlistOffset: 0,
      statusCodes: '200,204,301,302,307,401,403,405,500',
      expanded: true,
      noProgress: true,
      quiet: false,
      debug: false
    };
  }

  /**
   * Ejecutar escaneo Gobuster según modo
   */
  static async scan(target, outputDir, options = {}) {
    // Validación estricta de entrada
    const validatedOptions = this.validateOptions(options);
    const validatedTarget = this.validateTarget(target, validatedOptions.mode);
    
    // Normalizar target según modo
    const normalizedTarget = this.normalizeTarget(validatedTarget, validatedOptions.mode);
    
    // Generar nombre de archivo
    const timestamp = Date.now();
    const baseName = `gobuster_${validatedOptions.mode}_${this.sanitizeFilename(normalizedTarget)}_${timestamp}`;
    const outputFile = path.join(outputDir, `${baseName}.txt`);

    Logger.info(`[GOBUSTER] Iniciando escaneo ${validatedOptions.mode.toUpperCase()} contra: ${normalizedTarget}`);
    Logger.info(`[GOBUSTER] Threads: ${validatedOptions.threads}, Wordlist: ${validatedOptions.wordlist}`);

    try {
      const startTime = Date.now();

      // Verificar disponibilidad
      await this.checkAvailability();

      // Construir comando según modo (array de argumentos, nunca string concatenado)
      const gobusterArgs = this.buildCommandArgs(normalizedTarget, validatedOptions, outputFile);
      
      Logger.info(`[GOBUSTER] Comando: gobuster ${gobusterArgs.slice(0, 10).join(' ')}...`);

      // EJECUCIÓN SEGURA: execFile en lugar de exec con timeout
      const { stdout, stderr } = await this.executeWithTimeout(
        'gobuster',
        gobusterArgs,
        {
          timeout: this.calculateTimeout(validatedOptions),
          maxBuffer: 10 * 1024 * 1024
        }
      );

      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      Logger.info(`[GOBUSTER] Escaneo completado en ${duration}s`);

      // Parsear resultados
      const results = await this.parseResults(stdout, outputFile, validatedOptions.mode, normalizedTarget);
      
      // Enriquecer según modo
      await this.enrichResults(results, validatedOptions);
      
      // Calcular estadísticas
      results.stats = this.calculateStats(results, validatedOptions.mode);
      results.duration = duration;
      results.config = {
        mode: validatedOptions.mode,
        threads: validatedOptions.threads,
        wordlist: validatedOptions.wordlist
      };

      // Guardar JSON
      const jsonFile = path.join(outputDir, `${baseName}.json`);
      fs.writeFileSync(jsonFile, JSON.stringify(results, null, 2));

      return results;

    } catch (error) {
      Logger.error('[GOBUSTER] Error en escaneo:', error);
      
      // Intentar recuperar resultados parciales
      if (fs.existsSync(outputFile)) {
        try {
          const partial = await this.parseResults('', outputFile, validatedOptions.mode, normalizedTarget);
          partial.error = error.message;
          partial.partial = true;
          return partial;
        } catch (parseError) {
          Logger.error('[GOBUSTER] Error parseando resultados parciales:', parseError);
        }
      }
      
      throw error;
    }
  }

  /**
   * Construir array de argumentos para Gobuster (NUNCA concatenar strings)
   */
  static buildCommandArgs(target, config, outputFile) {
    const args = [config.mode];

    // Target según modo
    switch (config.mode) {
      case 'dns':
        args.push('-d', target);
        break;
      case 'dir':
      case 'vhost':
      case 'fuzz':
        args.push('-u', target);
        break;
      case 's3':
      case 'gcs':
      case 'tftp':
        if (config.bucket) {
          args.push('-b', config.bucket);
        }
        break;
    }

    // Wordlist
    if (config.wordlist && !['s3', 'gcs'].includes(config.mode)) {
      args.push('-w', config.wordlist);
    }

    // Wordlist offset
    if (config.wordlistOffset > 0) {
      args.push('--wordlist-offset', config.wordlistOffset.toString());
    }

    // Threads
    args.push('-t', config.threads.toString());

    // Timeout
    args.push('--timeout', `${config.timeout}s`);

    // Status codes
    if (config.statusCodes && config.mode !== 'dns') {
      args.push('-s', config.statusCodes);
    }

    // Extensions
    if (config.extensions && config.mode === 'dir') {
      args.push('-x', config.extensions);
    }

    // Method
    if (config.method !== 'GET') {
      args.push('-m', config.method);
    }

    // User-Agent
    if (config.randomAgent) {
      args.push('--random-agent');
    } else if (config.userAgent) {
      args.push('-a', config.userAgent);
    }

    // Follow redirects
    if (config.followRedirects) {
      args.push('-r');
    }

    // Skip SSL
    if (config.skipSSL) {
      args.push('-k');
    }

    // Proxy
    if (config.proxy) {
      args.push('--proxy', config.proxy);
    }

    // DNS options
    if (config.mode === 'dns') {
      if (config.dnsOptions.resolver) {
        args.push('-r', config.dnsOptions.resolver);
      }
      if (config.dnsOptions.showIPs) {
        args.push('-i');
      }
      if (config.dnsOptions.wildcard) {
        args.push('--wildcard');
      }
      if (config.dnsOptions.noFQDN) {
        args.push('--no-fqdn');
      }
    }

    // VHOST options
    if (config.mode === 'vhost') {
      if (config.vhostOptions.appendDomain) {
        args.push('--append-domain');
      }
      if (config.vhostOptions.excludeHostLength !== undefined) {
        args.push('--exclude-hostname-length', config.vhostOptions.excludeHostLength.toString());
      }
    }

    // DIR options
    if (config.mode === 'dir' && config.dirOptions.force) {
      args.push('--force');
    }

    // Output options
    args.push('-o', outputFile);
    
    if (config.expanded) {
      args.push('-e');
    }
    
    if (config.noProgress) {
      args.push('--no-progress');
    }
    
    if (config.quiet) {
      args.push('-q');
    }

    if (config.debug) {
      args.push('--debug');
    }

    return args;
  }

  /**
   * Ejecución segura con timeout usando execFile
   */
  static async executeWithTimeout(command, args, options) {
    return new Promise((resolve, reject) => {
      const child = execFile(
        command,
        args,
        {
          timeout: options.timeout,
          maxBuffer: options.maxBuffer,
          killSignal: 'SIGTERM'
        },
        (error, stdout, stderr) => {
          if (error) {
            // Gobuster a veces retorna error por timeouts individuales pero con output válido
            if (stdout && stdout.includes('http')) {
              resolve({ stdout, stderr });
            } else {
              reject(error);
            }
          } else {
            resolve({ stdout, stderr });
          }
        }
      );

      // Timeout manual adicional como respaldo
      const timeoutId = setTimeout(() => {
        child.kill('SIGTERM');
        setTimeout(() => {
          if (!child.killed) {
            child.kill('SIGKILL');
          }
        }, 5000);
      }, options.timeout);

      child.on('exit', () => {
        clearTimeout(timeoutId);
      });
    });
  }

  /**
   * Parsear resultados según modo
   */
  static async parseResults(stdout, outputFile, mode, target) {
    const results = {
      target,
      mode,
      scanTime: new Date().toISOString(),
      found: [],
      errors: [],
      stats: {
        totalTested: 0,
        found: 0,
        errors: 0
      }
    };

    try {
      let output = stdout;
      if (fs.existsSync(outputFile)) {
        output = fs.readFileSync(outputFile, 'utf8');
      }

      const lines = output.split('\n').filter(l => l.trim());

      for (const line of lines) {
        if (line.startsWith('Gobuster') || 
            line.startsWith('Starting') ||
            line.includes('[+]')) {
          continue;
        }

        const parsed = this.parseLine(line, mode);
        if (parsed) {
          if (parsed.type === 'result') {
            results.found.push(parsed.data);
          } else if (parsed.type === 'error') {
            results.errors.push(parsed.data);
          }
        }
      }

      const lastLine = lines[lines.length - 1];
      if (lastLine && lastLine.includes('tested')) {
        const statsMatch = lastLine.match(/(\d+)\s+tested.*?(\d+)\s+found/i);
        if (statsMatch) {
          results.stats.totalTested = parseInt(statsMatch[1], 10);
          results.stats.found = parseInt(statsMatch[2], 10);
        }
      } else {
        results.stats.found = results.found.length;
      }

    } catch (error) {
      Logger.error('[GOBUSTER] Error parseando resultados:', error);
      results.parseError = error.message;
    }

    return results;
  }

  /**
   * Parsear línea individual según modo
   */
  static parseLine(line, mode) {
    if (mode === 'dir') {
      const dirMatch = line.match(/(https?:\/\/\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]/);
      if (dirMatch) {
        return {
          type: 'result',
          data: {
            url: dirMatch[1],
            status: parseInt(dirMatch[2], 10),
            size: parseInt(dirMatch[3], 10),
            type: 'directory'
          }
        };
      }

      const fileMatch = line.match(/(https?:\/\/\S+\.[a-zA-Z0-9]+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]/);
      if (fileMatch) {
        return {
          type: 'result',
          data: {
            url: fileMatch[1],
            status: parseInt(fileMatch[2], 10),
            size: parseInt(fileMatch[3], 10),
            type: 'file',
            extension: path.extname(new URL(fileMatch[1]).pathname)
          }
        };
      }
    }

    if (mode === 'dns') {
      const dnsMatch = line.match(/Found:\s+(\S+)(?:\s+\[(.*?)\])?/);
      if (dnsMatch) {
        return {
          type: 'result',
          data: {
            subdomain: dnsMatch[1],
            records: dnsMatch[2] ? dnsMatch[2].split(',').map(r => r.trim()) : [],
            type: 'subdomain'
          }
        };
      }
    }

    if (mode === 'vhost') {
      const vhostMatch = line.match(/Found:\s+(\S+)\s+\(Status:\s+(\d+)\)\s+\[Size:\s+(\d+)\]/);
      
