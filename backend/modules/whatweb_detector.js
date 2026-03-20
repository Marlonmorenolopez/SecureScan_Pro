/**
 * ============================================================================
 * SECURITYSCAN PRO - MÓDULO WHATWEB (CORREGIDO - SEGURO)
 * ============================================================================
 * Detección de tecnologías web utilizando WhatWeb
 * 
 * SEGURIDAD IMPLEMENTADA:
 * - Uso de execFile() en lugar de exec() para prevenir RCE
 * - Validación estricta de target con whitelist de caracteres
 * - Sanitización de todos los argumentos pasados al proceso
 * - Timeouts configurables y manejo de errores robusto
 * - No se permite shell injection mediante caracteres especiales
 * ============================================================================
 */

const { execFile } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const https = require('https');
const http = require('http');
const { randomBytes } = require('crypto');
const Logger = require('../utils/logger');

const execFilePromise = util.promisify(execFile);

class WhatWebDetector {
  /**
   * Configuración de seguridad para validación de targets
   */
  static get SECURITY_CONFIG() {
    return {
      // Caracteres permitidos en hostname/URL (whitelist estricta)
      allowedTargetPattern: /^[a-zA-Z0-9][a-zA-Z0-9-._~:\/?#[\]@!$&'()*+,;=]*$/,
      
      // Longitud máxima para prevenir DoS
      maxTargetLength: 2048,
      
      // Protocolos permitidos
      allowedProtocols: ['http:', 'https:'],
      
      // Caracteres prohibidos en shell (defense in depth)
      forbiddenShellChars: /[;&|`$(){}[\]\\]/g,
      
      // Timeout por defecto (segundos)
      defaultTimeout: 60,
      
      // Máximo tamaño de respuesta (bytes)
      maxResponseSize: 10 * 1024 * 1024 // 10MB
    };
  }

  /**
   * Detectar tecnologías del objetivo usando WhatWeb (VERSIÓN SEGURA)
   * @param {string} target - URL o IP objetivo
   * @param {string} outputDir - Directorio de salida
   * @param {object} options - Opciones de detección
   * @returns {object} Tecnologías detectadas
   */
  static async scan(target, outputDir, options = {}) {
    const {
      aggression = 3,
      timeout = WhatWebDetector.SECURITY_CONFIG.defaultTimeout,
      maxThreads = 25,
      userAgent = 'WhatWeb/0.5.5',
      followRedirects = true,
      includeExtra = true
    } = options;

    // ===== VALIDACIÓN DE SEGURIDAD DEL TARGET =====
    const validation = this.validateTarget(target);
    if (!validation.valid) {
      throw new Error(`Target validation failed: ${validation.error}`);
    }

    // Usar target sanitizado
    const sanitizedTarget = validation.sanitized;
    
    // Normalizar target
    let normalizedTarget = sanitizedTarget;
    if (!sanitizedTarget.startsWith('http://') && !sanitizedTarget.startsWith('https://')) {
      normalizedTarget = `http://${sanitizedTarget}`;
    }

    // Validar URL normalizada
    let parsedUrl;
    try {
      parsedUrl = new URL(normalizedTarget);
    } catch (error) {
      throw new Error(`Invalid URL format after normalization: ${normalizedTarget}`);
    }

    // Verificar protocolo permitido
    if (!this.SECURITY_CONFIG.allowedProtocols.includes(parsedUrl.protocol)) {
      throw new Error(`Protocol not allowed: ${parsedUrl.protocol}`);
    }

    // Archivos de salida
    const outputFile = path.join(outputDir, 'whatweb_output.json');
    const verboseOutputFile = path.join(outputDir, 'whatweb_verbose.txt');

    Logger.info(`[WhatWeb] Starting secure scan for: ${normalizedTarget} (aggression level ${aggression})`);

    try {
      const startTime = Date.now();

      // Verificar que whatweb está disponible (usando execFile)
      await this.checkAvailability();

      // Construir argumentos de forma segura (array, no string)
      const whatwebArgs = this.buildSecureCommandArgs(normalizedTarget, {
        aggression,
        maxThreads,
        userAgent,
        followRedirects,
        includeExtra,
        outputFile,
        verboseOutputFile
      });

      Logger.info(`[WhatWeb] Executing: whatweb with ${whatwebArgs.length} arguments`);

      // ===== EJECUCIÓN SEGURA CON execFile =====
      const execOptions = {
        timeout: timeout * 1000,
        maxBuffer: WhatWebDetector.SECURITY_CONFIG.maxResponseSize,
        // Importante: shell: false (default), no expande variables ni ejecuta shell
        shell: false,
        // Kill signal para timeout
        killSignal: 'SIGTERM',
        // Directorio de trabajo
        cwd: process.cwd()
      };

      let stdout, stderr;
      try {
        const result = await execFilePromise('whatweb', whatwebArgs, execOptions);
        stdout = result.stdout;
        stderr = result.stderr;
      } catch (execError) {
        // whatweb retorna exit code 1 si no encuentra resultados, no es necesariamente error
        if (execError.code === 1 && execError.stdout) {
          stdout = execError.stdout;
          stderr = execError.stderr;
        } else {
          throw execError;
        }
      }

      // Parsear resultados
      const results = await this.parseResults(outputFile, normalizedTarget);

      // Si no hay resultados JSON, intentar parsear stdout
      if (!results.technologies.length && stdout) {
        const fallbackResults = this.parseStdout(stdout, normalizedTarget);
        if (fallbackResults.technologies.length > 0) {
          results.technologies = fallbackResults.technologies;
        }
      }

      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      Logger.info(`[WhatWeb] Scan completed in ${duration}s - ${results.technologies.length} technologies detected`);

      results.duration = duration;
      results.aggressionLevel = aggression;
      results.command = 'whatweb [SECURE_EXECUTION]'; // No loggear args por seguridad

      // Guardar resultado consolidado
      fs.writeFileSync(outputFile, JSON.stringify(results, null, 2));

      return results;

    } catch (error) {
      Logger.error('[WhatWeb] Scan error:', error);
      
      // Intentar fallback a análisis manual si WhatWeb falla
      try {
        Logger.warn('[WhatWeb] Attempting manual HTTP analysis fallback...');
        return await this.analyzeManually(normalizedTarget, timeout);
      } catch (manualError) {
        Logger.error('[WhatWeb] Manual analysis also failed:', manualError);
        throw error;
      }
    }
  }

  /**
   * Validar y sanitizar el target de forma segura
   * @param {string} target - Target a validar
   * @returns {object} Resultado de validación {valid, sanitized, error}
   */
  static validateTarget(target) {
    const config = this.SECURITY_CONFIG;

    // Verificar tipo
    if (typeof target !== 'string') {
      return { valid: false, error: 'Target must be a string' };
    }

    // Verificar longitud
    if (target.length === 0 || target.length > config.maxTargetLength) {
      return { 
        valid: false, 
        error: `Target length must be between 1 and ${config.maxTargetLength} characters` 
      };
    }

    // Verificar caracteres prohibidos de shell (defense in depth)
    if (config.forbiddenShellChars.test(target)) {
      return { 
        valid: false, 
        error: 'Target contains forbidden characters' 
      };
    }

    // Verificar patrones peligrosos comunes
    const dangerousPatterns = [
      /\.\./,           // Directory traversal
      /\/\//,           // Double slash (protocol bypass)
      /^\//,            // Absolute path
      /^\\/,            // Windows absolute path
      /[\x00-\x1f\x7f]/ // Control characters
    ];

    for (const pattern of dangerousPatterns) {
      if (pattern.test(target)) {
        return { valid: false, error: 'Target contains dangerous patterns' };
      }
    }

    // Verificar contra whitelist de caracteres permitidos
    // Extraer hostname para validación más estricta
    let hostname;
    try {
      const url = target.startsWith('http') ? new URL(target) : new URL(`http://${target}`);
      hostname = url.hostname;
    } catch {
      // Si no es URL válida, tratar como string plana
      hostname = target;
    }

    if (!config.allowedTargetPattern.test(hostname)) {
      return { valid: false, error: 'Target contains invalid characters' };
    }

    // Sanitización final: trim y remover caracteres de control
    const sanitized = target.trim().replace(/[\x00-\x1f\x7f]/g, '');

    return { valid: true, sanitized };
  }

  /**
   * Verificar que WhatWeb está instalado (VERSIÓN SEGURA)
   */
  static async checkAvailability() {
    try {
      // Usar execFile en lugar de exec
      const { stdout: whichOutput } = await execFilePromise('which', ['whatweb'], {
        timeout: 5000,
        shell: false
      });
      
      const versionResult = await execFilePromise('whatweb', ['--version'], {
        timeout: 5000,
        shell: false
      });
      
      Logger.info(`[WhatWeb] Available at: ${whichOutput.trim()} - Version: ${versionResult.stdout.trim()}`);
      return true;
    } catch (error) {
      throw new Error(
        'WhatWeb is not installed. Install with: sudo apt install whatweb\n' +
        'Or visit: https://github.com/urbanadventurer/WhatWeb'
      );
    }
  }

  /**
   * Construir argumentos del comando WhatWeb de forma SEGURA (array)
   * NUNCA concatenar strings para evitar inyección
   */
  static buildSecureCommandArgs(target, options) {
    const args = [];

    // Nivel de agresividad
    args.push('-a', options.aggression.toString());
    
    // Threads simultáneos
    args.push('-t', options.maxThreads.toString());
    
    // User-Agent (validado)
    if (typeof options.userAgent === 'string' && options.userAgent.length < 256) {
      args.push('-U', options.userAgent);
    }
    
    // No mostrar progreso en pantalla
    args.push('-q');
    
    // Suprimir errores
    args.push('--no-errors');
    
    // Log JSON
    args.push('--log-json', options.outputFile);

    // Log verbose adicional
    if (options.verboseOutputFile) {
      args.push('--log-verbose', options.verboseOutputFile);
    }

    // Seguir redirects
    if (options.followRedirects) {
      args.push('--follow-redirects');
    }

    // Target URL (último argumento, ya validado)
    args.push(target);

    return args;
  }

  /**
   * Parsear resultados JSON de WhatWeb
   */
  static async parseResults(jsonFile, targetUrl) {
    const results = {
      url: targetUrl,
      technologies: [],
      plugins: {},
      meta: {
        status: null,
        ip: null,
        country: null,
        poweredBy: null
      },
      headers: {},
      stats: {
        totalDetected: 0,
        categoriesFound: 0
      },
      duration: 0,
      aggressionLevel: 3
    };

    try {
      if (!fs.existsSync(jsonFile)) {
        Logger.warn(`[WhatWeb] JSON file not found: ${jsonFile}`);
        return results;
      }

      const rawContent = fs.readFileSync(jsonFile, 'utf8');
      
      // WhatWeb puede generar múltiples líneas JSON
      const lines = rawContent.split('\n').filter(line => line.trim());
      let parsedData = null;

      for (const line of lines) {
        try {
          const entry = JSON.parse(line);
          if (entry.target === targetUrl || entry.target === new URL(targetUrl).hostname) {
            parsedData = entry;
            break;
          }
          if (!parsedData) parsedData = entry;
        } catch {
          continue;
        }
      }

      if (!parsedData) {
        try {
          parsedData = JSON.parse(rawContent);
        } catch {
          Logger.warn('[WhatWeb] Could not parse JSON output');
          return results;
        }
      }

      // Extraer metadatos
      results.meta.status = parsedData.status || null;
      results.meta.ip = parsedData.ip || null;
      results.meta.country = parsedData.country || null;

      // Procesar plugins detectados
      if (parsedData.plugins) {
        Object.entries(parsedData.plugins).forEach(([pluginName, pluginData]) => {
          const tech = this.normalizePlugin(pluginName, pluginData);
          if (tech) {
            results.technologies.push(tech);
            results.plugins[pluginName] = pluginData;
          }
        });
      }

      // Extraer headers
      if (parsedData.headers) {
        results.headers = parsedData.headers;
        results.meta.poweredBy = parsedData.headers['X-Powered-By'] || null;
      }

      // Calcular estadísticas
      results.stats.totalDetected = results.technologies.length;
      const categories = new Set(results.technologies.map(t => t.category).filter(Boolean));
      results.stats.categoriesFound = categories.size;

    } catch (error) {
      Logger.error('[WhatWeb] Error parsing results:', error);
    }

    return results;
  }

  /**
   * Normalizar plugin de WhatWeb a formato estándar
   */
  static normalizePlugin(name, data) {
    const categoryMap = {
      'WordPress': { category: 'CMS', icon: 'wordpress' },
      'Drupal': { category: 'CMS', icon: 'drupal' },
      'Joomla': { category: 'CMS', icon: 'joomla' },
      'Magento': { category: 'Ecommerce', icon: 'magento' },
      'PrestaShop': { category: 'Ecommerce', icon: 'prestashop' },
      'Apache': { category: 'Web servers', icon: 'apache' },
      'Nginx': { category: 'Web servers', icon: 'nginx' },
      'IIS': { category: 'Web servers', icon: 'iis' },
      'LiteSpeed': { category: 'Web servers', icon: 'litespeed' },
      'PHP': { category: 'Programming languages', icon: 'php' },
      'Python': { category: 'Programming languages', icon: 'python' },
      'Ruby': { category: 'Programming languages', icon: 'ruby' },
      'Node.js': { category: 'Programming languages', icon: 'nodejs' },
      'Express': { category: 'Web frameworks', icon: 'express' },
      'React': { category: 'JavaScript frameworks', icon: 'react' },
      'Angular': { category: 'JavaScript frameworks', icon: 'angular' },
      'Vue.js': { category: 'JavaScript frameworks', icon: 'vue' },
      'jQuery': { category: 'JavaScript libraries', icon: 'jquery' },
      'Bootstrap': { category: 'UI frameworks', icon: 'bootstrap' },
      'Django': { category: 'Web frameworks', icon: 'django' },
      'Ruby on Rails': { category: 'Web frameworks', icon: 'rails' },
      'Laravel': { category: 'Web frameworks', icon: 'laravel' },
      'MySQL': { category: 'Databases', icon: 'mysql' },
      'PostgreSQL': { category: 'Databases', icon: 'postgresql' },
      'MongoDB': { category: 'Databases', icon: 'mongodb' },
      'Redis': { category: 'Databases', icon: 'redis' },
      'Google Analytics': { category: 'Analytics', icon: 'google-analytics' },
      'Google Tag Manager': { category: 'Tag managers', icon: 'google-tag-manager' },
      'Cloudflare': { category: 'CDN', icon: 'cloudflare' },
      'reCAPTCHA': { category: 'Security', icon: 'recaptcha' },
      'ModSecurity': { category: 'Security', icon: 'modsecurity' }
    };

    const mapping = categoryMap[name] || { category: 'Miscellaneous', icon: 'default' };

    let version = null;
    if (data && Array.isArray(data) && data.length > 0) {
      const firstEntry = data[0];
      if (typeof firstEntry === 'string') {
        version = firstEntry;
      } else if (firstEntry.version) {
        version = firstEntry.version;
      } else if (firstEntry.string) {
        version = firstEntry.string;
      }
    } else if (data && data.version) {
      version = data.version;
    } else if (data && typeof data === 'string') {
      version = data;
    }

    return {
      name: name,
      version: version || null,
      category: mapping.category,
      icon: mapping.icon,
      confidence: 100,
      raw: data
    };
  }

  /**
   * Parsear stdout como fallback
   */
  static parseStdout(stdout, targetUrl) {
    const results = {
      url: targetUrl,
      technologies: [],
      plugins: {},
      meta: {},
      headers: {},
      stats: { totalDetected: 0, categoriesFound: 0 }
    };

    const lines = stdout.split('\n');
    
    for (const line of lines) {
      const match = line.match(/(https?:\/\/\S+)\s+\[(\d+)\s+([^\]]+)\](.*)/);
      if (match) {
        const [, url, status, statusText, pluginsStr] = match;
        results.meta.status = `${status} ${statusText}`;
        
        const pluginMatches = pluginsStr.matchAll(/(\w+)(?:\[([^\]]+)\])?/g);
        for (const [, pluginName, version] of pluginMatches) {
          const tech = this.normalizePlugin(pluginName, version ? [version] : []);
          if (tech && !results.technologies.some(t => t.name === tech.name)) {
            results.technologies.push(tech);
          }
        }
      }
    }

    results.stats.totalDetected = results.technologies.length;
    return results;
  }

  /**
   * Análisis manual de respuesta HTTP (fallback final)
   */
  static async analyzeManually(target, timeout) {
    return new Promise((resolve, reject) => {
      const url = new URL(target);
      const protocol = url.protocol === 'https:' ? https : http;

      const options = {
        hostname: url.hostname,
        port: url.port || (url.protocol === 'https:' ? 443 : 80),
        path: url.pathname || '/',
        method: 'GET',
        timeout: timeout * 1000,
        headers: {
          'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
          'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
          'Accept-Language': 'en-US,en;q=0.5',
          'Accept-Encoding': 'identity',
          'Connection': 'close'
        },
        rejectUnauthorized: false
      };

      const req = protocol.request(options, (res) => {
        let body = '';
        
        res.on('data', chunk => {
          body += chunk;
          if (body.length > 500000) res.destroy();
        });

        res.on('end', () => {
          try {
            const results = this.analyzeResponse(res.headers, body, url);
            results.fallback = true;
            results.method = 'manual';
            resolve(results);
          } catch (error) {
            reject(error);
          }
        });
      });

      req.on('error', reject);
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Timeout in manual analysis'));
      });
      req.end();
    });
  }

  /**
   * Analizar respuesta HTTP para detección manual
   */
  static analyzeResponse(headers, body, url) {
    const technologies = [];
    const categories = {};
    const headersList = {};

    Object.entries(headers).forEach(([key, value]) => {
      headersList[key] = value;
    });

    if (headers['server']) {
      technologies.push(this.identifyServer(headers['server']));
    }

    if (headers['x-powered-by']) {
      technologies.push(this.identifyPoweredBy(headers['x-powered-by']));
    }

    if (headers['set-cookie']) {
      const cookies = Array.isArray(headers['set-cookie']) 
        ? headers['set-cookie'] 
        : [headers['set-cookie']];
      technologies.push(...this.identifyByCookies(cookies));
    }

    if (body) {
      technologies.push(...this.analyzeHtmlBody(body));
    }

    const uniqueTechnologies = [];
    const seen = new Set();

    for (const tech of technologies.flat().filter(Boolean)) {
      const key = `${tech.name}-${tech.version || 'unknown'}`;
      if (!seen.has(key)) {
        seen.add(key);
        uniqueTechnologies.push(tech);
        
        if (tech.category) {
          if (!categories[tech.category]) categories[tech.category] = [];
          categories[tech.category].push(tech.name);
        }
      }
    }

    return {
      url: url.href,
      technologies: uniqueTechnologies,
      categories,
      headers: headersList,
      meta: {
        status: null,
        ip: null,
        poweredBy: headers['x-powered-by'] || null
      },
      stats: {
        totalDetected: uniqueTechnologies.length,
        categoriesFound: Object.keys(categories).length
      }
    };
  }

  // Métodos de detección manual (sin cambios significativos)
  static identifyServer(serverHeader) {
    const servers = [
      { regex: /Apache\/?(\d+\.\d+\.?\d*)?/i, name: 'Apache', category: 'Web servers' },
      { regex: /nginx\/?(\d+\.\d+\.?\d*)?/i, name: 'nginx', category: 'Web servers' },
      { regex: /Microsoft-IIS\/?(\d+\.?\d*)?/i, name: 'IIS', category: 'Web servers' },
      { regex: /LiteSpeed/i, name: 'LiteSpeed', category: 'Web servers' },
      { regex: /Cloudflare/i, name: 'Cloudflare', category: 'CDN' },
      { regex: /openresty\/?(\d+\.\d+\.?\d*)?/i, name: 'OpenResty', category: 'Web servers' },
      { regex: /Caddy/i, name: 'Caddy', category: 'Web servers' }
    ];

    for (const server of servers) {
      const match = serverHeader.match(server.regex);
      if (match) {
        return {
          name: server.name,
          version: match[1] || null,
          category: server.category,
          confidence: 100
        };
      }
    }

    return {
      name: serverHeader.split('/')[0],
      version: serverHeader.split('/')[1] || null,
      category: 'Web servers',
      confidence: 50
    };
  }

  static identifyPoweredBy(poweredBy) {
    const frameworks = [
      { regex: /PHP\/?(\d+\.\d+\.?\d*)?/i, name: 'PHP', category: 'Programming languages' },
      { regex: /ASP\.NET/i, name: 'ASP.NET', category: 'Web frameworks' },
      { regex: /Express/i, name: 'Express', category: 'Web frameworks' },
      { regex: /Next\.js/i, name: 'Next.js', category: 'Web frameworks' },
      { regex: /Servlet\/?(\d+\.?\d*)?/i, name: 'Java Servlet', category: 'Web frameworks' }
    ];

    for (const fw of frameworks) {
      const match = poweredBy.match(fw.regex);
      if (match) {
        return {
          name: fw.name,
          version: match[1] || null,
          category: fw.category,
          confidence: 100
        };
      }
    }

    return {
      name: poweredBy,
      category: 'Miscellaneous',
      confidence: 50
    };
  }

  static identifyByCookies(cookies) {
    const cookiePatterns = [
      { pattern: /PHPSESSID/i, name: 'PHP', category: 'Programming languages' },
      { pattern: /JSESSIONID/i, name: 'Java', category: 'Programming languages' },
      { pattern: /ASP\.NET_SessionId/i, name: 'ASP.NET', category: 'Web frameworks' },
      { pattern: /laravel_session/i, name: 'Laravel', category: 'Web frameworks' },
      { pattern: /wordpress/i, name: 'WordPress', category: 'CMS' },
      { pattern: /drupal/i, name: 'Drupal', category: 'CMS' },
      { pattern: /joomla/i, name: 'Joomla', category: 'CMS' }
    ];

    const detected = [];
    const cookieStr = cookies.join(' ');

    for (const pattern of cookiePatterns) {
      if (pattern.pattern.test(cookieStr)) {
        detected.push({
          name: pattern.name,
          category: pattern.category,
          confidence: 80
        });
      }
    }

    return detected;
  }

  static analyzeHtmlBody(body) {
    const detected = [];

    const htmlPatterns = [
      { regex: /react/i, name: 'React', category: 'JavaScript frameworks' },
      { regex: /vue\.?js/i, name: 'Vue.js', category: 'JavaScript frameworks' },
      { regex: /angular/i, name: 'Angular', category: 'JavaScript frameworks' },
      { regex: /jquery/i, name: 'jQuery', category: 'JavaScript libraries' },
      { regex: /bootstrap/i, name: 'Bootstrap', category: 'UI frameworks' },
      { regex: /wp-content|wordpress/i, name: 'WordPress', category: 'CMS' },
      { regex: /google-analytics|gtag/i, name: 'Google Analytics', category: 'Analytics' }
    ];

    for (const pattern of htmlPatterns) {
      if (pattern.regex.test(body)) {
        detected.push({
          name: pattern.name,
          category: pattern.category,
          confidence: 70
        });
      }
    }

    return detected;
  }

  /**
   * Escaneo rápido (baja agresividad)
   */
  static async quickScan(target, outputDir) {
    return this.scan(target, outputDir, {
      aggression: 1,
      timeout: 30,
      maxThreads: 10
    });
  }

  /**
   * Escaneo profundo (alta agresividad)
   */
  static async deepScan(target, outputDir) {
    return this.scan(target, outputDir, {
      aggression: 4,
      timeout: 120,
      maxThreads: 50,
      includeExtra: true
    });
  }

  /**
   * Verificar estado de WhatWeb
   */
  static async getStatus() {
    try {
      const { stdout: version } = await execFilePromise('whatweb', ['--version'], {
        timeout: 5000,
        shell: false
      });
      
      // Contar plugins de forma segura
      let pluginCount = 0;
      try {
        const { stdout: pluginsOutput } = await execFilePromise('whatweb', ['--list-plugins'], {
          timeout: 10000,
          shell: false
        });
        pluginCount = pluginsOutput.split('\n').length;
      } catch {
        // Ignorar error de conteo
      }
      
      return {
        installed: true,
        version: version.trim(),
        pluginCount: pluginCount,
        method: 'whatweb-cli-secure'
      };
    } catch (error) {
      return {
        installed: false,
        error: error.message
      };
    }
  }
}

module.exports = WhatWebDetector;
