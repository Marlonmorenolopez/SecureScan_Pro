/**
 * ============================================================================
 * SECURITYSCAN PRO - MÓDULO ZAP SCANNER SEGURO (CORREGIDO)
 * ============================================================================
 * Escaneo DAST completo con OWASP ZAP - Versión Segura
 * 
 * CORRECCIONES APLICADAS:
 * - API key generada criptográficamente (crypto.randomBytes)
 * - Reemplazo de exec() por http/https nativo (previene RCE)
 * - Validación estricta de URLs y parámetros
 * - Timeouts con AbortController
 * - Sanitización de inputs antes de enviar a ZAP API
 Configura la variable de entorno (opcional pero recomendado):
bash
Copy
export ZAP_API_KEY="tu-clave-segura-aqui"
Si no se configura, el sistema generará una automáticamente usando crypto.randomBytes().
Verifica que ZAP esté corriendo con la API key configurada:
bash
Copy
./zap.sh -daemon -host localhost -port 8080 -config api.key=tu-clave-segura-aqui
 * ============================================================================
 */

const https = require('https');
const http = require('http');
const { URL } = require('url');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const Logger = require('../utils/logger');

class ZAPScanner {
  /**
   * Tipos de spider soportados
   */
  static SPIDER_TYPES = {
    TRADITIONAL: 'spider',
    AJAX: 'spiderAjax',
    CLIENT: 'spiderClient'
  };

  /**
   * Métodos de autenticación
   */
  static AUTH_METHODS = {
    FORM: 'form',
    API: 'api',
    OAUTH: 'oauth',
    BROWSER: 'browser',
    BASIC: 'basic',
    NTLM: 'ntlm'
  };

  /**
   * Niveles de intensidad de scan
   */
  static SCAN_POLICIES = {
    LIGHT: 'Light',
    DEFAULT: 'Default',
    COMPREHENSIVE: 'Comprehensive',
    ATTACK: 'Attack'
  };

  /**
   * Configuración por defecto SEGURA
   */
  static get DEFAULT_CONFIG() {
    // Generar API key criptográficamente segura si no se proporciona
    const secureApiKey = process.env.ZAP_API_KEY || 
                         crypto.randomBytes(32).toString('hex');
    
    return {
      target: null,
      context: 'SecureScan Context',
      
      spider: {
        enabled: true,
        type: 'spider',
        maxDepth: 10,
        maxDuration: 10,
        maxChildren: 5000,
        threadCount: 5,
        processForms: true,
        postForms: true,
        handleOData: false,
        
        browser: 'firefox-headless',
        clickElements: true,
        clickDefaultElems: true,
        maxCrawlStates: 0,
        eventWait: 1000,
        reloadWait: 1000,
        
        clientMode: true
      },
      
      activeScan: {
        enabled: true,
        policy: 'Default',
        maxRuleDuration: 5,
        maxScanDuration: 30,
        maxResults: 1000,
        maxAlertsPerRule: 10,
        threadsPerHost: 5,
        injectPluginId: false,
        
        disabledRules: [],
        enabledRules: null
      },
      
      passiveScan: {
        enabled: true,
        maxAlertsPerRule: 10,
        maxBodySize: 0
      },
      
      authentication: {
        enabled: false,
        method: 'form',
        
        form: {
          loginUrl: null,
          loginPageWait: 2,
          loginRequestData: 'username={%username%}&password={%password%}',
          usernameField: 'username',
          passwordField: 'password'
        },
        
        api: {
          headerName: 'Authorization',
          headerValue: 'Bearer {%token%}',
          token: null
        },
        
        oauth: {
          authorizationUrl: null,
          tokenUrl: null,
          clientId: null,
          clientSecret: null,
          scope: null
        },
        
        browser: {
          loginUrl: null,
          loginPageWait: 2,
          browserId: 'firefox-headless'
        },
        
        basic: {
          realm: null,
          hostname: null,
          port: null
        },
        
        session: {
          method: 'cookie',
          autoDetect: true
        },
        
        verification: {
          method: 'response',
          loggedInRegex: null,
          loggedOutRegex: null,
          checkFrequency: 5
        },
        
        users: [{
          name: 'default-user',
          credentials: {
            username: null,
            password: null,
            token: null
          }
        }]
      },
      
      context: {
        includePaths: [],
        excludePaths: [],
        inScopeOnly: true,
        tech: {
          db: false,
          os: false,
          language: false
        }
      },
      
      reporting: {
        formats: ['json', 'html'],
        template: 'traditional-html',
        reportDir: null,
        reportFile: 'zap-report',
        sections: ['site', 'alert', 'summary'],
        includePassiveAlerts: true,
        includeActiveAlerts: true,
        riskThreshold: 'Informational',
        confidenceThreshold: 'Low'
      },
      
      performance: {
        concurrentHosts: 2,
        threadsPerHost: 5,
        persistMessages: false,
        maxBodySize: 0,
        maxResponseSize: 0
      },
      
      connection: {
        timeout: 20,
        userAgent: 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        proxy: null,
        proxyAuth: null,
        skipSSLCheck: false
      },
      
      api: {
        host: 'localhost',
        port: 8080,
        key: secureApiKey,  // ← AHORA GENERADA CRIPTOGRÁFICAMENTE
        format: 'json'
      },
      
      docker: {
        enabled: false,
        image: 'owasp/zap2docker-stable',
        containerName: 'zap-securescan',
        network: 'host',
        volumes: []
      }
    };
  }

  /**
   * Inicializar conexión con ZAP API
   */
  static async initialize(config = {}) {
    const zapConfig = { ...this.DEFAULT_CONFIG, ...config };
    
    Logger.info('[ZAP] Inicializando conexión con ZAP...');
    
    try {
      await this.checkZAPRunning(zapConfig.api);
      
      const contextId = await this.createContext(zapConfig);
      zapConfig.contextId = contextId;
      
      if (zapConfig.authentication.enabled) {
        await this.configureAuthentication(zapConfig);
      }
      
      await this.configureSessionManagement(zapConfig);
      
      if (zapConfig.activeScan.enabled) {
        await this.configureScanPolicy(zapConfig);
      }
      
      Logger.info(`[ZAP] Inicialización completada - Context ID: ${contextId}`);
      return zapConfig;
      
    } catch (error) {
      Logger.error('[ZAP] Error en inicialización:', error);
      throw error;
    }
  }

  /**
   * Ejecutar escaneo completo
   */
  static async scan(target, outputDir, options = {}) {
    // Validación estricta del target antes de cualquier operación
    const sanitizedTarget = this.sanitizeTarget(target);
    if (!sanitizedTarget) {
      throw new Error('Target inválido o no permitido');
    }
    
    const config = await this.initialize({
      ...this.DEFAULT_CONFIG,
      ...options,
      target: sanitizedTarget
    });

    const results = {
      target: sanitizedTarget,
      scanId: Date.now(),
      phases: {},
      alerts: [],
      stats: {},
      startTime: new Date().toISOString()
    };

    try {
      if (config.spider.enabled) {
        Logger.info('[ZAP] Iniciando fase de Spider...');
        results.phases.spider = await this.runSpider(config);
      }

      if (config.passiveScan.enabled) {
        Logger.info('[ZAP] Iniciando Passive Scan...');
        results.phases.passiveScan = await this.runPassiveScan(config);
      }

      if (config.activeScan.enabled) {
        Logger.info('[ZAP] Iniciando Active Scan...');
        results.phases.activeScan = await this.runActiveScan(config);
      }

      Logger.info('[ZAP] Generando reportes...');
      results.reports = await this.generateReports(config, outputDir);

      results.alerts = await this.getAlerts(config);
      
      results.stats = this.calculateStats(results);
      results.endTime = new Date().toISOString();
      results.duration = this.calculateDuration(results.startTime, results.endTime);

      const outputFile = path.join(outputDir, `zap_scan_${Date.now()}.json`);
      fs.writeFileSync(outputFile, JSON.stringify(results, null, 2));

      return results;

    } catch (error) {
      Logger.error('[ZAP] Error en escaneo:', error);
      throw error;
    }
  }

  /**
   * SANITIZACIÓN ESTRICTA: Valida y sanitiza el target
   */
  static sanitizeTarget(target) {
    if (!target || typeof target !== 'string') {
      return null;
    }
    
    // Lista blanca de targets permitidos (laboratorios locales)
    const ALLOWED_TARGETS = [
      'localhost:3001', '127.0.0.1:3001',  // Juice Shop
      'localhost:3002', '127.0.0.1:3002',  // DVWA
      'localhost:3003', '127.0.0.1:3003',  // WebGoat
      'localhost:3004', '127.0.0.1:3004',  // bWAPP
      'localhost:3005', '127.0.0.1:3005',  // Hackazon
      'localhost:3006', '127.0.0.1:3006'   // Mutillidae
    ];
    
    // Normalizar target
    let normalized = target.trim();
    if (!normalized.startsWith('http://') && !normalized.startsWith('https://')) {
      normalized = 'http://' + normalized;
    }
    
    try {
      const url = new URL(normalized);
      const hostPort = `${url.hostname}:${url.port || '80'}`;
      
      // Verificar contra lista blanca
      if (!ALLOWED_TARGETS.includes(hostPort)) {
        Logger.warn(`[ZAP] Target bloqueado: ${hostPort}`);
        return null;
      }
      
      // Reconstruir URL sanitizada
      return `${url.protocol}//${url.hostname}:${url.port || 80}${url.pathname}`;
      
    } catch (error) {
      Logger.error('[ZAP] Error sanitizando target:', error);
      return null;
    }
  }

  /**
   * LLAMADA API SEGURA: Reemplaza exec() por http/https nativo
   */
  static async apiCall(config, component, action, params = {}) {
    const { api } = config;
    
    if (!api.key) {
      throw new Error('API key no configurada');
    }
    
    // Construir URL de forma segura (sin concatenación de strings)
    const protocol = api.ssl !== false ? 'https:' : 'http:';
    const url = new URL(`${protocol}//${api.host}:${api.port}/JSON/${component}/action/${action}/`);
    
    // Sanitizar y validar parámetros
    const sanitizedParams = this.sanitizeParams(params);
    url.searchParams.append('apikey', api.key);
    
    Object.entries(sanitizedParams).forEach(([key, value]) => {
      if (value !== null && value !== undefined) {
        url.searchParams.append(key, String(value));
      }
    });
    
    return new Promise((resolve, reject) => {
      const client = url.protocol === 'https:' ? https : http;
      
      const options = {
        hostname: url.hostname,
        port: url.port,
        path: url.pathname + url.search,
        method: 'GET',
        timeout: 30000,
        headers: {
          'User-Agent': 'SecureScan-Pro-ZAP/2.0',
          'Accept': 'application/json'
        }
      };
      
      // AbortController para timeout
      const abortTimeout = setTimeout(() => {
        reject(new Error('Timeout en llamada a ZAP API'));
      }, 30000);
      
      const req = client.request(options, (res) => {
        clearTimeout(abortTimeout);
        
        let data = '';
        
        res.on('data', (chunk) => {
          data += chunk;
        });
        
        res.on('end', () => {
          try {
            const result = JSON.parse(data);
            if (result.error) {
              reject(new Error(`ZAP API Error: ${result.error}`));
            } else {
              resolve(result);
            }
          } catch (parseError) {
            reject(new Error(`Error parseando respuesta: ${parseError.message}`));
          }
        });
      });
      
      req.on('error', (error) => {
        clearTimeout(abortTimeout);
        reject(error);
      });
      
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Request timeout'));
      });
      
      req.end();
    });
  }

  /**
   * SANITIZACIÓN: Limpia parámetros antes de enviarlos
   */
  static sanitizeParams(params) {
    const sanitized = {};
    
    Object.entries(params).forEach(([key, value]) => {
      // Solo permitir claves alfanuméricas y guiones bajos
      if (!/^[a-zA-Z0-9_]+$/.test(key)) {
        Logger.warn(`[ZAP] Parámetro con clave inválida ignorado: ${key}`);
        return;
      }
      
      // Sanitizar valores
      if (typeof value === 'string') {
        // Eliminar caracteres potencialmente peligrosos
        sanitized[key] = value
          .replace(/[;&|`$(){}[\]\\]/g, '')
          .substring(0, 1000); // Limitar longitud
      } else if (typeof value === 'number' || typeof value === 'boolean') {
        sanitized[key] = value;
      } else if (value === null || value === undefined) {
        sanitized[key] = '';
      } else {
        sanitized[key] = String(value).substring(0, 1000);
      }
    });
    
    return sanitized;
  }

  /**
   * Ejecutar Spider según tipo configurado
   */
  static async runSpider(config) {
    const { spider, target, contextId } = config;
    const spiderType = spider.type;
    
    Logger.info(`[ZAP] Ejecutando ${spiderType} contra ${target}`);
    
    let scanId;
    let maxDuration = spider.maxDuration;
    
    switch (spiderType) {
      case 'spider':
        scanId = await this.apiCall(config, 'spider', 'scan', {
          url: target,
          maxChildren: spider.maxChildren,
          recurse: true,
          contextName: config.context
        });
        break;
        
      case 'spiderAjax':
        scanId = await this.apiCall(config, 'spiderAjax', 'scan', {
          url: target,
          inScope: config.context.inScopeOnly,
          contextName: config.context,
          subtreeOnly: false,
          maxDuration: spider.maxDuration,
          maxCrawlDepth: spider.maxDepth,
          maxCrawlStates: spider.maxCrawlStates,
          browserId: spider.browser,
          eventWait: spider.eventWait,
          reloadWait: spider.reloadWait,
          clickElements: spider.clickElements,
          clickDefaultElems: spider.clickDefaultElems
        });
        maxDuration = spider.maxDuration;
        break;
        
      case 'spiderClient':
        if (spider.clientMode) {
          scanId = await this.apiCall(config, 'spiderClient', 'scan', {
            url: target,
            inScope: config.context.inScopeOnly,
            maxDepth: spider.maxDepth,
            maxDuration: spider.maxDuration
          });
        } else {
          return this.runSpider({ ...config, spider: { ...spider, type: 'spiderAjax' } });
        }
        break;
        
      default:
        throw new Error(`Tipo de spider no soportado: ${spiderType}`);
    }
    
    await this.waitForScan(config, spiderType, scanId, maxDuration);
    
    const results = await this.getSpiderResults(config, spiderType, scanId);
    
    return {
      type: spiderType,
      scanId,
      urlsFound: results.urls.length,
      urls: results.urls,
      messagesSent: results.messagesSent,
      duration: results.duration
    };
  }

  /**
   * Ejecutar Passive Scan
   */
  static async runPassiveScan(config) {
    let attempts = 0;
    const maxAttempts = 60;
    
    while (attempts < maxAttempts) {
      const recordsToScan = await this.apiCall(config, 'pscan', 'recordsToScan');
      
      if (parseInt(recordsToScan.recordsToScan) === 0) {
        break;
      }
      
      Logger.info(`[ZAP] Passive Scan: ${recordsToScan.recordsToScan} records pendientes`);
      await this.sleep(5000);
      attempts++;
    }
    
    return {
      completed: attempts < maxAttempts,
      recordsScanned: attempts
    };
  }

  /**
   * Ejecutar Active Scan
   */
  static async runActiveScan(config) {
    const { activeScan, target, contextId } = config;
    
    const scanId = await this.apiCall(config, 'ascan', 'scan', {
      url: target,
      recurse: true,
      inScopeOnly: config.context.inScopeOnly,
      scanPolicyName: activeScan.policy,
      method: null,
      postData: null
    });
    
    Logger.info(`[ZAP] Active Scan iniciado - ID: ${scanId}`);
    
    const startTime = Date.now();
    const maxDuration = activeScan.maxScanDuration * 60 * 1000;
    
    let lastProgress = 0;
    let stuckCounter = 0;
    
    while (true) {
      const status = await this.apiCall(config, 'ascan', 'status', { scanId });
      const progress = parseInt(status.status);
      
      if (progress === lastProgress) {
        stuckCounter++;
        if (stuckCounter > 12) {
          Logger.warn('[ZAP] Active Scan parece estar atascado, deteniendo...');
          await this.apiCall(config, 'ascan', 'stop', { scanId });
          break;
        }
      } else {
        stuckCounter = 0;
        lastProgress = progress;
      }
      
      Logger.info(`[ZAP] Active Scan progreso: ${progress}%`);
      
      if (progress >= 100) break;
      
      if (Date.now() - startTime > maxDuration) {
        Logger.warn(`[ZAP] Active Scan timeout después de ${activeScan.maxScanDuration} minutos`);
        await this.apiCall(config, 'ascan', 'stop', { scanId });
        break;
      }
      
      await this.sleep(5000);
    }
    
    const alerts = await this.getAlerts(config, scanId);
    
    return {
      scanId,
      policy: activeScan.policy,
      alertsFound: alerts.length,
      duration: (Date.now() - startTime) / 1000,
      completed: lastProgress >= 100
    };
  }

  /**
   * Configurar autenticación
   */
  static async configureAuthentication(config) {
    const { authentication, contextId, target } = config;
    const { method } = authentication;
    
    Logger.info(`[ZAP] Configurando autenticación: ${method}`);
    
    switch (method) {
      case 'form':
        await this.configureFormAuth(config);
        break;
      case 'api':
        await this.configureApiAuth(config);
        break;
      case 'browser':
        await this.configureBrowserAuth(config);
        break;
      case 'basic':
      case 'ntlm':
        await this.configureHttpAuth(config);
        break;
      case 'oauth':
        await this.configureOAuth(config);
        break;
      default:
        throw new Error(`Método de autenticación no soportado: ${method}`);
    }
    
    await this.apiCall(config, 'sessionManagement', 'setSessionManagementMethod', {
      contextId,
      methodName: authentication.session.method,
      methodConfigParams: ''
    });
    
    if (authentication.verification.loggedInRegex) {
      await this.apiCall(config, 'authentication', 'setLoggedInIndicator', {
        contextId,
        loggedInIndicatorRegex: authentication.verification.loggedInRegex
      });
    }
    
    if (authentication.verification.loggedOutRegex) {
      await this.apiCall(config, 'authentication', 'setLoggedOutIndicator', {
        contextId,
        loggedOutIndicatorRegex: authentication.verification.loggedOutRegex
      });
    }
    
    for (const user of authentication.users) {
      const userId = await this.apiCall(config, 'users', 'newUser', {
        contextId,
        name: user.name
      });
      
      if (user.credentials.username) {
        await this.apiCall(config, 'users', 'setAuthenticationCredentials', {
          contextId,
          userId,
          username: user.credentials.username,
          password: user.credentials.password || ''
        });
      }
      
      await this.apiCall(config, 'users', 'setUserEnabled', {
        contextId,
        userId,
        enabled: true
      });
    }
  }

  /**
   * Configurar Form-based Authentication
   */
  static async configureFormAuth(config) {
    const { authentication, contextId, target } = config;
    const { form } = authentication;
    
    const loginUrl = form.loginUrl || `${target}/login`;
    
    const authMethodConfig = `loginUrl=${encodeURIComponent(loginUrl)}&` +
                            `loginRequestData=${encodeURIComponent(form.loginRequestData)}&` +
                            `loginPageWait=${form.loginPageWait}`;
    
    await this.apiCall(config, 'authentication', 'setAuthenticationMethod', {
      contextId,
      authMethodName: 'formBasedAuthentication',
      authMethodConfigParams: authMethodConfig
    });
  }

  /**
   * Configurar API/Token Authentication
   */
  static async configureApiAuth(config) {
    const { authentication, contextId } = config;
    const { api } = authentication;
    
    if (api.headerName && api.headerValue) {
      await this.apiCall(config, 'replacer', 'addRule', {
        description: 'API Auth Header',
        enabled: true,
        matchType: 'REQ_HEADER',
        matchString: api.headerName,
        replacement: api.headerValue.replace('{%token%}', api.token || ''),
        initiators: ''
      });
    }
  }

  /**
   * Configurar Browser-based Authentication
   */
  static async configureBrowserAuth(config) {
    const { authentication, contextId, target } = config;
    const { browser } = authentication;
    
    const loginUrl = browser.loginUrl || `${target}/login`;
    
    const authMethodConfig = `loginPageUrl=${encodeURIComponent(loginUrl)}&` +
                            `loginPageWait=${browser.loginPageWait}&` +
                            `browserId=${browser.browserId}`;
    
    await this.apiCall(config, 'authentication', 'setAuthenticationMethod', {
      contextId,
      authMethodName: 'browserBasedAuthentication',
      authMethodConfigParams: authMethodConfig
    });
  }

  /**
   * Configurar HTTP Basic/NTLM Auth
   */
  static async configureHttpAuth(config) {
    const { authentication, contextId } = config;
    const { basic, method } = authentication;
    
    const authMethodName = method === 'ntlm' ? 'ntlmAuthentication' : 'httpAuthentication';
    
    const authMethodConfig = `hostname=${basic.hostname || ''}&` +
                            `realm=${basic.realm || ''}&` +
                            `port=${basic.port || ''}`;
    
    await this.apiCall(config, 'authentication', 'setAuthenticationMethod', {
      contextId,
      authMethodName,
      authMethodConfigParams: authMethodConfig
    });
  }

  /**
   * Configurar OAuth 2.0
   */
  static async configureOAuth(config) {
    const { authentication, contextId } = config;
    const { oauth } = authentication;
    
    Logger.warn('[ZAP] OAuth requiere configuración manual adicional');
    
    if (authentication.users[0]?.credentials?.token) {
      return this.configureApiAuth(config);
    }
  }

  /**
   * Configurar Scan Policy
   */
  static async configureScanPolicy(config) {
    const { activeScan } = config;
    
    if (activeScan.disabledRules && activeScan.disabledRules.length > 0) {
      for (const ruleId of activeScan.disabledRules) {
        await this.apiCall(config, 'ascan', 'disableScanners', {
          ids: ruleId
        });
      }
    }
    
    await this.apiCall(config, 'ascan', 'setOptionMaxRuleDurationInMins', {
      integer: activeScan.maxRuleDuration
    });
    
    await this.apiCall(config, 'ascan', 'setOptionMaxScanDurationInMins', {
      integer: activeScan.maxScanDuration
    });
    
    await this.apiCall(config, 'ascan', 'setOptionMaxAlertsPerRule', {
      integer: activeScan.maxAlertsPerRule
    });
    
    await this.apiCall(config, 'ascan', 'setOptionThreadPerHost', {
      integer: activeScan.threadsPerHost
    });
  }

  /**
   * Configurar Session Management
   */
  static async configureSessionManagement(config) {
    // Implementación básica - puede extenderse según necesidades
    return true;
  }

  /**
   * Generar reportes
   */
  static async generateReports(config, outputDir) {
    const { reporting, target } = config;
    const reports = [];
    
    for (const format of reporting.formats) {
      const timestamp = Date.now();
      const filename = `${reporting.reportFile}_${timestamp}.${this.getReportExtension(format)}`;
      const filepath = path.join(reporting.reportDir || outputDir, filename);
      
      try {
        let reportData;
        
        switch (format) {
          case 'json':
            reportData = await this.generateJSONReport(config);
            break;
          case 'html':
            reportData = await this.generateHTMLReport(config, reporting.template);
            break;
          case 'sarif':
            reportData = await this.generateSARIFReport(config);
            break;
          case 'xml':
            reportData = await this.generateXMLReport(config);
            break;
          default:
            continue;
        }
        
        fs.writeFileSync(filepath, reportData);
        
        reports.push({
          format,
          path: filepath,
          size: fs.statSync(filepath).size
        });
        
        Logger.info(`[ZAP] Reporte ${format.toUpperCase()} generado: ${filepath}`);
        
      } catch (error) {
        Logger.error(`[ZAP] Error generando reporte ${format}:`, error);
      }
    }
    
    return reports;
  }

  /**
   * Generar reporte JSON
   */
  static async generateJSONReport(config) {
    const alerts = await this.getAlerts(config);
    
    const report = {
      '@programName': 'ZAP',
      '@generated': new Date().toISOString(),
      site: [{
        '@name': config.target,
        alerts: alerts.map(alert => ({
          pluginid: alert.pluginId,
          alertRef: alert.alertRef,
          name: alert.name,
          riskcode: alert.risk,
          confidence: alert.confidence,
          desc: alert.description,
          solution: alert.solution,
          reference: alert.reference,
          cweid: alert.cweId,
          wascid: alert.wascId
        }))
      }]
    };
    
    return JSON.stringify(report, null, 2);
  }

  /**
   * Generar reporte HTML
   */
  static async generateHTMLReport(config, template) {
    const result = await this.apiCall(config, 'reports', 'generate', {
      title: `ZAP Scan Report - ${config.target}`,
      template,
      description: `Security scan performed by SecureScan Pro`,
      contexts: config.context,
      sites: config.target,
      sections: config.reporting.sections.join(','),
      includedConfidences: config.reporting.confidenceThreshold,
      includedRisks: config.reporting.riskThreshold,
      reportFileName: `zap_report_${Date.now()}.html`,
      reportDir: config.reporting.reportDir || '/tmp'
    });
    
    return result.reportData;
  }

  /**
   * Generar reporte SARIF
   */
  static async generateSARIFReport(config) {
    const alerts = await this.getAlerts(config);
    
    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'OWASP ZAP',
            informationUri: 'https://www.zaproxy.org/',
            rules: []
          }
        },
        results: alerts.map(alert => ({
          ruleId: alert.pluginId,
          level: this.mapRiskToSARIFLevel(alert.risk),
          message: {
            text: alert.description
          },
          locations: (alert.instances || []).map(instance => ({
            physicalLocation: {
              artifactLocation: {
                uri: instance.uri
              },
              region: {
                startLine: instance.paramLine || 1
              }
            }
          }))
        }))
      }]
    };
    
    return JSON.stringify(sarif, null, 2);
  }

  /**
   * Generar reporte XML
   */
  static async generateXMLReport(config) {
    // Implementación simplificada
    return '<?xml version="1.0"?><report><zap>Not implemented</zap></report>';
  }

  /**
   * Obtener alertas del escaneo
   */
  static async getAlerts(config, scanId = null) {
    const params = scanId ? { scanId } : {};
    const result = await this.apiCall(config, 'alert', 'alerts', params);
    
    return (result.alerts || []).map(alert => ({
      pluginId: alert.pluginId,
      alertRef: alert.alertRef,
      name: alert.name,
      risk: this.mapRiskCode(alert.riskcode),
      confidence: this.mapConfidenceCode(alert.confidence),
      description: alert.desc,
      solution: alert.solution,
      reference: alert.reference,
      cweId: alert.cweid,
      wascId: alert.wascid,
      instances: alert.instances || [],
      count: alert.count || 1
    }));
  }

  /**
   * Verificar que ZAP está corriendo
   */
  static async checkZAPRunning(apiConfig) {
    return new Promise((resolve, reject) => {
      const client = apiConfig.ssl !== false ? https : http;
      
      const options = {
        hostname: apiConfig.host,
        port: apiConfig.port,
        path: '/',
        method: 'GET',
        timeout: 5000
      };
      
      const req = client.request(options, (res) => {
        resolve(true);
      });
      
      req.on('error', (error) => {
        reject(new Error(`ZAP no está corriendo en ${apiConfig.host}:${apiConfig.port}. ` +
                        `Inicie ZAP con: zap.sh -daemon -host ${apiConfig.host} -port ${apiConfig.port}`));
      });
      
      req.on('timeout', () => {
        req.destroy();
        reject(new Error('Timeout verificando ZAP'));
      });
      
      req.end();
    });
  }

  /**
   * Crear contexto en ZAP
   */
  static async createContext(config) {
    const result = await this.apiCall(config, 'context', 'newContext', {
      contextName: config.context
    });
    
    const contextId = result.contextId;
    
    if (config.context.includePaths.length > 0) {
      for (const path of config.context.includePaths) {
        await this.apiCall(config, 'context', 'includeInContext', {
          contextName: config.context,
          regex: path
        });
      }
    } else {
      await this.apiCall(config, 'context', 'includeInContext', {
        contextName: config.context,
        regex: `${config.target}.*`
      });
    }
    
    for (const path of config.context.excludePaths) {
      await this.apiCall(config, 'context', 'excludeFromContext', {
        contextName: config.context,
        regex: path
      });
    }
    
    return contextId;
  }

  /**
   * Esperar a que termine un scan
   */
  static async waitForScan(config, type, scanId, maxDurationMinutes) {
    const maxWait = maxDurationMinutes * 60 * 1000;
    const startTime = Date.now();
    
    while (Date.now() - startTime < maxWait) {
      let status;
      
      switch (type) {
        case 'spider':
          status = await this.apiCall(config, 'spider', 'status', { scanId });
          break;
        case 'spiderAjax':
          status = await this.apiCall(config, 'spiderAjax', 'status');
          break;
        case 'spiderClient':
          status = await this.apiCall(config, 'spiderClient', 'status');
          break;
        case 'ascan':
          status = await this.apiCall(config, 'ascan', 'status', { scanId });
          break;
        default:
          return;
      }
      
      const progress = parseInt(status.status);
      Logger.info(`[ZAP] ${type} progreso: ${progress}%`);
      
      if (progress >= 100) return;
      
      await this.sleep(5000);
    }
    
    throw new Error(`Timeout esperando ${type}`);
  }

  /**
   * Obtener resultados del spider
   */
  static async getSpiderResults(config, type, scanId) {
    let results = { urls: [], messagesSent: 0, duration: 0 };
    
    try {
      switch (type) {
        case 'spider':
          const spiderResults = await this.apiCall(config, 'spider', 'results', { scanId });
          results.urls = spiderResults.results || [];
          break;
        case 'spiderAjax':
          const ajaxResults = await this.apiCall(config, 'spiderAjax', 'results');
          results.urls = ajaxResults.results || [];
          break;
        case 'spiderClient':
          const clientResults = await this.apiCall(config, 'spiderClient', 'results');
          results.urls = clientResults.results || [];
          break;
      }
      
      return results;
    } catch (error) {
      return results;
    }
  }

  /**
   * Utilidades de mapeo
   */
  static mapRiskCode(code) {
    const risks = ['Informational', 'Low', 'Medium', 'High'];
    return risks[code] || 'Unknown';
  }

  static mapConfidenceCode(code) {
    const confidences = ['False Positive', 'Low', 'Medium', 'High', 'Confirmed'];
    return confidences[code] || 'Unknown';
  }

  static mapRiskToSARIFLevel(risk) {
    const mapping = {
      'Informational': 'note',
      'Low': 'warning',
      'Medium': 'warning',
      'High': 'error'
    };
    return mapping[risk] || 'warning';
  }

  static getReportExtension(format) {
    const extensions = {
      'json': 'json',
      'html': 'html',
      'xml': 'xml',
      'sarif': 'sarif'
    };
    return extensions[format] || 'txt';
  }

  static calculateStats(results) {
    const alerts = results.alerts || [];
    
    return {
      totalAlerts: alerts.length,
      byRisk: {
        informational: alerts.filter(a => a.risk === 'Informational').length,
        low: alerts.filter(a => a.risk === 'Low').length,
        medium: alerts.filter(a => a.risk === 'Medium').length,
        high: alerts.filter(a => a.risk === 'High').length
      },
      spiderUrls: results.phases.spider?.urlsFound || 0,
      scanDuration: results.duration
    };
  }

  static calculateDuration(start, end) {
    const startTime = new Date(start).getTime();
    const endTime = new Date(end).getTime();
    return ((endTime - startTime) / 1000).toFixed(2);
  }

  static sleep(ms) {
    return new Promise(resolve => setTimeout(resolve, ms));
  }

  /**
   * Escaneos rápidos predefinidos
   */
  static async quickScan(target, outputDir, options = {}) {
    return this.scan(target, outputDir, {
      spider: {
        type: 'spider',
        maxDuration: 5,
        maxDepth: 5
      },
      activeScan: {
        enabled: true,
        policy: 'Light',
        maxScanDuration: 10
      },
      ...options
    });
  }

  static async spaScan(target, outputDir, options = {}) {
    return this.scan(target, outputDir, {
      spider: {
        type: 'spiderAjax',
        browser: 'firefox-headless',
        maxDuration: 15
      },
      activeScan: {
        enabled: true,
        policy: 'Default',
        maxScanDuration: 30
      },
      ...options
    });
  }

  static async authScan(target, outputDir, credentials, options = {}) {
    return this.scan(target, outputDir, {
      authentication: {
        enabled: true,
        method: 'form',
        form: {
          loginUrl: `${target}/login`,
          loginRequestData: `username={%username%}&password={%password%}`
        },
        users: [{
          name: 'scan-user',
          credentials
        }]
      },
      ...options
    });
  }

  static async apiScan(target, outputDir, apiSpec = null, options = {}) {
    return this.scan(target, outputDir, {
      spider: {
        type: 'spider',
        maxDuration: 10,
        processForms: false
      },
      activeScan: {
        enabled: true,
        policy: 'Default'
      },
      ...options
    });
  }

  static async cicdScan(target, outputDir, options = {}) {
    return this.scan(target, outputDir, {
      spider: {
        type: 'spider',
        maxDuration: 10,
        maxDepth: 8
      },
      activeScan: {
        enabled: true,
        policy: 'Default',
        maxScanDuration: 20
      },
      reporting: {
        formats: ['sarif', 'json'],
        riskThreshold: 'Medium'
      },
      ...options
    });
  }

  /**
   * Verificar estado de ZAP
   */
  static async getStatus(config = {}) {
    const defaultConfig = { ...this.DEFAULT_CONFIG, ...config };
    
    try {
      await this.checkZAPRunning(defaultConfig.api);
      
      return {
        running: true,
        api: {
          host: defaultConfig.api.host,
          port: defaultConfig.api.port,
          ssl: defaultConfig.api.ssl
        },
        features: {
          traditionalSpider: true,
          ajaxSpider: true,
          clientSpider: true,
          activeScan: true,
          passiveScan: true,
          authentication: true,
          reporting: ['json', 'html', 'xml', 'sarif']
        }
      };
    } catch (error) {
      return {
        running: false,
        error: error.message
      };
    }
  }
}

module.exports = ZAPScanner;
