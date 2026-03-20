/**
 * ============================================================================
 * SECURITYSCAN PRO - MÓDULO NMAP (SANITIZADO - WHITELIST ESTRICTA)
 * ============================================================================
 * Escaneo de puertos y detección de servicios/versiones
 * 
 * SEGURIDAD:
 * - Whitelist estricta: solo a-z, 0-9, ., -, :, /
 * - Bloqueo explícito de caracteres de shell peligrosos
 * - Uso de execFile() para prevenir RCE
 * - Validación en múltiples capas
 * ============================================================================
 */

const { execFile } = require('child_process');
const util = require('util');
const fs = require('fs');
const path = require('path');
const Logger = require('../utils/logger');

const execFilePromise = util.promisify(execFile);

class NmapScanner {
  /**
   * WHITELIST ESTRICTA DE CARACTERES PERMITIDOS
   * Solo permite: a-z, 0-9, ., -, :, /
   * Bloquea explícitamente: ; | & ` $ ( ) { } [ ] \ < >
   */
  static validateTarget(target) {
    if (!target || typeof target !== 'string') {
      throw new Error('Target es requerido y debe ser string');
    }

    const trimmed = target.trim();

    // ============================================================================
    // WHITELIST ESTRICTA
    // ============================================================================
    // Permitidos: letras minúsculas, números, punto, guion, dos puntos, slash
    // Esto cubre: hostnames, IPv4, IPv6 básico, CIDR, y paths simples
    const strictWhitelist = /^[a-z0-9.\-:/]+$/;
    
    if (!strictWhitelist.test(trimmed)) {
      // Identificar qué caracteres no permitidos se encontraron
      const invalidChars = [...trimmed].filter(char => !/^[a-z0-9.\-:/]$/.test(char));
      const uniqueInvalid = [...new Set(invalidChars)].join(', ');
      
      throw new Error(
        `Target contiene caracteres no permitidos: [${uniqueInvalid}]. ` +
        `Solo se permite: a-z, 0-9, punto, guion, dos puntos, slash`
      );
    }

    // ============================================================================
    // BLOQUEO EXPLÍCITO DE CARACTERES PELIGROSOS (defensa en profundidad)
    // ============================================================================
    const dangerousChars = [
      { char: ';', name: 'punto y coma' },
      { char: '|', name: 'pipe' },
      { char: '&', name: 'ampersand' },
      { char: '`', name: 'backtick' },
      { char: '$', name: 'dólar' },
      { char: '(', name: 'paréntesis izq' },
      { char: ')', name: 'paréntesis der' },
      { char: '{', name: 'llave izq' },
      { char: '}', name: 'llave der' },
      { char: '[', name: 'corchete izq' },
      { char: ']', name: 'corchete der' },
      { char: '\\', name: 'backslash' },
      { char: '<', name: 'menor que' },
      { char: '>', name: 'mayor que' }
    ];

    for (const { char, name } of dangerousChars) {
      if (trimmed.includes(char)) {
        throw new Error(
          `Target contiene caracter peligroso bloqueado: "${char}" (${name}). ` +
          `Este carácter puede usarse para inyección de comandos.`
        );
      }
    }

    // ============================================================================
    // VALIDACIONES ADICIONALES DE SEGURIDAD
    // ============================================================================
    
    // Prevenir null bytes
    if (trimmed.includes('\0')) {
      throw new Error('Target contiene null bytes (\\0)');
    }

    // Prevenir newlines
    if (/[\n\r]/.test(trimmed)) {
      throw new Error('Target contiene saltos de línea');
    }

    // Validar longitud máxima (hostname max 253 chars)
    if (trimmed.length > 253) {
      throw new Error('Target excede longitud máxima permitida (253 caracteres)');
    }

    // Prevenir encoding tricks: no permitir URL encoding básico
    if (/%[0-9a-f]{2}/i.test(trimmed)) {
      throw new Error('Target no debe contener URL encoding (%XX)');
    }

    // Prevenir path traversal básico
    if (trimmed.includes('..')) {
      throw new Error('Target contiene secuencia de path traversal (..)');
    }

    // Prevenir doble slash que pueda confundir parsing
    if (trimmed.includes('//')) {
      throw new Error('Target contiene doble slash (//)');
    }

    return trimmed;
  }

  /**
   * Validación de opciones de escaneo
   */
  static validateOptions(options) {
    const validated = {};

    // Validar puertos: solo números, guiones y comas
    if (options.ports) {
      const portsStr = String(options.ports);
      if (!/^[0-9,\-]+$/.test(portsStr)) {
        throw new Error('Formato de puertos inválido. Solo números, comas y guiones permitidos');
      }
      validated.ports = portsStr;
    } else {
      validated.ports = '1-1000';
    }

    // Validar timing: solo T0-T5
    if (options.timing) {
      const timing = String(options.timing).toUpperCase();
      if (!/^T[0-5]$/.test(timing)) {
        throw new Error('Timing debe ser T0, T1, T2, T3, T4 o T5');
      }
      validated.timing = timing;
    } else {
      validated.timing = 'T4';
    }

    // Validar versionIntensity: número 0-9
    if (options.versionIntensity !== undefined) {
      const intensity = parseInt(options.versionIntensity, 10);
      if (isNaN(intensity) || intensity < 0 || intensity > 9) {
        throw new Error('versionIntensity debe ser número entre 0 y 9');
      }
      validated.versionIntensity = intensity;
    } else {
      validated.versionIntensity = 5;
    }

    // Validar timeout: número positivo
    if (options.timeout !== undefined) {
      const timeout = parseInt(options.timeout, 10);
      if (isNaN(timeout) || timeout <= 0 || timeout > 3600) {
        throw new Error('Timeout debe ser número positivo (máx 3600 segundos)');
      }
      validated.timeout = timeout;
    } else {
      validated.timeout = 600;
    }

    // Flags booleanos
    validated.scripts = options.scripts !== false;
    validated.versionDetection = options.versionDetection !== false;
    validated.osDetection = options.osDetection === true;

    return validated;
  }

  /**
   * Ejecutar escaneo Nmap
   */
  static async scan(target, outputDir, options = {}) {
    // Validación estricta de entrada
    const validatedTarget = this.validateTarget(target);
    const validatedOptions = this.validateOptions(options);

    // Extraer hostname/IP del target validado
    const hostname = this.extractHost(validatedTarget);
    
    // Archivos de salida
    const xmlOutput = path.join(outputDir, 'nmap_output.xml');
    const txtOutput = path.join(outputDir, 'nmap_output.txt');
    const grepOutput = path.join(outputDir, 'nmap_output.gnmap');

    // Construir array de argumentos (NUNCA concatenar strings)
    const nmapArgs = [
      '-p', validatedOptions.ports,
      `-${validatedOptions.timing}`,
      '-oX', xmlOutput,
      '-oN', txtOutput,
      '-oG', grepOutput,
      '--open'
    ];

    if (validatedOptions.versionDetection) {
      nmapArgs.push('-sV');
      nmapArgs.push('--version-intensity', validatedOptions.versionIntensity.toString());
    }

    if (validatedOptions.scripts) {
      nmapArgs.push('-sC');
      nmapArgs.push('--script', 'vuln,safe');
    }

    if (validatedOptions.osDetection) {
      nmapArgs.push('-O');
    }

    // El hostname ya está validado, se agrega al final
    nmapArgs.push(hostname);

    Logger.info(`Ejecutando Nmap: nmap ${nmapArgs.join(' ')}`);

    try {
      const startTime = Date.now();
      
      // EJECUCIÓN SEGURA: execFile en lugar de exec
      const { stdout, stderr } = await execFilePromise(
        'nmap',
        nmapArgs,
        { 
          timeout: validatedOptions.timeout * 1000,
          killSignal: 'SIGTERM'
        }
      );

      const duration = ((Date.now() - startTime) / 1000).toFixed(2);
      Logger.info(`Nmap completado en ${duration}s`);

      // Parsear resultados
      const results = await this.parseResults(txtOutput, xmlOutput);
      results.duration = duration;
      results.command = `nmap ${nmapArgs.join(' ')}`;
      results.outputFiles = {
        xml: xmlOutput,
        txt: txtOutput,
        gnmap: grepOutput
      };

      return results;

    } catch (error) {
      Logger.error('Error ejecutando Nmap:', error);
      
      // Intentar parsear resultados parciales si existen
      if (fs.existsSync(txtOutput)) {
        try {
          const partialResults = await this.parseResults(txtOutput, xmlOutput);
          partialResults.error = error.message;
          partialResults.partial = true;
          return partialResults;
        } catch (parseError) {
          Logger.error('Error parseando resultados parciales:', parseError);
        }
      }

      throw error;
    }
  }

  /**
   * Extraer hostname/IP de una URL (después de validación)
   */
  static extractHost(target) {
    try {
      // Si ya es una IP validada, retornarla
      const ipv4Pattern = /^(\d{1,3}\.){3}\d{1,3}$/;
      const ipv6Pattern = /^[0-9a-f:]+$/;
      
      if (ipv4Pattern.test(target) || ipv6Pattern.test(target)) {
        return target;
      }

      // Extraer hostname de URL
      let urlStr = target;
      if (!target.startsWith('http://') && !target.startsWith('https://')) {
        urlStr = `http://${target}`;
      }
      
      const url = new URL(urlStr);
      const hostname = url.hostname;
      
      if (!hostname || hostname.length === 0) {
        throw new Error('No se pudo extraer hostname válido del target');
      }
      
      // Re-validar el hostname extraído contra whitelist estricta
      this.validateTarget(hostname);
      
      return hostname;
    } catch (error) {
      if (error.message.includes('caracteres no permitidos') || 
          error.message.includes('caracter peligroso')) {
        throw error;
      }
      // Si URL parsing falla, asumir que es hostname directo (ya validado)
      return target;
    }
  }

  /**
   * Parsear resultados de Nmap
   */
  static async parseResults(txtFile, xmlFile) {
    const results = {
      hosts: [],
      ports: [],
      services: [],
      scripts: [],
      vulnerabilities: [],
      cves: [],
      raw: null,
      stats: {},
      duration: 0,
      command: null,
      outputFiles: {},
      parseError: null
    };

    try {
      // Leer salida de texto
      if (fs.existsSync(txtFile)) {
        results.raw = fs.readFileSync(txtFile, 'utf8');
        
        // Parsear puertos abiertos
        const portRegex = /(\d+)\/(tcp|udp)\s+(\w+)\s+(\S+)\s*(.*)/g;
        let match;
        
        while ((match = portRegex.exec(results.raw)) !== null) {
          const [, port, protocol, state, service, version] = match;
          
          if (state === 'open') {
            const portInfo = {
              port: parseInt(port, 10),
              protocol,
              state,
              service: service || 'unknown',
              version: version.trim() || null
            };
            
            results.ports.push(portInfo);
            
            if (version.trim()) {
              results.services.push({
                name: service,
                version: version.trim(),
                port: parseInt(port, 10)
              });
            }
          }
        }

        // Parsear scripts NSE
        const scriptRegex = /\|_?\s*(\S+):\s*(.*)/g;
        while ((match = scriptRegex.exec(results.raw)) !== null) {
          const [, scriptName, scriptOutput] = match;
          results.scripts.push({
            name: scriptName,
            output: scriptOutput.trim()
          });

          // Detectar vulnerabilidades
          const outputLower = scriptOutput.toLowerCase();
          if (outputLower.includes('vulnerable') || outputLower.includes('vuln')) {
            results.vulnerabilities.push({
              source: 'nmap',
              type: scriptName,
              description: scriptOutput.trim(),
              severity: 'high'
            });
          }
        }

        // Extraer información del host
        const hostRegex = /Nmap scan report for (\S+)/;
        const hostMatch = results.raw.match(hostRegex);
        if (hostMatch) {
          results.hosts.push({
            hostname: hostMatch[1],
            status: 'up',
            openPorts: results.ports.length
          });
        }

        // Detectar OS si está disponible
        const osRegex = /OS details?: (.+)/;
        const osMatch = results.raw.match(osRegex);
        if (osMatch) {
          results.os = osMatch[1].trim();
        }
      }

      // Parsear XML para información adicional
      if (fs.existsSync(xmlFile)) {
        const xmlContent = fs.readFileSync(xmlFile, 'utf8');
        
        // Extraer CVEs de scripts
        const cveRegex = /CVE-\d{4}-\d+/gi;
        const cves = xmlContent.match(cveRegex) || [];
        results.cves = [...new Set(cves)];

        cves.forEach(cve => {
          results.vulnerabilities.push({
            source: 'nmap',
            type: 'CVE',
            cve: cve,
            severity: 'high'
          });
        });
      }

      // Estadísticas
      results.stats = {
        totalPorts: results.ports.length,
        tcpPorts: results.ports.filter(p => p.protocol === 'tcp').length,
        udpPorts: results.ports.filter(p => p.protocol === 'udp').length,
        servicesDetected: results.services.length,
        scriptsRun: results.scripts.length,
        vulnerabilitiesFound: results.vulnerabilities.length
      };

    } catch (error) {
      Logger.error('Error parseando resultados Nmap:', error);
      results.parseError = error.message;
    }

    return results;
  }

  /**
   * Escaneo rápido (solo puertos comunes)
   */
  static async quickScan(target, outputDir) {
    return this.scan(target, outputDir, {
      ports: '21,22,23,25,53,80,110,111,135,139,143,443,445,993,995,1723,3306,3389,5900,8080,8443',
      timing: 'T4',
      scripts: false,
      versionDetection: true
    });
  }

  /**
   * Escaneo completo
   */
  static async fullScan(target, outputDir) {
    return this.scan(target, outputDir, {
      ports: '1-65535',
      timing: 'T3',
      scripts: true,
      versionDetection: true,
      osDetection: true,
      timeout: 1800
    });
  }
}

module.exports = NmapScanner;
