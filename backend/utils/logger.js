/**
 * ============================================================================
 * SECURITYSCAN PRO - SISTEMA DE LOGGING SEGURO
 * ============================================================================
 * Utilidad centralizada para registro de eventos y errores
 * 
 * SEGURIDAD IMPLEMENTADA:
 * - Sanitización de inputs para prevenir Log Injection
 * - Eliminación de secuencias de control ANSI
 * - Truncamiento de mensajes excesivamente largos
 * - Validación de metadatos
 * - Rate limiting implícito via maxsize
 * ============================================================================
 */

const winston = require('winston');
const path = require('path');
const fs = require('fs');

// ============================================================================
// CONFIGURACIÓN DE SEGURIDAD
// ============================================================================

const LOG_SECURITY_CONFIG = {
  // Máximo tamaño de mensaje (prevenir DoS por logs masivos)
  MAX_MESSAGE_LENGTH: 10000,
  
  // Caracteres prohibidos en mensajes de log
  FORBIDDEN_CHARS: /[\x00-\x08\x0B\x0C\x0E-\x1F\x7F-\x9F]/g,
  
  // Secuencias ANSI (para prevenir manipulación visual)
  ANSI_PATTERN: /\x1B\[[0-9;]*[mGKHF]/g,
  
  // Pattern de newlines (para prevenir injection de entradas falsas)
  NEWLINE_PATTERN: /[\r\n]/g,
  
  // Caracteres permitidos en nombres de archivo
  SAFE_FILENAME_PATTERN: /^[a-zA-Z0-9_-]+$/
};

// ============================================================================
// FUNCIONES DE SANITIZACIÓN
// ============================================================================

/**
 * Sanitiza un mensaje de texto para log seguro
 * @param {string} message - Mensaje a sanitizar
 * @returns {string} - Mensaje sanitizado
 */
function sanitizeLogMessage(message) {
  if (typeof message !== 'string') {
    message = String(message);
  }

  // 1. Truncar mensajes excesivamente largos
  if (message.length > LOG_SECURITY_CONFIG.MAX_MESSAGE_LENGTH) {
    message = message.substring(0, LOG_SECURITY_CONFIG.MAX_MESSAGE_LENGTH) + '...[TRUNCATED]';
  }

  // 2. Eliminar caracteres de control (excepto tab y newline permitidos internamente)
  message = message.replace(LOG_SECURITY_CONFIG.FORBIDDEN_CHARS, '');

  // 3. Eliminar secuencias ANSI (manipulación de color/estilo)
  message = message.replace(LOG_SECURITY_CONFIG.ANSI_PATTERN, '');

  // 4. Escapar newlines para prevenir log injection
  // Reemplazar \r y \n con representación literal
  message = message.replace(LOG_SECURITY_CONFIG.NEWLINE_PATTERN, (match) => {
    return match === '\r' ? '\\r' : '\\n';
  });

  // 5. Eliminar secuencias de carriage return adicionales
  message = message.replace(/\r/g, '');

  // 6. Trim de espacios al inicio/final (prevenir padding attacks)
  message = message.trim();

  return message;
}

/**
 * Sanitiza metadatos para prevenir injection en objetos
 * @param {Object} meta - Metadatos a sanitizar
 * @returns {Object} - Metadatos sanitizados
 */
function sanitizeMetadata(meta) {
  if (!meta || typeof meta !== 'object') {
    return {};
  }

  const sanitized = {};
  
  for (const [key, value] of Object.entries(meta)) {
    // Sanitizar la clave
    const safeKey = sanitizeLogMessage(key).replace(/[^a-zA-Z0-9_]/g, '_').substring(0, 50);
    
    // Sanitizar el valor según su tipo
    if (typeof value === 'string') {
      sanitized[safeKey] = sanitizeLogMessage(value);
    } else if (typeof value === 'number' || typeof value === 'boolean') {
      sanitized[safeKey] = value;
    } else if (value === null || value === undefined) {
      sanitized[safeKey] = value;
    } else if (typeof value === 'object') {
      // Recursión limitada para objetos anidados
      const stringified = JSON.stringify(value);
      sanitized[safeKey] = sanitizeLogMessage(stringified);
    } else {
      sanitized[safeKey] = sanitizeLogMessage(String(value));
    }
  }

  return sanitized;
}

/**
 * Valida que un nombre de archivo de log sea seguro
 * @param {string} filename - Nombre de archivo propuesto
 * @returns {string} - Nombre de archivo seguro o default
 */
function validateLogFilename(filename) {
  if (!filename || typeof filename !== 'string') {
    return 'default';
  }

  // Eliminar path traversal
  const basename = path.basename(filename);
  
  // Validar caracteres permitidos
  if (!LOG_SECURITY_CONFIG.SAFE_FILENAME_PATTERN.test(basename)) {
    // Reemplazar caracteres no permitidos
    return basename.replace(/[^a-zA-Z0-9_-]/g, '_').substring(0, 100);
  }

  return basename.substring(0, 100);
}

// ============================================================================
// CONFIGURACIÓN DE DIRECTORIOS
// ============================================================================

// Crear directorio de logs si no existe
const logsDir = path.join(__dirname, '..', 'logs');
if (!fs.existsSync(logsDir)) {
  fs.mkdirSync(logsDir, { recursive: true });
}

// ============================================================================
// FORMATO PERSONALIZADO SEGURO
// ============================================================================

const customFormat = winston.format.combine(
  winston.format.timestamp({ format: 'YYYY-MM-DD HH:mm:ss' }),
  winston.format.errors({ stack: true }),
  winston.format.printf(({ level, message, timestamp, stack, ...meta }) => {
    // Sanitizar todos los componentes
    const safeLevel = sanitizeLogMessage(level).toUpperCase().padEnd(7);
    const safeMessage = sanitizeLogMessage(stack || message);
    const safeMeta = Object.keys(meta).length > 0 
      ? ' ' + JSON.stringify(sanitizeMetadata(meta))
      : '';
    
    return `[${timestamp}] ${safeLevel} ${safeMessage}${safeMeta}`;
  })
);

// Formato con colores para consola (desarrollo) - también sanitizado
const consoleFormat = winston.format.combine(
  winston.format.colorize(),
  winston.format.timestamp({ format: 'HH:mm:ss' }),
  winston.format.printf(({ level, message, timestamp }) => {
    const safeLevel = sanitizeLogMessage(level);
    const safeMessage = sanitizeLogMessage(message);
    return `[${timestamp}] ${safeLevel}: ${safeMessage}`;
  })
);

// ============================================================================
// CONFIGURACIÓN DEL LOGGER PRINCIPAL
// ============================================================================

const logger = winston.createLogger({
  level: process.env.LOG_LEVEL || 'info',
  format: customFormat,
  transports: [
    // Archivo de errores
    new winston.transports.File({
      filename: path.join(logsDir, 'error.log'),
      level: 'error',
      maxsize: 5242880, // 5MB
      maxFiles: 5,
      // Opciones de seguridad adicionales
      options: { flags: 'a', mode: 0o640 } // Append-only, permisos restringidos
    }),
    // Archivo combinado
    new winston.transports.File({
      filename: path.join(logsDir, 'combined.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 10,
      options: { flags: 'a', mode: 0o640 }
    }),
    // Archivo de escaneos (auditoría específica)
    new winston.transports.File({
      filename: path.join(logsDir, 'scans.log'),
      maxsize: 5242880, // 5MB
      maxFiles: 10,
      options: { flags: 'a', mode: 0o640 }
    })
  ],
  // Manejo de excepciones no capturadas
  exceptionHandlers: [
    new winston.transports.File({ 
      filename: path.join(logsDir, 'exceptions.log'),
      maxsize: 5242880,
      maxFiles: 5
    })
  ],
  // Manejo de rejection de promesas no capturadas
  rejectionHandlers: [
    new winston.transports.File({ 
      filename: path.join(logsDir, 'rejections.log'),
      maxsize: 5242880,
      maxFiles: 5
    })
  ]
});

// En desarrollo, también mostrar en consola
if (process.env.NODE_ENV !== 'production') {
  logger.add(new winston.transports.Console({
    format: consoleFormat
  }));
}

// ============================================================================
// WRAPPER SEGURO PARA FACILITAR USO
// ============================================================================

const Logger = {
  /**
   * Log de información
   * @param {string|Object} message - Mensaje a registrar
   * @param {Object} meta - Metadatos adicionales
   */
  info: (message, meta = {}) => {
    const safeMessage = typeof message === 'object' 
      ? sanitizeLogMessage(JSON.stringify(message))
      : sanitizeLogMessage(message);
    
    logger.info(safeMessage, sanitizeMetadata(meta));
  },
  
  /**
   * Log de advertencia
   * @param {string|Object} message - Mensaje a registrar
   * @param {Object} meta - Metadatos adicionales
   */
  warn: (message, meta = {}) => {
    const safeMessage = typeof message === 'object' 
      ? sanitizeLogMessage(JSON.stringify(message))
      : sanitizeLogMessage(message);
    
    logger.warn(safeMessage, sanitizeMetadata(meta));
  },
  
  /**
   * Log de error
   * @param {string} message - Mensaje descriptivo
   * @param {Error|null} error - Objeto de error opcional
   */
  error: (message, error = null) => {
    const safeMessage = sanitizeLogMessage(message);
    
    if (error instanceof Error) {
      // Sanitizar el stack trace también
      const safeError = {
        message: sanitizeLogMessage(error.message),
        stack: error.stack ? sanitizeLogMessage(error.stack) : undefined,
        name: sanitizeLogMessage(error.name)
      };
      
      logger.error(`${safeMessage} - ${safeError.message}`, { 
        error: safeError,
        stack: safeError.stack 
      });
    } else if (error) {
      logger.error(`${safeMessage} - ${sanitizeLogMessage(String(error))}`);
    } else {
      logger.error(safeMessage);
    }
  },
  
  /**
   * Log de debug
   * @param {string|Object} message - Mensaje a registrar
   * @param {Object} meta - Metadatos adicionales
   */
  debug: (message, meta = {}) => {
    const safeMessage = typeof message === 'object' 
      ? sanitizeLogMessage(JSON.stringify(message))
      : sanitizeLogMessage(message);
    
    logger.debug(safeMessage, sanitizeMetadata(meta));
  },

  /**
   * Log específico de escaneos (auditoría)
   * @param {string} scanId - ID del escaneo
   * @param {string} tool - Herramienta utilizada
   * @param {string} message - Mensaje del evento
   */
  scan: (scanId, tool, message) => {
    // Validar y sanitizar parámetros específicos de escaneo
    const safeScanId = validateLogFilename(scanId);
    const safeTool = sanitizeLogMessage(tool).toUpperCase();
    const safeMessage = sanitizeLogMessage(message);
    
    const auditMessage = `[SCAN:${safeScanId}] [${safeTool}] ${safeMessage}`;
    
    // Log a archivo de escaneos específico
    logger.info(auditMessage, { 
      scanId: safeScanId, 
      tool: safeTool,
      type: 'audit'
    });
  },

  /**
   * Log de seguridad para eventos críticos
   * @param {string} event - Tipo de evento de seguridad
   * @param {string} details - Detalles del evento
   * @param {Object} context - Contexto adicional
   */
  security: (event, details, context = {}) => {
    const safeEvent = sanitizeLogMessage(event).toUpperCase();
    const safeDetails = sanitizeLogMessage(details);
    
    logger.warn(`[SECURITY] ${safeEvent}: ${safeDetails}`, {
      type: 'security',
      event: safeEvent,
      ...sanitizeMetadata(context)
    });
  },

  /**
   * Crear un logger específico para un escaneo
   * @param {string} scanId - ID del escaneo
   * @returns {Object} - Logger contextualizado
   */
  forScan: (scanId) => {
    const safeScanId = validateLogFilename(scanId);
    
    return {
      info: (tool, message) => Logger.scan(safeScanId, tool, message),
      error: (tool, message, error) => {
        const safeTool = sanitizeLogMessage(tool).toUpperCase();
        const safeMessage = sanitizeLogMessage(message);
        Logger.error(`[SCAN:${safeScanId}] [${safeTool}] ${safeMessage}`, error);
      },
      security: (event, details) => Logger.security(event, details, { scanId: safeScanId })
    };
  }
};

// ============================================================================
// EXPORTAR MÓDULO
// ============================================================================

module.exports = Logger;
