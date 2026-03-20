#!/usr/bin/env node
/**
 * SecureScan Pro - Script de inicio del backend v2.0
 * 
 * Este script verifica las dependencias, herramientas y módulos necesarios
 * antes de iniciar el servidor backend, alineado con SecureScanOrchestrator v3.0.
 * 
 * Mejoras:
 * - Verificación de dependencias Node.js del orquestador (xml2js, axios)
 * - Validación de existencia de módulos críticos
 * - Verificación de sintaxis del orquestador
 * - Creación de estructura de directorios completa
 * - Manejo de errores por fases
 */

const { execSync, spawn } = require('child_process');
const fs = require('fs');
const path = require('path');

// Colores para la consola
const colors = {
  reset: '\x1b[0m',
  red: '\x1b[31m',
  green: '\x1b[32m',
  yellow: '\x1b[33m',
  blue: '\x1b[34m',
  cyan: '\x1b[36m',
  magenta: '\x1b[35m'
};

function log(message, color = 'reset') {
  console.log(`${colors[color]}${message}${colors.reset}`);
}

function checkCommand(command) {
  try {
    execSync(`which ${command}`, { stdio: 'ignore' });
    return true;
  } catch {
    return false;
  }
}

/**
 * Verifica que un módulo Node.js esté instalado
 */
function checkNodeModule(moduleName, backendPath) {
  try {
    require.resolve(moduleName, { paths: [path.join(backendPath, 'node_modules')] });
    return true;
  } catch {
    return false;
  }
}

/**
 * Verifica la sintaxis de un archivo JavaScript
 */
function checkSyntax(filePath) {
  try {
    execSync(`node -c ${filePath}`, { stdio: 'ignore' });
    return { valid: true };
  } catch (error) {
    return { valid: false, error: error.message };
  }
}

function checkSystemTools() {
  log('\n=== SecureScan Pro - Verificación de Herramientas del Sistema ===\n', 'cyan');
  
  const tools = [
    { name: 'nmap', required: true, description: 'Escaneo de puertos y servicios' },
    { name: 'whatweb', required: true, description: 'Detección de tecnologías web' },
    { name: 'gobuster', required: true, description: 'Fuerza bruta de directorios/DNS' },
    { name: 'zaproxy', required: false, alt: 'zap.sh', description: 'Escaneo DAST (OWASP ZAP)' },
    { name: 'searchsploit', required: true, description: 'Búsqueda en ExploitDB' },
    { name: 'msfconsole', required: false, description: 'Metasploit Framework (opcional)' },
    { name: 'docker', required: false, description: 'Contenedores para labs' },
    { name: 'docker-compose', required: false, description: 'Orquestación de labs' }
  ];
  
  let allRequired = true;
  let optionalMissing = 0;
  
  for (const tool of tools) {
    const exists = checkCommand(tool.name) || (tool.alt && checkCommand(tool.alt));
    const status = exists ? '✓' : '✗';
    const color = exists ? 'green' : (tool.required ? 'red' : 'yellow');
    const reqText = tool.required ? '[REQUERIDO]' : '[opcional]';
    
    log(`  ${status} ${tool.name.padEnd(15)} ${reqText} - ${tool.description}`, color);
    
    if (tool.required && !exists) {
      allRequired = false;
    } else if (!tool.required && !exists) {
      optionalMissing++;
    }
  }
  
  if (!allRequired) {
    log('\n⚠️  Faltan herramientas requeridas del sistema', 'red');
    log('   Instala con: sudo apt-get install nmap whatweb gobuster exploitdb\n', 'yellow');
    return false;
  }
  
  if (optionalMissing > 0) {
    log(`\n⚠️  ${optionalMissing} herramientas opcionales no encontradas (funcionalidad limitada)`, 'yellow');
  }
  
  log('\n✅ Todas las herramientas requeridas del sistema están instaladas.\n', 'green');
  return true;
}

function checkNodeDependencies() {
  log('=== Verificación de Dependencias Node.js ===\n', 'cyan');
  
  const backendPath = path.join(__dirname, '..', 'backend');
  const requiredModules = [
    { name: 'xml2js', required: true, description: 'Parseo de XML de Nmap' },
    { name: 'axios', required: true, description: 'Cliente HTTP para APIs' }
  ];
  
  let allRequired = true;
  
  for (const mod of requiredModules) {
    const exists = checkNodeModule(mod.name, backendPath);
    const status = exists ? '✓' : '✗';
    const color = exists ? 'green' : (mod.required ? 'red' : 'yellow');
    const reqText = mod.required ? '[REQUERIDO]' : '[opcional]';
    
    log(`  ${status} ${mod.name.padEnd(15)} ${reqText} - ${mod.description}`, color);
    
    if (mod.required && !exists) {
      allRequired = false;
    }
  }
  
  if (!allRequired) {
    log('\n⚠️  Faltan dependencias Node.js requeridas', 'red');
    log('   Instala con: cd backend && npm install xml2js axios\n', 'yellow');
    return false;
  }
  
  log('\n✅ Todas las dependencias Node.js están instaladas.\n', 'green');
  return true;
}

function checkOrchestratorModules() {
  log('=== Verificación de Módulos del Orquestador ===\n', 'cyan');
  
  const backendPath = path.join(__dirname, '..', 'backend');
  const requiredFiles = [
    'orchestrator.js',
    'utils/logger.js',
    'modules/whatweb_detector.js',
    'modules/nmap_scanner.js',
    'modules/gobuster_scanner.js',
    'modules/zap_scanner.js',
    'modules/exploitdb_unified.js',
    'modules/metasploit_integration.js',
    'modules/scoring_engine.js',
    'modules/report_generator.js'
  ];
  
  let allFound = true;
  
  for (const file of requiredFiles) {
    const filePath = path.join(backendPath, file);
    const exists = fs.existsSync(filePath);
    const status = exists ? '✓' : '✗';
    const color = exists ? 'green' : 'red';
    
    log(`  ${status} ${file}`, color);
    
    if (!exists) {
      allFound = false;
    } else if (file === 'orchestrator.js') {
      // Verificar sintaxis del orquestador
      const syntaxCheck = checkSyntax(filePath);
      if (!syntaxCheck.valid) {
        log(`    ⚠️  Error de sintaxis detectado: ${syntaxCheck.error}`, 'red');
        allFound = false;
      } else {
        log(`    ✅ Sintaxis válida`, 'green');
      }
    }
  }
  
  if (!allFound) {
    log('\n⚠️  Faltan módulos críticos del orquestador', 'red');
    log('   Verifica la estructura de directorios del backend/\n', 'yellow');
    return false;
  }
  
  log('\n✅ Todos los módulos del orquestador están presentes.\n', 'green');
  return true;
}

function installNodeDependencies() {
  const backendPath = path.join(__dirname, '..', 'backend');
  const nodeModulesPath = path.join(backendPath, 'node_modules');
  
  if (!fs.existsSync(nodeModulesPath)) {
    log('📦 Instalando dependencias del backend...', 'yellow');
    try {
      execSync('npm install', { cwd: backendPath, stdio: 'inherit' });
      log('✅ Dependencias instaladas correctamente\n', 'green');
    } catch (error) {
      log(`❌ Error instalando dependencias: ${error.message}`, 'red');
      return false;
    }
  } else {
    // Verificar si faltan dependencias específicas
    const requiredModules = ['xml2js', 'axios'];
    const missing = requiredModules.filter(mod => !checkNodeModule(mod, backendPath));
    
    if (missing.length > 0) {
      log(`📦 Instalando dependencias faltantes: ${missing.join(', ')}...`, 'yellow');
      try {
        execSync(`npm install ${missing.join(' ')}`, { cwd: backendPath, stdio: 'inherit' });
        log('✅ Dependencias instaladas correctamente\n', 'green');
      } catch (error) {
        log(`❌ Error instalando dependencias: ${error.message}`, 'red');
        return false;
      }
    }
  }
  
  return true;
}

function createDirectoryStructure() {
  log('=== Creación de Estructura de Directorios ===\n', 'cyan');
  
  const dirs = [
    path.join(__dirname, '..', 'reports'),     // Reportes finales
    path.join(__dirname, '..', 'logs'),        // Logs de ejecución
    path.join(__dirname, '..', 'temp'),        // Archivos temporales de escaneo
    path.join(__dirname, '..', 'temp', 'whatweb'),
    path.join(__dirname, '..', 'temp', 'nmap'),
    path.join(__dirname, '..', 'temp', 'gobuster'),
    path.join(__dirname, '..', 'temp', 'zap'),
    path.join(__dirname, '..', 'temp', 'exploitdb')
  ];
  
  for (const dir of dirs) {
    if (!fs.existsSync(dir)) {
      try {
        fs.mkdirSync(dir, { recursive: true });
        log(`  ✓ Creado: ${dir}`, 'blue');
      } catch (error) {
        log(`  ✗ Error creando ${dir}: ${error.message}`, 'red');
        return false;
      }
    } else {
      log(`  ✓ Existe: ${dir}`, 'green');
    }
  }
  
  log('\n✅ Estructura de directorios verificada.\n', 'green');
  return true;
}

function startServer() {
  log('\n=== Iniciando SecureScan Pro Backend ===\n', 'cyan');
  
  const backendPath = path.join(__dirname, '..', 'backend');
  const env = {
    ...process.env,
    NODE_ENV: process.env.NODE_ENV || 'production',
    SECURESCAN_LOG_LEVEL: process.env.SECURESCAN_LOG_LEVEL || 'info'
  };
  
  const server = spawn('node', ['server.js'], {
    cwd: backendPath,
    stdio: 'inherit',
    env: env
  });
  
  server.on('error', (err) => {
    log(`\n❌ Error al iniciar el servidor: ${err.message}`, 'red');
    process.exit(1);
  });
  
  server.on('close', (code) => {
    if (code !== 0) {
      log(`\n⚠️  El servidor terminó con código: ${code}`, 'red');
    } else {
      log('\n👋 Servidor detenido correctamente', 'cyan');
    }
    process.exit(code);
  });
  
  // Manejar señales de terminación de forma graceful
  const shutdown = (signal) => {
    log(`\n🛑 Recibida señal ${signal}, deteniendo servidor graceful...`, 'yellow');
    server.kill(signal);
  };
  
  process.on('SIGINT', () => shutdown('SIGINT'));
  process.on('SIGTERM', () => shutdown('SIGTERM'));
  process.on('SIGHUP', () => shutdown('SIGHUP'));
  
  // Manejo de errores no capturados
  process.on('uncaughtException', (err) => {
    log(`\n💥 Uncaught Exception: ${err.message}`, 'red');
    server.kill('SIGTERM');
    process.exit(1);
  });
  
  process.on('unhandledRejection', (reason, promise) => {
    log(`\n💥 Unhandled Rejection at: ${promise}, reason: ${reason}`, 'red');
  });
}

// ============================================================================
// EJECUCIÓN PRINCIPAL
// ============================================================================

function main() {
  log('\n🔐 SecureScan Pro Backend Starter v2.0', 'magenta');
  log('   Compatible con Orchestrator v3.0 (Resiliente)\n', 'cyan');
  
  try {
    // Fase 1: Verificar herramientas del sistema
    if (!checkSystemTools()) {
      process.exit(1);
    }
    
    // Fase 2: Instalar/verificar dependencias Node.js
    if (!installNodeDependencies()) {
      process.exit(1);
    }
    
    // Fase 3: Verificar dependencias específicas del orquestador
    if (!checkNodeDependencies()) {
      process.exit(1);
    }
    
    // Fase 4: Verificar módulos del orquestador
    if (!checkOrchestratorModules()) {
      process.exit(1);
    }
    
    // Fase 5: Crear estructura de directorios
    if (!createDirectoryStructure()) {
      process.exit(1);
    }
    
    // Fase 6: Iniciar servidor
    startServer();
    
  } catch (error) {
    log(`\n💥 Error fatal en startup: ${error.message}`, 'red');
    log(error.stack, 'red');
    process.exit(1);
  }
}

// Ejecutar
main();