# Consideraciones Éticas y Legales - SecureScan Pro v3.0

## ⚠️ ADVERTENCIA IMPORTANTE

**Este proyecto es EXCLUSIVAMENTE para uso educativo y en entornos controlados.**

El uso indebido de herramientas de escaneo de seguridad puede tener graves consecuencias legales y éticas. SecureScan Pro v3.0 incluye **mecanismos de seguridad técnicos** (Target Validator, Circuit Breaker, whitelist hardcodeada) diseñados para prevenir uso no autorizado, pero la responsabilidad legal final recae en el usuario.

---

## 1. Marco Legal

### 1.1 Legislación Aplicable

El escaneo de sistemas sin autorización puede violar múltiples leyes:

**Colombia (SENA):**
- **Ley 1273 de 2009** (Delitos informáticos)
  - Artículo 269A: Acceso abusivo a sistema informático
  - Artículo 269B: Obstaculización ilegítima de sistema informático  
  - Artículo 269C: Interceptación de datos informáticos

**Penalidades:**
- Prisión de 48 a 96 meses
- Multas de 100 a 1000 SMLMV

**Internacional:**
- CFAA (Computer Fraud and Abuse Act) - Estados Unidos
- Computer Misuse Act 1990 - Reino Unido
- Convenio de Budapest sobre Ciberdelincuencia

### 1.2 Requisitos Legales Obligatorios

Antes de realizar CUALQUIER escaneo, debe:

1. ✅ **Obtener autorización por escrito** del propietario del sistema
2. ✅ **Definir el alcance** exacto de las pruebas (IPs, URLs, puertos)
3. ✅ **Establecer fechas y horarios** autorizados
4. ✅ **Acordar métodos de comunicación** de hallazgos
5. ✅ **Firmar acuerdos de confidencialidad** (NDA)
6. ✅ **Verificar que el target está en la whitelist** del sistema

---

## 2. Autorización Obligatoria

### 2.1 Plantilla de Autorización

```text
AUTORIZACIÓN PARA PRUEBAS DE SEGURIDAD

Fecha: _______________

DATOS DEL PROPIETARIO:
Empresa/Organización: _______________________
Representante Legal: ________________________
Cargo: ____________________________________
Documento de Identidad: _____________________
Correo Electrónico: _________________________
Teléfono: _________________________________

DATOS DEL EVALUADOR:
Nombre Completo: __________________________
Documento de Identidad: _____________________
Organización/Institución: _____________________
Correo Electrónico: _________________________

ALCANCE DE LAS PRUEBAS:

Sistemas autorizados:
[ ] ______________________________________
[ ] ______________________________________
[ ] ______________________________________

Direcciones IP/URLs autorizadas:
[ ] ______________________________________
[ ] ______________________________________

Tipos de pruebas autorizadas:
[ ] Escaneo de puertos (Nmap)
[ ] Detección de tecnologías (WhatWeb)
[ ] Enumeración de directorios (Gobuster)
[ ] Pruebas de aplicaciones web (OWASP ZAP)
[ ] Búsqueda de exploits (ExploitDB)
[ ] Verificación de exploits (Metasploit dry-run)
[ ] Otros: ________________________________

Pruebas NO autorizadas:
[ ] Explotación activa de vulnerabilidades (sin dry-run)
[ ] Denegación de servicio (DoS)
[ ] Ingeniería social
[ ] Fuerza bruta de credenciales
[ ] Otros: ________________________________

PERIODO DE AUTORIZACIÓN:
Fecha inicio: _______________
Fecha fin: _________________
Horario permitido: ___________

CONDICIONES:
1. Las pruebas se realizarán únicamente sobre los sistemas listados.
2. No se explotarán vulnerabilidades sin autorización adicional explícita.
3. Todos los hallazgos serán reportados al propietario.
4. La información obtenida será tratada confidencialmente.
5. Se proporcionará un informe final de los resultados.
6. Se respetarán los límites técnicos del sistema (whitelist).

FIRMAS:

_______________________          _______________________
Propietario del Sistema           Evaluador de Seguridad
Fecha: _______________          Fecha: _______________
2.2 Sistemas NUNCA Escanear
Absolutamente prohibido (el sistema técnicamente lo bloqueará):
❌ Sistemas de producción sin autorización
❌ Infraestructura gubernamental
❌ Sistemas bancarios o financieros
❌ Redes hospitalarias
❌ Infraestructura crítica
❌ Sistemas de terceros sin autorización escrita
❌ Redes públicas (WiFi público, universidades, etc.)
❌ Cualquier objetivo fuera de la whitelist del sistema
3. Laboratorio Local Seguro (Docker Compose)
3.1 Entorno Controlado v3.0
Este proyecto incluye un laboratorio con 4 aplicaciones vulnerables que se ejecutan localmente en Docker:
Table
Aplicación	Puerto	Stack	Propósito	Dificultad
Juice Shop	3001	Node.js/Express/Angular	OWASP Top 10 2021, API REST/GraphQL	⭐⭐⭐ Principiante-Avanzado
DVWA	3002	PHP/Apache/MariaDB	Vulnerabilidades web clásicas, niveles ajustables	⭐ Principiante
WebGoat	3003	Java/Spring Boot	Tutoriales interactivos OWASP	⭐⭐ Principiante-Intermedio
WebWolf	9090	Java/Spring Boot	Companion de WebGoat (phishing/email interception)	⭐⭐ Intermedio
Red interna: 172.20.0.0/24 (aislada del host)
3.2 Ventajas del Laboratorio
✅ 100% legal (son tus propios sistemas locales)
✅ Sin riesgo de daño a terceros
✅ Entorno controlado y reproducible
✅ Puedes romper cosas sin consecuencias
✅ Aprendizaje práctico seguro
✅ Metasploit en modo dry-run por defecto
3.3 Configuraciones de Seguridad Reducida
Las aplicaciones del laboratorio están configuradas intencionalmente con seguridad mínima:
Juice Shop: NODE_ENV=unsafe (deshabilita protecciones)
DVWA: SECURITY_LEVEL=low, PHPIDS_ENABLED=false
WebGoat: WEBGOAT_SECURITY_XFRAMEOPTIONS=false
Todas: Sin CAPTCHA, sin firewalls, sin rate-limiting
4. Mecanismos de Seguridad Técnicos v3.0
SecureScan Pro v3.0 incluye múltiples capas de protección técnica para prevenir uso no autorizado:
4.1 Target Validator (Validación de Objetivos)
Implementación técnica: Clase interna del orquestador
JavaScript
Copy
// Whitelist hardcodeada - NO MODIFICABLE sin cambiar código fuente
const ALLOWED_TARGETS = [
  'localhost:3001',      // Juice Shop
  'localhost:3002',      // DVWA
  'localhost:3003',      // WebGoat
  '127.0.0.1:3001',
  '127.0.0.1:3002',
  '127.0.0.1:3003',
  '172.20.0.0/24'        // Red Docker interna
];
Validaciones realizadas:
Scope Check: El target debe estar en la whitelist
Health Check: Conexión TCP exitosa antes de escanear
DNS Resolution: Verificación de que el hostname resuelve a IP permitida
Si el target no está permitido:
JSON
Copy
{
  "error": "Target \"http://ejemplo.com\" fuera de alcance permitido",
  "allowedTargets": ["localhost:3001", "localhost:3002", "localhost:3003"],
  "code": "TARGET_NOT_ALLOWED"
}
4.2 Circuit Breaker (Aislamiento de Fallos)
Propósito: Prevenir que errores en una herramienta afecten todo el sistema.
Estados:
CLOSED: Funcionamiento normal
OPEN: Servicio temporalmente deshabilitado tras 2-3 fallos
HALF_OPEN: Período de prueba antes de reactivar
Herramientas protegidas:
Table
Herramienta	Fallos para abrir	Tiempo de recuperación
Nmap	2	120 segundos
ZAP	2	300 segundos
Gobuster	3	60 segundos
WhatWeb	3	60 segundos
4.3 Process Manager (Gestión de Procesos)
Características:
Registro de todos los PIDs de procesos hijos
Cleanup automático en señales SIGTERM/SIGINT
Timeout forzado tras 30-60 minutos de escaneo
Prevención de procesos zombis
4.4 Metasploit - Modo Dry-Run por Defecto
Configuración de seguridad:
JavaScript
Copy
metasploit: {
  enabled: false,        // Deshabilitado por defecto
  dryRun: true,          // Solo verificación, nunca explota realmente
  requireConfirmation: true,  // Requiere confirmación manual adicional
  maxSessions: 3,        // Límite de sesiones
  minRanking: 'good'     // Solo exploits con ranking "good" o superior
}
En modo dry-run, Metasploit:
✅ Verifica la existencia de exploits en la base de datos
✅ Comprueba compatibilidad con versiones detectadas
✅ Simula el proceso de explotación sin ejecutar payload real
❌ NO establece sesiones reales
❌ NO ejecuta código en el target
❌ NO modifica el sistema objetivo
4.5 Rate Limiting y Cuotas
JavaScript
Copy
// Límites del sistema
const RATE_LIMITS = {
  maxScansPerHour: 10,
  maxConcurrentScans: 2,
  cooldownBetweenScans: 60,  // segundos
  maxTargetsPerScan: 1,
  maxScanDuration: 3600       // 1 hora máximo
};
4.6 Logging de Auditoría
Todas las actividades se registran inmutablemente:
JavaScript
Copy
// Estructura del log
{
  timestamp: "2026-03-19T22:45:00.000Z",
  action: "SCAN_STARTED",
  target: "http://localhost:3001",
  user: "local",
  ipAddress: "127.0.0.1",
  tools: ["whatweb", "nmap", "gobuster", "zap", "exploitdb"],
  profile: "standard",
  circuitBreakerStates: {
    nmap: "CLOSED",
    zap: "CLOSED"
  },
  targetValidation: {
    passed: true,
    healthCheck: "SUCCESS",
    scopeCheck: "ALLOWED"
  }
}
Ubicación: backend/logs/audit-YYYY-MM-DD.log
5. Principios Éticos del Hacking
5.1 Código de Ética
Como profesional de seguridad, debes:
Actuar con integridad
Nunca usar conocimientos para daño
Reportar vulnerabilidades responsablemente
Proteger la privacidad de otros
Obtener autorización siempre
Sin autorización = ilegal
Documentar todo por escrito
Respetar los límites técnicos (whitelist) y acordados
Minimizar el impacto
No causar daños innecesarios
Evitar interrupciones de servicio
Proteger datos sensibles encontrados
Usar perfiles de escaneo apropiados (quick vs comprehensive)
Reportar responsablemente
Notificar al propietario primero
Dar tiempo para remediar (90 días es estándar)
No divulgar públicamente sin permiso
5.2 Divulgación Responsable (Responsible Disclosure)
Si encuentras vulnerabilidades en sistemas reales:
🔒 Notifica al propietario de forma privada y segura
📋 Proporciona detalles técnicos suficientes (CWE, CVSS, PoC)
💡 Sugiere remediaciones específicas si es posible
⏱️ Da tiempo razonable (90 días estándar de la industria)
🚫 No explotes la vulnerabilidad
💰 No vendas la información a terceros
6. Mejores Prácticas de Uso
6.1 Antes del Escaneo
[ ] Verificar que el target está en la whitelist del sistema
[ ] Confirmar autorización escrita del propietario (si no es laboratorio)
[ ] Seleccionar el perfil de escaneo apropiado (quick, standard, comprehensive, passive)
[ ] Verificar que el laboratorio está saludable (docker-compose ps)
[ ] Documentar fecha y hora de inicio
[ ] Tener contacto de emergencia (si aplica)
6.2 Durante el Escaneo
[ ] Monitorear el progreso vía /api/scan/:id/status
[ ] Verificar estados de los Circuit Breakers
[ ] No interrumpir el proceso (a menos que sea emergencia)
[ ] Revisar logs en tiempo real si es necesario
6.3 Después del Escaneo
[ ] Revisar el score de seguridad calculado
[ ] Analizar hallazgos críticos y altos primero
[ ] Descargar reportes en múltiples formatos (HTML, PDF, SARIF)
[ ] Eliminar datos sensibles de archivos temporales (backend/temp/)
[ ] Mantener confidencialidad de los resultados
7. Perfiles de Escaneo y su Impacto
SecureScan Pro v3.0 ofrece 4 perfiles con diferentes niveles de invasividad:
Table
Perfil	Duración	Invasividad	Uso Recomendado
Quick	5-10 min	Mínima	Validación rápida, CI/CD
Standard	20-30 min	Moderada	Auditoría regular (default)
Comprehensive	45-90 min	Alta	Evaluación profunda
Passive	10-15 min	Mínima	Entornos sensibles
Herramientas por perfil:
Quick: WhatWeb → Nmap (top 1000) → ZAP (spider only) → Scoring
Standard: WhatWeb → Nmap (all ports) → Gobuster → ZAP (full) → ExploitDB → Scoring
Comprehensive: + Metasploit (dry-run) + DNS/VHost enumeration
Passive: Sin active scanning de ZAP, solo scripts seguros de Nmap
8. Responsabilidad y Descargo
8.1 Descargo de Responsabilidad
Text
Copy
DESCARGO DE RESPONSABILIDAD - SECURESCAN PRO v3.0

El software SecureScan Pro se proporciona "tal cual", sin 
garantías de ningún tipo. Los autores, colaboradores y el 
SENA no serán responsables de:

- Uso indebido del software contra sistemas no autorizados
- Daños causados a sistemas de terceros por incumplimiento 
  de las restricciones técnicas (whitelist, dry-run)
- Consecuencias legales por uso no autorizado
- Pérdida de datos o interrupciones de servicio en entornos 
  de producción
- Fallos en los mecanismos de seguridad técnica por 
  modificaciones no autorizadas del código

El usuario asume toda la responsabilidad por:

- Obtener autorización adecuada antes de escanear (incluso 
  si modifica la whitelist)
- Cumplir con las leyes aplicables de Colombia y 
  jurisdicciones internacionales
- Usar el software de manera ética y responsable
- Proteger la información sensible obtenida durante pruebas
- No intentar deshabilitar mecanismos de seguridad técnica

Al usar este software, acepta estos términos y se 
compromete a usarlo exclusivamente de manera legal y ética, 
entendiendo que los mecanismos técnicos de seguridad son 
una ayuda, no una garantía absoluta.
8.2 Uso Académico (SENA)
Para proyectos académicos del SENA:
📚 Usar exclusivamente el laboratorio local (puertos 3001, 3002, 3003, 9090)
📝 Documentar el propósito educativo en el informe del proyecto
📖 Incluir esta sección de ética en la documentación técnica
🚫 NO escanear sistemas de la institución sin autorización formal del coordinador
✅ Demostrar comprensión de implicaciones legales en la defensa del proyecto
9. Recursos de Aprendizaje Legal
9.1 Plataformas de Práctica Legal
Table
Plataforma	Tipo	Costo	Notas
HackTheBox	Labs online	Freemium	Máquinas vulnerables legales
TryHackMe	Tutoriales	Freemium	Paths guiados para principiantes
VulnHub	VMs descargables	Gratis	Laboratorio local completo
OWASP WebGoat	Tutorial	Gratis	Incluido en este proyecto
PortSwigger Academy	Web security	Gratis	De los creadores de Burp Suite
9.2 Certificaciones Éticas Reconocidas
CEH (Certified Ethical Hacker) - EC-Council
OSCP (Offensive Security Certified Professional) - Offensive Security
GPEN (GIAC Penetration Tester) - SANS Institute
CompTIA PenTest+ - CompTIA
eJPT (eLearnSecurity Junior Penetration Tester) - INE
9.3 Programas de Bug Bounty (Práctica Legal)
Plataformas donde puedes practicar legalmente con autorización implícita:
HackerOne (hackerone.com)
Bugcrowd (bugcrowd.com)
Synack (synack.com) - Requiere invitación
Open Bug Bounty (openbugbounty.org)
10. Checklist Final de Ética y Legalidad
Antes de usar SecureScan Pro v3.0, confirma:
✅ Para Uso en Laboratorio (Recomendado)
[ ] Entiendo que solo puedo escanear: localhost:3001-3003, 127.0.0.1:3001-3003
[ ] He verificado que el laboratorio está corriendo (docker-compose ps)
[ ] Comprendo que Metasploit está en modo dry-run por defecto
[ ] Acepto que los logs de auditoría registran todas mis actividades
✅ Para Uso en Sistemas Autorizados (Requiere Autorización Escrita)
[ ] Tengo autorización por escrita del propietario
[ ] El target está explícitamente listado en la autorización
[ ] He verificado que el target está en la whitelist del sistema
[ ] Entiendo las implicaciones legales de mi país y el objetivo
[ ] Me comprometo a reportar hallazgos de manera responsable
[ ] Protegeré la información sensible encontrada
[ ] Actuaré de manera ética en todo momento
🚫 Compromisos que Acepto
[ ] NO intentaré modificar la whitelist hardcodeada
[ ] NO usaré Metasploit fuera de modo dry-run sin autorización explícita
[ ] NO escanearé sistemas de producción sin autorización
[ ] NO compartiré hallazgos con terceros sin permiso
[ ] NO usaré este conocimiento para dañar a otros
Firma de Compromiso Ético:
Yo, _________________________, estudiante del programa de
Tecnología en Análisis y Desarrollo de Sistemas de Información
del SENA, me comprometo a usar SecureScan Pro v3.0 de manera
legal, ética y responsable, siguiendo todas las pautas establecidas
en este documento.
Entiendo que el sistema incluye mecanismos técnicos de protección
(Target Validator, Circuit Breaker, whitelist) diseñados para prevenir
uso no autorizado, pero que la responsabilidad legal final es mía.
Fecha: _______________
Firma: _______________
Documento: _______________
11. Contacto y Reporte de Incidentes
Para reportar problemas de seguridad en el propio SecureScan Pro:
📧 Instructor del SENA
📧 Coordinador del programa
🐛 GitHub Issues (si es proyecto open source)
Para emergencias legales: Consultar con el departamento jurídico de la institución o abogado especializado en derecho informático.
Recuerda: La seguridad informática es una responsabilidad, no un juego.
"With great power comes great responsibility" - Principio del Hacking Ético
Documento: ETICA_Y_LEGALIDAD.md
Versión: 3.0.0 (Resiliente)
Fecha: Marzo 2026
Proyecto: SecureScan Pro - SENA
tecnico en seguridad de aplicaciones web