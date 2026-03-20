# Consideraciones Eticas y Legales

## ADVERTENCIA IMPORTANTE

**Este proyecto es EXCLUSIVAMENTE para uso educativo y en entornos controlados.**

El uso indebido de herramientas de escaneo de seguridad puede tener graves consecuencias legales y eticas. Este documento establece las pautas obligatorias para el uso responsable de SecureScan Pro.

---

## 1. Marco Legal

### 1.1 Legislacion Aplicable

El escaneo de sistemas sin autorizacion puede violar multiples leyes:

**Colombia (SENA):**
- Ley 1273 de 2009 (Delitos informaticos)
- Articulo 269A: Acceso abusivo a sistema informatico
- Articulo 269B: Obstaculizacion ilegitima de sistema informatico
- Articulo 269C: Interceptacion de datos informaticos

**Penalidades:**
- Prision de 48 a 96 meses
- Multas de 100 a 1000 SMLMV

**Internacional:**
- CFAA (Computer Fraud and Abuse Act) - Estados Unidos
- Computer Misuse Act 1990 - Reino Unido
- Convenio de Budapest sobre Ciberdelincuencia

### 1.2 Requisitos Legales Obligatorios

Antes de realizar CUALQUIER escaneo, debe:

1. **Obtener autorizacion por escrito** del propietario del sistema
2. **Definir el alcance** exacto de las pruebas
3. **Establecer fechas y horarios** autorizados
4. **Acordar metodos de comunicacion** de hallazgos
5. **Firmar acuerdos de confidencialidad** (NDA)

---

## 2. Autorizacion Obligatoria

### 2.1 Plantilla de Autorizacion

```
AUTORIZACION PARA PRUEBAS DE SEGURIDAD

Fecha: _______________

DATOS DEL PROPIETARIO:
Empresa/Organizacion: _______________________
Representante Legal: ________________________
Cargo: ____________________________________
Documento de Identidad: _____________________
Correo Electronico: _________________________
Telefono: _________________________________

DATOS DEL EVALUADOR:
Nombre Completo: __________________________
Documento de Identidad: _____________________
Organizacion/Institucion: _____________________
Correo Electronico: _________________________

ALCANCE DE LAS PRUEBAS:

Sistemas autorizados:
[ ] ______________________________________
[ ] ______________________________________
[ ] ______________________________________

Direcciones IP/URLs autorizadas:
[ ] ______________________________________
[ ] ______________________________________

Tipos de pruebas autorizadas:
[ ] Escaneo de puertos
[ ] Deteccion de vulnerabilidades
[ ] Enumeracion de directorios
[ ] Pruebas de aplicaciones web
[ ] Busqueda de exploits
[ ] Otros: ________________________________

Pruebas NO autorizadas:
[ ] Explotacion activa de vulnerabilidades
[ ] Denegacion de servicio (DoS)
[ ] Ingenieria social
[ ] Otros: ________________________________

PERIODO DE AUTORIZACION:
Fecha inicio: _______________
Fecha fin: _________________
Horario permitido: ___________

CONDICIONES:
1. Las pruebas se realizaran unicamente sobre los sistemas listados.
2. No se explotaran vulnerabilidades sin autorizacion adicional.
3. Todos los hallazgos seran reportados al propietario.
4. La informacion obtenida sera tratada confidencialmente.
5. Se proporcionara un informe final de los resultados.

FIRMAS:

_______________________          _______________________
Propietario del Sistema           Evaluador de Seguridad
Fecha: _______________          Fecha: _______________
```

### 2.2 Que Sistemas NUNCA Escanear

**Absolutamente prohibido:**
- Sistemas de produccion sin autorizacion
- Infraestructura gubernamental
- Sistemas bancarios o financieros
- Redes hospitalarias
- Infraestructura critica
- Sistemas de terceros
- Redes publicas (WiFi publico, universidades, etc.)

---

## 3. Uso del Laboratorio Local

### 3.1 Entorno Seguro

Este proyecto incluye un laboratorio con aplicaciones vulnerables que se ejecutan **localmente** en Docker:

| Aplicacion | Puerto | Proposito |
|------------|--------|-----------|
| Juice Shop | 3001 | Practica de vulnerabilidades modernas |
| DVWA | 3002 | Vulnerabilidades web clasicas |
| WebGoat | 3003 | Tutoriales OWASP |
| bWAPP | 3004 | 100+ vulnerabilidades |
| Hackazon | 3005 | E-commerce vulnerable |

### 3.2 Por Que Usar el Laboratorio

**Ventajas:**
- 100% legal (son tus propios sistemas)
- Sin riesgo de dano a terceros
- Entorno controlado y reproducible
- Puedes romper cosas sin consecuencias
- Aprendizaje practico seguro

### 3.3 Restricciones del Sistema

SecureScan Pro incluye restricciones de seguridad:

```javascript
// El sistema solo permite escanear:
const ALLOWED_TARGETS = [
  'localhost',
  '127.0.0.1',
  '192.168.*.*',  // Redes privadas
  '10.*.*.*',     // Redes privadas
  '172.16.*.*',   // Redes privadas
];

// Objetivos externos requieren confirmacion explicita
```

---

## 4. Principios Eticos del Hacking

### 4.1 Codigo de Etica

Como profesional de seguridad, debes:

1. **Actuar con integridad**
   - Nunca usar conocimientos para dano
   - Reportar vulnerabilidades responsablemente
   - Proteger la privacidad de otros

2. **Obtener autorizacion siempre**
   - Sin autorizacion = ilegal
   - Documentar todo por escrito
   - Respetar los limites acordados

3. **Minimizar el impacto**
   - No causar danos innecesarios
   - Evitar interrupciones de servicio
   - Proteger datos sensibles encontrados

4. **Reportar responsablemente**
   - Notificar al propietario primero
   - Dar tiempo para remediar
   - No divulgar publicamente sin permiso

### 4.2 Divulgacion Responsable

Si encuentras vulnerabilidades en sistemas reales:

1. **Notifica al propietario** de forma privada
2. **Proporciona detalles tecnicos** suficientes
3. **Sugiere remediaciones** si es posible
4. **Da tiempo razonable** (90 dias es estandar)
5. **No explotes** la vulnerabilidad
6. **No vendas** la informacion

---

## 5. Mejores Practicas

### 5.1 Antes del Escaneo

- [ ] Verificar autorizacion escrita
- [ ] Confirmar alcance permitido
- [ ] Documentar fecha y hora de inicio
- [ ] Verificar que el objetivo es correcto
- [ ] Tener contacto de emergencia del cliente

### 5.2 Durante el Escaneo

- [ ] Registrar todas las actividades
- [ ] Monitorear impacto en el sistema
- [ ] Detener si hay problemas inesperados
- [ ] No exceder el alcance autorizado
- [ ] Proteger cualquier dato sensible encontrado

### 5.3 Despues del Escaneo

- [ ] Documentar todos los hallazgos
- [ ] Clasificar por severidad
- [ ] Preparar reporte profesional
- [ ] Entregar al cliente de forma segura
- [ ] Eliminar datos sensibles de tus sistemas
- [ ] Mantener confidencialidad

---

## 6. Limitaciones del Sistema

### 6.1 Whitelist de Objetivos

Por defecto, SecureScan Pro solo permite escanear:

```javascript
// Configuracion en backend/server.js
const WHITELIST = {
  // Siempre permitidos (laboratorio local)
  localhost: true,
  '127.0.0.1': true,
  
  // Rangos de red privada
  privateRanges: [
    '192.168.0.0/16',
    '10.0.0.0/8',
    '172.16.0.0/12'
  ],
  
  // Dominios personalizados (agregar con autorizacion)
  customDomains: []
};
```

### 6.2 Rate Limiting

El sistema incluye limites para prevenir abuso:

```javascript
// Limites de escaneo
const RATE_LIMITS = {
  maxScansPerHour: 10,
  maxConcurrentScans: 2,
  cooldownBetweenScans: 60, // segundos
  maxTargetsPerScan: 1
};
```

### 6.3 Logging de Actividades

Todas las actividades se registran:

```javascript
// Ejemplo de log
{
  timestamp: "2024-03-14T15:00:00.000Z",
  action: "SCAN_STARTED",
  target: "http://localhost:3001",
  user: "local",
  ipAddress: "127.0.0.1",
  tools: ["nmap", "nikto", "gobuster"]
}
```

---

## 7. Responsabilidad

### 7.1 Descargo de Responsabilidad

```
DESCARGO DE RESPONSABILIDAD

El software SecureScan Pro se proporciona "tal cual", sin 
garantias de ningun tipo. Los autores y colaboradores no 
seran responsables de:

- Uso indebido del software
- Danos causados a sistemas de terceros
- Consecuencias legales por uso no autorizado
- Perdida de datos o interrupciones de servicio

El usuario asume toda la responsabilidad por:

- Obtener autorizacion adecuada antes de escanear
- Cumplir con las leyes aplicables
- Usar el software de manera etica
- Proteger la informacion obtenida

Al usar este software, acepta estos terminos y se 
compromete a usarlo exclusivamente de manera legal y etica.
```

### 7.2 Uso Academico (SENA)

Para proyectos academicos:

1. **Usar exclusivamente el laboratorio local**
2. **Documentar el proposito educativo**
3. **Incluir esta seccion de etica en el proyecto**
4. **No escanear sistemas de la institucion** sin autorizacion
5. **Demostrar comprension de implicaciones legales**

---

## 8. Recursos Adicionales

### 8.1 Certificaciones Eticas

- CEH (Certified Ethical Hacker)
- OSCP (Offensive Security Certified Professional)
- GPEN (GIAC Penetration Tester)
- CompTIA PenTest+

### 8.2 Organizaciones

- OWASP (Open Web Application Security Project)
- SANS Institute
- EC-Council
- Offensive Security

### 8.3 Programas de Bug Bounty (Legales)

Plataformas donde puedes practicar legalmente:
- HackerOne (hackerone.com)
- Bugcrowd (bugcrowd.com)
- Synack (synack.com)
- Open Bug Bounty (openbugbounty.org)

### 8.4 Laboratorios de Practica (Legales)

- HackTheBox (hackthebox.eu)
- TryHackMe (tryhackme.com)
- VulnHub (vulnhub.com)
- OWASP WebGoat
- PortSwigger Web Security Academy

---

## 9. Checklist Final

Antes de usar SecureScan Pro, confirma:

- [ ] Entiendo las implicaciones legales
- [ ] Solo escaneara sistemas con autorizacion
- [ ] Usara el laboratorio local para practicar
- [ ] Reportara hallazgos de manera responsable
- [ ] Protegera la informacion sensible
- [ ] Actuara de manera etica en todo momento

**Firma de compromiso:**

Yo, _________________________, me comprometo a usar 
SecureScan Pro de manera legal, etica y responsable, 
siguiendo todas las pautas establecidas en este documento.

Fecha: _______________
Firma: _______________

---

## 10. Contacto

Para dudas sobre uso etico:
- Instructor del SENA
- Coordinador del programa
- Departamento legal de la institucion

**Recuerda: La seguridad informatica es una responsabilidad, no un juego.**
