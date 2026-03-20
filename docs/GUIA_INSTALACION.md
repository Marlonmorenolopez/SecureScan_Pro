# 📘 GUÍA DE INSTALACIÓN COMPLETA - SecureScan Pro v3.0

## Para Principiantes: De Cero a Escaneo Funcional

**Tiempo estimado:** 45-60 minutos  
**Dificultad:** 🟢 Principiante  
**Última actualización:** Marzo 2026

---

## 📋 ÍNDICE

1. [Antes de Empezar](#1-antes-de-empezar)
2. [Paso 1: Instalar Kali Linux](#2-paso-1-instalar-kali-linux)
3. [Paso 2: Actualizar el Sistema](#3-paso-2-actualizar-el-sistema)
4. [Paso 3: Instalar Docker](#4-paso-3-instalar-docker)
5. [Paso 4: Instalar VS Code](#5-paso-4-instalar-visual-studio-code)
6. [Paso 5: Instalar Herramientas de Seguridad](#6-paso-5-instalar-herramientas-de-seguridad)
7. [Paso 6: Descargar el Proyecto](#7-paso-6-descargar-el-proyecto)
8. [Paso 7: Levantar el Laboratorio](#8-paso-7-levantar-el-laboratorio-vulnerable)
9. [Paso 8: Instalar Dependencias](#9-paso-8-instalar-dependencias-del-proyecto)
10. [Paso 9: Configurar Variables de Entorno](#10-paso-9-configurar-variables-de-entorno)
11. [Paso 10: Iniciar la Aplicación](#11-paso-10-iniciar-la-aplicación)
12. [Paso 11: Tu Primer Escaneo](#12-paso-11-tu-primer-escaneo)
13. [Solución de Problemas](#13-solución-de-problemas-comunes)
14. [Verificación Final](#14-verificación-final)

---

## 1. ANTES DE EMPEZAR

### 1.1 ¿Qué es SecureScan Pro?

Es una plataforma web que **automatiza** el análisis de seguridad de aplicaciones web. Imagina que tienes que revisar si una página web tiene agujeros de seguridad. Normalmente tendrías que usar 6 herramientas diferentes, una por una, copiar los resultados a mano y hacer un reporte. **SecureScan Pro hace todo eso automáticamente.**

### 1.2 ¿Qué necesitas?

| Requisito             | Especificación                 | ¿Por qué?                                            |
| --------------------- | ------------------------------ | ---------------------------------------------------- |
| **Computador**        | PC o laptop con 8GB RAM mínimo | Las herramientas de seguridad consumen memoria       |
| **Sistema Operativo** | Kali Linux 2024.x              | Ya viene con herramientas de seguridad preinstaladas |
| **Internet**          | Conexión estable               | Para descargar dependencias y actualizaciones        |
| **Espacio en disco**  | 50 GB libres                   | Docker, herramientas y reportes ocupan espacio       |
| **Tiempo**            | 1 hora                         | Para instalar todo sin prisa                         |

### 1.3 Arquitectura del Sistema (Simplificada)

┌─────────────────────────────────────────┐
│ TU NAVEGADOR │
│ (Chrome, Firefox, Edge) │
│ http://localhost:3000 │
└─────────────────┬───────────────────────┘
│
▼
┌─────────────────────────────────────────┐
│ SECURESCAN PRO (Aplicación) │
│ ┌─────────────┐ ┌─────────────┐ │
│ │ Frontend │◄──►│ Backend │ │
│ │ (Next.js) │ │ (Node.js) │ │
│ │ Interfaz │ │ Orquestador│ │
│ │ bonita │ │ + 6 tools │ │
│ └─────────────┘ └─────────────┘ │
└─────────────────┬─────────────────────┘
│
▼
┌─────────────────────────────────────────┐
│ LABORATORIO DE PRÁCTICA │
│ ┌─────────┐ ┌─────────┐ ┌─────────┐ │
│ │ Juice │ │ DVWA │ │ WebGoat │ │
│ │ Shop │ │ │ │ │ │
│ │ :3001 │ │ :3002 │ │ :3003 │ │
│ └─────────┘ └─────────┘ └─────────┘ │
│ (Aplicaciones vulnerables para │
│ practicar sin romper nada real) │
└─────────────────────────────────────────┘
plain
Copy

---

## 2. PASO 1: INSTALAR KALI LINUX

### 2.1 ¿Qué es Kali Linux?

Es una versión especial de Linux hecha **exclusivamente para ciberseguridad**. Viene con cientos de herramientas preinstaladas. Es como tener un taller completo instead of una caja de herramientas básica.

### 2.2 Opción A: Máquina Virtual (Recomendado para principiantes)

Una **máquina virtual** es como tener una computadora dentro de tu computadora. Si algo sale mal, no afecta tu sistema principal.

#### Paso A.1: Descargar VirtualBox

1. Ve a [virtualbox.org](https://virtualbox.org)
2. Descarga la versión para tu sistema operativo (Windows/Mac/Linux)
3. Instálalo como cualquier programa (siguiente, siguiente, finalizar)

#### Paso A.2: Descargar Kali Linux para VirtualBox

1. Ve a [kali.org/get-kali](https://kali.org/get-kali/)
2. Busca **"Kali Linux VirtualBox Images"**
3. Descarga la versión **64-bit** (aproximadamente 3-4 GB)
4. El archivo tendrá extensión `.ova` (Open Virtual Appliance)

#### Paso A.3: Importar en VirtualBox

1. Abre VirtualBox
2. Ve a **Archivo** → **Importar servicio virtualizado**
3. Selecciona el archivo `.ova` que descargaste
4. Haz clic en **Siguiente** → **Importar**

#### Paso A.4: Configurar recursos

1. En VirtualBox, selecciona la máquina Kali
2. Haz clic en **Configuración** (icono de engranaje)
3. Ve a **Sistema** → **Placa base**:
   - **Memoria base**: Mínimo 4096 MB (4 GB), recomendado 8192 MB (8 GB)
4. Ve a **Sistema** → **Procesador**:
   - **CPUs**: Mínimo 2, recomendado 4
5. Haz clic en **Aceptar**

#### Paso A.5: Iniciar Kali Linux

1. Selecciona la máquina y haz clic en **Iniciar**
2. Espera a que cargue (puede tomar 1-2 minutos la primera vez)
3. **Credenciales de login**:
   - **Usuario**: `kali`
   - **Contraseña**: `kali`

### 2.3 Opción B: Instalación Nativa (Avanzado)

> ⚠️ **Advertencia**: Esto borrará todo en tu disco duro. Solo para usuarios avanzados.

1. Descarga la imagen ISO de [kali.org](https://kali.org)
2. Crea un USB booteable con [Rufus](https://rufus.ie) (Windows) o `dd` (Linux)
3. Arranca desde el USB y sigue el instalador gráfico

---

## 3. PASO 2: ACTUALIZAR EL SISTEMA

### 3.1 Abrir la Terminal

La **terminal** es como el "modo experto" de la computadora. Escribes comandos y la computadora los ejecuta.

**Para abrir la terminal en Kali:**

- Presiona el botón de actividades (esquina superior izquierda)
- Escribe "terminal"
- Haz clic en el icono negro que aparece

### 3.2 Ejecutar Actualización

Copia y pega estos comandos uno por uno (presiona Enter después de cada uno):

```bash
# Actualizar la lista de paquetes disponibles
sudo apt update
¿Qué hace? Pregunta a los servidores de Kali qué programas nuevos hay disponibles.
bash
Copy
# Actualizar todos los programas instalados
sudo apt full-upgrade -y
¿Qué hace? Descarga e instala las últimas versiones de todo. El -y significa "sí a todo" automáticamente.
⏱️ Tiempo estimado: 10-20 minutos dependiendo de tu internet.
bash
Copy
# Reiniciar si se actualizó el kernel (el núcleo del sistema)
sudo reboot
¿Qué es el kernel? Es el "cerebro" de Linux. Si se actualiza, necesitas reiniciar para usar la nueva versión.
Después de reiniciar, vuelve a iniciar sesión (kali/kali) y abre la terminal de nuevo.
4. PASO 3: INSTALAR DOCKER
4.1 ¿Qué es Docker?
Imagina que quieres enviar una carta, pero cada persona tiene un buzón diferente. Docker es como tener buzones estandarizados: pones tu aplicación en una "caja" (contenedor) y funciona igual en cualquier computadora.
En SecureScan Pro, usamos Docker para crear el laboratorio de práctica: 3 aplicaciones vulnerables que puedes escanear sin romper nada real.
4.2 Instalación Paso a Paso
bash
Copy
# Instalar Docker y Docker Compose
sudo apt install -y docker.io docker-compose
Componentes:
docker: El motor que ejecuta contenedores
docker-compose: Herramienta para manejar múltiples contenedores juntos
bash
Copy
# Agregar tu usuario al grupo docker (para no usar sudo siempre)
sudo usermod -aG docker $USER
¿Qué hace? Te da permisos para usar Docker sin ser administrador.
bash
Copy
# Aplicar los cambios de grupo (sin cerrar sesión)
newgrp docker
bash
Copy
# Verificar que Docker funciona
docker run hello-world
Si ves: Hello from Docker! → ✅ Éxito
Si ves error de permisos: Cierra la terminal, ábrela de nuevo, y prueba de nuevo.
5. PASO 4: INSTALAR VISUAL STUDIO CODE
5.1 ¿Por qué VS Code?
Es el editor de código más popular. Tiene:
Colores en el código (sintaxis resaltada)
Autocompletado (te sugiere comandos)
Extensiones para todo
5.2 Instalación
Copia y pega todo este bloque de una vez:
bash
Copy
# Paso 1: Instalar herramientas necesarias
sudo apt install -y curl gpg apt-transport-https

# Paso 2: Descargar la llave de seguridad de Microsoft
curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-archive-keyring.gpg

# Paso 3: Agregar el repositorio de VS Code
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-archive-keyring.gpg] https://packages.microsoft.com/repos/vscode stable main" | sudo tee /etc/apt/sources.list.d/vscode.list

# Paso 4: Actualizar e instalar
sudo apt update && sudo apt install -y code
Verificación:
bash
Copy
code --version
Deberías ver algo como: 1.85.1 (el número de versión)
6. PASO 5: INSTALAR HERRAMIENTAS DE SEGURIDAD
6.1 ¿Qué vamos a instalar?
SecureScan Pro no reinventa la rueda: usa herramientas profesionales existentes y las orquesta. Aquí están las 6 herramientas:
Table
Herramienta	Función	Analogía
WhatWeb	Detecta tecnologías (WordPress, React, etc.)	Como ver de qué está hecha una casa
Nmap	Escanea puertos y servicios	Como tocar timbres para ver quién abre
Gobuster	Busca directorios ocultos	Como buscar puertas traseras
ZAP	Encuentra vulnerabilidades web	Como un inspector de edificios
ExploitDB	Busca exploits conocidos	Como buscar si hay llaves maestras públicas
Metasploit	Verifica explotación (opcional)	Como probar si la cerradura es realmente mala
6.2 Comando de Instalación
bash
Copy
# Instalar todas las herramientas de una vez
sudo apt install -y whatweb nmap gobuster zaproxy exploitdb metasploit-framework nodejs npm
Desglose del comando:
sudo: Ejecutar como administrador
apt install: Instalar programas
-y: Decir "sí" automáticamente a todo
La lista: todas las herramientas separadas por espacios
6.3 Actualizar Base de Datos de Exploits
bash
Copy
# Descargar la última base de datos de vulnerabilidades
searchsploit -u
⏱️ Tiempo: 2-5 minutos. Descarga miles de exploits conocidos.
6.4 Verificar Instalaciones
Ejecuta estos comandos uno por uno. Todos deben mostrar números de versión:
bash
Copy
# Verificar WhatWeb
whatweb --version
# Esperado: WhatWeb version 0.5.5 (o similar)

# Verificar Nmap
nmap --version
# Esperado: Nmap version 7.94 (o similar)

# Verificar Gobuster
gobuster version
# Esperado: Version 3.6.0 (o similar)

# Verificar ZAP (solo verifica que existe)
which zap
# Esperado: /usr/bin/zap

# Verificar ExploitDB
searchsploit --version
# Esperado: ExploitDB version 1.8 (o similar)

# Verificar Metasploit
msfconsole --version
# Esperado: Metasploit 6.3.x (o similar)

# Verificar Node.js
node --version
# Esperado: v20.x.x (IMPORTANTE: debe ser 18 o superior)

# Verificar npm
npm --version
# Esperado: 10.x.x
⚠️ Si alguno falla: Repite el paso 6.2 para esa herramienta específica.
7. PASO 6: DESCARGAR EL PROYECTO
7.1 Crear Estructura de Carpetas
bash
Copy
# Ir a tu carpeta de inicio
cd ~

# Crear carpeta para proyectos
mkdir -p proyectos

# Entrar a esa carpeta
cd proyectos
7.2 Clonar el Repositorio
bash
Copy
# Descargar el código fuente
git clone https://github.com/tu-usuario/securescan-pro.git
¿Qué es git clone? Copia todo el proyecto desde internet a tu computadora.
Si no tienes acceso al repositorio privado, descarga el ZIP y extráelo en ~/proyectos/securescan-pro.
7.3 Verificar Estructura
bash
Copy
# Entrar al proyecto
cd securescan-pro

# Ver qué hay dentro
ls -la
Deberías ver:
backend/ (carpeta azul)
app/ (carpeta azul)
docker-compose.yml (archivo blanco)
package.json (archivo blanco)
etc.
8. PASO 7: LEVANTAR EL LABORATORIO VULNERABLE
8.1 ¿Qué es el Laboratorio?
Son 3 aplicaciones web intencionalmente rotas donde puedes practicar sin:
Romper nada real
Ir a la cárcel (es tu propia computadora)
Pagar daños
Es como un simulador de vuelo, pero para hackers éticos.
8.2 Iniciar los Contenedores
Asegúrate de estar en la carpeta del proyecto:
bash
Copy
cd ~/proyectos/securescan-pro
Luego:
bash
Copy
# Levantar los 3 laboratorios
docker-compose up -d
¿Qué hace?
docker-compose: Lee el archivo docker-compose.yml
up: Crea y enciende los contenedores
-d: "Detached" (corre en segundo plano, no bloquea la terminal)
⏱️ Tiempo: 5-10 minutos la primera vez (descarga imágenes).
8.3 Verificar que Funcionan
bash
Copy
# Ver estado de los contenedores
docker-compose ps
Esperado:
plain
Copy
NAME                    STATUS
securescan-juice-shop   Up (healthy)
securescan-dvwa         Up (healthy)
securescan-webgoat      Up (healthy)
securescan-webwolf      Up (healthy)
8.4 Probar en Navegador
Abre tu navegador y prueba estas URLs:
Table
URL	Aplicación	Descripción
http://localhost:3001	Juice Shop	Tienda online vulnerable, moderna (Node.js)
http://localhost:3002	DVWA	Clásica, fácil para empezar (PHP)
http://localhost:3003	WebGoat	Tutoriales interactivos (Java)
http://localhost:9090	WebWolf	Companion de WebGoat (email interception)
Si todas cargan: ✅ Laboratorio listo
Si alguna no carga: Espera 2-3 minutos más y refresca.
9. PASO 8: INSTALAR DEPENDENCIAS DEL PROYECTO
9.1 ¿Qué son las Dependencias?
Son librerías de código que otros programadores ya escribieron. En lugar de reinventar todo, usamos código existente.
9.2 Backend (El Cerebro)
bash
Copy
# Ir a la carpeta del backend
cd ~/proyectos/securescan-pro/backend

# Instalar todas las dependencias de Node.js
npm install
⏱️ Tiempo: 2-5 minutos.
¿Qué instala? Express (servidor web), parsers XML/JSON, utilidades de archivos, etc.
Estructura del backend que verás:
plain
Copy
backend/
├── modules/           ← Aquí están los 8 módulos de escaneo
│   ├── orchestrator.js          ← El jefe que coordina todo
│   ├── whatweb_detector.js      ← Detecta tecnologías
│   ├── nmap_scanner.js          ← Escanea puertos
│   ├── gobuster_scanner.js      ← Busca directorios
│   ├── zap_scanner.js           ← Análisis de vulnerabilidades
│   ├── exploitdb_unified.js     ← Busca exploits
│   ├── metasploit_integration.js ← Verifica exploits (opcional)
│   ├── scoring_engine.js        ← Calcula riesgo
│   └── report_generator.js      ← Crea reportes
├── server.js          ← Punto de entrada
└── package.json       ← Lista de dependencias
9.3 Frontend (La Cara Bonita)
Abre otra terminal (sin cerrar la primera):
bash
Copy
# Ir a la raíz del proyecto
cd ~/proyectos/securescan-pro

# Instalar dependencias del frontend
npm install
⏱️ Tiempo: 3-7 minutos (instala React, Next.js, Tailwind, etc.)
10. PASO 9: CONFIGURAR VARIABLES DE ENTORNO
10.1 ¿Qué son las Variables de Entorno?
Son configuraciones secretas que no queremos guardar en el código (porque el código se comparte). Incluyen contraseñas, claves API, etc.
10.2 Crear el Archivo de Configuración
bash
Copy
# En la raíz del proyecto
cd ~/proyectos/securescan-pro

# Copiar el archivo de ejemplo
cp .env.example .env

# Abrir en VS Code para editar
code .env
10.3 Configuración Básica
El archivo se abrirá en VS Code. Modifica estas líneas:
env
Copy
# Puerto donde correrá el backend
PORT=4000

# Clave para la API de ZAP (cambia 'securescanpro' por algo único)
ZAP_API_KEY=securescanpro2026

# Contraseña para Metasploit RPC (solo si usas Metasploit)
MSF_RPC_PASSWORD=securescanpro2026

# Directorio donde guardar reportes
REPORTS_DIR=./reports

# Modo de desarrollo
NODE_ENV=development
Guardar en VS Code: Ctrl + S (o Cmd + S en Mac)
10.4 Configuración Opcional Avanzada
Si quieres personalizar más, puedes agregar:
env
Copy
# Timeouts (en segundos)
NMAP_TIMEOUT=600        # 10 minutos
ZAP_TIMEOUT=1800        # 30 minutos
GOBUSTER_TIMEOUT=300    # 5 minutos

# Perfil de escaneo por defecto
DEFAULT_SCAN_PROFILE=standard

# Whitelist de targets permitidos (separados por coma)
ALLOWED_TARGETS=localhost:3001,localhost:3002,localhost:3003,127.0.0.1
11. PASO 10: INICIAR LA APLICACIÓN
11.1 Terminal 1: Backend (El Motor)
En la primera terminal:
bash
Copy
# Asegúrate de estar en backend
cd ~/proyectos/securescan-pro/backend

# Iniciar el servidor
npm run dev
Éxito verás:
plain
Copy
[SERVER] SecureScan Pro API iniciada en puerto 4000
[ORCHESTRATOR] v3.0 Resiliente cargado
[ZAP] Verificando daemon...
[DB] Conectado a almacenamiento local
Deja esta terminal ABIERTA (no cierres).
11.2 Terminal 2: Frontend (La Interfaz)
Abre nueva terminal (Ctrl + Shift + T o pestaña nueva):
bash
Copy
# Ir a raíz del proyecto
cd ~/proyectos/securescan-pro

# Iniciar el frontend
npm run dev
Éxito verás:
plain
Copy
ready - started server on 0.0.0.0:3000, url: http://localhost:3000
event - compiled client and server successfully
Deja esta terminal ABIERTA también.
11.3 Verificar que Todo Funciona
Abre tu navegador y ve a:
http://localhost:3000
Deberías ver la página de inicio de SecureScan Pro con:
Logo del proyecto
Botón "Nuevo Escaneo"
Botón "Ver Laboratorio"
Diseño moderno con colores
Si ves error "Cannot connect":
Revisa que ambas terminales estén corriendo sin errores rojos
Espera 30 segundos y refresca
Verifica que no haya otro programa usando el puerto 3000
12. PASO 11: TU PRIMER ESCANEO
12.1 Ir al Escáner
En la página de inicio, haz clic en "Nuevo Escaneo" o ve directo a:
http://localhost:3000/scanner
12.2 Configurar el Escaneo
Verás un formulario. Completa:
Table
Campo	Valor	Explicación
URL Objetivo	http://localhost:3001	Juice Shop (el más moderno)
Perfil de Escaneo	Standard	Balance entre velocidad y profundidad
Herramientas	Deja todas marcadas	Para ver el escaneo completo
12.3 Iniciar y Observar
Haz clic en "Iniciar Escaneo"
Aparecerá una barra de progreso que muestra:
Qué herramienta está corriendo ahora
Porcentaje completado
Logs en tiempo real
Fases del escaneo:
plain
Copy
1. WhatWeb (10%)     → Detectando tecnologías...
2. Nmap (35%)        → Escaneando puertos...
3. Gobuster (55%)    → Buscando directorios...
4. ZAP (80%)         → Analizando vulnerabilidades...
5. ExploitDB (90%)   → Buscando exploits...
6. Scoring (95%)     → Calculando riesgo...
7. Reporte (100%)    → Generando documento...
⏱️ Tiempo estimado: 15-25 minutos para Standard.
12.4 Ver Resultados
Cuando termine (100%), haz clic en "Ver Resultados".
Verás:
Score de Seguridad: 0-100 (menor = más vulnerable)
Tecnologías Detectadas: Node.js, Express, Angular, etc.
Puertos Abiertos: 3001/tcp (HTTP)
Vulnerabilidades: Listado con severidad (Critical, High, Medium, Low)
Exploits Relacionados: Enlaces a Exploit-DB
12.5 Descargar Reporte
Haz clic en "Descargar Reporte HTML" o "PDF" para guardar el informe profesional.
13. SOLUCIÓN DE PROBLEMAS COMUNES
13.1 Error: "Permission denied" en Docker
Síntoma: docker: permission denied while trying to connect to daemon
Solución:
bash
Copy
# Agregar usuario al grupo docker
sudo usermod -aG docker $USER

# Cerrar sesión y volver a entrar (o reiniciar)
# Luego prueba:
docker run hello-world
13.2 Error: ZAP no responde
Síntoma: [ZAP] Error: Connection refused
Solución manual:
bash
Copy
# Iniciar ZAP en modo daemon (en una tercera terminal)
zap.sh -daemon -port 8080 -config api.key=securescanpro2026
13.3 Error: "Module not found" en npm install
Síntoma: Cannot find module 'express'
Solución:
bash
Copy
# Borrar node_modules y reinstalar
rm -rf node_modules package-lock.json
npm install
13.4 Error: Puerto 3000 o 4000 ocupado
Síntoma: EADDRINUSE: Address already in use :::3000
Solución:
bash
Copy
# Encontrar qué proceso usa el puerto
sudo lsof -i :3000

# Matar el proceso (reemplaza #### con el número que salga)
sudo kill -9 ####

# O usar puerto diferente
npm run dev -- --port 3001
13.5 Error: Metasploit RPC no conecta
Síntoma: Metasploit no aparece en resultados
Solución: Es opcional por diseño. Si quieres usarlo:
bash
Copy
# Iniciar el servicio RPC de Metasploit
msfrpcd -P securescanpro2026 -S -f
13.6 Laboratorio no responde
Síntoma: localhost:3001 no carga
Solución:
bash
Copy
# Verificar estado
docker-compose ps

# Si dice "Exited" o "Restarting":
docker-compose restart

# Si persiste, recrear todo:
docker-compose down
docker-compose up -d
14. VERIFICACIÓN FINAL
14.1 Checklist de Instalación Exitosa
Marca con ✅ cada ítem:
[ ] Kali Linux corre en VirtualBox o nativo
[ ] Terminal abre sin errores
[ ] docker run hello-world muestra mensaje de éxito
[ ] whatweb --version muestra versión
[ ] nmap --version muestra versión
[ ] node --version muestra v18+ o v20+
[ ] Proyecto clonado en ~/proyectos/securescan-pro
[ ] docker-compose up -d creó 4 contenedores healthy
[ ] http://localhost:3001 carga Juice Shop
[ ] Backend corre en puerto 4000 sin errores
[ ] Frontend corre en puerto 3000 sin errores
[ ] Página http://localhost:3000 carga correctamente
[ ] Escaneo de prueba se inicia y progresa
[ ] Reporte se genera y descarga
14.2 Comandos Rápidos de Referencia
Guarda esta tabla:
Table
Acción	Comando
Ver laboratorio	docker-compose ps
Reiniciar laboratorio	docker-compose restart
Destruir laboratorio	docker-compose down
Ver logs de Juice Shop	docker-compose logs juice-shop
Iniciar solo backend	cd backend && npm run dev
Iniciar solo frontend	npm run dev
Actualizar herramientas	sudo apt update && sudo apt upgrade
Actualizar exploits	searchsploit -u
14.3 ¿Y Ahora Qué?
Prácticas recomendadas:
Escanea DVWA (http://localhost:3002) - Es más fácil, bueno para empezar
Intenta resolver desafíos en Juice Shop mientras escaneas
Compara perfiles: Prueba "Quick" vs "Comprehensive" y mide tiempo
Explora reportes SARIF: Abre en GitHub para ver formato estándar
Aprendizaje adicional:
Documentación oficial: /docs/ en el proyecto
OWASP Juice Shop hints: Presiona ? en la app
DVWA help: Cada nivel tiene "View Source" y "View Help"
📞 SOPORTE Y RECURSOS
Si todo falla:
Revisa logs: docker-compose logs y terminales de npm
Googlea el error exacto (copia y pega el mensaje)
Pregunta en foros: Stack Overflow, Reddit r/cybersecurity, Discord de SENA
Recursos útiles:
Kali Linux Docs: https://www.kali.org/docs/
Docker Getting Started: https://docs.docker.com/get-started/
Node.js Docs: https://nodejs.org/en/docs/
OWASP Juice Shop: https://owasp.org/www-project-juice-shop/
¡Felicidades! Ahora tienes un laboratorio profesional de ciberseguridad funcionando en tu computadora.
Recuerda: Estas herramientas son poderosas. Úsalas solo en:
Tu propio laboratorio (localhost)
Sistemas donde tengas autorización escrita explícita
Hack ético = Permiso explícito + Propósito educativo/defensivo
Guía creada para el Servicio Nacional de Aprendizaje - SENA
tecnico en seguridad de aplicaciones web
Marzo 2026
```
