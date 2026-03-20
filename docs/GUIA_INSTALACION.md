GUÍA DE INSTALACIÓN PASO A PASO
SecureScan Pro - Para Principiantes (Versión Modular)
INTRODUCCIÓN
Esta guía te llevará paso a paso desde cero hasta tener el proyecto SecureScan Pro funcionando. El sistema utiliza una arquitectura modular de backend para integrar herramientas de seguridad profesionales.

Tiempo estimado de instalación: 30-45 minutos

PASO 1: INSTALAR KALI LINUX
Opción A: Máquina Virtual (Recomendado)
Descargar VirtualBox: virtualbox.org

Descargar Kali Linux: kali.org/get-kali/ (Versión VirtualBox 64-bit).

Importar: Abre VirtualBox > Archivo > Importar servicio virtualizado > Selecciona el .ova.

Configurar: Mínimo 4GB RAM y 2 CPUs.

Credenciales: kali / kali.

PASO 2: ACTUALIZAR EL SISTEMA
Abre una terminal y ejecuta:

Bash
sudo apt update && sudo apt full-upgrade -y

# Reiniciar si hay actualizaciones de kernel

# sudo reboot

PASO 3: INSTALAR DOCKER Y DOCKER COMPOSE
Bash

# Instalar Docker y Compose

sudo apt install -y docker.io docker-compose

# Configurar permisos para tu usuario

sudo usermod -aG docker $USER
newgrp docker

# Verificar

docker run hello-world
PASO 4: INSTALAR VISUAL STUDIO CODE
Bash
sudo apt install -y curl gpg apt-transport-https
curl -fsSL https://packages.microsoft.com/keys/microsoft.asc | sudo gpg --dearmor -o /usr/share/keyrings/microsoft-archive-keyring.gpg
echo "deb [arch=amd64 signed-by=/usr/share/keyrings/microsoft-archive-keyring.gpg] https://packages.microsoft.com/repos/vscode stable main" | sudo tee /etc/apt/sources.list.d/vscode.list
sudo apt update && sudo apt install -y code
PASO 5: INSTALAR HERRAMIENTAS DE SEGURIDAD (BACKEND)
El backend de SecureScan Pro requiere que las siguientes herramientas estén instaladas en el sistema operativo:

Bash

# Instalar herramientas vinculadas a los módulos JS

sudo apt install -y nmap gobuster zaproxy exploitdb metasploit-framework nodejs npm whatweb

# Actualizar base de datos de exploits

searchsploit -u

# Verificar instalaciones

nmap --version
gobuster version
msfconsole --version
PASO 6: CLONAR EL PROYECTO
Bash
cd ~
mkdir -p proyectos && cd proyectos
git clone https://github.com/tu-usuario/securescan-pro.git
cd securescan-pro
PASO 7: LEVANTAR EL LABORATORIO VULNERABLE
El laboratorio de prácticas se compone exclusivamente de tres entornos controlados:

Bash

# Iniciar los contenedores del laboratorio

docker-compose up -d
Entornos disponibles:

OWASP Juice Shop: http://localhost:3001

DVWA: http://localhost:3002

OWASP WebGoat: http://localhost:3003

PASO 8: INSTALAR DEPENDENCIAS DEL PROYECTO
Backend (Arquitectura Modular)
El backend gestiona la lógica de escaneo mediante módulos independientes:

Bash
cd ~/proyectos/securescan-pro/backend
npm install
Módulos configurados en backend/modules/:

nmap_scanner.js: Escaneo de puertos y servicios.

gobuster_scanner.js: Enumeración de directorios.

zap_scanner.js: Análisis de vulnerabilidades web (DAST).

metasploit_integration.js: Verificación de exploits.

orchestrator.js: Coordinación de tareas.

scoring_engine.js: Motor de cálculo de criticidad.

Frontend
Bash
cd ~/proyectos/securescan-pro
npm install
PASO 9: CONFIGURAR VARIABLES DE ENTORNO
Bash
cp .env.example .env
nano .env
Configuración requerida:

Fragmento de código
PORT=4000
ZAP_API_KEY=securescanpro
MSF_RPC_PASSWORD=securescanpro
PASO 10: INICIAR LA APLICACIÓN
Terminal 1: Backend
Bash
cd ~/proyectos/securescan-pro/backend
npm run dev
Terminal 2: Frontend
Bash
cd ~/proyectos/securescan-pro
npm run dev
PASO 11: ACCEDER Y ESCANEAR
Entra a http://localhost:3000.

Ingresa la URL de uno de tus laboratorios (ej. http://localhost:3001).

Selecciona los módulos de escaneo (Nmap, ZAP, etc.).

El Orchestrator ejecutará los scripts y el Scoring Engine generará el reporte.

SOLUCIÓN DE PROBLEMAS
Error en Metasploit: Asegúrate de que el servicio RPC esté activo: msfrpcd -P securescanpro -S.

Error en ZAP: ZAP debe estar corriendo: zap-proxy -daemon -config api.key=securescanpro.

Permisos de Docker: Si falla el laboratorio, usa sudo systemctl start docker.
