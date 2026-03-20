#!/bin/bash

# ============================================================================
# SecureScan Pro - Script de Instalación de Herramientas v2.0
# ============================================================================
# Este script instala las herramientas necesarias para el proyecto
# SecureScan Pro basado en el Orchestrator v3.0.
#
# Herramientas instaladas:
#   - nmap: Escaneo de puertos y servicios
#   - whatweb: Detección de tecnologías web
#   - gobuster: Fuerza bruta de directorios y subdominios
#   - zaproxy: Escaneo DAST (OWASP ZAP)
#   - exploitdb/searchsploit: Búsqueda de exploits
#   - metasploit-framework: Framework de explotación (opcional)
#   - docker/docker-compose: Para laboratorios vulnerables
#   - nodejs/npm: Runtime del backend
#
# Uso:
#   sudo ./install_tools.sh
# ============================================================================

set -e

# Colores
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[OK]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_step() {
    echo -e "${CYAN}[STEP]${NC} $1"
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║     SecureScan Pro - Instalador de Herramientas v2.0             ║"
    echo "║              Compatible con Orchestrator v3.0                     ║"
    echo "║                    Para Kali Linux                                ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_root() {
    if [ "$EUID" -ne 0 ]; then
        log_error "Este script debe ejecutarse como root (sudo)"
        log_info "Uso: sudo $0"
        exit 1
    fi
}

check_kali() {
    if [ -f /etc/os-release ]; then
        . /etc/os-release
        if [[ "$ID" != "kali" ]]; then
            log_warning "Este script está optimizado para Kali Linux"
            log_warning "Sistema detectado: $PRETTY_NAME"
            read -p "¿Deseas continuar de todos modos? (s/n): " confirm
            if [[ "$confirm" != "s" && "$confirm" != "S" ]]; then
                exit 1
            fi
        fi
    fi
}

install_system_packages() {
    log_step "Actualizando repositorios..."
    apt-get update
    
    log_step "Instalando herramientas de escaneo..."
    apt-get install -y \
        nmap \
        whatweb \
        gobuster \
        zaproxy \
        exploitdb \
        searchsploit
    
    log_step "Instalando Metasploit Framework..."
    apt-get install -y metasploit-framework || {
        log_warning "No se pudo instalar Metasploit desde repos oficiales"
        log_info "Puedes instalarlo manualmente desde: https://docs.metasploit.com/"
    }
    
    log_step "Instalando dependencias del sistema..."
    apt-get install -y \
        curl \
        wget \
        git \
        jq \
        python3 \
        python3-pip \
        nodejs \
        npm \
        docker.io \
        docker-compose
    
    log_step "Instalando wordlists..."
    apt-get install -y \
        wordlists \
        seclists
    
    log_success "Paquetes del sistema instalados"
}

configure_docker() {
    log_step "Configurando Docker..."
    
    # Iniciar servicio Docker
    systemctl start docker 2>/dev/null || true
    systemctl enable docker 2>/dev/null || true
    
    # Agregar usuario actual al grupo docker
    SUDO_USER=${SUDO_USER:-$USER}
    if [ -n "$SUDO_USER" ] && [ "$SUDO_USER" != "root" ]; then
        usermod -aG docker "$SUDO_USER" 2>/dev/null || true
        log_success "Usuario $SUDO_USER agregado al grupo docker"
    fi
    
    log_success "Docker configurado"
    log_warning "Cierra sesión y vuelve a entrar para aplicar cambios de grupo docker"
}

install_node_dependencies() {
    log_step "Configurando Node.js..."
    
    # Actualizar npm a última versión
    npm install -g npm@latest
    
    log_success "Node.js configurado (Node: $(node --version), NPM: $(npm --version))"
}

setup_wordlists() {
    log_step "Configurando wordlists..."
    
    # Crear directorio si no existe
    mkdir -p /usr/share/wordlists
    
    # Descomprimir rockyou si está comprimido
    if [ -f "/usr/share/wordlists/rockyou.txt.gz" ]; then
        log_info "Descomprimiendo rockyou.txt..."
        gunzip -k /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
    fi
    
    # Verificar que exista rockyou.txt
    if [ ! -f "/usr/share/wordlists/rockyou.txt" ]; then
        log_warning "rockyou.txt no encontrado. Descargando..."
        curl -L "https://github.com/praetorian-inc/Hob0Rules/raw/master/wordlists/rockyou.txt.gz" -o /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
        gunzip /usr/share/wordlists/rockyou.txt.gz 2>/dev/null || true
    fi
    
    # Crear enlaces útiles para Gobuster
    if [ -d "/usr/share/seclists" ]; then
        ln -sf /usr/share/seclists/Discovery/Web-Content /usr/share/wordlists/web-content 2>/dev/null || true
    fi
    
    log_success "Wordlists configuradas"
}

update_databases() {
    log_step "Actualizando bases de datos..."
    
    # Actualizar Exploit-DB
    log_info "Actualizando Exploit-DB..."
    searchsploit -u 2>/dev/null || log_warning "No se pudo actualizar Exploit-DB"
    
    # Actualizar Nmap scripts
    if command -v nmap &> /dev/null; then
        log_info "Actualizando scripts de Nmap..."
        nmap --script-updatedb 2>/dev/null || true
    fi
    
    log_success "Bases de datos actualizadas"
}

verify_installation() {
    echo ""
    log_step "Verificando instalación..."
    echo "═══════════════════════════════════════════════════════════════════"
    
    # Herramientas principales del orquestador
    declare -A tools=(
        ["nmap"]="nmap --version"
        ["whatweb"]="whatweb --version"
        ["gobuster"]="gobuster version"
        ["searchsploit"]="searchsploit --version"
        ["docker"]="docker --version"
        ["docker-compose"]="docker-compose --version"
        ["node"]="node --version"
        ["npm"]="npm --version"
    )
    
    for tool in "${!tools[@]}"; do
        cmd="${tools[$tool]}"
        if command -v "$tool" &> /dev/null; then
            version=$($cmd 2>&1 | head -1)
            log_success "$(printf '%-15s' "$tool") $version"
        else
            log_error "$(printf '%-15s' "$tool") No encontrado"
        fi
    done
    
    # Verificaciones especiales
    echo "───────────────────────────────────────────────────────────────────"
    
    # ZAP
    if command -v zaproxy &> /dev/null || [ -f "/usr/share/zaproxy/zap.sh" ] || [ -f "/usr/bin/zap.sh" ]; then
        log_success "$(printf '%-15s' "zaproxy") Instalado"
    else
        log_warning "$(printf '%-15s' "zaproxy") No encontrado"
    fi
    
    # Metasploit
    if command -v msfconsole &> /dev/null; then
        version=$(msfconsole --version 2>&1 | head -1)
        log_success "$(printf '%-15s' "metasploit") $version"
    else
        log_warning "$(printf '%-15s' "metasploit") No instalado (opcional)"
    fi
    
    # Wordlists
    if [ -f "/usr/share/wordlists/rockyou.txt" ]; then
        size=$(du -h /usr/share/wordlists/rockyou.txt | cut -f1)
        log_success "$(printf '%-15s' "rockyou.txt") $size"
    else
        log_warning "$(printf '%-15s' "rockyou.txt") No encontrado"
    fi
    
    echo "═══════════════════════════════════════════════════════════════════"
}

print_next_steps() {
    echo ""
    echo -e "${GREEN}╔═══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║              INSTALACIÓN COMPLETADA                               ║${NC}"
    echo -e "${GREEN}╚═══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo "Próximos pasos:"
    echo ""
    echo "1. Cierra sesión y vuelve a entrar para aplicar permisos de Docker"
    echo ""
    echo "2. Navega al directorio del proyecto:"
    echo "   cd /ruta/al/proyecto/securescan-pro"
    echo ""
    echo "3. Inicia los laboratorios de práctica:"
    echo "   docker-compose -f docker-compose.lab.yml up -d"
    echo ""
    echo "4. Instala dependencias del backend:"
    echo "   cd backend && npm install xml2js axios"
    echo ""
    echo "5. Verifica la instalación del backend:"
    echo "   node start-backend.js"
    echo ""
    echo "6. El backend estará disponible en http://localhost:3000"
    echo ""
    echo "Herramientas instaladas:"
    echo "  • nmap, whatweb, gobuster (descubrimiento)"
    echo "  • zaproxy (escaneo de vulnerabilidades web)"
    echo "  • searchsploit (búsqueda de exploits)"
    echo "  • metasploit (explotación - opcional)"
    echo ""
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    print_banner
    check_root
    check_kali
    
    echo ""
    log_info "Iniciando instalación de herramientas para SecureScan Pro..."
    log_info "Esta instalación puede tardar varios minutos."
    echo ""
    
    # Fases de instalación
    install_system_packages
    configure_docker
    install_node_dependencies
    setup_wordlists
    update_databases
    
    # Verificación final
    verify_installation
    
    # Instrucciones finales
    print_next_steps
}

# Manejo de errores
trap 'log_error "Error en la instalación. Línea: $LINENO"' ERR

main "$@"