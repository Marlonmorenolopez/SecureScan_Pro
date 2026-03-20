#!/bin/bash
# ============================================================================
# SecureScan Pro - Script de Configuración del Laboratorio v2.0
# ============================================================================
# Este script configura el laboratorio de aplicaciones vulnerables
# compatible con SecureScanOrchestrator v3.0.
#
# Aplicaciones incluidas (según allowedTargets del orquestador):
#   - Juice Shop (localhost:3001)
#   - DVWA (localhost:3002)
#   - WebGoat (localhost:3003)
#
# USO: chmod +x setup_lab.sh && ./setup_lab.sh
# ============================================================================

set -e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Banner
print_banner() {
    echo -e "${CYAN}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║     ███████╗███████╗ ██████╗██╗      █████╗ ██████╗              ║"
    echo "║     ██╔════╝██╔════╝██╔════╝██║     ██╔══██╗██╔══██╗             ║"
    echo "║     ███████╗█████╗  ██║     ██║     ███████║██████╔╝             ║"
    echo "║     ╚════██║██╔══╝  ██║     ██║     ██╔══██║██╔══██╗             ║"
    echo "║     ███████║███████╗╚██████╗███████╗██║  ██║██████╔╝             ║"
    echo "║     ╚══════╝╚══════╝ ╚═════╝╚══════╝╚═╝  ╚═╝╚═════╝              ║"
    echo "║                                                                  ║"
    echo "║         LABORATORIO SEGURIDAD - Orchestrator v3.0               ║"
    echo "║              Targets: 3001 (JS) | 3002 (DVWA) | 3003 (WG)       ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

# Funciones de logging
log_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[✓]${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}[!]${NC} $1"
}

log_error() {
    echo -e "${RED}[✗]${NC} $1"
}

log_step() {
    echo -e "${MAGENTA}[STEP]${NC} $1"
}

# Verificar Docker
check_docker() {
    log_step "Verificando instalación de Docker..."
    
    if ! command -v docker &> /dev/null; then
        log_error "Docker no está instalado."
        echo ""
        echo "Instala Docker con:"
        echo "  sudo apt update"
        echo "  sudo apt install -y docker.io docker-compose"
        echo "  sudo systemctl enable docker --now"
        echo "  sudo usermod -aG docker \$USER"
        echo ""
        echo "Cierra sesión y vuelve a iniciar."
        exit 1
    fi
    
    log_success "Docker: $(docker --version | cut -d' ' -f3 | tr -d ',')"
}

# Verificar Docker Compose
check_docker_compose() {
    log_step "Verificando Docker Compose..."
    
    if command -v docker-compose &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker-compose"
        log_success "Docker Compose: $(docker-compose --version | cut -d' ' -f3)"
    elif docker compose version &> /dev/null; then
        DOCKER_COMPOSE_CMD="docker compose"
        log_success "Docker Compose V2 (plugin)"
    else
        log_error "Docker Compose no está instalado."
        echo "  sudo apt install -y docker-compose"
        exit 1
    fi
}

# Verificar permisos Docker
check_docker_permissions() {
    log_step "Verificando permisos de Docker..."
    
    if ! docker info &> /dev/null; then
        log_error "Sin permisos para ejecutar Docker."
        echo ""
        echo "Ejecuta:"
        echo "  sudo usermod -aG docker \$USER"
        echo ""
        echo "Cierra sesión completamente y vuelve a iniciar."
        exit 1
    fi
    
    log_success "Permisos verificados"
}

# Crear directorios necesarios (alineados con orquestador)
create_directories() {
    log_step "Creando estructura de directorios..."
    
    # Estructura compatible con SecureScanOrchestrator v3.0
    mkdir -p reports
    mkdir -p logs
    mkdir -p temp/{whatweb,nmap,gobuster,zap,exploitdb}
    mkdir -p backend/outputs
    
    log_success "Estructura creada:"
    log_info "  ./reports/    - Reportes finales"
    log_info "  ./logs/       - Logs de ejecución"
    log_info "  ./temp/       - Resultados temporales de escaneo"
    log_info "  ./backend/    - Código del backend"
}

# Crear archivo docker-compose.yml optimizado
create_docker_compose() {
    log_step "Generando docker-compose.yml..."
    
    cat > docker-compose.yml << 'EOF'
version: '3.8'

services:
  # ============================================================================
  # JUICE SHOP - OWASP Top 10 2021 (Puerto 3001)
  # Aplicación moderna en Node.js con múltiples vulnerabilidades
  # ============================================================================
  juice-shop:
    image: bkimminich/juice-shop:latest
    container_name: securescan-juice-shop
    ports:
      - "3001:3000"
    environment:
      - NODE_ENV=unsafe
      - JWT_SECRET=securescan-testing-key
    networks:
      - securescan-lab
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ============================================================================
  # DVWA - Damn Vulnerable Web Application (Puerto 3002)
  # Aplicación PHP clásica para práctica de vulnerabilidades web
  # ============================================================================
  dvwa:
    image: vulnerables/web-dvwa:latest
    container_name: securescan-dvwa
    ports:
      - "3002:80"
    environment:
      - MYSQL_ROOT_PASSWORD=securescan
      - MYSQL_DATABASE=dvwa
      - MYSQL_USER=dvwa
      - MYSQL_PASSWORD=p@ssw0rd
    networks:
      - securescan-lab
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost/login.php"]
      interval: 30s
      timeout: 10s
      retries: 3

  # ============================================================================
  # WEBGOAT - Aplicación de enseñanza OWASP (Puerto 3003)
  # Tutoriales interactivos de seguridad web
  # ============================================================================
  webgoat:
    image: webgoat/webgoat:latest
    container_name: securescan-webgoat
    ports:
      - "3003:8080"
    environment:
      - WEBGOAT_PORT=8080
      - WEBGOAT_HOST=0.0.0.0
    networks:
      - securescan-lab
    restart: unless-stopped
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:8080/WebGoat"]
      interval: 30s
      timeout: 10s
      retries: 3

networks:
  securescan-lab:
    driver: bridge
    ipam:
      config:
        - subnet: 172.20.0.0/24
          gateway: 172.20.0.1

volumes:
  dvwa-data:
EOF

    log_success "docker-compose.yml generado"
    log_info "  Red: 172.20.0.0/24 (compatible con allowedTargets)"
    log_info "  Servicios: juice-shop (3001), dvwa (3002), webgoat (3003)"
}

# Descargar imágenes Docker
pull_images() {
    log_step "Descargando imágenes Docker..."
    echo ""
    
    local images=(
        "bkimminich/juice-shop:latest"
        "vulnerables/web-dvwa:latest"
        "webgoat/webgoat:latest"
    )
    
    for image in "${images[@]}"; do
        log_info "Descargando: $image"
        docker pull "$image" || log_warning "Error descargando $image (se reintentará al iniciar)"
    done
    
    echo ""
    log_success "Descarga completada"
}

# Verificar imágenes descargadas
check_images() {
    log_step "Verificando imágenes..."
    
    local images=(
        "bkimminich/juice-shop"
        "vulnerables/web-dvwa"
        "webgoat/webgoat"
    )
    
    for image in "${images[@]}"; do
        if docker image inspect "$image:latest" &> /dev/null; then
            log_success "$image"
        else
            log_warning "$image no disponible localmente"
        fi
    done
}

# Iniciar contenedores
start_containers() {
    log_step "Iniciando laboratorio..."
    echo ""
    
    $DOCKER_COMPOSE_CMD up -d
    
    echo ""
    log_success "Contenedores iniciados"
}

# Esperar a que los servicios estén listos
wait_for_services() {
    log_step "Esperando servicios (healthcheck)..."
    echo ""
    
    local services=(
        "juice-shop:3001:/"
        "dvwa:3002:/login.php"
        "webgoat:3003:/WebGoat"
    )
    
    local max_attempts=30
    local wait_time=3
    
    for service in "${services[@]}"; do
        IFS=':' read -r name port path <<< "$service"
        local attempts=0
        
        echo -n "  $name (localhost:$port)..."
        
        while [ $attempts -lt $max_attempts ]; do
            local http_code
            http_code=$(curl -s -o /dev/null -w "%{http_code}" "http://localhost:$port$path" 2>/dev/null || echo "000")
            
            if [[ "$http_code" =~ ^(200|301|302|401|403)$ ]]; then
                echo -e " ${GREEN}LISTO${NC} (HTTP $http_code)"
                break
            fi
            
            attempts=$((attempts + 1))
            sleep $wait_time
            echo -n "."
        done
        
        if [ $attempts -eq $max_attempts ]; then
            echo -e " ${YELLOW}TIMEOUT${NC}"
            log_warning "$name puede estar iniciando aún. Verificar manualmente."
        fi
    done
    
    echo ""
}

# Verificar estado de contenedores
check_container_status() {
    log_step "Estado de los contenedores:"
    echo ""
    $DOCKER_COMPOSE_CMD ps
    echo ""
}

# Mostrar información final
show_status() {
    echo ""
    echo -e "${CYAN}╔══════════════════════════════════════════════════════════════════╗${NC}"
    echo -e "${CYAN}║              LABORATORIO SECURESCAN PRO - ACTIVO                 ║${NC}"
    echo -e "${CYAN}╚══════════════════════════════════════════════════════════════════╝${NC}"
    echo ""
    echo -e "${GREEN}Aplicaciones vulnerables disponibles:${NC}"
    echo ""
    echo "  ┌─────────────────────────────────────────────────────────────────┐"
    echo "  │ Juice Shop  │ http://localhost:3001  │ Node.js moderno, OWASP  │"
    echo "  │ DVWA        │ http://localhost:3002  │ PHP clásico, básico     │"
    echo "  │ WebGoat     │ http://localhost:3003  │ Java, tutoriales OWASP  │"
    echo "  └─────────────────────────────────────────────────────────────────┘"
    echo ""
    echo -e "${YELLOW}Credenciales por defecto:${NC}"
    echo ""
    echo "  DVWA:    admin / password"
    echo "  WebGoat: Crear cuenta en http://localhost:3003/WebGoat/register.mvc"
    echo ""
    echo -e "${CYAN}Integración con Orchestrator:${NC}"
    echo ""
    echo "  Los puertos 3001, 3002, 3003 están en allowedTargets[]"
    echo "  Red Docker: 172.20.0.0/24 (scope permitido)"
    echo ""
    echo "  Ejemplo de escaneo:"
    echo "    ./run_all_scans.sh http://localhost:3001"
    echo "    node start-backend.js"
    echo ""
    echo -e "${CYAN}Comandos de gestión:${NC}"
    echo ""
    echo "  Ver estado:     $DOCKER_COMPOSE_CMD ps"
    echo "  Ver logs:       $DOCKER_COMPOSE_CMD logs -f [juice-shop|dvwa|webgoat]"
    echo "  Detener:        $DOCKER_COMPOSE_CMD down"
    echo "  Reiniciar:      $DOCKER_COMPOSE_CMD restart"
    echo "  Limpiar todo:   $DOCKER_COMPOSE_CMD down -v --remove-orphans"
    echo ""
    echo -e "${GREEN}¡Laboratorio listo para escanear con SecureScanOrchestrator!${NC}"
    echo ""
}

# Función principal
main() {
    print_banner
    
    # Verificaciones previas
    check_docker
    check_docker_compose
    check_docker_permissions
    
    echo ""
    
    # Configuración
    create_directories
    create_docker_compose
    
    echo ""
    
    # Descargar e iniciar
    pull_images
    check_images
    
    echo ""
    
    start_containers
    wait_for_services
    check_container_status
    
    show_status
}

# Manejo de argumentos
case "${1:-}" in
    --status|-s)
        check_docker_compose 2>/dev/null || DOCKER_COMPOSE_CMD="${2:-docker-compose}"
        check_container_status
        ;;
    --stop|-d)
        log_info "Deteniendo laboratorio..."
        check_docker_compose 2>/dev/null || DOCKER_COMPOSE_CMD="${2:-docker-compose}"
        $DOCKER_COMPOSE_CMD down
        log_success "Laboratorio detenido"
        ;;
    --restart|-r)
        log_info "Reiniciando laboratorio..."
        check_docker_compose 2>/dev/null || DOCKER_COMPOSE_CMD="${2:-docker-compose}"
        $DOCKER_COMPOSE_CMD restart
        wait_for_services
        check_container_status
        show_status
        ;;
    --clean|-c)
        log_warning "Esto eliminará TODOS los datos del laboratorio."
        read -p "¿Continuar? (s/n): " confirm
        if [[ "$confirm" =~ ^[sS]$ ]]; then
            check_docker_compose 2>/dev/null || DOCKER_COMPOSE_CMD="${2:-docker-compose}"
            $DOCKER_COMPOSE_CMD down --volumes --remove-orphans
            rm -f docker-compose.yml
            log_success "Laboratorio limpiado completamente"
        fi
        ;;
    --logs|-l)
        shift
        check_docker_compose 2>/dev/null || DOCKER_COMPOSE_CMD="${2:-docker-compose}"
        $DOCKER_COMPOSE_CMD logs -f "${1:-}" 2>/dev/null || $DOCKER_COMPOSE_CMD logs -f
        ;;
    --help|-h)
        echo "SecureScan Pro - Laboratorio v2.0"
        echo ""
        echo "Uso: ./setup_lab.sh [opción]"
        echo ""
        echo "Opciones:"
        echo "  (sin args)        Configurar e iniciar laboratorio completo"
        echo "  --status, -s      Ver estado de los contenedores"
        echo "  --stop, -d        Detener todos los contenedores"
        echo "  --restart, -r     Reiniciar contenedores"
        echo "  --logs, -l [svc]  Ver logs (svc: juice-shop, dvwa, webgoat)"
        echo "  --clean, -c       Eliminar contenedores, volúmenes y configuración"
        echo "  --help, -h        Mostrar esta ayuda"
        echo ""
        echo "Servicios: juice-shop (3001), dvwa (3002), webgoat (3003)"
        ;;
    *)
        main
        ;;
esac