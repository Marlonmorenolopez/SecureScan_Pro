#!/bin/bash

# ============================================================================
# SecureScan Pro - Script Orquestador de Escaneo v2.0
# ============================================================================
# Este script ejecuta las herramientas de seguridad del Orchestrator v3.0
# de forma secuencial y guarda los resultados en estructura compatible.
#
# Herramientas ejecutadas (en orden):
#   1. whatweb    - Detección de tecnologías web
#   2. nmap       - Escaneo de puertos, servicios y vulnerabilidades
#   3. gobuster   - Descubrimiento de directorios/subdominios
#   4. zap        - Escaneo DAST de aplicaciones web
#   5. searchsploit - Búsqueda de exploits relacionados
#
# Uso:
#   ./run_all_scans.sh <URL_OBJETIVO>
#   ./run_all_scans.sh http://localhost:3001
#
# Requisitos:
#   - whatweb, nmap, gobuster, zaproxy, searchsploit
#   - Permisos de ejecución: chmod +x run_all_scans.sh
# ============================================================================

# Modo NO estricto - continuar si una herramienta falla (resiliencia)
set +e

# Colores para output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
CYAN='\033[0;36m'
MAGENTA='\033[0;35m'
NC='\033[0m'

# Iconos
ICON_CHECK="✓"
ICON_FAIL="✗"
ICON_INFO="ℹ"
ICON_WARN="⚠"
ICON_RUN="▶"

# ============================================================================
# FUNCIONES DE UTILIDAD
# ============================================================================

log_info() {
    echo -e "${BLUE}${ICON_INFO}${NC} $1"
}

log_success() {
    echo -e "${GREEN}${ICON_CHECK}${NC} $1"
}

log_warning() {
    echo -e "${YELLOW}${ICON_WARN}${NC} $1"
}

log_error() {
    echo -e "${RED}${ICON_FAIL}${NC} $1"
}

log_running() {
    echo -e "${CYAN}${ICON_RUN}${NC} $1"
}

log_phase() {
    echo -e "${MAGENTA}[FASE $1/5]${NC} $2"
}

print_banner() {
    echo -e "${CYAN}"
    echo "╔═══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                   ║"
    echo "║   ███████╗███████╗ ██████╗██╗   ██╗██████╗ ███████╗              ║"
    echo "║   ██╔════╝██╔════╝██╔════╝██║   ██║██╔══██╗██╔════╝              ║"
    echo "║   ███████╗█████╗  ██║     ██║   ██║██████╔╝█████╗                ║"
    echo "║   ╚════██║██╔══╝  ██║     ██║   ██║██╔══██╗██╔══╝                ║"
    echo "║   ███████║███████╗╚██████╗╚██████╔╝██║  ██║███████╗              ║"
    echo "║   ╚══════╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝              ║"
    echo "║                                                                   ║"
    echo "║         SecureScan Pro - Orchestrator v2.0 (Resiliente)          ║"
    echo "║              Compatible con Orchestrator JS v3.0                   ║"
    echo "║                                                                   ║"
    echo "╚═══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
}

check_tool() {
    if command -v "$1" &> /dev/null; then
        log_success "$1 encontrado"
        return 0
    else
        log_error "$1 no encontrado"
        return 1
    fi
}

extract_host_port() {
    local url=$1
    # Extraer host y puerto de la URL
    HOST=$(echo "$url" | sed -e 's|^[^/]*//||' -e 's|/.*$||' -e 's|:.*$||')
    PORT=$(echo "$url" | grep -oP ':\K[0-9]+' | head -1)
    
    if [ -z "$PORT" ]; then
        if [[ "$url" == https://* ]]; then
            PORT="443"
        else
            PORT="80"
        fi
    fi
}

# ============================================================================
# FUNCIONES DE ESCANEO (ALINEADAS CON ORCHESTRATOR JS V3.0)
# ============================================================================

run_whatweb() {
    local target=$1
    local output_dir=$2
    
    log_running "WhatWeb - Detección de tecnologías web..."
    
    local output_file="$output_dir/whatweb_output.json"
    
    # WhatWeb con formato JSON (agresión nivel 3 como en el orquestador)
    whatweb --aggression 3 \
            --colour never \
            --log-json "$output_file" \
            "$target" 2>&1 || true
    
    if [ -s "$output_file" ]; then
        log_success "WhatWeb completado -> $output_file"
        
        # Extraer tecnologías para búsqueda posterior en ExploitDB
        if command -v jq &> /dev/null; then
            jq -r '.[0].plugins | keys[]' "$output_file" 2>/dev/null > "$output_dir/whatweb_technologies.txt" || true
        fi
    else
        log_warning "WhatWeb no produjo resultados"
        echo "[]" > "$output_file"
    fi
}

run_nmap() {
    local host=$1
    local port=$2
    local output_dir=$3
    
    log_running "Nmap - Escaneo de puertos, servicios y vulnerabilidades..."
    
    local output_base="$output_dir/nmap_output"
    
    # Escaneo compatible con NmapScanner del orquestador:
    # - T4 timing (agresivo pero estable)
    # - Detección de versiones (intensidad 7)
    # - Scripts de vulnerabilidad (vuln,vulners)
    # - Detección de OS
    # - Todos los puertos
    nmap -sV -sC \
         --version-intensity 7 \
         --script vuln,vulners,safe \
         -O \
         --traceroute \
         -p- \
         --min-rate 1000 \
         --max-retries 6 \
         --host-timeout 30m \
         -T4 \
         -oN "${output_base}.txt" \
         -oX "${output_base}.xml" \
         "$host" 2>&1 || true
    
    if [ -f "${output_base}.xml" ] && [ -s "${output_base}.xml" ]; then
        log_success "Nmap completado -> ${output_base}.xml"
        
        # Extraer servicios para búsqueda en ExploitDB
        grep -oP 'product="\K[^"]+' "${output_base}.xml" 2>/dev/null | sort -u > "$output_dir/nmap_products.txt" || true
        grep -oP 'version="\K[^"]+' "${output_base}.xml" 2>/dev/null | sort -u > "$output_dir/nmap_versions.txt" || true
        
        # Extraer pares producto+versión
        grep -oP 'product="[^"]+" version="[^"]*"' "${output_base}.xml" 2>/dev/null | \
            sed 's/product="\([^"]*\)" version="\([^"]*\)"/\1 \2/' | sort -u > "$output_dir/nmap_services.txt" || true
    else
        log_warning "Nmap no produjo resultados XML válidos"
        echo '<?xml version="1.0"?><nmaprun></nmaprun>' > "${output_base}.xml"
    fi
}

run_gobuster() {
    local target=$1
    local output_dir=$2
    
    log_running "Gobuster - Descubrimiento de directorios..."
    
    local output_file="$output_dir/gobuster_dir_$(date +%s).txt"
    local wordlist="/usr/share/wordlists/dirb/common.txt"
    
    # Buscar wordlist alternativa si no existe
    if [ ! -f "$wordlist" ]; then
        wordlist="/usr/share/wordlists/dirbuster/directory-list-2.3-small.txt"
    fi
    if [ ! -f "$wordlist" ]; then
        wordlist="/usr/share/seclists/Discovery/Web-Content/common.txt"
    fi
    
    # Crear wordlist mínima si no hay ninguna
    if [ ! -f "$wordlist" ]; then
        log_warning "Wordlist no encontrada, creando lista básica..."
        wordlist="/tmp/basic_wordlist.txt"
        cat > "$wordlist" << 'EOF'
admin
api
backup
config
css
dev
images
js
login
scripts
test
uploads
wp-admin
wp-content
wp-includes
robots.txt
sitemap.xml
.env
.git
EOF
    fi
    
    # Gobuster modo DIR (como en el orquestador)
    gobuster dir \
        -u "$target" \
        -w "$wordlist" \
        -t 50 \
        -x php,html,txt,bak,zip,sql,env,config,xml,json \
        -q \
        -o "$output_file" \
        --no-error 2>&1 || true
    
    if [ -s "$output_file" ]; then
        log_success "Gobuster DIR completado -> $output_file"
        
        # Contar resultados
        local count=$(grep -c "Status:" "$output_file" 2>/dev/null || echo "0")
        log_info "Directorios encontrados: $count"
    else
        log_warning "Gobuster no encontró directorios"
        touch "$output_file"
    fi
    
    # Modo DNS si el target no es IP
    if [[ ! "$HOST" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        log_running "Gobuster - Escaneo de subdominios..."
        local dns_output="$output_dir/gobuster_dns_$(date +%s).txt"
        
        local dns_wordlist="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
        [ ! -f "$dns_wordlist" ] && dns_wordlist="$wordlist"
        
        gobuster dns \
            -d "$HOST" \
            -w "$dns_wordlist" \
            -t 50 \
            -q \
            -o "$dns_output" 2>&1 || true
        
        if [ -s "$dns_output" ]; then
            log_success "Gobuster DNS completado -> $dns_output"
        fi
    fi
}

run_zap() {
    local target=$1
    local output_dir=$2
    
    log_running "OWASP ZAP - Escaneo DAST completo..."
    
    local output_file="$output_dir/zap_scan_$(date +%s).json"
    local html_report="$output_dir/zap_report_$(date +%s).html"
    
    # Verificar disponibilidad de ZAP
    local zap_cmd=""
    
    if command -v zap-baseline.py &> /dev/null; then
        zap_cmd="zap-baseline.py"
    elif command -v zaproxy &> /dev/null; then
        zap_cmd="zaproxy"
    elif [ -f "/usr/share/zaproxy/zap.sh" ]; then
        zap_cmd="/usr/share/zaproxy/zap.sh"
    elif [ -f "/usr/bin/zap.sh" ]; then
        zap_cmd="/usr/bin/zap.sh"
    fi
    
    if [ -z "$zap_cmd" ]; then
        log_warning "ZAP no disponible, saltando..."
        echo '{"alerts": [], "scanId": "skipped", "error": "ZAP not available"}' > "$output_file"
        return 1
    fi
    
    # Ejecutar ZAP según el comando disponible
    if [ "$zap_cmd" = "zap-baseline.py" ]; then
        # Modo baseline (rápido, sin spidering activo)
        $zap_cmd -t "$target" \
                 -r "$html_report" \
                 -J "$output_file" \
                 -T 5 \
                 -m 15 2>&1 || true
    else
        # Modo full con ZAP CLI (como en el orquestador)
        $zap_cmd -cmd \
                 -quickurl "$target" \
                 -quickout "$html_report" 2>&1 || true
        
        # Intentar generar JSON si es posible
        if [ -f "$html_report" ]; then
            echo '{"alerts": [], "scanId": "cli-mode", "note": "HTML report generated"}' > "$output_file"
        fi
    fi
    
    if [ -f "$output_file" ] && [ -s "$output_file" ]; then
        log_success "ZAP completado -> $output_file"
        
        # Contar alertas si es JSON válido
        if command -v jq &> /dev/null; then
            local alerts=$(jq '.alerts | length' "$output_file" 2>/dev/null || echo "0")
            log_info "Alertas ZAP: $alerts"
        fi
    else
        log_warning "ZAP no generó reporte JSON, revisar HTML"
        echo '{"alerts": [], "scanId": "unknown"}' > "$output_file"
    fi
}

run_searchsploit() {
    local output_dir=$1
    
    log_running "Searchsploit - Búsqueda de exploits..."
    
    local output_file="$output_dir/exploitdb_$(date +%s).json"
    local temp_results="$output_dir/searchsploit_temp.txt"
    
    > "$temp_results"
    
    # Buscar por servicios de Nmap
    if [ -f "$output_dir/nmap_services.txt" ]; then
        log_info "Buscando exploits para servicios detectados..."
        
        while IFS= read -r service; do
            [ -z "$service" ] && continue
            
            log_info "  Buscando: $service"
            searchsploit "$service" --json >> "$temp_results" 2>/dev/null || true
            
            # Limitar para no sobrecargar
            local count=$(wc -l < "$temp_results")
            if [ "$count" -gt 1000 ]; then
                log_warning "Límite de resultados alcanzado, deteniendo búsqueda..."
                break
            fi
        done < "$output_dir/nmap_services.txt"
    fi
    
    # Buscar por tecnologías de WhatWeb
    if [ -f "$output_dir/whatweb_technologies.txt" ]; then
        log_info "Buscando exploits para tecnologías web..."
        
        local tech_count=0
        while IFS= read -r tech; do
            [ -z "$tech" ] && continue
            [ "$tech_count" -ge 5 ] && break  # Limitar a 5 tecnologías
            
            log_info "  Buscando: $tech"
            searchsploit "$tech" --json >> "$temp_results" 2>/dev/null || true
            ((tech_count++))
        done < "$output_dir/whatweb_technologies.txt"
    fi
    
    # Consolidar resultados
    if [ -s "$temp_results" ]; then
        # Usar jq para consolidar si está disponible
        if command -v jq &> /dev/null; then
            cat "$temp_results" | jq -s '
                map(.RESULTS_EXPLOIT // []) | 
                add | 
                unique_by(.EDB_ID) |
                {exploits: ., total: length, source: "searchsploit"}
            ' > "$output_file" 2>/dev/null || echo '{"exploits": []}' > "$output_file"
        else
            # Fallback simple
            echo '{"exploits": [], "note": "jq not available for consolidation"}' > "$output_file"
        fi
        
        log_success "Searchsploit completado -> $output_file"
        
        local total=$(jq '.total // 0' "$output_file" 2>/dev/null || echo "0")
        log_info "Total exploits encontrados: $total"
    else
        log_warning "Searchsploit no encontró exploits relacionados"
        echo '{"exploits": [], "total": 0}' > "$output_file"
    fi
    
    # Limpiar temporal
    rm -f "$temp_results"
}

# ============================================================================
# MAIN
# ============================================================================

main() {
    print_banner
    
    # Verificar argumentos
    if [ -z "$1" ]; then
        echo ""
        log_error "Uso: $0 <URL_OBJETIVO>"
        echo ""
        echo "Ejemplos:"
        echo "  $0 http://localhost:3001    # Juice Shop"
        echo "  $0 http://localhost:3002    # DVWA"
        echo "  $0 http://localhost:3003    # WebGoat"
        echo "  $0 https://ejemplo.com"
        echo ""
        echo "Nota: Asegúrate de tener permiso para escanear el objetivo"
        echo ""
        exit 1
    fi
    
    TARGET="$1"
    
    # Validar URL
    if [[ ! "$TARGET" =~ ^https?:// ]]; then
        TARGET="http://$TARGET"
        log_warning "Protocolo añadido: $TARGET"
    fi
    
    # Extraer host y puerto
    extract_host_port "$TARGET"
    
    echo ""
    log_info "Objetivo: $TARGET"
    log_info "Host: $HOST"
    log_info "Puerto: $PORT"
    echo ""
    
    # Crear estructura de directorios compatible con Orchestrator v3.0
    TIMESTAMP=$(date +"%Y%m%d_%H%M%S")
    SCAN_ID="scan_${TIMESTAMP}"
    
    # Estructura: ./temp/<herramienta>/ (como en el orquestador JS)
    BASE_DIR="$(dirname "$0")/.."
    TEMP_DIR="$BASE_DIR/temp"
    OUTPUT_DIR="$TEMP_DIR"  # Resultados van directo a temp/
    
    mkdir -p "$TEMP_DIR"/{whatweb,nmap,gobuster,zap,exploitdb}
    mkdir -p "$BASE_DIR/reports"
    mkdir -p "$BASE_DIR/logs"
    
    log_info "Directorio base: $BASE_DIR"
    log_info "ID de escaneo: $SCAN_ID"
    echo ""
    
    # Verificar herramientas requeridas
    echo "═══════════════════════════════════════════════════════════════════"
    echo " Verificando herramientas del Orchestrator..."
    echo "═══════════════════════════════════════════════════════════════════"
    
    REQUIRED_TOOLS=("whatweb" "nmap" "gobuster" "searchsploit")
    OPTIONAL_TOOLS=("zaproxy" "zap-baseline.py" "zap.sh")
    MISSING_REQUIRED=0
    
    for tool in "${REQUIRED_TOOLS[@]}"; do
        check_tool "$tool" || ((MISSING_REQUIRED++))
    done
    
    echo ""
    log_info "Herramientas opcionales:"
    for tool in "${OPTIONAL_TOOLS[@]}"; do
        if command -v "$tool" &> /dev/null || [ -f "/usr/share/zaproxy/$tool" ] || [ -f "/usr/bin/$tool" ]; then
            log_success "$tool disponible"
        else
            log_warning "$tool no encontrado"
        fi
    done
    
    if [ $MISSING_REQUIRED -gt 0 ]; then
        echo ""
        log_error "Faltan herramientas requeridas. Instala con:"
        log_info "  sudo apt-get install whatweb nmap gobuster exploitdb"
        exit 1
    fi
    
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
    echo " Iniciando secuencia de escaneo (Resiliente - continúa ante fallos)"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    
    START_TIME=$(date +%s)
    PHASE=0
    
    # ============================================================================
    # FASE 1: WhatWeb (Detección de tecnologías)
    # ============================================================================
    ((PHASE++))
    echo "─────────────────────────────────────────────────────────────────"
    log_phase "$PHASE" "WhatWeb - Detección de Tecnologías"
    echo "─────────────────────────────────────────────────────────────────"
    run_whatweb "$TARGET" "$TEMP_DIR/whatweb"
    echo ""
    
    # ============================================================================
    # FASE 2: Nmap (Puertos, servicios, OS, vulnerabilidades)
    # ============================================================================
    ((PHASE++))
    echo "─────────────────────────────────────────────────────────────────"
    log_phase "$PHASE" "Nmap - Escaneo de Infraestructura"
    echo "─────────────────────────────────────────────────────────────────"
    run_nmap "$HOST" "$PORT" "$TEMP_DIR/nmap"
    echo ""
    
    # ============================================================================
    # FASE 3: Gobuster (Descubrimiento de contenido)
    # ============================================================================
    ((PHASE++))
    echo "─────────────────────────────────────────────────────────────────"
    log_phase "$PHASE" "Gobuster - Descubrimiento de Directorios/DNS"
    echo "─────────────────────────────────────────────────────────────────"
    run_gobuster "$TARGET" "$TEMP_DIR/gobuster"
    echo ""
    
    # ============================================================================
    # FASE 4: ZAP (Escaneo DAST)
    # ============================================================================
    ((PHASE++))
    echo "─────────────────────────────────────────────────────────────────"
    log_phase "$PHASE" "OWASP ZAP - Análisis de Vulnerabilidades Web"
    echo "─────────────────────────────────────────────────────────────────"
    run_zap "$TARGET" "$TEMP_DIR/zap"
    echo ""
    
    # ============================================================================
    # FASE 5: Searchsploit (Inteligencia de exploits)
    # ============================================================================
    ((PHASE++))
    echo "─────────────────────────────────────────────────────────────────"
    log_phase "$PHASE" "ExploitDB - Búsqueda de Exploits Relacionados"
    echo "─────────────────────────────────────────────────────────────────"
    run_searchsploit "$TEMP_DIR/exploitdb"
    echo ""
    
    # ============================================================================
    # FINALIZACIÓN
    # ============================================================================
    END_TIME=$(date +%s)
    DURATION=$((END_TIME - START_TIME))
    MINUTES=$((DURATION / 60))
    SECONDS=$((DURATION % 60))
    
    echo "═══════════════════════════════════════════════════════════════════"
    echo -e "${GREEN}  SECUENCIA DE ESCANEO COMPLETADA${NC}"
    echo "═══════════════════════════════════════════════════════════════════"
    echo ""
    log_success "Duración total: ${MINUTES}m ${SECONDS}s"
    log_success "Resultados temporales: $TEMP_DIR"
    log_success "Reportes finales: $BASE_DIR/reports"
    echo ""
    echo "Estructura de archivos generada:"
    find "$TEMP_DIR" -type f -name "*.json" -o -name "*.xml" -o -name "*.txt" 2>/dev/null | \
        while read f; do
            size=$(du -h "$f" 2>/dev/null | cut -f1)
            echo "  $size  $f"
        done | sort -k2
    echo ""
    echo "Próximos pasos:"
    echo "  1. Ejecutar parser: node parse_results.js $TEMP_DIR"
    echo "  2. Generar reporte: node parse_results.js $TEMP_DIR"
    echo "  3. Iniciar backend: node start-backend.js"
    echo ""
    echo "═══════════════════════════════════════════════════════════════════"
}

# Manejo de señales para limpieza graceful
cleanup() {
    echo ""
    log_warning "Escaneo interrumpido por el usuario"
    log_info "Los resultados parciales están en: $TEMP_DIR"
    exit 130
}

trap cleanup INT TERM

# Ejecutar main
main "$@"