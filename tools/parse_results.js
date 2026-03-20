#!/usr/bin/env node

/**
 * SecureScan Pro - Parser de Resultados v2.0
 * 
 * Este script parsea los resultados de las herramientas del Orchestrator v3.0
 * y los consolida en un formato unificado JSON.
 * 
 * Herramientas soportadas:
 *   - whatweb: Detección de tecnologías (reemplaza wappalyzer)
 *   - nmap: Escaneo de puertos y servicios (XML)
 *   - gobuster: Descubrimiento de directorios/subdominios
 *   - zap: Escaneo de vulnerabilidades web (JSON)
 *   - searchsploit/exploitdb: Búsqueda de exploits
 * 
 * Uso:
 *   node parse_results.js <directorio_resultados>
 *   node parse_results.js ./temp
 */

const fs = require('fs');
const path = require('path');
const { parseString } = require('xml2js');

// ============================================================================
// UTILIDADES
// ============================================================================

function fileExists(filePath) {
    return fs.existsSync(filePath);
}

function readFileSafe(filePath, defaultValue = '') {
    try {
        if (!fileExists(filePath)) return defaultValue;
        return fs.readFileSync(filePath, 'utf-8');
    } catch (error) {
        console.error(`Error leyendo ${filePath}:`, error.message);
        return defaultValue;
    }
}

function parseJsonSafe(content, defaultValue = []) {
    try {
        return JSON.parse(content);
    } catch (error) {
        // Intentar parsear líneas individuales (NDJSON)
        const lines = content.split('\n').filter(l => l.trim());
        const results = [];
        lines.forEach(line => {
            try {
                results.push(JSON.parse(line));
            } catch {}
        });
        return results.length > 0 ? results : defaultValue;
    }
}

// ============================================================================
// PARSERS
// ============================================================================

/**
 * Parser para resultados de WhatWeb (JSON)
 * Reemplaza a Wappalyzer en el orquestador v3.0
 */
function parseWhatWeb(filePath) {
    try {
        const content = readFileSafe(filePath, '[]');
        const data = parseJsonSafe(content, []);

        // WhatWeb puede devolver array de objetos o objeto único
        const entries = Array.isArray(data) ? data : [data];

        const technologies = entries.flatMap(entry => {
            if (!entry.plugins) return [];
            
            return Object.entries(entry.plugins).map(([name, plugin]) => ({
                name: name,
                version: plugin.version?.[0] || plugin.string?.[0] || null,
                category: plugin.module?.[0] || 'Unknown',
                confidence: plugin.certainty?.[0] || 100,
                description: plugin.string?.join(', ') || null
            }));
        });

        // Eliminar duplicados por nombre
        const uniqueTech = technologies.filter((tech, index, self) =>
            index === self.findIndex(t => t.name === tech.name)
        );

        return {
            technologies: uniqueTech,
            target: entries[0]?.target || null,
            http_status: entries[0]?.http_status || null
        };
    } catch (error) {
        console.error('Error parsing WhatWeb:', error.message);
        return { technologies: [], target: null, http_status: null };
    }
}

/**
 * Parser para resultados de Nmap XML
 * Compatible con el formato del orquestador v3.0
 */
function parseNmap(filePath) {
    return new Promise((resolve) => {
        try {
            const content = readFileSafe(filePath, '');
            if (!content) {
                resolve({ ports: [], services: [], vulnerabilities: [], os: null });
                return;
            }

            parseString(content, (err, result) => {
                if (err) {
                    console.error('Error parsing Nmap XML:', err.message);
                    resolve({ ports: [], services: [], vulnerabilities: [], os: null });
                    return;
                }

                const ports = [];
                const services = [];
                const vulnerabilities = [];
                let os = null;

                try {
                    const hosts = result.nmaprun?.host || [];
                    
                    hosts.forEach(host => {
                        // Extraer OS si está disponible
                        const osMatch = host.os?.[0]?.osmatch?.[0];
                        if (osMatch) {
                            os = {
                                name: osMatch.$.name,
                                accuracy: parseInt(osMatch.$.accuracy) || 0,
                                family: osMatch.$.osfamily || 'unknown'
                            };
                        }

                        const hostPorts = host.ports?.[0]?.port || [];
                        
                        hostPorts.forEach(port => {
                            const portInfo = {
                                port: parseInt(port.$.portid),
                                protocol: port.$.protocol,
                                state: port.state?.[0]?.$.state || 'unknown',
                                reason: port.state?.[0]?.$.reason || null,
                                service: port.service?.[0]?.$.name || 'unknown',
                                product: port.service?.[0]?.$.product || null,
                                version: port.service?.[0]?.$.version || null,
                                extrainfo: port.service?.[0]?.$.extrainfo || null,
                                tunnel: port.service?.[0]?.$.tunnel || null,
                                method: port.service?.[0]?.$.method || null
                            };

                            ports.push(portInfo);

                            if (portInfo.product || portInfo.service !== 'unknown') {
                                services.push({
                                    name: portInfo.product || portInfo.service,
                                    version: portInfo.version,
                                    port: portInfo.port,
                                    protocol: portInfo.protocol,
                                    product: portInfo.product
                                });
                            }

                            // Extraer vulnerabilidades de scripts NSE
                            const scripts = port.script || [];
                            scripts.forEach(script => {
                                const scriptId = script.$.id;
                                const output = script.$.output || '';

                                // Parsear vulnerabilidades conocidas
                                if (scriptId.includes('vuln') || scriptId.includes('cve')) {
                                    const cveMatches = output.match(/CVE-\d{4}-\d+/g) || [];
                                    
                                    vulnerabilities.push({
                                        tool: 'nmap',
                                        type: 'vulnerability',
                                        port: portInfo.port,
                                        service: portInfo.service,
                                        script: scriptId,
                                        description: output.substring(0, 200),
                                        cves: cveMatches,
                                        severity: inferSeverityFromOutput(output),
                                        host: host.address?.[0]?.$.addr
                                    });
                                }
                            });
                        });
                    });
                } catch (e) {
                    console.error('Error extracting Nmap data:', e.message);
                }

                resolve({ ports, services, vulnerabilities, os });
            });
        } catch (error) {
            console.error('Error reading Nmap file:', error.message);
            resolve({ ports: [], services: [], vulnerabilities: [], os: null });
        }
    });
}

/**
 * Inferir severidad basada en output de script NSE
 */
function inferSeverityFromOutput(output) {
    const lower = output.toLowerCase();
    if (lower.includes('critical') || lower.includes('remote code execution') || 
        lower.includes('rce')) return 'critical';
    if (lower.includes('vulnerable') || lower.includes('exploit')) return 'high';
    if (lower.includes('version') || lower.includes('outdated')) return 'medium';
    return 'low';
}

/**
 * Parser para resultados de Gobuster
 * Soporta modo dir, dns y vhost
 */
function parseGobuster(filePath) {
    try {
        const content = readFileSafe(filePath, '');
        if (!content) return { directories: [], subdomains: [], vhosts: [] };

        const lines = content.split('\n').filter(line => line.trim());
        const directories = [];
        const subdomains = [];
        const vhosts = [];

        lines.forEach(line => {
            // Modo DIR: /path (Status: 200) [Size: 1234]
            const dirMatch = line.match(/^(https?:\/\/[^\s]+|\/[^\s]*)\s*\(Status:\s*(\d+)\)\s*\[Size:\s*(\d+)\]/);
            if (dirMatch) {
                directories.push({
                    url: dirMatch[1],
                    status: parseInt(dirMatch[2]),
                    size: parseInt(dirMatch[3]),
                    type: 'directory'
                });
                return;
            }

            // Modo DNS: Found: subdomain.domain.com [IP]
            const dnsMatch = line.match(/^Found:\s+([^\s]+)\s+\[([^\]]+)\]/);
            if (dnsMatch) {
                subdomains.push({
                    subdomain: dnsMatch[1],
                    ip: dnsMatch[2],
                    type: 'subdomain'
                });
                return;
            }

            // Modo VHOST: Found: vhost (Status: 200) [Size: 1234]
            const vhostMatch = line.match(/^Found:\s+([^\s]+)\s+\(Status:\s*(\d+)\)/);
            if (vhostMatch) {
                vhosts.push({
                    vhost: vhostMatch[1],
                    status: parseInt(vhostMatch[2]),
                    type: 'vhost'
                });
            }
        });

        return { directories, subdomains, vhosts };
    } catch (error) {
        console.error('Error parsing Gobuster:', error.message);
        return { directories: [], subdomains: [], vhosts: [] };
    }
}

/**
 * Parser para resultados de ZAP (JSON)
 * Compatible con el formato del orquestador v3.0
 */
function parseZap(filePath) {
    try {
        const content = readFileSafe(filePath, '');
        if (!content) return { vulnerabilities: [], scan_id: null };

        const data = parseJsonSafe(content, {});
        
        // El orquestador guarda el formato de ZAP API
        const alerts = data.alerts || data.site?.[0]?.alerts || [];
        const scanId = data.scanId || data.scan_id || null;

        const riskMap = {
            '0': 'info',
            '1': 'low',
            '2': 'medium',
            '3': 'high',
            '4': 'critical',
            'Informational': 'info',
            'Low': 'low',
            'Medium': 'medium',
            'High': 'high',
            'Critical': 'critical'
        };

        const vulnerabilities = alerts.map((alert, index) => {
            const riskCode = alert.riskcode || alert.risk;
            const severity = riskMap[riskCode] || riskMap[alert.risk] || 'info';

            return {
                id: `ZAP-${alert.pluginid || alert.alertRef || index + 1}`,
                tool: 'zap',
                name: alert.name || alert.alert,
                description: alert.desc || alert.description || alert.riskdesc,
                severity: severity,
                confidence: alert.confidence || alert.relid,
                solution: alert.solution,
                reference: alert.reference,
                cweId: alert.cweid || alert.cwe,
                wascId: alert.wascid,
                riskcode: alert.riskcode,
                count: alert.count || (alert.instances || []).length,
                instances: (alert.instances || []).map(i => ({
                    uri: i.uri,
                    method: i.method,
                    param: i.param || i.paramName,
                    evidence: i.evidence || i.attack,
                    attack: i.attack
                }))
            };
        });

        return { vulnerabilities, scan_id: scanId };
    } catch (error) {
        console.error('Error parsing ZAP:', error.message);
        return { vulnerabilities: [], scan_id: null };
    }
}

/**
 * Parser para resultados de ExploitDB/Searchsploit
 * Compatible con el módulo exploitdb_unified del orquestador
 */
function parseSearchsploit(filePath) {
    try {
        const content = readFileSafe(filePath, '');
        if (!content) return { exploits: [], services: [] };

        let data;
        try {
            data = JSON.parse(content);
        } catch {
            // Intentar parsear como NDJSON
            data = content.split('\n')
                .filter(l => l.trim())
                .map(l => JSON.parse(l))
                .filter(Boolean);
        }

        // El orquestador puede guardar en diferentes formatos
        let exploits = [];
        let services = [];

        if (Array.isArray(data)) {
            exploits = data;
        } else if (data.exploits) {
            exploits = data.exploits;
        } else if (data.RESULTS_EXPLOIT) {
            exploits = data.RESULTS_EXPLOIT;
        } else if (data.services) {
            // Formato del orquestador: { services: [{technology, version, exploits: []}] }
            services = data.services;
            exploits = services.flatMap(s => s.exploits || []);
        }

        const normalizedExploits = exploits.map(exp => ({
            id: exp.EDB_ID || exp['EDB-ID'] || exp.id || null,
            title: exp.Title || exp.title || exp.name,
            path: exp.Path || exp.path || exp.file,
            type: exp.Type || exp.type || 'unknown',
            platform: exp.Platform || exp.platform || 'multiple',
            date: exp.Date || exp.date || exp.published,
            author: exp.Author || exp.author,
            cve: exp.CVE || exp.cve || null,
            cvss: exp.CVSS || exp.cvss || null,
            verified: exp.Verified || exp.verified || false,
            source: exp.source || 'exploitdb'
        })).filter(e => e.title);

        // Eliminar duplicados
        const uniqueExploits = normalizedExploits.filter((exp, index, self) =>
            index === self.findIndex(e => e.id === exp.id && e.title === exp.title)
        );

        return { 
            exploits: uniqueExploits, 
            services,
            total_found: uniqueExploits.length 
        };
    } catch (error) {
        console.error('Error parsing Searchsploit:', error.message);
        return { exploits: [], services: [], total_found: 0 };
    }
}

// ============================================================================
// SCORING ENGINE (Compatible con ScoringEngine del orquestador)
// ============================================================================

function calculateCVSSScore(vulnerability) {
    // Extracción básica de CVSS si existe
    if (vulnerability.cvss) return parseFloat(vulnerability.cvss);
    
    // Mapeo de severidad a CVSS aproximado (v3.1)
    const severityMap = {
        'critical': 9.0,
        'high': 7.5,
        'medium': 5.5,
        'low': 3.0,
        'info': 0.0
    };
    
    return severityMap[vulnerability.severity?.toLowerCase()] || 5.0;
}

function calculateScore(vulnerabilities, exploits) {
    const breakdown = {
        critical: 0,
        high: 0,
        medium: 0,
        low: 0,
        info: 0
    };

    // Contar vulnerabilidades por severidad
    vulnerabilities.forEach(vuln => {
        const severity = vuln.severity?.toLowerCase() || 'info';
        if (breakdown.hasOwnProperty(severity)) {
            breakdown[severity]++;
        }
    });

    // Agregar exploits disponibles como riesgo potencial
    // (no son vulnerabilidades confirmadas, pero indican superficie de ataque)
    const exploitBonus = Math.min(exploits.length * 2, 20); // Max 20 puntos de penalización

    // Calcular puntuación (100 = mejor, 0 = peor)
    const weights = {
        critical: 25,
        high: 15,
        medium: 8,
        low: 3,
        info: 0.5
    };

    let deductions = 0;
    deductions += breakdown.critical * weights.critical;
    deductions += breakdown.high * weights.high;
    deductions += breakdown.medium * weights.medium;
    deductions += breakdown.low * weights.low;
    deductions += breakdown.info * weights.info;
    deductions += exploitBonus;

    const score = Math.max(0, Math.min(100, 100 - deductions));

    // Asignar grado y riesgo general
    let grade;
    let overallRisk;
    
    if (score >= 90) { grade = 'A'; overallRisk = 'Low'; }
    else if (score >= 80) { grade = 'B'; overallRisk = 'Low-Medium'; }
    else if (score >= 70) { grade = 'C'; overallRisk = 'Medium'; }
    else if (score >= 60) { grade = 'D'; overallRisk = 'Medium-High'; }
    else if (score >= 40) { grade = 'E'; overallRisk = 'High'; }
    else { grade = 'F'; overallRisk = 'Critical'; }

    return {
        total: Math.round(score * 10) / 10,
        grade: grade,
        overall_risk: overallRisk,
        breakdown: breakdown,
        exploit_exposure: exploits.length,
        max_possible_deduction: deductions + (100 - deductions - score)
    };
}

// ============================================================================
// MAIN
// ============================================================================

async function main() {
    const args = process.argv.slice(2);
    
    if (args.length === 0) {
        console.log('SecureScan Pro - Parser de Resultados v2.0');
        console.log('Uso: node parse_results.js <directorio_resultados>');
        console.log('');
        console.log('El directorio debe contener los archivos de salida del orquestador:');
        console.log('  - whatweb_output.json (WhatWeb)');
        console.log('  - nmap_output.xml (Nmap)');
        console.log('  - gobuster_*.txt (Gobuster)');
        console.log('  - zap_scan_*.json (OWASP ZAP)');
        console.log('  - exploitdb_*.json (ExploitDB)');
        process.exit(1);
    }

    const resultsDir = args[0];

    if (!fileExists(resultsDir)) {
        console.error(`❌ Directorio no encontrado: ${resultsDir}`);
        process.exit(1);
    }

    console.log(`🔍 Parseando resultados en: ${resultsDir}\n`);

    // Buscar archivos con patrones flexibles (el orquestador usa timestamps)
    const files = fs.readdirSync(resultsDir);
    
    const findFile = (pattern) => files.find(f => pattern.test(f));
    
    const whatwebFile = findFile(/whatweb.*\.json$/);
    const nmapFile = findFile(/nmap.*\.xml$/);
    const gobusterFile = findFile(/gobuster.*\.txt$/);
    const zapFile = findFile(/zap.*\.json$/);
    const exploitdbFile = findFile(/exploitdb.*\.json$/);

    console.log('Archivos detectados:');
    console.log(`  WhatWeb: ${whatwebFile || 'No encontrado'}`);
    console.log(`  Nmap: ${nmapFile || 'No encontrado'}`);
    console.log(`  Gobuster: ${gobusterFile || 'No encontrado'}`);
    console.log(`  ZAP: ${zapFile || 'No encontrado'}`);
    console.log(`  ExploitDB: ${exploitdbFile || 'No encontrado'}`);
    console.log('');

    // Parsear todos los archivos
    const whatwebData = parseWhatWeb(whatwebFile ? path.join(resultsDir, whatwebFile) : null);
    const nmapData = await parseNmap(nmapFile ? path.join(resultsDir, nmapFile) : null);
    const gobusterData = parseGobuster(gobusterFile ? path.join(resultsDir, gobusterFile) : null);
    const zapData = parseZap(zapFile ? path.join(resultsDir, zapFile) : null);
    const exploitdbData = parseSearchsploit(exploitdbFile ? path.join(resultsDir, exploitdbFile) : null);

    // Consolidar todas las vulnerabilidades
    const allVulnerabilities = [
        ...(nmapData.vulnerabilities || []),
        ...(zapData.vulnerabilities || [])
    ];

    // Calcular score con el nuevo algoritmo
    const score = calculateScore(allVulnerabilities, exploitdbData.exploits || []);

    // Crear resultado consolidado compatible con el orquestador
    const consolidated = {
        scan_info: {
            timestamp: new Date().toISOString(),
            results_directory: resultsDir,
            parser_version: '2.0',
            compatible_with: 'orchestrator-v3.0'
        },
        score: score,
        target: whatwebData.target,
        technologies: whatwebData.technologies,
        infrastructure: {
            ports: nmapData.ports,
            services: nmapData.services,
            os: nmapData.os,
            http_status: whatwebData.http_status
        },
        discovery: {
            directories: gobusterData.directories,
            subdomains: gobusterData.subdomains,
            vhosts: gobusterData.vhosts,
            total_urls: gobusterData.directories.length + gobusterData.subdomains.length + gobusterData.vhosts.length
        },
        vulnerabilities: {
            total: allVulnerabilities.length,
            by_tool: {
                nmap: nmapData.vulnerabilities?.length || 0,
                zap: zapData.vulnerabilities?.length || 0
            },
            by_severity: score.breakdown,
            items: allVulnerabilities.sort((a, b) => {
                const severityOrder = { critical: 0, high: 1, medium: 2, low: 3, info: 4 };
                return severityOrder[a.severity] - severityOrder[b.severity];
            })
        },
        exploits: {
            total: exploitdbData.exploits?.length || 0,
            by_service: exploitdbData.services || [],
            items: exploitdbData.exploits || []
        },
        summary: {
            total_technologies: whatwebData.technologies.length,
            total_ports_open: nmapData.ports.filter(p => p.state === 'open').length,
            total_services: nmapData.services.length,
            total_directories: gobusterData.directories.length,
            total_subdomains: gobusterData.subdomains.length,
            total_vulnerabilities: allVulnerabilities.length,
            total_exploits_available: exploitdbData.exploits?.length || 0,
            risk_grade: score.grade,
            risk_score: score.total
        }
    };

    // Guardar resultado
    const outputPath = path.join(resultsDir, 'consolidated_results.json');
    fs.writeFileSync(outputPath, JSON.stringify(consolidated, null, 2));

    console.log('✅ Resultados consolidados guardados en:', outputPath);
    console.log('\n📊 Resumen del Análisis:');
    console.log('═══════════════════════════════════════════════════════════════');
    console.log(`  🎯 Target: ${consolidated.target || 'N/A'}`);
    console.log(`  🔧 Tecnologías detectadas: ${consolidated.summary.total_technologies}`);
    console.log(`  🌐 Puertos abiertos: ${consolidated.summary.total_ports_open}/${nmapData.ports.length}`);
    console.log(`  📁 Directorios descubiertos: ${consolidated.summary.total_directories}`);
    console.log(`  🌐 Subdominios encontrados: ${consolidated.summary.total_subdomains}`);
    console.log(`  ⚠️  Vulnerabilidades totales: ${consolidated.summary.total_vulnerabilities}`);
    console.log(`     └─ Críticas: ${score.breakdown.critical} | Altas: ${score.breakdown.high} | Medias: ${score.breakdown.medium} | Bajas: ${score.breakdown.low}`);
    console.log(`  💣 Exploits disponibles: ${consolidated.summary.total_exploits_available}`);
    console.log(`  📈 Score de Seguridad: ${score.total}/100 (Grado ${score.grade})`);
    console.log(`  🎨 Riesgo General: ${score.overall_risk}`);
    console.log('═══════════════════════════════════════════════════════════════');

    // Retornar código de salida basado en riesgo
    if (score.grade === 'F' || score.grade === 'E') {
        process.exit(2); // Riesgo crítico
    } else if (score.grade === 'D') {
        process.exit(1); // Riesgo alto
    } else {
        process.exit(0); // Aceptable
    }
}

main().catch(error => {
    console.error('💥 Error fatal:', error);
    process.exit(1);
});