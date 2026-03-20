/**
 * ============================================================================
 * SECURITYSCAN PRO - REPORT GENERATOR v2.1 CORREGIDO
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const { exec } = require('child_process');
const util = require('util');
const Logger = require('../utils/logger');

const execPromise = util.promisify(exec);

class ReportGenerator {
  static FORMATS = {
    HTML: 'html', PDF: 'pdf', DOCX: 'docx', MARKDOWN: 'md',
    JSON: 'json', SARIF: 'sarif', XML: 'xml', CSV: 'csv'
  };

  static REPORT_TYPES = {
    EXECUTIVE: 'executive', TECHNICAL: 'technical', COMPLIANCE: 'compliance',
    REMEDIATION: 'remediation', COMPARATIVE: 'comparative', TACTICAL: 'tactical'
  };

  static get DEFAULT_CONFIG() {
    return {
      reportInfo: {
        title: 'Security Assessment Report',
        subtitle: 'Automated Vulnerability Assessment',
        company: 'SecureScan Pro',
        client: null,
        project: null,
        date: new Date().toISOString().split('T')[0],
        version: '2.1',
        classification: 'Confidential'
      },
      output: {
        format: 'html', dir: './reports', filename: null,
        template: 'default', theme: 'light', language: 'es'
      },
      sections: {
        executiveSummary: true, methodology: true, scope: true,
        techStack: true, networkDiscovery: true, contentDiscovery: true,
        webAssessment: true, exploitIntelligence: true, exploitationResults: false,
        findings: true, riskAssessment: true, remediationPlan: true,
        complianceMapping: false, appendices: true, evidence: true
      },
      visualizations: {
        riskMatrix: true, severityChart: true, categoryChart: true,
        timelineChart: true, cvssCalculator: true, owaspRiskMatrix: true,
        techStackChart: true, networkTopology: true, exploitAvailability: true
      },
      filters: {
        minSeverity: 'Low', maxFindings: null, excludeCategories: [],
        includeEvidence: true, includeMetasploit: false, includeExploitDB: true
      },
      html: {
        interactive: true, responsive: true, embedImages: true,
        tableOfContents: true, searchFunction: true,
        techDetailsExpandable: true, exploitLinksVerified: true
      },
      pdf: {
        pageSize: 'A4', orientation: 'portrait',
        margins: { top: '2cm', right: '2cm', bottom: '2cm', left: '2cm' },
        header: true, footer: true, pageNumbers: true
      },
      sarif: {
        version: '2.1.0', toolName: 'SecureScan Pro', toolVersion: '2.1.0'
      }
    };
  }

  constructor(config = {}) {
    this.config = { ...ReportGenerator.DEFAULT_CONFIG, ...config };
    this.data = null;
    this.chartsData = null;
    this.toolData = {
      whatweb: null, nmap: null, gobuster: null,
      zap: null, exploitdb: null, metasploit: null
    };
  }

  setToolData(toolName, data) {
    if (this.toolData.hasOwnProperty(toolName)) {
      this.toolData[toolName] = data;
      Logger.info(`[REPORT] Datos de ${toolName} cargados para reporte`);
    }
  }

  async generate(scanData, outputPath = null) {
    this.data = scanData;
    
    if (scanData.phases) {
      this.setToolData('whatweb', scanData.phases.whatweb);
      this.setToolData('nmap', scanData.phases.nmap);
      this.setToolData('gobuster', scanData.phases.gobuster);
      this.setToolData('zap', scanData.phases.zap);
      this.setToolData('exploitdb', scanData.phases.exploitdb);
      this.setToolData('metasploit', scanData.phases.metasploit);
    }
    
    Logger.info(`[REPORT] Generando reporte tipo: ${this.config.output.format}`);

    try {
      await this.preprocessData();
      const format = this.config.output.format;
      let result;

      switch (format) {
        case 'html': result = await this.generateHTML(outputPath); break;
        case 'pdf': result = await this.generatePDF(outputPath); break;
        case 'docx': result = await this.generateDOCX(outputPath); break;
        case 'md': case 'markdown': result = await this.generateMarkdown(outputPath); break;
        case 'json': result = await this.generateJSON(outputPath); break;
        case 'sarif': result = await this.generateSARIF(outputPath); break;
        case 'xml': result = await this.generateXML(outputPath); break;
        case 'csv': result = await this.generateCSV(outputPath); break;
        default: throw new Error(`Formato no soportado: ${format}`);
      }

      Logger.info(`[REPORT] Reporte generado: ${result.path}`);
      return result;
    } catch (error) {
      Logger.error('[REPORT] Error generando reporte:', error);
      throw error;
    }
  }

  async preprocessData() {
    const findings = this.data.findings || [];
    this.chartsData = {
      severityDistribution: this.calculateSeverityDistribution(findings),
      categoryDistribution: this.calculateCategoryDistribution(findings),
      toolDistribution: this.calculateToolDistribution(findings),
      timeline: this.calculateTimeline(findings),
      riskMatrix: this.calculateRiskMatrix(findings),
      owaspRisk: this.calculateOWASPRisk(findings),
      topRisks: this.getTopRisks(findings, 10),
      statistics: this.calculateStatistics(findings),
      techStack: this.processTechStackData(),
      networkData: this.processNetworkData(),
      exploitData: this.processExploitData()
    };
  }

  processTechStackData() {
    if (!this.toolData.whatweb || !this.toolData.whatweb.technologies) return null;
    const techs = this.toolData.whatweb.technologies;
    return {
      totalTechnologies: techs.length,
      byCategory: techs.reduce((acc, t) => { acc[t.category] = (acc[t.category] || 0) + 1; return acc; }, {}),
      highRiskTechs: techs.filter(t => ['WordPress', 'Drupal', 'Joomla', 'Apache Struts', 'WebLogic'].includes(t.name)),
      outdatedTechs: techs.filter(t => t.version && this.isOutdatedVersion(t.name, t.version))
    };
  }

  processNetworkData() {
    if (!this.toolData.nmap) return null;
    const nmap = this.toolData.nmap;
    return {
      hostsScanned: nmap.hosts ? nmap.hosts.length : 0,
      totalPorts: nmap.stats ? nmap.stats.totalPorts : 0,
      servicesDetected: nmap.services ? nmap.services.length : 0,
      osDetected: nmap.os || null,
      vulnerabilitiesFromScripts: nmap.vulnerabilities ? nmap.vulnerabilities.length : 0,
      cvesDetected: nmap.cves ? nmap.cves.length : 0
    };
  }

  processExploitData() {
    if (!this.toolData.exploitdb) return null;
    const exploitdb = this.toolData.exploitdb;
    let totalExploits = 0, remoteExploits = 0, webExploits = 0, verifiedExploits = 0;
    
    if (exploitdb.services) {
      exploitdb.services.forEach(service => {
        if (service.exploits) {
          totalExploits += service.exploits.length;
          remoteExploits += service.exploits.filter(e => e.type === 'remote').length;
          webExploits += service.exploits.filter(e => e.type === 'webapps').length;
          verifiedExploits += service.exploits.filter(e => e.verified).length;
        }
      });
    }
    
    return { totalExploits, remoteExploits, webExploits, verifiedExploits };
  }

  async generateHTML(outputPath) {
    const filename = outputPath || this.getOutputFilename('html');
    const fullPath = path.join(this.config.output.dir, filename);
    if (!fs.existsSync(this.config.output.dir)) fs.mkdirSync(this.config.output.dir, { recursive: true });
    
    const html = this.buildHTMLDocument();
    fs.writeFileSync(fullPath, html);
    
    return { path: fullPath, format: 'html', size: fs.statSync(fullPath).size, pages: this.estimatePages(), generatedAt: new Date().toISOString() };
  }

  buildHTMLDocument() {
    const { reportInfo, sections } = this.config;
    const theme = this.config.output.theme;

    return `<!DOCTYPE html>
<html lang="${this.config.output.language}">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>${reportInfo.title} - ${reportInfo.client || 'Cliente'}</title>
    <style>${this.getCSSStyles(theme)}</style>
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
</head>
<body class="theme-${theme}">
    ${this.buildHeader()}
    ${sections.executiveSummary ? this.buildExecutiveSummary() : ''}
    ${sections.methodology ? this.buildMethodology() : ''}
    ${sections.scope ? this.buildScope() : ''}
    ${sections.techStack ? this.buildTechStackSection() : ''}
    ${sections.networkDiscovery ? this.buildNetworkDiscoverySection() : ''}
    ${sections.contentDiscovery ? this.buildContentDiscoverySection() : ''}
    ${sections.webAssessment ? this.buildWebAssessmentSection() : ''}
    ${sections.exploitIntelligence ? this.buildExploitIntelligenceSection() : ''}
    ${sections.exploitationResults && this.config.filters.includeMetasploit ? this.buildExploitationSection() : ''}
    ${sections.findings ? this.buildFindings() : ''}
    ${sections.riskAssessment ? this.buildRiskAssessment() : ''}
    ${sections.remediationPlan ? this.buildRemediationPlan() : ''}
    ${sections.complianceMapping ? this.buildComplianceMapping() : ''}
    ${sections.appendices ? this.buildAppendices() : ''}
    ${this.buildFooter()}
    <script>${this.getJavaScript()}</script>
</body>
</html>`;
  }

  buildTechStackSection() {
    if (!this.chartsData.techStack) return '';
    const tech = this.chartsData.techStack;
    
    return `
    <section id="tech-stack" class="page-break">
        <h1><i class="fas fa-layer-group"></i> Stack Tecnológico</h1>
        <p class="section-intro">Tecnologías detectadas en el objetivo mediante análisis pasivo (WhatWeb).</p>
        
        <div class="tech-overview">
            <div class="metric-cards">
                <div class="metric-card">
                    <i class="fas fa-cube"></i>
                    <span class="number">${tech.totalTechnologies}</span>
                    <span class="label">Tecnologías Totales</span>
                </div>
                <div class="metric-card warning">
                    <i class="fas fa-exclamation-triangle"></i>
                    <span class="number">${tech.highRiskTechs ? tech.highRiskTechs.length : 0}</span>
                    <span class="label">Tecnologías de Alto Riesgo</span>
                </div>
            </div>
        </div>

        <div class="tech-categories">
            <h3>Por Categoría</h3>
            <div class="category-grid">
                ${Object.entries(tech.byCategory || {}).map(([cat, count]) => `
                    <div class="category-item">
                        <span class="category-name">${cat}</span>
                        <span class="category-count">${count}</span>
                    </div>
                `).join('')}
            </div>
        </div>

        <div class="tech-details">
            <h3>Detalle de Tecnologías</h3>
            <table class="data-table">
                <thead>
                    <tr><th>Tecnología</th><th>Versión</th><th>Categoría</th><th>Confianza</th><th>Riesgo</th></tr>
                </thead>
                <tbody>
                    ${(this.toolData.whatweb && this.toolData.whatweb.technologies ? this.toolData.whatweb.technologies : []).map(t => `
                        <tr class="risk-${this.getTechRiskLevel(t.name)}">
                            <td><strong>${t.name}</strong></td>
                            <td>${t.version || 'N/A'}</td>
                            <td>${t.category}</td>
                            <td>${t.confidence}%</td>
                            <td>${this.getTechRiskBadge(t.name)}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    </section>`;
  }

  buildNetworkDiscoverySection() {
    if (!this.chartsData.networkData) return '';
    const net = this.chartsData.networkData;
    
    return `
    <section id="network-discovery" class="page-break">
        <h1><i class="fas fa-network-wired"></i> Descubrimiento de Red</h1>
        <p class="section-intro">Resultados del escaneo de puertos y servicios (Nmap).</p>
        
        <div class="network-overview">
            <div class="metric-cards">
                <div class="metric-card"><i class="fas fa-server"></i><span class="number">${net.hostsScanned}</span><span class="label">Hosts Escaneados</span></div>
                <div class="metric-card"><i class="fas fa-plug"></i><span class="number">${net.totalPorts}</span><span class="label">Puertos Abiertos</span></div>
                <div class="metric-card"><i class="fas fa-cogs"></i><span class="number">${net.servicesDetected}</span><span class="label">Servicios Detectados</span></div>
                ${net.cvesDetected > 0 ? `<div class="metric-card critical"><i class="fas fa-bug"></i><span class="number">${net.cvesDetected}</span><span class="label">CVEs Detectados</span></div>` : ''}
            </div>
        </div>

        ${net.osDetected ? `<div class="os-detection"><h3>Sistema Operativo Detectado</h3><div class="os-info"><i class="fas fa-desktop"></i><span>${net.osDetected}</span></div></div>` : ''}

        <div class="ports-detail">
            <h3>Puertos y Servicios</h3>
            <table class="data-table">
                <thead><tr><th>Puerto</th><th>Protocolo</th><th>Servicio</th><th>Versión</th><th>Estado</th></tr></thead>
                <tbody>
                    ${(this.toolData.nmap && this.toolData.nmap.ports ? this.toolData.nmap.ports : []).map(p => `
                        <tr>
                            <td><strong>${p.port}</strong></td>
                            <td>${p.protocol ? p.protocol.toUpperCase() : 'TCP'}</td>
                            <td>${p.service}</td>
                            <td>${p.version || 'N/A'}</td>
                            <td><span class="status-badge ${p.state}">${p.state}</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        </div>
    </section>`;
  }

  buildContentDiscoverySection() {
    if (!this.toolData.gobuster) return '';
    const gobuster = this.toolData.gobuster;
    
    return `
    <section id="content-discovery" class="page-break">
        <h1><i class="fas fa-search"></i> Descubrimiento de Contenido</h1>
        <p class="section-intro">Resultados de fuerza bruta de directorios, subdominios y virtual hosts (Gobuster).</p>
        
        ${gobuster.dir ? `
        <div class="gobuster-mode">
            <h3><i class="fas fa-folder-open"></i> Directorios y Archivos</h3>
            <div class="stats-bar">
                <span>${gobuster.dir.stats ? gobuster.dir.stats.found : 0} recursos encontrados</span>
                <span>${gobuster.dir.stats ? gobuster.dir.stats.totalTested : 0} probados</span>
            </div>
            <table class="data-table">
                <thead><tr><th>Recurso</th><th>Status</th><th>Tamaño</th><th>Tipo</th><th>Riesgo</th></tr></thead>
                <tbody>
                    ${(gobuster.dir.found || []).slice(0, 50).map(item => `
                        <tr class="${item.sensitive ? 'sensitive-row' : ''}">
                            <td><a href="${item.url}" target="_blank">${item.url}</a></td>
                            <td><span class="status-code ${item.status}">${item.status}</span></td>
                            <td>${item.size ? item.size.toLocaleString() + ' bytes' : 'N/A'}</td>
                            <td>${item.type || 'Unknown'}</td>
                            <td>${item.risk ? '<span class="risk-badge ' + item.risk + '">' + item.risk + '</span>' : 'N/A'}</td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
            ${gobuster.dir.found && gobuster.dir.found.length > 50 ? '<p class="table-note">... y ' + (gobuster.dir.found.length - 50) + ' más</p>' : ''}
        </div>` : ''}

        ${gobuster.dns ? `
        <div class="gobuster-mode">
            <h3><i class="fas fa-globe"></i> Subdominios (DNS)</h3>
            <div class="subdomain-grid">
                ${(gobuster.dns.found || []).map(item => `
                    <div class="subdomain-item">
                        <span class="subdomain-name">${item.subdomain}</span>
                        <span class="subdomain-purpose">${item.purpose || 'General'}</span>
                        <span class="risk-badge ${item.risk}">${item.risk}</span>
                    </div>
                `).join('')}
            </div>
        </div>` : ''}
    </section>`;
  }

  buildWebAssessmentSection() {
    if (!this.toolData.zap) return '';
    const zap = this.toolData.zap;
    
    return `
    <section id="web-assessment" class="page-break">
        <h1><i class="fas fa-shield-alt"></i> Evaluación de Seguridad Web</h1>
        <p class="section-intro">Resultados del escaneo DAST (Dynamic Application Security Testing) con OWASP ZAP.</p>
        
        <div class="zap-overview">
            <div class="metric-cards">
                <div class="metric-card"><i class="fas fa-bug"></i><span class="number">${zap.alerts ? zap.alerts.length : 0}</span><span class="label">Alertas Totales</span></div>
                <div class="metric-card"><i class="fas fa-spider"></i><span class="number">${zap.phases && zap.phases.spider ? zap.phases.spider.urlsFound : 0}</span><span class="label">URLs Descubiertas</span></div>
                <div class="metric-card"><i class="fas fa-bolt"></i><span class="number">${zap.phases && zap.phases.activeScan ? zap.phases.activeScan.alertsFound : 0}</span><span class="label">Vulns. Activo Scan</span></div>
            </div>
        </div>

        <div class="zap-phases">
            <h3>Fases del Escaneo</h3>
            <div class="phase-timeline">
                ${zap.phases && zap.phases.spider ? `<div class="phase-item completed"><span class="phase-name">Spider (${zap.phases.spider.type})</span><span class="phase-status">✓ Completado</span><span class="phase-detail">${zap.phases.spider.urlsFound} URLs en ${zap.phases.spider.duration}s</span></div>` : ''}
                ${zap.phases && zap.phases.passiveScan ? `<div class="phase-item completed"><span class="phase-name">Passive Scan</span><span class="phase-status">✓ Completado</span></div>` : ''}
                ${zap.phases && zap.phases.activeScan ? `<div class="phase-item completed"><span class="phase-name">Active Scan</span><span class="phase-status">✓ Completado</span><span class="phase-detail">${zap.phases.activeScan.alertsFound} alertas</span></div>` : ''}
            </div>
        </div>

        <div class="zap-alerts">
            <h3>Alertas de Seguridad por Severidad</h3>
            <div class="alerts-by-risk">
                ${['High', 'Medium', 'Low', 'Informational'].map(risk => {
                  const alerts = (zap.alerts || []).filter(a => a.risk === risk);
                  if (alerts.length === 0) return '';
                  return `<div class="risk-section ${risk.toLowerCase()}"><h4>${risk} (${alerts.length})</h4><div class="alert-list">
                    ${alerts.slice(0, 10).map(a => `<div class="alert-item"><span class="alert-name">${a.name}</span><span class="alert-cwe">${a.cweId ? 'CWE-' + a.cweId : ''}</span><p>${a.description ? a.description.substring(0, 200) + '...' : ''}</p>${a.solution ? '<div class="alert-solution"><strong>Solución:</strong> ' + a.solution.substring(0, 150) + '...</div>' : ''}</div>`).join('')}
                    ${alerts.length > 10 ? '<p class="more-alerts">... y ' + (alerts.length - 10) + ' más</p>' : ''}
                  </div></div>`;
                }).join('')}
            </div>
        </div>
    </section>`;
  }

  buildExploitIntelligenceSection() {
    if (!this.config.filters.includeExploitDB || !this.toolData.exploitdb) return '';
    const exploitdb = this.chartsData.exploitData;
    if (!exploitdb || exploitdb.totalExploits === 0) return '';
    
    return `
    <section id="exploit-intelligence" class="page-break">
        <h1><i class="fas fa-database"></i> Inteligencia de Exploits</h1>
        <p class="section-intro">Análisis de disponibilidad de exploits públicos para servicios detectados (ExploitDB).</p>
        
        <div class="exploit-overview">
            <div class="metric-cards">
                <div class="metric-card critical"><i class="fas fa-bomb"></i><span class="number">${exploitdb.totalExploits}</span><span class="label">Exploits Encontrados</span></div>
                <div class="metric-card"><i class="fas fa-globe"></i><span class="number">${exploitdb.remoteExploits}</span><span class="label">Exploits Remotos</span></div>
                <div class="metric-card"><i class="fas fa-window-maximize"></i><span class="number">${exploitdb.webExploits}</span><span class="label">Web Exploits</span></div>
                <div class="metric-card"><i class="fas fa-check-circle"></i><span class="number">${exploitdb.verifiedExploits}</span><span class="label">Verificados</span></div>
            </div>
        </div>

        <div class="exploit-by-service">
            <h3>Exploits por Servicio</h3>
            <table class="data-table">
                <thead><tr><th>Servicio</th><th>Target</th><th>Exploits</th><th>Max CVSS</th><th>Tipos</th></tr></thead>
                <tbody>
                    ${(this.toolData.exploitdb.services || []).filter(s => s.exploits && s.exploits.length > 0).map(s => {
                      const types = [...new Set(s.exploits.map(e => e.type))];
                      const maxCvss = Math.max(...s.exploits.map(e => e.cvss || 0));
                      return `<tr><td><strong>${s.service}</strong></td><td>${s.target}</td><td>${s.exploits.length}</td><td>${maxCvss > 0 ? '<span class="cvss-badge ' + (maxCvss >= 7 ? 'high' : 'medium') + '">' + maxCvss + '</span>' : 'N/A'}</td><td>${types.join(', ')}</td></tr>`;
                    }).join('')}
                </tbody>
            </table>
        </div>

        <div class="exploit-details">
            <h3>Top Exploits por Severidad</h3>
            <div class="exploit-list">
                ${(this.toolData.exploitdb.services || []).flatMap(s => s.exploits || []).sort((a, b) => (b.cvss || 0) - (a.cvss || 0)).slice(0, 10).map(e => `
                    <div class="exploit-item">
                        <div class="exploit-header"><span class="exploit-id">EDB-${e.EDB_ID}</span>${e.cvss ? '<span class="cvss-badge ' + (e.cvss >= 7 ? 'high' : e.cvss >= 4 ? 'medium' : 'low') + '">CVSS: ' + e.cvss + '</span>' : ''}<span class="exploit-type">${e.type}</span></div>
                        <p class="exploit-title">${e.Title}</p>
                        <div class="exploit-meta"><span>Plataforma: ${e.Platform || 'N/A'}</span><span>Autor: ${e.Author || 'Unknown'}</span>${e.cves ? '<span>CVEs: ' + e.cves.join(', ') + '</span>' : ''}</div>
                    </div>
                `).join('')}
            </div>
        </div>
    </section>`;
  }

  buildExploitationSection() {
    if (!this.toolData.metasploit || !this.toolData.metasploit.enabled) return '';
    const msf = this.toolData.metasploit;
    
    return `
    <section id="exploitation-results" class="page-break sensitive">
        <h1><i class="fas fa-skull-crossbones"></i> Resultados de Explotación</h1>
        <div class="sensitive-warning"><i class="fas fa-exclamation-triangle"></i><span>SECCIÓN CONFIDENCIAL - Solo para personal autorizado</span></div>
        
        <div class="msf-overview">
            <div class="metric-cards">
                <div class="metric-card"><i class="fas fa-crosshairs"></i><span class="number">${msf.attempts || 0}</span><span class="label">Intentos de Explotación</span></div>
                <div class="metric-card ${msf.successful > 0 ? 'success' : ''}"><i class="fas fa-check-circle"></i><span class="number">${msf.successful || 0}</span><span class="label">Exitosos</span></div>
                <div class="metric-card"><i class="fas fa-terminal"></i><span class="number">${(msf.sessions || []).length}</span><span class="label">Sesiones Activas</span></div>
            </div>
        </div>

        ${msf.dryRun ? '<div class="dry-run-notice"><i class="fas fa-info-circle"></i><span>Modo SIMULACIÓN (Dry Run) - No se ejecutaron exploits reales</span></div>' : ''}

        ${(msf.details && msf.details.length > 0) ? `
        <div class="msf-attempts">
            <h3>Detalle de Intentos</h3>
            <table class="data-table">
                <thead><tr><th>Target</th><th>Módulo</th><th>Estado</th><th>Sesión</th></tr></thead>
                <tbody>
                    ${msf.details.map(d => `<tr class="${d.success ? 'success-row' : d.status === 'simulated' ? 'simulated-row' : 'failed-row'}"><td>${d.target}</td><td>${d.module || 'N/A'}</td><td><span class="status-badge ${d.success ? 'success' : d.status === 'simulated' ? 'warning' : 'failed'}">${d.success ? 'Éxito' : d.status === 'simulated' ? 'Simulado' : 'Fallido'}</span></td><td>${d.sessionId || 'N/A'}</td></tr>`).join('')}
                </tbody>
            </table>
        </div>` : ''}
    </section>`;
  }

  buildExecutiveSummary() {
    const stats = this.chartsData.statistics;
    const topRisks = this.chartsData.topRisks;
    
    return `
    <section id="executive-summary" class="page-break">
        <h1>Resumen Ejecutivo</h1>
        
        <div class="exec-summary-box">
            <h2>Síntesis del Assessment</h2>
            <p>Este reporte presenta los resultados del assessment de seguridad automatizado realizado el <strong>${this.config.reportInfo.date}</strong> utilizando SecureScan Pro v2.1.</p>
            
            <div class="tools-used">
                <h4>Herramientas Utilizadas:</h4>
                <span class="tool-tag"><i class="fas fa-layer-group"></i> WhatWeb</span>
                <span class="tool-tag"><i class="fas fa-network-wired"></i> Nmap</span>
                <span class="tool-tag"><i class="fas fa-search"></i> Gobuster</span>
                <span class="tool-tag"><i class="fas fa-shield-alt"></i> OWASP ZAP</span>
                <span class="tool-tag"><i class="fas fa-database"></i> ExploitDB</span>
                ${this.config.filters.includeMetasploit ? '<span class="tool-tag"><i class="fas fa-skull-crossbones"></i> Metasploit</span>' : ''}
            </div>
            
            <div class="key-metrics">
                <div class="metric critical"><span class="number">${stats.critical}</span><span class="label">Críticos</span></div>
                <div class="metric high"><span class="number">${stats.high}</span><span class="label">Altos</span></div>
                <div class="metric medium"><span class="number">${stats.medium}</span><span class="label">Medios</span></div>
                <div class="metric low"><span class="number">${stats.low}</span><span class="label">Bajos</span></div>
            </div>
        </div>

        ${this.chartsData.techStack ? `<div class="tech-summary"><h3>Resumen Tecnológico</h3><p>Se detectaron <strong>${this.chartsData.techStack.totalTechnologies} tecnologías</strong>, incluyendo ${this.chartsData.techStack.highRiskTechs ? this.chartsData.techStack.highRiskTechs.length : 0} consideradas de alto riesgo.</p></div>` : ''}

        ${this.chartsData.exploitData && this.chartsData.exploitData.totalExploits > 0 ? `<div class="exploit-summary alert-box"><h3><i class="fas fa-exclamation-triangle"></i> Alerta de Exploits Disponibles</h3><p>Se encontraron <strong>${this.chartsData.exploitData.totalExploits} exploits públicos</strong> (${this.chartsData.exploitData.remoteExploits} remotos) para servicios detectados. ${this.chartsData.exploitData.verifiedExploits} están verificados.</p></div>` : ''}

        <div class="top-risks">
            <h2>Principales Riesgos Identificados</h2>
            <ol>
                ${topRisks.map(risk => `<li><strong>${risk.title}</strong> <span class="severity-badge ${risk.severity.toLowerCase()}">${risk.severity}</span>${risk.hasExploit ? '<span class="exploit-badge"><i class="fas fa-bomb"></i> Exploit disponible</span>' : ''}${risk.hasMetasploit ? '<span class="metasploit-badge"><i class="fas fa-skull"></i> Metasploit</span>' : ''}<p>${risk.businessImpact}</p></li>`).join('')}
            </ol>
        </div>
    </section>`;
  }

  buildMethodology() {
    return `
    <section id="methodology" class="page-break">
        <h1>Metodología</h1>
        <div class="methodology-grid">
            <div class="method-item"><h3><i class="fas fa-layer-group"></i> 1. Detección de Tecnologías (WhatWeb)</h3><p>Fingerprinting pasivo del stack tecnológico mediante análisis de respuestas HTTP, cookies, headers y patrones en el HTML. Reemplaza a Wappalyzer por mejor rendimiento y compatibilidad nativa con Kali Linux.</p></div>
            <div class="method-item"><h3><i class="fas fa-network-wired"></i> 2. Escaneo de Red (Nmap)</h3><p>Descubrimiento de puertos abiertos, servicios y versiones. Ejecución de scripts NSE para detección de vulnerabilidades conocidas (CVE) y configuraciones inseguras.</p></div>
            <div class="method-item"><h3><i class="fas fa-search"></i> 3. Descubrimiento de Contenido (Gobuster)</h3><p>Fuerza bruta de directorios, archivos, subdominios y virtual hosts. Incluye enumeración de buckets S3/GCS y fuzzing de parámetros.</p></div>
            <div class="method-item"><h3><i class="fas fa-shield-alt"></i> 4. Escaneo DAST (OWASP ZAP)</h3><p>Pruebas de seguridad dinámicas con Spider tradicional, AJAX Spider para SPAs, y Active Scan para detección de vulnerabilidades OWASP Top 10. <strong>Reemplaza a Nikto</strong> por capacidades superiores de autenticación y reporting SARIF.</p></div>
            <div class="method-item"><h3><i class="fas fa-database"></i> 5. Inteligencia de Exploits (ExploitDB)</h3><p>Búsqueda unificada de exploits públicos correlacionando servicios detectados con la base de datos de Exploit-DB, incluyendo enriquecimiento con CVSS desde NVD.</p></div>
            ${this.config.filters.includeMetasploit ? '<div class="method-item"><h3><i class="fas fa-skull-crossbones"></i> 6. Explotación Controlada (Metasploit)</h3><p>Validación de vulnerabilidades críticas mediante explotación controlada con confirmación manual, modo dry-run disponible, y recolección de evidencia de post-explotación.</p></div>' : ''}
            <div class="method-item"><h3><i class="fas fa-calculator"></i> ${this.config.filters.includeMetasploit ? '7' : '6'}. Scoring de Riesgo</h3><p>Cálculo de riesgo compuesto usando CVSS v3.1/v4.0, EPSS (probabilidad de explotación), SSVC (priorización por stakeholder), y contexto de activos organizacionales.</p></div>
        </div>
    </section>`;
  }

  buildScope() {
    return `
    <section id="scope" class="page-break">
        <h1>Alcance del Assessment</h1>
        <div class="scope-content">
            <h3>Target Principal</h3><p>${this.data.target || 'No especificado'}</p>
            <h3>Herramientas Ejecutadas</h3>
            <ul class="scope-tools">
                <li><i class="fas fa-check"></i> WhatWeb - Detección de tecnologías</li>
                <li><i class="fas fa-check"></i> Nmap - Escaneo de puertos y servicios</li>
                <li><i class="fas fa-check"></i> Gobuster - Fuerza bruta de directorios y subdominios</li>
                <li><i class="fas fa-check"></i> OWASP ZAP - Pruebas de seguridad dinámicas (DAST)</li>
                <li><i class="fas fa-check"></i> ExploitDB - Inteligencia de exploits</li>
                ${this.config.filters.includeMetasploit ? '<li><i class="fas fa-check"></i> Metasploit - Validación de exploits</li>' : ''}
            </ul>
            <h3>Exclusiones</h3>
            <p>Este assessment no incluye pruebas de ingeniería social, acceso físico, ni denegación de servicio (DoS) intencional. Los exploits de Metasploit se ejecutan únicamente en modo dry-run a menos que se especifique explícitamente lo contrario.</p>
        </div>
    </section>`;
  }

  buildFindings() {
    const findings = this.filterFindings(this.data.findings || []);
    return `
    <section id="findings" class="page-break">
        <h1>Hallazgos Detallados</h1>
        ${this.config.visualizations.severityChart ? this.buildSeverityChart() : ''}
        ${this.config.visualizations.categoryChart ? this.buildCategoryChart() : ''}
        <div class="findings-list">
            ${findings.map((finding, index) => this.buildFindingDetail(finding, index + 1)).join('')}
        </div>
    </section>`;
  }

  buildFindingDetail(finding, number) {
    const cvss = finding.scoring && finding.scoring.components ? finding.scoring.components.cvssBase : (finding.cvss || 'N/A');
    const cvssColor = this.getCVSSColor(cvss);
    
    return `
    <div class="finding-card" id="finding-${finding.id || number}">
        <div class="finding-header">
            <span class="finding-number">${number}</span>
            <h3>${finding.title || (finding.description ? finding.description.substring(0, 100) : 'Sin título')}</h3>
            <div class="finding-badges">
                <span class="severity-badge ${(finding.severity || 'info').toLowerCase()}">${finding.severity || 'Info'}</span>
                <span class="cvss-badge" style="background-color: ${cvssColor}">CVSS: ${cvss}</span>
                ${finding.scoring && finding.scoring.components && finding.scoring.components.exploitdbCount > 0 ? '<span class="exploit-badge"><i class="fas fa-bomb"></i> Exploit disponible</span>' : ''}
                ${finding.scoring && finding.scoring.components && finding.scoring.components.hasMetasploitModule ? '<span class="metasploit-badge"><i class="fas fa-skull"></i> Metasploit</span>' : ''}
            </div>
        </div>
        <div class="finding-body">
            <div class="finding-meta">
                <p><strong>Herramienta:</strong> ${finding.tool || 'N/A'}</p>
                <p><strong>Categoría:</strong> ${finding.category || 'General'}</p>
                <p><strong>Target:</strong> ${finding.target || 'N/A'}</p>
                ${finding.cve ? '<p><strong>CVE:</strong> <a href="https://cve.mitre.org/cgi-bin/cvename.cgi?name=' + finding.cve + '" target="_blank">' + finding.cve + '</a></p>' : ''}
                ${finding.scoring && finding.scoring.components && finding.scoring.components.exploitdbCount > 0 ? '<p><strong>Exploits disponibles:</strong> ' + finding.scoring.components.exploitdbCount + '</p>' : ''}
            </div>
            <div class="finding-description"><h4>Descripción</h4><p>${finding.description || 'Sin descripción disponible.'}</p></div>
            ${finding.evidence ? '<div class="finding-evidence"><h4>Evidencia</h4><pre><code>' + this.escapeHtml(finding.evidence) + '</code></pre></div>' : ''}
            ${finding.scoring && finding.scoring.recommendedAction ? '<div class="finding-remediation"><h4>Acción Recomendada</h4><p>' + finding.scoring.recommendedAction.replace(/\\n/g, '<br>') + '</p></div>' : ''}
        </div>
    </div>`;
  }

  buildRiskAssessment() {
    if (!this.config.visualizations.riskMatrix) return '';
    return `
    <section id="risk-assessment" class="page-break">
        <h1>Evaluación de Riesgo</h1>
        <div class="risk-matrix-container"><h3>Matriz de Riesgo (CVSS vs EPSS)</h3><canvas id="riskMatrixChart"></canvas></div>
        <div class="risk-legend">
            <div class="legend-item"><span class="dot critical"></span> Crítico (Acción inmediata)</div>
            <div class="legend-item"><span class="dot high"></span> Alto (7 días)</div>
            <div class="legend-item"><span class="dot medium"></span> Medio (30 días)</div>
            <div class="legend-item"><span class="dot low"></span> Bajo (90 días)</div>
        </div>
    </section>`;
  }

  buildRemediationPlan() {
    const findings = this.data.findings || [];
    const byPriority = {
      immediate: findings.filter(f => f.scoring && f.scoring.priority === 'immediate'),
      high: findings.filter(f => f.scoring && f.scoring.priority === 'high'),
      medium: findings.filter(f => f.scoring && f.scoring.priority === 'medium'),
      low: findings.filter(f => f.scoring && f.scoring.priority === 'low')
    };

    return `
    <section id="remediation" class="page-break">
        <h1>Plan de Remediación</h1>
        <div class="remediation-timeline">
            <h3>24 Horas (Inmediato)</h3>
            <div class="remediation-list">
                ${byPriority.immediate.map(f => '<div class="remediation-item critical"><span class="remediation-id">' + f.id + '</span><span class="remediation-title">' + f.title + '</span><span class="remediation-score">CVSS: ' + (f.scoring && f.scoring.components ? f.scoring.components.cvssBase : 'N/A') + '</span></div>').join('') || '<p class="no-items">Sin items críticos</p>'}
            </div>
            <h3>7 Días (Alto)</h3>
            <div class="remediation-list">
                ${byPriority.high.map(f => '<div class="remediation-item high"><span class="remediation-id">' + f.id + '</span><span class="remediation-title">' + f.title + '</span></div>').join('') || '<p class="no-items">Sin items de alta prioridad</p>'}
            </div>
            <h3>30 Días (Medio)</h3>
            <div class="remediation-list">
                ${byPriority.medium.map(f => '<div class="remediation-item medium"><span class="remediation-id">' + f.id + '</span><span class="remediation-title">' + f.title + '</span></div>').join('') || '<p class="no-items">Sin items de prioridad media</p>'}
            </div>
        </div>
    </section>`;
  }

  buildComplianceMapping() {
    return `
    <section id="compliance" class="page-break">
        <h1>Mapeo de Cumplimiento</h1>
        <p>Mapeo de hallazgos contra frameworks de seguridad estándar.</p>
        <div class="compliance-frameworks">
            <div class="framework">
                <h3>OWASP Top 10</h3>
                <table class="data-table">
                    <thead><tr><th>Categoría</th><th>Hallazgos</th><th>Riesgo</th></tr></thead>
                    <tbody>
                        <tr><td>A01:2021-Broken Access Control</td><td>${(this.data.findings || []).filter(f => f.category && f.category.includes('access')).length}</td><td>Alto</td></tr>
                        <tr><td>A02:2021-Cryptographic Failures</td><td>${(this.data.findings || []).filter(f => f.category && (f.category.includes('crypto') || f.category.includes('ssl'))).length}</td><td>Medio</td></tr>
                        <tr><td>A03:2021-Injection</td><td>${(this.data.findings || []).filter(f => f.category && (f.category.includes('injection') || f.category.includes('sql'))).length}</td><td>Crítico</td></tr>
                    </tbody>
                </table>
            </div>
        </div>
    </section>`;
  }

  buildAppendices() {
    return `
    <section id="appendices" class="page-break">
        <h1>Apéndices</h1>
        <div class="appendix">
            <h3>A. Glosario de Herramientas</h3>
            <dl>
                <dt>WhatWeb</dt><dd>Herramienta de fingerprinting de tecnologías web. Reemplaza a Wappalyzer.</dd>
                <dt>Nmap</dt><dd>Escáner de puertos y descubridor de servicios de red.</dd>
                <dt>Gobuster</dt><dd>Herramienta de fuerza bruta para directorios, subdominios y virtual hosts.</dd>
                <dt>OWASP ZAP</dt><dd>Proxy de seguridad web y escáner DAST. Reemplaza a Nikto.</dd>
                <dt>ExploitDB</dt><dd>Base de datos de exploits públicos con búsqueda unificada.</dd>
                <dt>Metasploit</dt><dd>Framework de explotación para validación de vulnerabilidades.</dd>
            </dl>
        </div>
        <div class="appendix">
            <h3>B. Referencias</h3>
            <ul>
                <li>CVSS v3.1 Specification - <a href="https://www.first.org/cvss/v3.1/specification">FIRST.org</a></li>
                <li>EPSS - <a href="https://www.first.org/epss/">Exploit Prediction Scoring System</a></li>
                <li>OWASP Testing Guide v4.2</li>
                <li>NIST SP 800-115 - Technical Guide to Information Security Testing</li>
            </ul>
        </div>
    </section>`;
  }

  buildHeader() {
    return `
    <header class="report-header">
        <div class="header-content">
            <h1>${this.config.reportInfo.title}</h1>
            <h2>${this.config.reportInfo.subtitle}</h2>
            <div class="header-meta">
                <p><strong>Cliente:</strong> ${this.config.reportInfo.client || 'No especificado'}</p>
                <p><strong>Fecha:</strong> ${this.config.reportInfo.date}</p>
                <p><strong>Versión:</strong> ${this.config.reportInfo.version}</p>
                <p class="classification"><strong>Clasificación:</strong> ${this.config.reportInfo.classification}</p>
            </div>
        </div>
    </header>`;
  }

  buildFooter() {
    return `
    <footer class="report-footer">
        <p>Generado por SecureScan Pro v2.1 | ${new Date().toISOString()}</p>
        <p class="classification">${this.config.reportInfo.classification}</p>
    </footer>`;
  }

  buildSeverityChart() { return '<div class="chart-container"><canvas id="severityChart"></canvas></div>'; }
  buildCategoryChart() { return '<div class="chart-container"><canvas id="categoryChart"></canvas></div>'; }

  getCSSStyles(theme) {
    const themes = {
      light: { bg: '#ffffff', text: '#1f2937', primary: '#2563eb', critical: '#dc2626', high: '#ea580c', medium: '#ca8a04', low: '#16a34a' },
      dark: { bg: '#111827', text: '#f3f4f6', primary: '#3b82f6', critical: '#ef4444', high: '#f97316', medium: '#eab308', low: '#22c55e' }
    };
    const t = themes[theme] || themes.light;

    return `
    :root { --bg-color: ${t.bg}; --text-color: ${t.text}; --primary: ${t.primary}; --critical: ${t.critical}; --high: ${t.high}; --medium: ${t.medium}; --low: ${t.low}; }
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; line-height: 1.6; color: var(--text-color); background: var(--bg-color); max-width: 1200px; margin: 0 auto; padding: 20px; }
    .page-break { page-break-before: always; }
    h1, h2, h3 { color: var(--primary); margin: 1.5em 0 0.5em; }
    h1 { font-size: 2em; border-bottom: 3px solid var(--primary); padding-bottom: 0.3em; }
    h2 { font-size: 1.5em; } h3 { font-size: 1.2em; }
    .report-header { background: linear-gradient(135deg, var(--primary), #1e40af); color: white; padding: 40px; margin: -20px -20px 40px -20px; border-radius: 0 0 20px 20px; }
    .report-header h1 { color: white; border: none; margin: 0; }
    .report-header h2 { color: #bfdbfe; font-weight: normal; margin: 10px 0; }
    .header-meta { margin-top: 20px; display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; }
    .classification { background: #fee2e2; color: #991b1b; padding: 5px 15px; border-radius: 20px; display: inline-block; font-weight: bold; margin-top: 10px; }
    .section-intro { color: #6b7280; font-style: italic; margin-bottom: 20px; padding-left: 15px; border-left: 3px solid var(--primary); }
    .tool-tag { display: inline-flex; align-items: center; gap: 5px; padding: 8px 16px; margin: 5px; background: #e0e7ff; color: #3730a3; border-radius: 20px; font-size: 0.9em; font-weight: 500; }
    .metric-cards { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 30px 0; }
    .metric-card { background: #f8fafc; padding: 25px; border-radius: 12px; text-align: center; border: 1px solid #e2e8f0; transition: transform 0.2s; }
    .metric-card:hover { transform: translateY(-5px); }
    .metric-card i { font-size: 2.5em; color: var(--primary); margin-bottom: 15px; }
    .metric-card.warning i { color: #f59e0b; } .metric-card.critical i { color: #dc2626; } .metric-card.success i { color: #16a34a; }
    .metric-card .number { display: block; font-size: 3em; font-weight: bold; color: var(--primary); margin: 10px 0; }
    .severity-badge { display: inline-block; padding: 6px 14px; border-radius: 6px; font-size: 0.85em; font-weight: bold; text-transform: uppercase; letter-spacing: 0.5px; }
    .severity-badge.critical { background: var(--critical); color: white; } .severity-badge.high { background: var(--high); color: white; } .severity-badge.medium { background: var(--medium); color: white; } .severity-badge.low { background: var(--low); color: white; } .severity-badge.info { background: #6b7280; color: white; }
    .cvss-badge { display: inline-block; padding: 4px 10px; border-radius: 4px; font-size: 0.85em; font-weight: bold; color: white; margin-left: 10px; }
    .exploit-badge { background: #fecaca; color: #991b1b; padding: 4px 10px; border-radius: 4px; font-size: 0.8em; margin-left: 10px; font-weight: bold; }
    .metasploit-badge { background: #374151; color: #f3f4f6; padding: 4px 10px; border-radius: 4px; font-size: 0.8em; margin-left: 10px; }
    .data-table { width: 100%; border-collapse: collapse; margin: 20px 0; background: white; border-radius: 8px; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .data-table th, .data-table td { padding: 14px; text-align: left; border-bottom: 1px solid #e5e7eb; }
    .data-table th { background: #f8fafc; font-weight: 600; color: #374151; text-transform: uppercase; font-size: 0.85em; letter-spacing: 0.5px; }
    .data-table tr:hover { background: #f9fafb; }
    .finding-card { border: 1px solid #e5e7eb; border-radius: 12px; margin: 25px 0; overflow: hidden; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .finding-header { background: #f8fafc; padding: 20px; display: flex; align-items: center; gap: 15px; border-bottom: 1px solid #e5e7eb; flex-wrap: wrap; }
    .finding-number { background: var(--primary); color: white; width: 35px; height: 35px; border-radius: 50%; display: flex; align-items: center; justify-content: center; font-weight: bold; font-size: 1.1em; }
    .finding-body { padding: 25px; }
    .finding-meta { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 10px; margin-bottom: 20px; padding: 15px; background: #f8fafc; border-radius: 8px; }
    .finding-description { margin: 20px 0; } .finding-description p { line-height: 1.8; color: #4b5563; }
    .finding-evidence { margin: 20px 0; }
    .finding-evidence pre { background: #1f2937; color: #e5e7eb; padding: 20px; border-radius: 8px; overflow-x: auto; font-family: 'Consolas', 'Monaco', monospace; font-size: 0.9em; line-height: 1.5; }
    .alert-box { background: #fef3c7; border-left: 4px solid #f59e0b; padding: 20px; margin: 20px 0; border-radius: 0 8px 8px 0; }
    .alert-box h3 { color: #92400e; margin-top: 0; }
    .sensitive-warning { background: #fee2e2; color: #991b1b; padding: 15px 20px; border-radius: 8px; margin: 20px 0; font-weight: bold; display: flex; align-items: center; gap: 10px; border: 2px solid #fecaca; }
    .dry-run-notice { background: #dbeafe; color: #1e40af; padding: 15px 20px; border-radius: 8px; margin: 20px 0; display: flex; align-items: center; gap: 10px; }
    .methodology-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(350px, 1fr)); gap: 25px; margin: 30px 0; }
    .method-item { padding: 25px; background: #f8fafc; border-radius: 12px; border: 1px solid #e2e8f0; transition: box-shadow 0.2s; }
    .method-item:hover { box-shadow: 0 4px 6px rgba(0,0,0,0.1); }
    .method-item h3 { margin-top: 0; color: #1e40af; font-size: 1.1em; display: flex; align-items: center; gap: 10px; }
    .method-item p { font-size: 0.95em; line-height: 1.7; color: #4b5563; margin-bottom: 0; }
    .phase-timeline { border-left: 3px solid #e2e8f0; margin-left: 20px; padding-left: 25px; }
    .phase-item { position: relative; padding: 20px 0; border-bottom: 1px solid #e5e7eb; }
    .phase-item::before { content: ''; position: absolute; left: -31px; top: 25px; width: 14px; height: 14px; background: #10b981; border-radius: 50%; border: 3px solid white; box-shadow: 0 0 0 3px #10b981; }
    .phase-name { font-weight: bold; display: block; color: #111827; } .phase-status { color: #10b981; font-size: 0.9em; font-weight: 500; } .phase-detail { color: #6b7280; font-size: 0.85em; display: block; margin-top: 5px; }
    .risk-section { margin: 20px 0; padding: 20px; border-radius: 8px; }
    .risk-section.high { background: #fee2e2; border-left: 4px solid #dc2626; } .risk-section.medium { background: #fef3c7; border-left: 4px solid #f59e0b; } .risk-section.low { background: #dcfce7; border-left: 4px solid #16a34a; } .risk-section.informational { background: #e0f2fe; border-left: 4px solid #0ea5e9; }
    .status-code { padding: 4px 10px; border-radius: 4px; font-weight: bold; font-size: 0.9em; }
    .status-code.200 { background: #dcfce7; color: #166534; } .status-code.301, .status-code.302 { background: #fef3c7; color: #92400e; } .status-code.401, .status-code.403 { background: #fee2e2; color: #991b1b; } .status-code.404 { background: #f3f4f6; color: #6b7280; } .status-code.500 { background: #fecaca; color: #991b1b; }
    .sensitive-row { background: #fef2f2 !important; }
    .exploit-item { border: 1px solid #e2e8f0; border-radius: 8px; padding: 20px; margin: 15px 0; background: white; }
    .exploit-header { display: flex; gap: 15px; align-items: center; margin-bottom: 10px; flex-wrap: wrap; }
    .exploit-id { font-weight: bold; color: #2563eb; font-family: monospace; } .exploit-title { font-weight: 500; margin: 10px 0; color: #111827; }
    .exploit-meta { display: flex; gap: 20px; font-size: 0.85em; color: #6b7280; flex-wrap: wrap; }
    .category-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(250px, 1fr)); gap: 15px; margin: 20px 0; }
    .category-item { display: flex; justify-content: space-between; padding: 15px 20px; background: #f1f5f9; border-radius: 8px; font-weight: 500; }
    .category-count { background: var(--primary); color: white; padding: 2px 10px; border-radius: 12px; font-size: 0.9em; }
    .chart-container { margin: 30px 0; padding: 20px; background: white; border-radius: 12px; box-shadow: 0 1px 3px rgba(0,0,0,0.1); }
    .remediation-timeline h3 { margin-top: 30px; padding-bottom: 10px; border-bottom: 2px solid #e5e7eb; }
    .remediation-list { margin: 15px 0; }
    .remediation-item { display: flex; align-items: center; gap: 15px; padding: 15px; margin: 10px 0; border-radius: 8px; background: #f8fafc; border-left: 4px solid; }
    .remediation-item.critical { border-left-color: #dc2626; } .remediation-item.high { border-left-color: #ea580c; } .remediation-item.medium { border-left-color: #ca8a04; }
    .remediation-id { background: #e5e7eb; padding: 4px 10px; border-radius: 4px; font-family: monospace; font-size: 0.9em; }
    .remediation-title { flex: 1; font-weight: 500; } .remediation-score { color: #6b7280; font-size: 0.9em; }
    .no-items { color: #9ca3af; font-style: italic; padding: 20px; }
    .report-footer { margin-top: 60px; padding: 30px; background: #f8fafc; border-radius: 12px 12px 0 0; text-align: center; color: #6b7280; border-top: 1px solid #e5e7eb; }
    @media print { .page-break { page-break-before: always; } body { max-width: none; } .report-header { margin: 0; border-radius: 0; } .finding-card { break-inside: avoid; } }
    `;
  }

  getJavaScript() {
    return `
    document.querySelectorAll('.finding-header').forEach(header => {
      header.style.cursor = 'pointer';
      header.addEventListener('click', () => {
        const body = header.nextElementSibling;
        body.style.display = body.style.display === 'none' ? 'block' : 'none';
      });
    });
    
    const searchDiv = document.createElement('div');
    searchDiv.style.cssText = 'position:fixed;top:20px;right:20px;z-index:1000;';
    searchDiv.innerHTML = '<input type="text" placeholder="Buscar hallazgos..." style="padding:12px 20px;border:2px solid #e5e7eb;border-radius:25px;width:300px;font-size:14px;box-shadow:0 4px 6px rgba(0,0,0,0.1);">';
    document.body.appendChild(searchDiv);
    
    searchDiv.querySelector('input').addEventListener('input', (e) => {
      const term = e.target.value.toLowerCase();
      document.querySelectorAll('.finding-card').forEach(card => {
        card.style.display = card.textContent.toLowerCase().includes(term) ? 'block' : 'none';
      });
    });
    
    if (typeof Chart !== 'undefined') {
      const severityCtx = document.getElementById('severityChart');
      if (severityCtx) {
        new Chart(severityCtx, {
          type: 'doughnut',
          data: {
            labels: ['Crítico', 'Alto', 'Medio', 'Bajo', 'Info'],
            datasets: [{
              data: [
                document.querySelectorAll('.severity-badge.critical').length,
                document.querySelectorAll('.severity-badge.high').length,
                document.querySelectorAll('.severity-badge.medium').length,
                document.querySelectorAll('.severity-badge.low').length,
                document.querySelectorAll('.severity-badge.info').length
              ],
              backgroundColor: ['#dc2626', '#ea580c', '#ca8a04', '#16a34a', '#6b7280']
            }]
          },
          options: { responsive: true, plugins: { legend: { position: 'bottom' } } }
        });
n      }
n    }
n    `;
n  }

  // Métodos de utilidad
  filterFindings(findings) {
    const { minSeverity, maxFindings, excludeCategories } = this.config.filters;
    const severityOrder = ['None', 'Low', 'Medium', 'High', 'Critical'];
    const minIndex = severityOrder.indexOf(minSeverity);

    let filtered = findings.filter(f => {
      const severityIndex = severityOrder.indexOf(f.severity || 'None');
      if (severityIndex < minIndex) return false;
      if (excludeCategories.includes(f.category)) return false;
      return true;
    });

    if (maxFindings && filtered.length > maxFindings) {
      filtered = filtered.slice(0, maxFindings);
    }
    return filtered;
  }

  calculateSeverityDistribution(findings) {
    const distribution = { Critical: 0, High: 0, Medium: 0, Low: 0, Info: 0 };
    findings.forEach(f => { const severity = f.severity || 'Info'; distribution[severity] = (distribution[severity] || 0) + 1; });
    return distribution;
  }

  calculateCategoryDistribution(findings) {
    const categories = {};
    findings.forEach(f => { const cat = f.category || 'General'; categories[cat] = (categories[cat] || 0) + 1; });
    return Object.entries(categories).sort((a, b) => b[1] - a[1]).slice(0, 10);
  }

  calculateToolDistribution(findings) {
    const tools = {};
    findings.forEach(f => { const tool = f.tool || 'Unknown'; tools[tool] = (tools[tool] || 0) + 1; });
    return tools;
  }

  calculateTimeline(findings) {
    const timeline = {};
    findings.forEach(f => { const date = f.timestamp ? f.timestamp.split('T')[0] : 'Unknown'; timeline[date] = (timeline[date] || 0) + 1; });
    return Object.entries(timeline).sort();
  }

  calculateRiskMatrix(findings) {
    return findings.map(f => ({ x: f.scoring && f.scoring.components ? f.scoring.components.cvssBase : (f.cvss || 0), y: f.scoring && f.scoring.components ? f.scoring.components.epss : 0, r: 5, title: f.title || (f.description ? f.description.substring(0, 50) : ''), severity: f.severity }));
  }

  calculateOWASPRisk(findings) {
    return findings.map(f => { const likelihood = 5; const impact = f.cvss >= 7 ? 3 : f.cvss >= 4 ? 2 : 1; const risk = likelihood * impact; return { ...f, owaspRisk: risk > 10 ? 'High' : risk > 5 ? 'Medium' : 'Low' }; });
  }

  getTopRisks(findings, count = 10) {
    return findings.sort((a, b) => ((b.scoring ? b.scoring.compositeScore : 0) || b.cvss || 0) - ((a.scoring ? a.scoring.compositeScore : 0) || a.cvss || 0)).slice(0, count).map(f => ({ title: f.title || (f.description ? f.description.substring(0, 100) : ''), severity: f.severity, cvss: f.scoring && f.scoring.components ? f.scoring.components.cvssBase : f.cvss, businessImpact: f.businessImpact || 'Impacto potencial en operaciones críticas', hasExploit: f.scoring && f.scoring.components && f.scoring.components.exploitdbCount > 0, hasMetasploit: f.scoring && f.scoring.components && f.scoring.components.hasMetasploitModule }));
  }

  calculateStatistics(findings) {
    const distribution = this.calculateSeverityDistribution(findings);
    const total = findings.length;
    let overallRisk = 'Low';
    if (distribution.Critical > 0) overallRisk = 'Critical';
    else if (distribution.High > 0) overallRisk = 'High';
    else if (distribution.Medium > 5) overallRisk = 'Medium';

    return { total, critical: distribution.Critical, high: distribution.High, medium: distribution.Medium, low: distribution.Low, info: distribution.Info, overallRisk, averageCvss: findings.reduce((sum, f) => sum + (f.scoring && f.scoring.components ? f.scoring.components.cvssBase : (f.cvss || 0)), 0) / total || 0, withExploit: findings.filter(f => f.scoring && f.scoring.components && f.scoring.components.exploitdbCount > 0).length, withMetasploit: findings.filter(f => f.scoring && f.scoring.components && f.scoring.components.hasMetasploitModule).length };
  }

  getTechRiskLevel(techName) {
    const highRisk = ['WordPress', 'Drupal', 'Joomla', 'Apache Struts', 'WebLogic', 'Windows XP'];
    return highRisk.some(t => techName.includes(t)) ? 'high' : 'medium';
  }

  getTechRiskBadge(techName) {
    const level = this.getTechRiskLevel(techName);
    return '<span class="severity-badge ' + level + '">' + (level === 'high' ? 'Alto' : 'Medio') + '</span>';
  }

  isOutdatedVersion(name, version) {
    const eolPatterns = [{ name: 'PHP', pattern: /^5\./ }, { name: 'Apache', pattern: /^2\.2/ }, { name: 'nginx', pattern: /^1\.8/ }, { name: 'WordPress', pattern: /^4\./ }];
    return eolPatterns.some(p => name.includes(p.name) && p.pattern.test(version));
  }

  getCVSSColor(score) {
    if (score >= 9) return '#dc2626'; if (score >= 7) return '#ea580c'; if (score >= 4) return '#ca8a04'; if (score > 0) return '#16a34a'; return '#6b7280';
  }

  getOutputFilename(extension) {
    const { reportInfo, output } = this.config;
    const base = output.filename || 'securescan_report_' + (reportInfo.client || 'client') + '_' + reportInfo.date;
    return base + '.' + extension;
  }

  escapeHtml(text) {
    if (!text) return '';
    return text.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
  }

  estimatePages() {
    const findings = this.filterFindings(this.data.findings || []);
    return findings.length + 8;
  }

  // Generadores de otros formatos
  async generatePDF(outputPath) {
    const htmlPath = await this.generateHTML();
    const pdfPath = outputPath || this.getOutputFilename('pdf');
    const fullPath = path.join(this.config.output.dir, pdfPath);

    try {
      await execPromise('wkhtmltopdf "' + htmlPath.path + '" "' + fullPath + '"');
    } catch (error) {
      Logger.warn('[REPORT] wkhtmltopdf no disponible, usando alternativa');
    }
    return { path: fullPath, format: 'pdf', size: fs.statSync(fullPath).size };
  }

  async generateMarkdown(outputPath) {
    const filename = outputPath || this.getOutputFilename('md');
    const fullPath = path.join(this.config.output.dir, filename);

    const md = '# ' + this.config.reportInfo.title + '\n\n**Cliente:** ' + (this.config.reportInfo.client || 'No especificado') + '  \n**Fecha:** ' + this.config.reportInfo.date + '  \n**Versión:** ' + this.config.reportInfo.version + '\n\n## Resumen Ejecutivo\n\nEste reporte fue generado con SecureScan Pro v2.1 utilizando:\n- WhatWeb (detección de tecnologías)\n- Nmap (escaneo de red)\n- Gobuster (descubrimiento de contenido)\n- OWASP ZAP (pruebas DAST)\n- ExploitDB (inteligencia de exploits)\n' + (this.config.filters.includeMetasploit ? '- Metasploit (validación de exploits)\n' : '') + '\n### Estadísticas\n- **Críticos:** ' + this.chartsData.statistics.critical + '\n- **Altos:** ' + this.chartsData.statistics.high + '\n- **Medios:** ' + this.chartsData.statistics.medium + '\n- **Bajos:** ' + this.chartsData.statistics.low + '\n\n## Hallazgos\n\n' + (this.data.findings || []).map((f, i) => '### ' + (i + 1) + '. ' + (f.title || 'Sin título') + '\n- **Severidad:** ' + (f.severity || 'Info') + '\n- **CVSS:** ' + (f.scoring && f.scoring.components ? f.scoring.components.cvssBase : (f.cvss || 'N/A')) + '\n- **Herramienta:** ' + (f.tool || 'N/A') + '\n' + (f.scoring && f.scoring.components && f.scoring.components.exploitdbCount > 0 ? '- **Exploits disponibles:** ' + f.scoring.components.exploitdbCount + '\n' : '') + '\n' + (f.description || 'Sin descripción') + '\n').join('\n') + '\n\n---\n*Generado por SecureScan Pro v2.1*';

    fs.writeFileSync(fullPath, md);
    return { path: fullPath, format: 'markdown', size: fs.statSync(fullPath).size };
  }

  async generateJSON(outputPath) {
    const filename = outputPath || this.getOutputFilename('json');
    const fullPath = path.join(this.config.output.dir, filename);

    const report = {
      metadata: { tool: 'SecureScan Pro', version: '2.1', generatedAt: new Date().toISOString(), ...this.config.reportInfo },
      tools: {
        whatweb: this.toolData.whatweb ? { technologies: this.toolData.whatweb.technologies ? this.toolData.whatweb.technologies.length : 0 } : null,
        nmap: this.toolData.nmap ? { ports: this.toolData.nmap.ports ? this.toolData.nmap.ports.length : 0, cves: this.toolData.nmap.cves ? this.toolData.nmap.cves.length : 0 } : null,
        gobuster: this.toolData.gobuster ? { dirs: this.toolData.gobuster.dir && this.toolData.gobuster.dir.found ? this.toolData.gobuster.dir.found.length : 0, dns: this.toolData.gobuster.dns && this.toolData.gobuster.dns.found ? this.toolData.gobuster.dns.found.length : 0 } : null,
        zap: this.toolData.zap ? { alerts: this.toolData.zap.alerts ? this.toolData.zap.alerts.length : 0 } : null,
        exploitdb: this.toolData.exploitdb ? { exploits: this.chartsData.exploitData ? this.chartsData.exploitData.totalExploits : 0 } : null,
        metasploit: this.toolData.metasploit ? { attempts: this.toolData.metasploit.attempts, successful: this.toolData.metasploit.successful } : null
      },
      findings: this.data.findings,
      statistics: this.chartsData.statistics
    };

    fs.writeFileSync(fullPath, JSON.stringify(report, null, 2));
    return { path: fullPath, format: 'json', size: fs.statSync(fullPath).size };
  }

  async generateSARIF(outputPath) {
    const filename = outputPath || this.getOutputFilename('sarif');
    const fullPath = path.join(this.config.output.dir, filename);

    const sarif = {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: { driver: { name: 'SecureScan Pro', version: '2.1', informationUri: 'https://securescan.pro', rules: this.extractSARIFRules() } },
        results: this.extractSARIFResults(),
        invocations: [{ executionSuccessful: true, startTimeUtc: this.data.startTime, endTimeUtc: this.data.endTime }]
      }]
    };

    fs.writeFileSync(fullPath, JSON.stringify(sarif, null, 2));
    return { path: fullPath, format: 'sarif', size: fs.statSync(fullPath).size };
  }

  extractSARIFRules() {
    const findings = this.data.findings || [];
    const rules = new Map();
    findings.forEach(f => {
      if (!rules.has(f.id)) {
        rules.set(f.id, {
          id: f.id,
          name: f.title || (f.description ? f.description.substring(0, 50) : ''),
          shortDescription: { text: f.description ? f.description.substring(0, 100) : '' },
          fullDescription: { text: f.description || '' },
          defaultConfiguration: { level: this.mapSeverityToSARIF(f.severity) },
          properties: { category: f.category, cvss: f.scoring && f.scoring.components ? f.scoring.components.cvssBase : f.cvss, cwe: f.cweId, exploitdbCount: f.scoring && f.scoring.components ? f.scoring.components.exploitdbCount : 0, hasMetasploitModule: f.scoring && f.scoring.components ? f.scoring.components.hasMetasploitModule : false }
        });
      }
    });
    return Array.from(rules.values());
  }

  extractSARIFResults() {
    return (this.data.findings || []).map(f => ({
      ruleId: f.id,
      level: this.mapSeverityToSARIF(f.severity),
      message: { text: f.description || '' },
      locations: [{ physicalLocation: { artifactLocation: { uri: f.target || 'unknown' }, region: { startLine: f.line || 1 } } }],
      properties: { cvss: f.scoring && f.scoring.components ? f.scoring.components.cvssBase : f.cvss, epss: f.scoring && f.scoring.components ? f.scoring.components.epss : 0, exploitdbCount: f.scoring && f.scoring.components ? f.scoring.components.exploitdbCount : 0, hasMetasploitModule: f.scoring && f.scoring.components ? f.scoring.components.hasMetasploitModule : false, tool: f.tool }
    }));
  }

  mapSeverityToSARIF(severity) {
    const mapping = { 'Critical': 'error', 'High': 'error', 'Medium': 'warning', 'Low': 'note', 'Info': 'none' };
    return mapping[severity] || 'warning';
  }

  async generateDOCX(outputPath) {
    const filename = outputPath || this.getOutputFilename('docx');
    const fullPath = path.join(this.config.output.dir, filename);
    Logger.warn('[REPORT] Generación DOCX requiere librería adicional (docx-templates)');
    return { path: null, format: 'docx', error: 'Implementación DOCX pendiente' };
  }

  async generateXML(outputPath) {
    const filename = outputPath || this.getOutputFilename('xml');
    const fullPath = path.join(this.config.output.dir, filename);
    
    const xml = '<?xml version="1.0" encoding="UTF-8"?>\n<securescan version="2.1">\n  <metadata>\n    <title>' + this.escapeHtml(this.config.reportInfo.title) + '</title>\n    <date>' + this.config.reportInfo.date + '</date>\n  </metadata>\n  <findings count="' + (this.data.findings || []).length + '">\n    ' + (this.data.findings || []).map(f => '<finding id="' + f.id + '"><title>' + this.escapeHtml(f.title) + '</title><severity>' + f.severity + '</severity><cvss>' + (f.scoring && f.scoring.components ? f.scoring.components.cvssBase : '') + '</cvss></finding>').join('\n    ') + '\n  </findings>\n</securescan>';
    
    fs.writeFileSync(fullPath, xml);
    return { path: fullPath, format: 'xml', size: fs.statSync(fullPath).size };
  }

  async generateCSV(outputPath) {
    const filename = outputPath || this.getOutputFilename('csv');
    const fullPath = path.join(this.config.output.dir, filename);
    
    const headers = ['ID', 'Title', 'Severity', 'CVSS', 'EPSS', 'Tool', 'Category', 'Target', 'ExploitDB Count', 'Metasploit', 'Priority'];
    const rows = (this.data.findings || []).map(f => [f.id, '"' + (f.title || '').replace(/"/g, '""') + '"', f.severity, f.scoring && f.scoring.components ? f.scoring.components.cvssBase : '', f.scoring && f.scoring.components ? f.scoring.components.epss : '', f.tool, f.category, f.target, f.scoring && f.scoring.components ? f.scoring.components.exploitdbCount : 0, f.scoring && f.scoring.components && f.scoring.components.hasMetasploitModule ? 'Yes' : 'No', f.scoring ? f.scoring.priority : ''].join(','));
    
    fs.writeFileSync(fullPath, [headers.join(','), ...rows].join('\n'));
    return { path: fullPath, format: 'csv', size: fs.statSync(fullPath).size };
  }
}

module.exports = ReportGenerator;