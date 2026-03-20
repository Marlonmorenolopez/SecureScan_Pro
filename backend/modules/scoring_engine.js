/**
 * ============================================================================
 * SECURITYSCAN PRO - SCORING ENGINE v2.1 CORREGIDO
 * ============================================================================
 * Motor de puntuación de riesgos con integración completa a:
 * - WhatWeb (detección de tecnologías)
 * - ExploitDB Unified (búsqueda de exploits)
 * - Metasploit Integration (confirmación de explotación)
 * - ZAP Scanner (hallazgos DAST)
 * - Nmap Scanner (PUERTOS, SERVICIOS, VERSIONES, CVEs - CORREGIDO)
 * 
 * CAMBIOS CRÍTICOS:
 * - CORREGIDO: Ahora procesa TODOS los hallazgos de Nmap, no solo vulnerabilidades NSE
 * - Agregado: Procesamiento de puertos abiertos como findings de información
 * - Agregado: Procesamiento de servicios/versiones para enriquecimiento
 * - Agregado: Procesamiento de CVEs extraídos del XML de Nmap
 * - Mejorado: Normalización consistente de severidad entre herramientas
 * ============================================================================
 */

const fs = require('fs');
const path = require('path');
const https = require('https');
const Logger = require('../utils/logger');

class ScoringEngine {
  /**
   * Versiones de CVSS soportadas
   */
  static CVSS_VERSIONS = {
    V3_1: '3.1',
    V4_0: '4.0'
  };

  /**
   * Niveles de severidad normalizados
   */
  static SEVERITY_LEVELS = {
    NONE: { min: 0.0, max: 0.0, label: 'None', color: '#808080' },
    LOW: { min: 0.1, max: 3.9, label: 'Low', color: '#FFD700' },
    MEDIUM: { min: 4.0, max: 6.9, label: 'Medium', color: '#FFA500' },
    HIGH: { min: 7.0, max: 8.9, label: 'High', color: '#FF4500' },
    CRITICAL: { min: 9.0, max: 10.0, label: 'Critical', color: '#DC143C' }
  };

  /**
   * Mapeo de puertos a riesgo inherente (basado en exposición común)
   */
  static PORT_RISK_MAPPING = {
    // Puertos críticos - acceso directo o administrativo
    22: { service: 'SSH', risk: 'High', rationale: 'Acceso remoto administrativo' },
    23: { service: 'Telnet', risk: 'Critical', rationale: 'Protocolo sin cifrado - obsoleto' },
    25: { service: 'SMTP', risk: 'Medium', rationale: 'Servicio de correo potencialmente abusable' },
    53: { service: 'DNS', risk: 'Low', rationale: 'Servicio de infraestructura' },
    80: { service: 'HTTP', risk: 'Medium', rationale: 'Web sin cifrar - redirección recomendada' },
    110: { service: 'POP3', risk: 'Medium', rationale: 'Protocolo de correo potencialmente sin cifrar' },
    135: { service: 'MSRPC', risk: 'High', rationale: 'Windows RPC - históricamente atacado' },
    139: { service: 'NetBIOS', risk: 'High', rationale: 'Compartición Windows - información sensible' },
    143: { service: 'IMAP', risk: 'Medium', rationale: 'Protocolo de correo' },
    443: { service: 'HTTPS', risk: 'Low', rationale: 'Web cifrado - verificar configuración TLS' },
    445: { service: 'SMB', risk: 'Critical', rationale: 'Compartición de archivos Windows - alto riesgo' },
    3306: { service: 'MySQL', risk: 'High', rationale: 'Base de datos - nunca debe estar expuesta' },
    3389: { service: 'RDP', risk: 'Critical', rationale: 'Escritorio remoto - alto valor objetivo' },
    5432: { service: 'PostgreSQL', risk: 'High', rationale: 'Base de datos - nunca debe estar expuesta' },
    5900: { service: 'VNC', risk: 'Critical', rationale: 'Acceso remoto gráfico - sin cifrar por defecto' },
    6379: { service: 'Redis', risk: 'Critical', rationale: 'Base de datos en memoria - sin auth por defecto' },
    8080: { service: 'HTTP-Alt', risk: 'Medium', rationale: 'Servicio web alternativo - verificar aplicación' },
    8443: { service: 'HTTPS-Alt', risk: 'Medium', rationale: 'HTTPS alternativo' },
    9200: { service: 'Elasticsearch', risk: 'High', rationale: 'Motor de búsqueda - información sensible' },
    27017: { service: 'MongoDB', risk: 'Critical', rationale: 'Base de datos NoSQL - verificar autenticación' }
  };

  /**
   * Métricas CVSS v3.1 Base
   */
  static CVSS31_BASE_METRICS = {
    AV: {
      N: { value: 0.85, label: 'Network' },
      A: { value: 0.62, label: 'Adjacent' },
      L: { value: 0.55, label: 'Local' },
      P: { value: 0.20, label: 'Physical' }
    },
    AC: {
      L: { value: 0.77, label: 'Low' },
      H: { value: 0.44, label: 'High' }
    },
    PR: {
      N: { value: 0.85, label: 'None' },
      L: { value: 0.62, label: 'Low' },
      H: { value: 0.27, label: 'High' }
    },
    UI: {
      N: { value: 0.85, label: 'None' },
      R: { value: 0.62, label: 'Required' }
    },
    CIA: {
      N: { value: 0.00, label: 'None' },
      L: { value: 0.22, label: 'Low' },
      H: { value: 0.56, label: 'High' }
    }
  };

  /**
   * Métricas CVSS v3.1 Temporal
   */
  static CVSS31_TEMPORAL_METRICS = {
    E: {
      X: { value: 1.00, label: 'Not Defined' },
      U: { value: 0.91, label: 'Unproven' },
      P: { value: 0.94, label: 'Proof-of-Concept' },
      F: { value: 0.97, label: 'Functional' },
      H: { value: 1.00, label: 'High' }
    },
    RL: {
      X: { value: 1.00, label: 'Not Defined' },
      O: { value: 0.95, label: 'Official Fix' },
      T: { value: 0.96, label: 'Temporary Fix' },
      W: { value: 0.97, label: 'Workaround' },
      U: { value: 1.00, label: 'Unavailable' }
    },
    RC: {
      X: { value: 1.00, label: 'Not Defined' },
      U: { value: 0.92, label: 'Unknown' },
      R: { value: 0.96, label: 'Reasonable' },
      C: { value: 1.00, label: 'Confirmed' }
    }
  };

  /**
   * Configuración por defecto ACTUALIZADA
   */
  static get DEFAULT_CONFIG() {
    return {
      cvssVersion: '3.1',
      calculateTemporal: true,
      calculateEnvironmental: true,
      useEPSS: true,
      epssApiUrl: 'https://api.first.org/data/v1/epss',
      
      // Enriquecimiento con ExploitDB
      useExploitDB: true,
      exploitdbMinReliability: 'good',
      
      // Contexto de tecnologías (WhatWeb)
      useTechContext: true,
      techRiskWeights: {
        outdated: 1.5,
        eol: 2.0,
        exposed_admin: 1.8,
        default_creds: 2.5
      },
      
      // Confirmación de Metasploit
      useMetasploitConfirmation: true,
      metasploitWeight: 0.15,
      
      organizationContext: {
        confidentialityRequirement: 'H',
        integrityRequirement: 'H',
        availabilityRequirement: 'H',
        modifiedAttackVector: null,
        modifiedAttackComplexity: null,
        modifiedPrivilegesRequired: null,
        modifiedUserInteraction: null,
        modifiedScope: null,
        modifiedConfidentiality: null,
        modifiedIntegrity: null,
        modifiedAvailability: null
      },
      
      // Ponderación ACTUALIZADA
      weights: {
        cvssBase: 0.25,
        cvssTemporal: 0.15,
        cvssEnvironmental: 0.15,
        epss: 0.15,
        exploitdb: 0.10,
        metasploit: 0.10,
        assetCriticality: 0.05,
        exposure: 0.05
      },
      
      thresholds: {
        immediateAction: 9.0,
        highPriority: 7.0,
        mediumPriority: 4.0,
        riskAcceptance: 2.0
      },
      
      triage: {
        autoTriage: true,
        businessImpactLevels: {
          critical: ['production', 'customer-facing', 'payment'],
          high: ['internal', 'database', 'authentication'],
          medium: ['staging', 'development', 'monitoring'],
          low: ['test', 'documentation', 'archive']
        }
      }
    };
  }

  /**
   * Constructor
   */
  constructor(config = {}) {
    this.config = { ...ScoringEngine.DEFAULT_CONFIG, ...config };
    this.findings = [];
    this.scoredVulnerabilities = new Map();
    this.techStack = null;
    this.exploitdbResults = null;
    this.metasploitResults = null;
    this.zapResults = null;
    this.nmapResults = null; // NUEVO: Almacenar resultados de Nmap completos
  }

  /**
   * Establecer contexto de tecnologías desde WhatWeb
   */
  setTechStack(technologies) {
    this.techStack = technologies;
    Logger.info(`[SCORING] Tech stack cargado: ${technologies?.length || 0} tecnologías`);
  }

  /**
   * Establecer resultados de ExploitDB
   */
  setExploitDBResults(results) {
    this.exploitdbResults = results;
    Logger.info(`[SCORING] ExploitDB results cargados: ${results?.exploits?.length || 0} exploits`);
  }

  /**
   * Establecer resultados de Metasploit
   */
  setMetasploitResults(results) {
    this.metasploitResults = results;
    Logger.info(`[SCORING] Metasploit results cargados: ${results?.attempts || 0} intentos`);
  }

  /**
   * Establecer resultados de ZAP
   */
  setZAPResults(results) {
    this.zapResults = results;
    Logger.info(`[SCORING] ZAP results cargados: ${results?.alerts?.length || 0} alertas`);
  }

  /**
   * NUEVO: Establecer resultados completos de Nmap
   */
  setNmapResults(results) {
    this.nmapResults = results;
    Logger.info(`[SCORING] Nmap results cargados: ${results?.ports?.length || 0} puertos, ${results?.services?.length || 0} servicios, ${results?.cves?.length || 0} CVEs`);
  }

  addFinding(finding) {
    this.findings.push({
      ...finding,
      id: finding.id || `finding-${Date.now()}-${Math.random().toString(36).substr(2, 9)}`,
      timestamp: new Date().toISOString()
    });
  }

  /**
   * Calcular score CVSS v3.1 Base
   */
  calculateCVSS31Base(metrics) {
    const { AV, AC, PR, UI, S, C, I, A } = metrics;
    const m = ScoringEngine.CVSS31_BASE_METRICS;

    const exploitability = 8.22 * 
      m.AV[AV].value * 
      m.AC[AC].value * 
      m.PR[PR].value * 
      m.UI[UI].value;

    const iss = 1 - (
      (1 - m.CIA[C].value) * 
      (1 - m.CIA[I].value) * 
      (1 - m.CIA[A].value)
    );

    const impact = S === 'U' ? 
      6.42 * iss : 
      7.52 * (iss - 0.029) - 3.25 * Math.pow(iss - 0.02, 13);

    let baseScore = 0;
    if (impact > 0) {
      const formula = S === 'U' ? 
        Math.min(impact + exploitability, 10) :
        Math.min(1.08 * (impact + exploitability), 10);
      baseScore = Math.ceil(formula * 10) / 10;
    }

    return {
      score: baseScore,
      severity: this.getSeverityLevel(baseScore),
      vector: `CVSS:3.1/AV:${AV}/AC:${AC}/PR:${PR}/UI:${UI}/S:${S}/C:${C}/I:${I}/A:${A}`,
      exploitability,
      impact,
      metrics: { AV, AC, PR, UI, S, C, I, A }
    };
  }

  /**
   * Calcular score CVSS v3.1 Temporal
   */
  calculateCVSS31Temporal(baseScore, metrics) {
    const { E, RL, RC } = metrics;
    const m = ScoringEngine.CVSS31_TEMPORAL_METRICS;

    const temporalScore = Math.ceil(
      baseScore * 
      m.E[E].value * 
      m.RL[RL].value * 
      m.RC[RC].value * 
      10
    ) / 10;

    return {
      score: temporalScore,
      severity: this.getSeverityLevel(temporalScore),
      vector: `E:${E}/RL:${RL}/RC:${RC}`,
      metrics: { E, RL, RC }
    };
  }

  /**
   * Calcular score CVSS v3.1 Environmental
   */
  calculateCVSS31Environmental(baseMetrics, temporalMetrics, envMetrics, orgContext) {
    const m = ScoringEngine.CVSS31_BASE_METRICS;
    const { CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA } = envMetrics;

    const modAV = MAV || baseMetrics.AV;
    const modAC = MAC || baseMetrics.AC;
    const modPR = MPR || baseMetrics.PR;
    const modUI = MUI || baseMetrics.UI;
    const modS = MS || baseMetrics.S;
    const modC = MC || baseMetrics.C;
    const modI = MI || baseMetrics.I;
    const modA = MA || baseMetrics.A;

    const miss = Math.min(1 - (
      (1 - m.CIA[modC].value * this.getRequirementWeight(CR)) *
      (1 - m.CIA[modI].value * this.getRequirementWeight(IR)) *
      (1 - m.CIA[modA].value * this.getRequirementWeight(AR))
    ), 0.915);

    const modifiedImpact = modS === 'U' ?
      6.42 * miss :
      7.52 * (miss - 0.029) - 3.25 * Math.pow(miss * 0.9731 - 0.02, 13);

    const modifiedExploitability = 8.22 *
      m.AV[modAV].value *
      m.AC[modAC].value *
      m.PR[modPR].value *
      m.UI[modUI].value;

    let envScore = 0;
    if (modifiedImpact > 0) {
      const baseFormula = modS === 'U' ?
        Math.min(modifiedImpact + modifiedExploitability, 10) :
        Math.min(1.08 * (modifiedImpact + modifiedExploitability), 10);
      
      if (temporalMetrics) {
        const tm = ScoringEngine.CVSS31_TEMPORAL_METRICS;
        envScore = Math.ceil(
          baseFormula * 
          tm.E[temporalMetrics.E].value * 
          tm.RL[temporalMetrics.RL].value * 
          tm.RC[temporalMetrics.RC].value * 
          10
        ) / 10;
      } else {
        envScore = Math.ceil(baseFormula * 10) / 10;
      }
    }

    return {
      score: envScore,
      severity: this.getSeverityLevel(envScore),
      vector: `CR:${CR}/IR:${IR}/AR:${AR}/MAV:${modAV}/MAC:${modAC}/MPR:${modPR}/MUI:${modUI}/MS:${modS}/MC:${modC}/MI:${modI}/MA:${modA}`,
      modifiedImpact,
      modifiedExploitability,
      metrics: { CR, IR, AR, MAV, MAC, MPR, MUI, MS, MC, MI, MA }
    };
  }

  /**
   * Calcular scoring compuesto mejorado
   */
  async calculateCompositeScore(vulnerability) {
    const { cve, cvssMetrics, assetContext, edbId, affectedTech } = vulnerability;
    
    let cvssBase = { score: 0, severity: 'None' };
    if (cvssMetrics) {
      cvssBase = this.calculateCVSS31Base(cvssMetrics);
    }
    
    let cvssTemporal = null;
    if (this.config.calculateTemporal && cvssMetrics?.temporal) {
      cvssTemporal = this.calculateCVSS31Temporal(cvssBase.score, cvssMetrics.temporal);
    }
    
    let cvssEnvironmental = null;
    if (this.config.calculateEnvironmental && cvssMetrics?.environmental) {
      cvssEnvironmental = this.calculateCVSS31Environmental(
        cvssMetrics,
        cvssMetrics.temporal,
        cvssMetrics.environmental,
        this.config.organizationContext
      );
    }
    
    const epss = cve ? await this.getEPSS(cve) : null;
    
    let exploitdbInfo = null;
    if (this.config.useExploitDB && (edbId || cve)) {
      exploitdbInfo = this.getExploitDBInfo(edbId, cve);
    }
    
    let metasploitInfo = null;
    if (this.config.useMetasploitConfirmation && cve) {
      metasploitInfo = this.getMetasploitInfo(cve, vulnerability.service);
    }
    
    let techContext = null;
    if (this.config.useTechContext && affectedTech) {
      techContext = this.analyzeTechRisk(affectedTech);
    }
    
    const assetCriticality = this.calculateAssetCriticality(assetContext);
    const exposure = this.calculateExposure(assetContext);
    
    const weights = this.config.weights;
    
    const exploitdbFactor = exploitdbInfo ? (exploitdbInfo.reliabilityScore / 100) * 10 : 0;
    const metasploitFactor = metasploitInfo ? (metasploitInfo.hasWorkingModule ? 10 : 0) : 0;
    const techFactor = techContext ? techContext.riskMultiplier * 2 : 0;
    
    const compositeScore = (
      (cvssBase.score * weights.cvssBase) +
      ((cvssTemporal?.score || cvssBase.score) * weights.cvssTemporal) +
      ((cvssEnvironmental?.score || cvssBase.score) * weights.cvssEnvironmental) +
      ((epss?.score * 10 || 0) * weights.epss) +
      (exploitdbFactor * weights.exploitdb) +
      (metasploitFactor * weights.metasploit) +
      (techFactor * weights.assetCriticality) +
      (assetCriticality * weights.assetCriticality) +
      (exposure * weights.exposure)
    );

    const ssvc = this.determineSSVC(cvssBase, epss, assetContext, {
      exploitdb: exploitdbInfo,
      metasploit: metasploitInfo
    });

    return {
      compositeScore: Math.min(Math.round(compositeScore * 10) / 10, 10.0),
      severity: this.getSeverityLevel(compositeScore),
      components: {
        cvssBase: cvssBase.score,
        cvssTemporal: cvssTemporal?.score,
        cvssEnvironmental: cvssEnvironmental?.score,
        epss: epss?.score,
        epssProbability: epss?.probability,
        exploitdbScore: exploitdbFactor,
        exploitdbCount: exploitdbInfo?.count || 0,
        metasploitScore: metasploitFactor,
        hasMetasploitModule: metasploitInfo?.hasWorkingModule || false,
        techRiskMultiplier: techContext?.riskMultiplier || 1.0,
        assetCriticality,
        exposure
      },
      vectors: {
        base: cvssBase.vector,
        temporal: cvssTemporal?.vector,
        environmental: cvssEnvironmental?.vector
      },
      ssvc,
      exploitdbDetails: exploitdbInfo,
      metasploitDetails: metasploitInfo,
      techContext,
      priority: this.determinePriority(compositeScore, ssvc, epss, exploitdbInfo),
      recommendedAction: this.getRecommendedAction(compositeScore, ssvc, exploitdbInfo)
    };
  }

  /**
   * Obtener información de ExploitDB
   */
  getExploitDBInfo(edbId, cve) {
    if (!this.exploitdbResults) return null;
    
    let exploits = [];
    
    if (edbId) {
      const byId = this.exploitdbResults.exploits?.find(e => e.EDB_ID === edbId);
      if (byId) exploits.push(byId);
    }
    
    if (cve && this.exploitdbResults.services) {
      this.exploitdbResults.services.forEach(service => {
        if (service.exploits) {
          const matches = service.exploits.filter(e => 
            e.cves?.includes(cve) || e.Title?.includes(cve)
          );
          exploits.push(...matches);
        }
      });
    }
    
    if (exploits.length === 0) return null;
    
    const reliabilityScores = exploits.map(e => {
      const type = e.type || 'unknown';
      if (type === 'remote') return 90;
      if (type === 'webapps') return 80;
      if (type === 'local') return 60;
      if (type === 'dos') return 40;
      return 50;
    });
    
    const maxReliability = Math.max(...reliabilityScores);
    
    return {
      count: exploits.length,
      exploits: exploits.slice(0, 3),
      maxCvss: Math.max(...exploits.map(e => e.cvss || 0)),
      reliabilityScore: maxReliability,
      hasRemote: exploits.some(e => e.type === 'remote'),
      hasWebExploit: exploits.some(e => e.type === 'webapps'),
      verified: exploits.some(e => e.verified || e.reliability === 'excellent')
    };
  }

  /**
   * Obtener información de Metasploit
   */
  getMetasploitInfo(cve, service) {
    if (!this.metasploitResults || !this.metasploitResults.details) return null;
    
    const matchingAttempt = this.metasploitResults.details.find(d => 
      d.cve === cve || (service && d.target?.includes(service))
    );
    
    if (!matchingAttempt) return null;
    
    return {
      hasWorkingModule: matchingAttempt.success,
      moduleUsed: matchingAttempt.module,
      sessionId: matchingAttempt.sessionId,
      dryRun: matchingAttempt.status === 'simulated',
      ranking: matchingAttempt.ranking || 'unknown'
    };
  }

  /**
   * Analizar riesgo de tecnología
   */
  analyzeTechRisk(techName) {
    if (!this.techStack) return null;
    
    const tech = this.techStack.find(t => 
      t.name.toLowerCase() === techName.toLowerCase() ||
      techName.toLowerCase().includes(t.name.toLowerCase())
    );
    
    if (!tech) return null;
    
    let riskMultiplier = 1.0;
    const riskFactors = [];
    
    const criticalRiskTechs = ['Windows XP', 'Windows 7', 'SMBv1', 'Telnet', 'FTP'];
    const highRiskTechs = ['WordPress', 'Drupal', 'Joomla', 'Apache', 'nginx', 'PHP', 'MySQL'];
    
    if (criticalRiskTechs.some(t => tech.name.includes(t))) {
      riskMultiplier = this.config.techRiskWeights.eol;
      riskFactors.push('end_of_life');
    } else if (highRiskTechs.some(t => tech.name.includes(t))) {
      riskMultiplier = this.config.techRiskWeights.outdated;
      riskFactors.push('common_target');
    }
    
    if (tech.category === 'CMS' || tech.name.includes('Admin') || tech.name.includes('Panel')) {
      riskMultiplier *= this.config.techRiskWeights.exposed_admin;
      riskFactors.push('exposed_admin');
    }
    
    return {
      technology: tech.name,
      version: tech.version,
      category: tech.category,
      riskMultiplier: Math.min(riskMultiplier, 3.0),
      riskFactors,
      confidence: tech.confidence
    };
  }

  determineSSVC(cvssBase, epss, assetContext, exploitContext) {
    const exploitation = epss?.score > 0.5 ? 'active' :
                         epss?.score > 0.1 ? 'PoC' : 
                         exploitContext?.exploitdb?.count > 0 ? 'PoC' : 'none';
    
    const automatable = cvssBase.metrics?.UI === 'N' && cvssBase.metrics?.AC === 'L' ? 'yes' : 'no';
    const technicalImpact = cvssBase.severity === 'Critical' ? 'total' : cvssBase.severity === 'High' ? 'partial' : 'minimal';
    const missionPrevalence = assetContext?.criticality === 'critical' ? 'critical' : assetContext?.criticality === 'high' ? 'essential' : 'supporting';
    
    let decision = 'defer';
    
    if (exploitation === 'active' && technicalImpact === 'total') {
      decision = 'act';
    } else if (exploitation === 'active' || 
               (technicalImpact === 'total' && missionPrevalence === 'critical') ||
               (exploitContext?.metasploit?.hasWorkingModule && technicalImpact === 'total')) {
      decision = 'attend';
    } else if (technicalImpact === 'partial' && exploitation !== 'none') {
      decision = 'track';
    }
    
    return {
      exploitation,
      automatable,
      technicalImpact,
      missionPrevalence,
      hasExploitDBEntry: exploitContext?.exploitdb?.count > 0 || false,
      hasMetasploitModule: exploitContext?.metasploit?.hasWorkingModule || false,
      decision,
      decisionLabel: this.getSSVCLabel(decision)
    };
  }

  determinePriority(compositeScore, ssvc, epss, exploitdbInfo) {
    if (compositeScore >= 9.0 || ssvc.decision === 'act') return 'immediate';
    if (compositeScore >= 7.0 || ssvc.decision === 'attend') return 'high';
    if (compositeScore >= 4.0 || epss?.score > 0.3) return 'medium';
    if (compositeScore >= 2.0) return 'low';
    
    if (exploitdbInfo?.hasRemote && compositeScore >= 6.0) return 'high';
    if (exploitdbInfo?.verified && compositeScore >= 5.0) return 'medium';
    
    return 'informational';
  }

  getRecommendedAction(score, ssvc, exploitdbInfo) {
    let baseAction = '';
    
    if (score >= 9.0 || ssvc.decision === 'act') {
      baseAction = 'Immediate remediation required - Patch within 24 hours or implement compensating controls';
    } else if (score >= 7.0 || ssvc.decision === 'attend') {
      baseAction = 'High priority - Schedule remediation within 7 days';
    } else if (score >= 4.0) {
      baseAction = 'Medium priority - Include in next maintenance window';
    } else if (score >= 2.0) {
      baseAction = 'Low priority - Address when convenient';
    } else {
      return 'Informational - Monitor for changes';
    }
    
    if (exploitdbInfo?.count > 0) {
      baseAction += `\n⚠️  ${exploitdbInfo.count} exploits públicos disponibles (${exploitdbInfo.hasRemote ? 'incluye remoto' : 'local/web only'})`;
    }
    
    if (ssvc.hasMetasploitModule) {
      baseAction += '\n🔴 Módulo de Metasploit confirmado funcional';
    }
    
    return baseAction;
  }

  calculateAssetCriticality(assetContext) {
    if (!assetContext) return 5.0;
    
    const factors = {
      internetFacing: assetContext.exposure === 'internet' ? 10 : 0,
      containsPII: assetContext.dataClassification === 'pii' ? 8 : 0,
      production: assetContext.environment === 'production' ? 7 : 0,
      criticalBusiness: assetContext.businessCritical ? 9 : 0,
      privilegedAccess: assetContext.privileged ? 8 : 0
    };
    
    const sum = Object.values(factors).reduce((a, b) => a + b, 0);
    return Math.min(sum / 5, 10);
  }

  calculateExposure(assetContext) {
    if (!assetContext) return 5.0;
    
    const exposureMap = {
      internet: 10,
      dmz: 7,
      internal: 5,
      restricted: 3,
      isolated: 1
    };
    
    return exposureMap[assetContext.exposure] || 5;
  }

  /**
   * ============================================================================
   * MÉTODO CRÍTICO CORREGIDO: addFindingsToEngine()
   * ============================================================================
   * 
   * CAMBIOS PRINCIPALES:
   * 1. Ahora procesa TODOS los resultados de Nmap, no solo vulnerabilidades NSE
   * 2. Agrega findings para puertos abiertos (información de superficie de ataque)
   * 3. Agrega findings para servicios/versiones detectados
   * 4. Agrega findings para CVEs extraídos del XML de Nmap
   * 5. Mejora la normalización de severidad entre herramientas
   * ============================================================================
   */
  addFindingsToEngine(engine) {
    Logger.info(`[SCORING] Iniciando agregación de findings de todas las fuentes...`);

    // 1. Agregar findings de WhatWeb (tecnologías detectadas)
    if (this.results?.whatweb?.technologies) {
      Logger.info(`[SCORING] Procesando ${this.results.whatweb.technologies.length} tecnologías de WhatWeb`);
      
      for (const tech of this.results.whatweb.technologies) {
        // Determinar riesgo basado en categoría de tecnología
        let severity = 'Info';
        let category = 'technology_detection';
        
        // Tecnologías de alto riesgo por defecto
        const highRiskTechs = ['WordPress', 'Drupal', 'Joomla', 'Apache Struts', 'WebLogic', 'PHP', 'MySQL'];
        const criticalRiskTechs = ['Windows XP', 'SMBv1', 'Telnet', 'FTP'];
        
        if (criticalRiskTechs.some(t => tech.name.includes(t))) {
          severity = 'High';
          category = 'outdated_technology';
        } else if (highRiskTechs.some(t => tech.name.includes(t))) {
          severity = 'Medium';
          category = 'common_technology';
        }
        
        engine.addFinding({
          tool: 'whatweb',
          category: category,
          title: `Detected ${tech.name} ${tech.version || ''}`,
          description: `Technology detected: ${tech.name} (${tech.category})${tech.version ? ` version ${tech.version}` : ''}. Confidence: ${tech.confidence}%`,
          severity: severity,
          target: this.results.whatweb.url,
          metadata: {
            technology: tech.name,
            version: tech.version,
            category: tech.category,
            confidence: tech.confidence
          }
        });
      }
    }

    // ============================================================================
    // 2. NMAP - PROCESAMIENTO COMPLETO CORREGIDO
    // ============================================================================
    
    if (this.results?.nmap) {
      const nmap = this.results.nmap;
      Logger.info(`[SCORING] Procesando resultados de Nmap: ${nmap.ports?.length || 0} puertos, ${nmap.services?.length || 0} servicios, ${nmap.cves?.length || 0} CVEs`);

      // 2.1 Procesar VULNERABILIDADES de scripts NSE (comportamiento original mejorado)
      if (nmap.vulnerabilities && nmap.vulnerabilities.length > 0) {
        Logger.info(`[SCORING] Procesando ${nmap.vulnerabilities.length} vulnerabilidades NSE`);
        
        for (const vuln of nmap.vulnerabilities) {
          const severity = this.mapNmapSeverity(vuln.severity);
          
          engine.addFinding({
            tool: 'nmap',
            category: vuln.type || 'vulnerability',
            title: vuln.description?.substring(0, 100) || 'Nmap NSE Vulnerability',
            description: vuln.description || 'Vulnerability detected by Nmap NSE script',
            severity: severity,
            cvss: vuln.cvss,
            cve: vuln.cves?.[0],
            target: vuln.host ? `${vuln.host}:${vuln.port}` : (vuln.port ? `port:${vuln.port}` : 'unknown'),
            metadata: {
              source: 'nmap-nse',
              script: vuln.script || 'unknown',
              port: vuln.port,
              cves: vuln.cves || []
            }
          });
        }
      }

      // 2.2 NUEVO: Procesar PUERTOS ABIERTOS como findings de información
      // Esto es crítico: antes estos datos se perdían completamente
      if (nmap.ports && nmap.ports.length > 0) {
        Logger.info(`[SCORING] Procesando ${nmap.ports.length} puertos abiertos como findings`);
        
        for (const port of nmap.ports) {
          // Determinar riesgo inherente del puerto
          const portRisk = ScoringEngine.PORT_RISK_MAPPING[port.port] || { 
            service: port.service || 'Unknown', 
            risk: 'Info',
            rationale: 'Puerto no categorizado'
          };
          
          // Ajustar severidad basada en el servicio detectado
          let severity = portRisk.risk;
          
          // Si el servicio es desconocido o sospechoso, aumentar riesgo
          if (!port.version && port.service === 'unknown') {
            severity = 'Medium'; // Servicio desconocido = investigar
          }
          
          // Construir descripción informativa
          const description = [
            `Puerto ${port.port}/${port.protocol} abierto detectado por Nmap`,
            `Servicio: ${port.service || 'Unknown'}`,
            port.version ? `Versión: ${port.version}` : 'Versión no detectada',
            `Riesgo inherente: ${portRisk.rationale}`
          ].join('. ');

          engine.addFinding({
            tool: 'nmap',
            category: 'network_discovery',
            title: `Open Port ${port.port}/${port.protocol} - ${portRisk.service}`,
            description: description,
            severity: severity,
            target: `${nmap.hosts?.[0]?.hostname || 'target'}:${port.port}`,
            metadata: {
              source: 'nmap-portscan',
              port: port.port,
              protocol: port.protocol,
              service: port.service,
              version: port.version,
              state: port.state,
              portRisk: portRisk
            }
          });
        }
      }

      // 2.3 NUEVO: Procesar SERVICIOS con versiones para enriquecimiento de exploits
      // Los servicios son más específicos que los puertos (incluyen versiones exactas)
      if (nmap.services && nmap.services.length > 0) {
        Logger.info(`[SCORING] Procesando ${nmap.services.length} servicios con versiones`);
        
        for (const service of nmap.services) {
          // Solo agregar si tiene información de versión valiosa
          if (service.version && service.version !== 'unknown') {
            engine.addFinding({
              tool: 'nmap',
              category: 'service_fingerprinting',
              title: `Service Version Detected: ${service.name} ${service.version}`,
              description: `Servicio ${service.name} versión ${service.version} detectado en puerto ${service.port}. Esta información puede usarse para buscar exploits específicos.`,
              severity: 'Info', // Es información técnica, no una vulnerabilidad directa
              target: `port:${service.port}`,
              metadata: {
                source: 'nmap-service',
                service: service.name,
                version: service.version,
                port: service.port
              }
            });
          }
        }
      }

      // 2.4 NUEVO: Procesar CVEs extraídos del XML de Nmap
      // Estos CVEs provienen de scripts vulners o similares
      if (nmap.cves && nmap.cves.length > 0) {
        Logger.info(`[SCORING] Procesando ${nmap.cves.length} CVEs desde Nmap XML`);
        
        for (const cve of nmap.cves) {
          engine.addFinding({
            tool: 'nmap',
            category: 'cve_identification',
            title: `CVE Detected: ${cve}`,
            description: `Vulnerabilidad conocida ${cve} identificada por scripts NSE de Nmap. Requiere verificación y evaluación de impacto.`,
            severity: 'High', // CVEs son potencialmente críticos hasta verificar
            cve: cve,
            target: nmap.hosts?.[0]?.hostname || 'target',
            metadata: {
              source: 'nmap-cve',
              cve: cve,
              requiresVerification: true
            }
          });
        }
      }

      // 2.5 NUEVO: Procesar información del SISTEMA OPERATIVO si está disponible
      if (nmap.os) {
        engine.addFinding({
          tool: 'nmap',
          category: 'os_fingerprinting',
          title: `Operating System Detected: ${nmap.os}`,
          description: `Sistema operativo identificado: ${nmap.os}. Esta información es valiosa para seleccionar exploits específicos.`,
          severity: 'Info',
          target: nmap.hosts?.[0]?.hostname || 'target',
          metadata: {
            source: 'nmap-os',
            os: nmap.os
          }
        });
      }

      // 2.6 NUEVO: Procesar SCRIPTS NSE ejecutados (incluso sin vulnerabilidades explícitas)
      if (nmap.scripts && nmap.scripts.length > 0) {
        for (const script of nmap.scripts) {
          // Solo agregar scripts con output interesante (no solo "vulnerable")
          if (script.output && script.output.length > 10) {
            engine.addFinding({
              tool: 'nmap',
              category: 'script_output',
              title: `NSE Script: ${script.name}`,
              description: script.output.substring(0, 200) + (script.output.length > 200 ? '...' : ''),
              severity: 'Info',
              target: nmap.hosts?.[0]?.hostname || 'target',
              metadata: {
                source: 'nmap-script',
                scriptName: script.name,
                fullOutput: script.output
              }
            });
          }
        }
      }
    }

    // 3. Agregar findings de ZAP (ya convertidos desde alertas)
    if (this.zapFindings) {
      Logger.info(`[SCORING] Procesando ${this.zapFindings.length} findings de ZAP`);
      
      for (const finding of this.zapFindings) {
        // Normalizar severidad de ZAP al formato del scoring engine
        const normalizedSeverity = this.normalizeZapSeverity(finding.severity);
        
        engine.addFinding({
          ...finding,
          tool: 'zap',
          severity: normalizedSeverity,
          category: finding.category || this.categorizeZapFinding(finding)
        });
      }
    }

    // 4. Agregar findings de Gobuster (información sensible expuesta)
    if (this.results?.gobuster?.dir?.found) {
      Logger.info(`[SCORING] Procesando findings de Gobuster`);
      
      const sensitive = this.results.gobuster.dir.found.filter(f => f.sensitive);
      
      for (const item of sensitive) {
        engine.addFinding({
          tool: 'gobuster',
          category: 'information_disclosure',
          title: `Sensitive file/directory exposed: ${item.url}`,
          description: `Potentially sensitive resource found: ${item.url}. Type: ${item.type || 'Unknown'}. Status: ${item.status}`,
          severity: item.risk === 'high' ? 'High' : 'Medium',
          target: item.url,
          metadata: {
            source: 'gobuster',
            statusCode: item.status,
            size: item.size,
            type: item.type
          }
        });
      }
    }

    Logger.info(`[SCORING] Agregación de findings completada. Total en engine: ${engine.findings?.length || 'N/A'}`);
  }

  /**
   * NUEVO: Normalizar severidad de ZAP al formato estándar
   */
  normalizeZapSeverity(zapSeverity) {
    const mapping = {
      'Informational': 'Info',
      'Low': 'Low',
      'Medium': 'Medium',
      'High': 'High',
      'Critical': 'Critical'
    };
    return mapping[zapSeverity] || 'Info';
  }

  /**
   * NUEVO: Categorizar finding de ZAP basado en CWE/WASC
   */
  categorizeZapFinding(finding) {
    if (finding.cweId) {
      const cweCategories = {
        '79': 'xss',
        '89': 'injection',
        '200': 'information_disclosure',
        '287': 'authentication',
        '352': 'csrf',
        '434': 'file_upload',
        '611': 'xxe'
      };
      return cweCategories[finding.cweId] || 'web_vulnerability';
    }
    return 'web_vulnerability';
  }

  /**
   * Mapear severidad de Nmap al formato estándar
   */
  mapNmapSeverity(severity) {
    const mapping = {
      'critical': 'Critical',
      'high': 'High',
      'medium': 'Medium',
      'low': 'Low',
      'info': 'Info'
    };
    return mapping[severity?.toLowerCase()] || 'Info';
  }

  async runScoring() {
    Logger.info(`[SCORING] Iniciando scoring de ${this.findings.length} hallazgos`);
    
    const results = [];
    
    for (const finding of this.findings) {
      try {
        const scored = await this.calculateCompositeScore(finding);
        
        results.push({
          ...finding,
          scoring: scored
        });
        
        this.scoredVulnerabilities.set(finding.id, scored);
        
      } catch (error) {
        Logger.error(`[SCORING] Error procesando ${finding.id}:`, error);
      }
    }
    
    results.sort((a, b) => b.scoring.compositeScore - a.scoring.compositeScore);
    
    return {
      totalScored: results.length,
      criticalCount: results.filter(r => r.scoring.severity === 'Critical').length,
      highCount: results.filter(r => r.scoring.severity === 'High').length,
      results: results,
      summary: this.generateSummary(results)
    };
  }

  generateSummary(results) {
    const byTool = {};
    const byCategory = {};
    const withExploits = [];
    const withMetasploit = [];
    
    for (const result of results) {
      const tool = result.tool || 'unknown';
      const category = result.category || 'general';
      
      byTool[tool] = (byTool[tool] || 0) + 1;
      byCategory[category] = (byCategory[category] || 0) + 1;
      
      if (result.exploitdbDetails?.count > 0) {
        withExploits.push(result.id);
      }
      if (result.metasploitDetails?.hasWorkingModule) {
        withMetasploit.push(result.id);
      }
    }
    
    return {
      totalVulnerabilities: results.length,
      severityDistribution: {
        critical: results.filter(r => r.scoring.severity === 'Critical').length,
        high: results.filter(r => r.scoring.severity === 'High').length,
        medium: results.filter(r => r.scoring.severity === 'Medium').length,
        low: results.filter(r => r.scoring.severity === 'Low').length,
        informational: results.filter(r => r.scoring.severity === 'None' || r.scoring.severity === 'Low' && r.scoring.compositeScore < 2).length
      },
      byTool,
      byCategory,
      threatIntelligence: {
        withExploitDBEntries: withExploits.length,
        withMetasploitModules: withMetasploit.length,
        withRemoteExploits: results.filter(r => r.exploitdbDetails?.hasRemote).length,
        withVerifiedExploits: results.filter(r => r.exploitdbDetails?.verified).length
      },
      topRisks: results.slice(0, 10).map(r => ({
        id: r.id,
        title: r.title || r.description?.substring(0, 50),
        score: r.scoring.compositeScore,
        priority: r.scoring.priority,
        ssvc: r.scoring.ssvc.decision,
        hasExploit: r.exploitdbDetails?.count > 0,
        hasMetasploit: r.metasploitDetails?.hasWorkingModule
      })),
      immediateActionRequired: results.filter(r => r.scoring.priority === 'immediate').length
    };
  }

  async getEPSS(cveId) {
    if (!this.config.useEPSS) return null;
    
    try {
      const url = `${this.config.epssApiUrl}?cve=${cveId}`;
      
      return new Promise((resolve) => {
        https.get(url, (res) => {
          let data = '';
          res.on('data', chunk => data += chunk);
          res.on('end', () => {
            try {
              const parsed = JSON.parse(data);
              if (parsed.data?.length > 0) {
                resolve({
                  score: parseFloat(parsed.data[0].epss),
                  percentile: parseFloat(parsed.data[0].percentile),
                  date: parsed.data[0].date,
                  probability: parsed.data[0].epss
                });
              } else {
                resolve(null);
              }
            } catch {
              resolve(null);
            }
          });
        }).on('error', () => resolve(null)).setTimeout(5000, () => resolve(null));
      });
    } catch {
      return null;
    }
  }

  getSeverityLevel(score) {
    if (score === 0) return 'None';
    if (score <= 3.9) return 'Low';
    if (score <= 6.9) return 'Medium';
    if (score <= 8.9) return 'High';
    return 'Critical';
  }

  getRequirementWeight(level) {
    const weights = { L: 0.5, M: 1.0, H: 1.5, X: 1.0 };
    return weights[level] || 1.0;
  }

  getSSVCLabel(decision) {
    const labels = {
      act: 'Act - Immediate action required',
      attend: 'Attend - Action required soon',
      track: 'Track - Monitor and triage',
      defer: 'Defer - No action required now'
    };
    return labels[decision] || decision;
  }

  exportResults(format = 'json', outputPath) {
    const results = Array.from(this.scoredVulnerabilities.entries()).map(([id, scoring]) => ({
      id,
      ...scoring,
      toolContext: {
        hasExploitDBEntry: scoring.exploitdbDetails?.count > 0,
        hasMetasploitConfirmation: scoring.metasploitDetails?.hasWorkingModule,
        techStackAnalyzed: scoring.techContext !== null
      }
    }));

    let output;
    switch (format) {
      case 'json':
        output = JSON.stringify({
          results,
          summary: this.generateSummary(results),
          metadata: {
            techStackUsed: !!this.techStack,
            exploitdbUsed: !!this.exploitdbResults,
            metasploitUsed: !!this.metasploitResults,
            zapUsed: !!this.zapResults,
            nmapUsed: !!this.nmapResults // NUEVO
          }
        }, null, 2);
        break;
      case 'csv':
        output = this.convertToCSV(results);
        break;
      case 'sarif':
        output = JSON.stringify(this.convertToSARIF(results), null, 2);
        break;
      default:
        output = JSON.stringify(results, null, 2);
    }

    if (outputPath) {
      fs.writeFileSync(outputPath, output);
    }

    return output;
  }

  convertToCSV(results) {
    const headers = ['ID', 'Composite Score', 'Severity', 'CVSS Base', 'EPSS', 'ExploitDB Count', 'Metasploit', 'Priority', 'SSVC Decision'];
    const rows = results.map(r => [
      r.id,
      r.compositeScore,
      r.severity,
      r.components.cvssBase,
      r.components.epss,
      r.components.exploitdbCount,
      r.components.hasMetasploitModule ? 'Yes' : 'No',
      r.priority,
      r.ssvc.decision
    ].join(','));
    
    return [headers.join(','), ...rows].join('\n');
  }

  convertToSARIF(results) {
    return {
      $schema: 'https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json',
      version: '2.1.0',
      runs: [{
        tool: {
          driver: {
            name: 'SecureScan Pro Scoring Engine',
            version: '2.1',
            informationUri: 'https://securescan.pro'
          }
        },
        results: results.map(r => ({
          ruleId: r.id,
          level: r.severity.toLowerCase() === 'critical' ? 'error' : 'warning',
          message: { 
            text: `Score: ${r.compositeScore}, Priority: ${r.priority}, Exploits: ${r.components.exploitdbCount}` 
          },
          properties: {
            cvssScore: r.components.cvssBase,
            epssScore: r.components.epss,
            exploitdbCount: r.components.exploitdbCount,
            hasMetasploitModule: r.components.hasMetasploitModule,
            ssvcDecision: r.ssvc.decision
          }
        }))
      }]
    };
  }

  static async quickScore(vulnerability, config = {}) {
    const engine = new ScoringEngine(config);
    engine.addFinding(vulnerability);
    const results = await engine.runScoring();
    return results.results[0]?.scoring;
  }

  static calculateCVSS31Vector(vectorString) {
    const metrics = {};
    const parts = vectorString.split('/');
    
    for (const part of parts) {
      if (part.startsWith('CVSS:')) continue;
      const [key, value] = part.split(':');
      metrics[key] = value;
    }
    
    const engine = new ScoringEngine();
    return engine.calculateCVSS31Base(metrics);
  }
}

module.exports = ScoringEngine;
