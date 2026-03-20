# API Reference - SecureScan Pro v3.0

## URL Base
http://localhost:4000/api
plain
Copy

---

## Endpoints

### 1. Iniciar Escaneo

**POST** `/scan`

Inicia un nuevo escaneo de seguridad contra el objetivo especificado.

#### Cuerpo de la Petición

```json
{
  "target": "http://localhost:3001",
  "options": {
    "profile": "standard",
    "tools": ["whatweb", "nmap", "gobuster", "zap", "exploitdb", "scoring", "reporting"],
    "failFast": false,
    "nmapOptions": {
      "timing": "T4",
      "scripts": "vuln,vulners,safe",
      "osDetection": true,
      "traceroute": true,
      "topPorts": "all"
    },
    "gobusterOptions": {
      "modes": ["dir", "dns"],
      "threads": 50,
      "extensions": "php,html,txt,bak,zip,sql,env,config,xml,json"
    },
    "zapOptions": {
      "spider": {
        "type": "spiderClient",
        "maxDuration": 15
      },
      "activeScan": {
        "enabled": true,
        "policy": "Default",
        "maxScanDuration": 30
      }
    },
    "exploitdbOptions": {
      "enrichWithNVD": true,
      "maxResults": 10,
      "excludeTerms": "dos"
    },
    "metasploitOptions": {
      "enabled": false,
      "dryRun": true,
      "minRanking": "good",
      "maxSessions": 3
    },
    "scoringOptions": {
      "cvssVersion": "3.1",
      "useEPSS": true,
      "calculateTemporal": true,
      "calculateEnvironmental": true
    },
    "reportingOptions": {
      "formats": ["html", "pdf", "sarif", "json"],
      "sections": {
        "executiveSummary": true,
        "methodology": true,
        "findings": true,
        "riskAssessment": true,
        "remediationPlan": true
      }
    }
  }
}
Campos de la Petición
Table
Campo	Tipo	Requerido	Descripción
target	string	Sí	URL o dominio objetivo (solo localhost o red 172.20.0.0/24)
options.profile	string	No	Perfil predefinido: "quick", "standard", "comprehensive", "passive"
options.tools	array	No	Herramientas a ejecutar (por defecto: todas las habilitadas)
options.failFast	boolean	No	Si es true, detiene el escaneo ante cualquier error
options.nmapOptions	object	No	Configuración específica de Nmap
options.gobusterOptions	object	No	Configuración específica de Gobuster
options.zapOptions	object	No	Configuración específica de ZAP
options.exploitdbOptions	object	No	Configuración de búsqueda en ExploitDB
options.metasploitOptions	object	No	Configuración de Metasploit (deshabilitado por defecto)
options.scoringOptions	object	No	Opciones del motor de puntuación CVSS/EPSS
options.reportingOptions	object	No	Configuración de generación de reportes
Respuesta - 202 Accepted (Escaneo Iniciado)
JSON
Copy
{
  "success": true,
  "scanId": "scan_1710432000000_abc123",
  "message": "Escaneo iniciado exitosamente",
  "status": "created",
  "target": "http://localhost:3001",
  "estimatedTime": "20-30 minutos",
  "statusUrl": "/api/scan/scan_1710432000000_abc123/status",
  "resilience": {
    "circuitBreakersInitialized": 5,
    "fileStabilizerReady": true,
    "targetValidatorReady": true
  }
}
Respuesta - 400 Bad Request
JSON
Copy
{
  "success": false,
  "error": "URL objetivo requerida",
  "code": "MISSING_TARGET"
}
Respuesta - 403 Forbidden (Target No Permitido)
JSON
Copy
{
  "success": false,
  "error": "Target no permitido. Solo se permite localhost o dominios autorizados (172.20.0.0/24)",
  "code": "TARGET_NOT_ALLOWED",
  "allowedTargets": [
    "localhost:3001",
    "localhost:3002", 
    "localhost:3003",
    "127.0.0.1:3001",
    "127.0.0.1:3002",
    "127.0.0.1:3003",
    "172.20.0.0/24"
  ]
}
Respuesta - 409 Conflict (Escaneo en Progreso)
JSON
Copy
{
  "success": false,
  "error": "Ya existe un escaneo en progreso para este objetivo",
  "code": "SCAN_IN_PROGRESS",
  "existingScanId": "scan_1710432000000_xyz789"
}
Respuesta - 503 Service Unavailable (Circuit Breaker Abierto)
JSON
Copy
{
  "success": false,
  "error": "Servicio temporalmente no disponible - Circuit Breaker ABIERTO para la herramienta 'zap'",
  "code": "CIRCUIT_BREAKER_OPEN",
  "circuitBreaker": {
    "name": "zap",
    "state": "OPEN",
    "failures": 3,
    "lastFailure": "2024-03-14T15:00:00.000Z",
    "resetTimeout": 300000
  }
}
2. Consultar Estado del Escaneo
GET /scan/:scanId/status
Obtiene el estado actual de un escaneo en ejecución o completado.
Parámetros de URL
Table
Parámetro	Tipo	Descripción
scanId	string	ID del escaneo devuelto por POST /api/scan
Respuesta - 200 OK (En Progreso)
JSON
Copy
{
  "success": true,
  "scanId": "scan_1710432000000_abc123",
  "status": "running",
  "progress": {
    "overall": 65,
    "currentPhase": "zap",
    "currentStep": "Escaneando aplicación (ZAP)",
    "completedPhases": ["whatweb", "nmap", "gobuster"],
    "pendingPhases": ["exploitdb", "scoring", "reporting"],
    "phaseProgress": {
      "whatweb": { 
        "status": "completed", 
        "progress": 100,
        "duration": "12s",
        "technologiesFound": 4
      },
      "nmap": { 
        "status": "completed", 
        "progress": 100,
        "duration": "45s",
        "portsFound": 3
      },
      "gobuster": { 
        "status": "completed", 
        "progress": 100,
        "duration": "2m 15s",
        "directoriesFound": 12
      },
      "zap": { 
        "status": "running", 
        "progress": 60,
        "spiderProgress": 100,
        "activeScanProgress": 60,
        "alertsFound": 8
      },
      "exploitdb": { 
        "status": "pending", 
        "progress": 0 
      },
      "scoring": { 
        "status": "pending", 
        "progress": 0 
      },
      "reporting": { 
        "status": "pending", 
        "progress": 0 
      }
    }
  },
  "startedAt": "2024-03-14T15:00:00.000Z",
  "elapsedTime": "15m 23s",
  "resilience": {
    "circuitBreakers": {
      "whatweb": { "name": "whatweb", "state": "CLOSED", "failures": 0 },
      "nmap": { "name": "nmap", "state": "CLOSED", "failures": 0 },
      "gobuster": { "name": "gobuster", "state": "CLOSED", "failures": 0 },
      "zap": { "name": "zap", "state": "CLOSED", "failures": 0 },
      "exploitdb": { "name": "exploitdb", "state": "CLOSED", "failures": 0 }
    },
    "fileStabilizer": {
      "activeWaits": 1,
      "lastStabilized": "2024-03-14T15:15:00.000Z"
    },
    "targetValidation": {
      "validated": true,
      "hostname": "localhost",
      "port": 3001,
      "reachable": true
    },
    "processManager": {
      "activeProcesses": 1
    }
  }
}
Respuesta - 200 OK (Completado)
JSON
Copy
{
  "success": true,
  "scanId": "scan_1710432000000_abc123",
  "status": "completed",
  "progress": {
    "overall": 100,
    "currentPhase": null,
    "currentStep": "Completado",
    "completedPhases": [
      "whatweb",
      "nmap",
      "gobuster",
      "zap",
      "exploitdb",
      "scoring",
      "reporting"
    ],
    "phaseProgress": {
      "whatweb": { "status": "completed", "progress": 100, "duration": "12s" },
      "nmap": { "status": "completed", "progress": 100, "duration": "45s" },
      "gobuster": { "status": "completed", "progress": 100, "duration": "2m 15s" },
      "zap": { "status": "completed", "progress": 100, "duration": "12m 30s" },
      "exploitdb": { "status": "completed", "progress": 100, "duration": "8s" },
      "scoring": { "status": "completed", "progress": 100, "duration": "2s" },
      "reporting": { "status": "completed", "progress": 100, "duration": "5s" }
    }
  },
  "startedAt": "2024-03-14T15:00:00.000Z",
  "completedAt": "2024-03-14T15:25:00.000Z",
  "elapsedTime": "25m 00s",
  "summary": {
    "totalFindings": 23,
    "criticalCount": 2,
    "highCount": 5,
    "mediumCount": 8,
    "lowCount": 6,
    "infoCount": 2,
    "overallScore": 35,
    "riskLevel": "HIGH",
    "riskColor": "#ef4444",
    "phasesCompleted": 7,
    "phasesFailed": 0
  },
  "validation": {
    "target": "http://localhost:3001",
    "hostname": "localhost",
    "port": 3001,
    "reachable": true,
    "checkedAt": "2024-03-14T15:00:00.000Z"
  },
  "resilience": {
    "circuitBreakers": {
      "whatweb": { "name": "whatweb", "state": "CLOSED", "failures": 0 },
      "nmap": { "name": "nmap", "state": "CLOSED", "failures": 0 },
      "gobuster": { "name": "gobuster", "state": "CLOSED", "failures": 0 },
      "zap": { "name": "zap", "state": "CLOSED", "failures": 0 },
      "exploitdb": { "name": "exploitdb", "state": "CLOSED", "failures": 0 },
      "metasploit": { "name": "metasploit", "state": "CLOSED", "failures": 0 }
    },
    "fileStabilizer": {
      "totalWaits": 7,
      "successfulWaits": 7,
      "failedWaits": 0
    },
    "processManager": {
      "activeProcesses": 0,
      "cleanedProcesses": 6
    }
  },
  "reportUrl": "/api/scan/scan_1710432000000_abc123/report",
  "resultsUrl": "/api/scan/scan_1710432000000_abc123/results"
}
Respuesta - 404 Not Found
JSON
Copy
{
  "success": false,
  "error": "Escaneo no encontrado",
  "code": "SCAN_NOT_FOUND"
}
3. Obtener Resultados del Escaneo
GET /scan/:scanId/results
Obtiene los resultados detallados del escaneo con hallazgos y vulnerabilidades.
Parámetros de URL
Table
Parámetro	Tipo	Descripción
scanId	string	ID del escaneo
Parámetros de Consulta (Query)
Table
Parámetro	Tipo	Descripción
phase	string	Filtrar por fase específica: whatweb, nmap, gobuster, zap, exploitdb, scoring, reporting
severity	string	Filtrar por severidad: critical, high, medium, low, info
tool	string	Alias para el parámetro phase
Respuesta - 200 OK
JSON
Copy
{
  "success": true,
  "scanId": "scan_1710432000000_abc123",
  "target": "http://localhost:3001",
  "status": "completed",
  "duration": 1500.00,
  "timestamp": "2024-03-14T15:25:00.000Z",
  "phases": {
    "whatweb": {
      "status": "completed",
      "duration": "12s",
      "technologies": [
        {
          "name": "Express",
          "version": "4.18.2",
          "category": "Web frameworks",
          "confidence": 100,
          "website": "https://expressjs.com"
        },
        {
          "name": "Node.js",
          "version": "18.x",
          "category": "Programming languages",
          "confidence": 100,
          "website": "https://nodejs.org"
        },
        {
          "name": "Angular",
          "version": "15.x",
          "category": "JavaScript frameworks",
          "confidence": 95,
          "website": "https://angular.io"
        }
      ],
      "url": "http://localhost:3001/"
    },
    "nmap": {
      "status": "completed",
      "duration": "45s",
      "hosts": [
        {
          "address": "127.0.0.1",
          "hostnames": ["localhost"],
          "status": "up",
          "ports": [
            {
              "port": 3001,
              "protocol": "tcp",
              "state": "open",
              "service": {
                "name": "http",
                "product": "Node.js Express framework",
                "version": "4.18.2",
                "extrainfo": "",
                "method": "probed"
              },
              "scripts": []
            }
          ],
          "os": {
            "name": "Linux",
            "accuracy": 95
          }
        }
      ],
      "scanInfo": {
        "type": "syn",
        "protocol": "tcp",
        "startTime": "2024-03-14T15:00:00.000Z",
        "endTime": "2024-03-14T15:00:45.000Z"
      },
      "vulnerabilities": []
    },
    "gobuster": {
      "status": "completed",
      "duration": "2m 15s",
      "directories": [
        { 
          "path": "/api", 
          "statusCode": 200, 
          "size": 1234,
          "type": "directory",
          "risk": "medium"
        },
        { 
          "path": "/admin", 
          "statusCode": 200, 
          "size": 5678,
          "type": "directory",
          "risk": "high"
        },
        { 
          "path": "/login", 
          "statusCode": 200, 
          "size": 3456,
          "type": "page",
          "risk": "low"
        },
        { 
          "path": "/assets", 
          "statusCode": 301, 
          "size": 0,
          "type": "directory",
          "risk": "low"
        },
        { 
          "path": "/.git", 
          "statusCode": 403, 
          "size": 0,
          "type": "directory",
          "risk": "high"
        }
      ],
      "summary": {
        "total": 5,
        "byStatus": {
          "200": 3,
          "301": 1,
          "403": 1
        },
        "highRisk": 2,
        "interestingFindings": [
          { "path": "/admin", "reason": "Panel de administración detectado", "risk": "high" },
          { "path": "/.git", "reason": "Posible exposición de repositorio Git", "risk": "high" }
        ]
      }
    },
    "zap": {
      "status": "completed",
      "duration": "12m 30s",
      "spider": {
        "scanId": "0",
        "urlsFound": 45,
        "urlsScanned": 45,
        "duration": "3m 00s"
      },
      "activeScan": {
        "scanId": "0",
        "progress": 100,
        "duration": "9m 30s"
      },
      "alerts": [
        {
          "name": "X-Content-Type-Options Header Missing",
          "risk": "Low",
          "confidence": "Medium",
          "severity": "low",
          "description": "El header X-Content-Type-Options no está configurado como 'nosniff'",
          "solution": "Configurar el header X-Content-Type-Options: nosniff en el servidor web",
          "reference": "https://owasp.org/www-community/Security_Headers",
          "cweid": "693",
          "wascid": "15",
          "instances": [
            { "uri": "http://localhost:3001/", "method": "GET", "param": "", "evidence": "" }
          ],
          "count": 1
        },
        {
          "name": "Content Security Policy (CSP) Header Not Set",
          "risk": "Medium",
          "confidence": "High",
          "severity": "medium",
          "description": "El header Content Security Policy no está implementado",
          "solution": "Configurar el header CSP apropiadamente para mitigar XSS y data injection",
          "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
          "cweid": "693",
          "wascid": "15",
          "instances": [
            { "uri": "http://localhost:3001/", "method": "GET", "param": "", "evidence": "" }
          ],
          "count": 1
        },
        {
          "name": "Cross-Site Scripting (Reflected)",
          "risk": "High",
          "confidence": "Medium",
          "severity": "high",
          "description": "Se detectó una vulnerabilidad de XSS reflejado en el parámetro de búsqueda",
          "solution": "Validar y sanitizar todas las entradas de usuario, implementar CSP",
          "reference": "https://owasp.org/www-community/attacks/xss/",
          "cweid": "79",
          "wascid": "8",
          "instances": [
            { 
              "uri": "http://localhost:3001/search", 
              "method": "GET", 
              "param": "q", 
              "evidence": "<script>alert(1)</script>" 
            }
          ],
          "count": 1
        }
      ],
      "summary": {
        "high": 1,
        "medium": 1,
        "low": 1,
        "informational": 0,
        "total": 3
      }
    },
    "exploitdb": {
      "status": "completed",
      "duration": "8s",
      "searches": [
        {
          "query": "Node.js Express 4.18",
          "resultsCount": 2
        },
        {
          "query": "Angular 15",
          "resultsCount": 3
        }
      ],
      "exploits": [
        {
          "title": "Express.js 4.x - Path Traversal",
          "edbId": "12345",
          "date": "2023-01-15",
          "type": "webapps",
          "platform": "multiple",
          "path": "/usr/share/exploitdb/exploits/multiple/webapps/12345.txt",
          "relatedQuery": "Node.js Express 4.18",
          "severity": "high",
          "url": "https://www.exploit-db.com/exploits/12345",
          "cvss": 7.5
        }
      ],
      "summary": {
        "totalExploits": 5,
        "bySeverity": {
          "critical": 0,
          "high": 1,
          "medium": 2,
          "low": 2
        }
      }
    },
    "metasploit": {
      "status": "completed",
      "duration": "0s",
      "enabled": false,
      "dryRun": true,
      "attempts": 0,
      "successful": 0,
      "sessions": [],
      "details": []
    },
    "scoring": {
      "status": "completed",
      "duration": "2s",
      "score": 35,
      "riskLevel": {
        "level": "critical",
        "label": "Crítico",
        "color": "#ef4444"
      },
      "breakdown": {
        "totalPenalty": 244,
        "normalizationFactor": 4,
        "weightsApplied": {
          "critical": 25,
          "high": 15,
          "medium": 8,
          "low": 3,
          "info": 1
        }
      },
      "stats": {
        "totalScored": 23,
        "bySeverity": {
          "critical": 2,
          "high": 5,
          "medium": 8,
          "low": 6,
          "info": 2
        },
        "byTool": {
          "whatweb": 4,
          "nmap": 0,
          "gobuster": 2,
          "zap": 3,
          "exploitdb": 1
        }
      },
      "findings": [
        {
          "source": "zap",
          "severity": "high",
          "title": "Cross-Site Scripting (Reflected)",
          "description": "Se detectó una vulnerabilidad de XSS reflejado",
          "cweId": "79",
          "target": "http://localhost:3001/search"
        },
        {
          "source": "gobuster",
          "severity": "medium",
          "title": "Directorio sensible expuesto: /admin",
          "path": "/admin",
          "target": "http://localhost:3001/admin"
        }
      ],
      "recommendations": [
        "Implementar headers de seguridad (CSP, X-Frame-Options, X-Content-Type-Options)",
        "Configurar cookies con flags HttpOnly y Secure",
        "Actualizar dependencias con vulnerabilidades conocidas",
        "Restringir acceso al panel de administración /admin",
        "Revisar exposición de directorio .git"
      ]
    },
    "reporting": {
      "status": "completed",
      "duration": "5s",
      "formats": [
        { 
          "format": "html", 
          "path": "/reports/scan_1710432000000_abc123/report.html", 
          "size": 45234,
          "mimeType": "text/html"
        },
        { 
          "format": "pdf", 
          "path": "/reports/scan_1710432000000_abc123/report.pdf", 
          "size": 89201,
          "mimeType": "application/pdf"
        },
        { 
          "format": "sarif", 
          "path": "/reports/scan_1710432000000_abc123/report.sarif", 
          "size": 12345,
          "mimeType": "application/sarif+json"
        },
        { 
          "format": "json", 
          "path": "/reports/scan_1710432000000_abc123/report.json", 
          "size": 67890,
          "mimeType": "application/json"
        }
      ],
      "template": "default",
      "sectionsGenerated": {
        "executiveSummary": true,
        "methodology": true,
        "findings": true,
        "riskAssessment": true,
        "remediationPlan": true
      }
    }
  },
  "resilience": {
    "circuitBreakers": {
      "whatweb": { "name": "whatweb", "state": "CLOSED", "failures": 0, "successes": 1 },
      "nmap": { "name": "nmap", "state": "CLOSED", "failures": 0, "successes": 1 },
      "gobuster": { "name": "gobuster", "state": "CLOSED", "failures": 0, "successes": 1 },
      "zap": { "name": "zap", "state": "CLOSED", "failures": 0, "successes": 1 },
      "exploitdb": { "name": "exploitdb", "state": "CLOSED", "failures": 0, "successes": 1 },
      "metasploit": { "name": "metasploit", "state": "CLOSED", "failures": 0, "successes": 0 }
    },
    "fileStabilizer": {
      "totalWaits": 7,
      "successfulWaits": 7,
      "failedWaits": 0,
      "averageWaitTime": "1.2s"
    },
    "targetValidation": {
      "performed": true,
      "hostname": "localhost",
      "port": 3001,
      "reachable": true,
      "validatedAt": "2024-03-14T15:00:00.000Z"
    }
  }
}
4. Descargar Reporte
GET /scan/:scanId/report
Descarga el reporte generado en el formato especificado.
Parámetros de URL
Table
Parámetro	Tipo	Descripción
scanId	string	ID del escaneo
Parámetros de Consulta (Query)
Table
Parámetro	Tipo	Default	Descripción
format	string	"html"	Formato: "html", "pdf", "sarif", "json", "md"
Respuesta - 200 OK
Retorna el archivo del reporte con headers apropiados:
plain
Copy
Content-Type: text/html (o application/pdf, application/sarif+json, application/json, text/markdown)
Content-Disposition: attachment; filename="securescan_report_scan_1710432000000_abc123.html"
Content-Length: 45234
Respuesta - 404 Not Found (Reporte No Generado)
JSON
Copy
{
  "success": false,
  "error": "Reporte no generado aún",
  "code": "REPORT_NOT_READY",
  "status": "running",
  "progress": 65
}
5. Listar Escaneos
GET /scans
Lista todos los escaneos con paginación y filtros.
Parámetros de Consulta (Query)
Table
Parámetro	Tipo	Default	Descripción
page	number	1	Página de resultados
limit	number	10	Resultados por página (máx 100)
status	string	-	Filtrar por estado: running, completed, failed, completed_with_errors
target	string	-	Filtrar por objetivo específico
sortBy	string	"createdAt"	Campo de ordenamiento
sortOrder	string	"desc"	Orden: asc, desc
Respuesta - 200 OK
JSON
Copy
{
  "success": true,
  "scans": [
    {
      "scanId": "scan_1710432000000_abc123",
      "target": "http://localhost:3001",
      "status": "completed",
      "profile": "standard",
      "createdAt": "2024-03-14T15:00:00.000Z",
      "completedAt": "2024-03-14T15:25:00.000Z",
      "elapsedTime": "25m 00s",
      "summary": {
        "totalFindings": 23,
        "riskLevel": "HIGH",
        "overallScore": 35,
        "criticalCount": 2,
        "highCount": 5,
        "mediumCount": 8
      },
      "resilience": {
        "phasesCompleted": 7,
        "phasesFailed": 0,
        "circuitBreakersTriggered": 0
      }
    },
    {
      "scanId": "scan_1710431900000_def456",
      "target": "http://localhost:3002",
      "status": "running",
      "profile": "quick",
      "createdAt": "2024-03-14T14:30:00.000Z",
      "progress": 45,
      "currentPhase": "zap"
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 25,
    "totalPages": 3,
    "hasNext": true,
    "hasPrev": false
  }
}
6. Verificar Salud del Sistema
GET /health
Verifica el estado del servidor API y dependencias core.
Respuesta - 200 OK
JSON
Copy
{
  "success": true,
  "status": "healthy",
  "timestamp": "2024-03-14T15:00:00.000Z",
  "uptime": "2h 30m",
  "version": "3.0.0",
  "resilience": {
    "circuitBreakers": 6,
    "circuitBreakersOpen": 0,
    "activeProcesses": 0,
    "fileStabilizer": "ready",
    "targetValidator": "ready"
  },
  "system": {
    "platform": "linux",
    "nodeVersion": "20.11.0",
    "memory": {
      "used": 512000000,
      "total": 2048000000,
      "percentage": 25
    }
  }
}
Respuesta - 503 Service Unavailable
JSON
Copy
{
  "success": false,
  "status": "degraded",
  "timestamp": "2024-03-14T15:00:00.000Z",
  "issues": [
    {
      "component": "zap",
      "status": "unavailable",
      "reason": "Circuit Breaker OPEN",
      "recovery": "300000ms"
    }
  ]
}
7. Estado de las Herramientas
GET /tools/status
Verifica la disponibilidad de todas las herramientas de escaneo.
Respuesta - 200 OK
JSON
Copy
{
  "success": true,
  "tools": {
    "whatweb": {
      "installed": true,
      "version": "0.5.5",
      "path": "/usr/bin/whatweb",
      "circuitBreaker": "CLOSED"
    },
    "nmap": {
      "installed": true,
      "version": "7.94SVN",
      "path": "/usr/bin/nmap",
      "circuitBreaker": "CLOSED"
    },
    "gobuster": {
      "installed": true,
      "version": "3.6",
      "path": "/usr/bin/gobuster",
      "circuitBreaker": "CLOSED"
    },
    "zap": {
      "installed": true,
      "version": "2.14.0",
      "path": "/usr/share/zaproxy/zap.sh",
      "daemonRunning": true,
      "apiPort": 8080,
      "circuitBreaker": "CLOSED"
    },
    "searchsploit": {
      "installed": true,
      "version": "ExploitDB 2024-03-14",
      "path": "/usr/bin/searchsploit",
      "databaseUpdated": "2024-03-14T00:00:00.000Z",
      "circuitBreaker": "CLOSED"
    },
    "metasploit": {
      "installed": true,
      "version": "6.3.55-dev",
      "path": "/usr/bin/msfconsole",
      "rpcAvailable": false,
      "circuitBreaker": "CLOSED"
    }
  },
  "allInstalled": true,
  "missingTools": [],
  "resilienceStatus": "healthy"
}
8. Estado del Laboratorio
GET /lab/apps
Obtiene el estado de las aplicaciones vulnerables del laboratorio.
Respuesta - 200 OK
JSON
Copy
{
  "success": true,
  "labStatus": "running",
  "network": "172.20.0.0/24",
  "apps": [
    {
      "name": "Juice Shop",
      "container": "securescan-juice-shop",
      "port": 3001,
      "url": "http://localhost:3001",
      "status": "running",
      "health": "healthy",
      "stack": "Node.js, Express, Angular, SQLite",
      "difficulty": "Principiante-Avanzado",
      "features": ["OWASP Top 10 2021", "API REST/GraphQL", "Gamificación"],
      "lastChecked": "2024-03-14T15:00:00.000Z"
    },
    {
      "name": "DVWA",
      "container": "securescan-dvwa",
      "port": 3002,
      "url": "http://localhost:3002",
      "status": "running",
      "health": "healthy",
      "stack": "PHP, Apache, MariaDB",
      "difficulty": "Principiante",
      "features": ["Niveles ajustables", "Código fuente visible", "Clásico educativo"],
      "lastChecked": "2024-03-14T15:00:00.000Z"
    },
    {
      "name": "WebGoat",
      "container": "securescan-webgoat",
      "port": 3003,
      "url": "http://localhost:3003",
      "status": "running",
      "health": "healthy",
      "stack": "Java, Spring Boot",
      "difficulty": "Principiante",
      "features": ["Tutoriales interactivos", "Lecciones guiadas", "WebWolf companion"],
      "lastChecked": "2024-03-14T15:00:00.000Z"
    },
    {
      "name": "WebWolf",
      "container": "securescan-webwolf",
      "port": 9090,
      "url": "http://localhost:9090",
      "status": "running",
      "health": "healthy",
      "stack": "Java, Spring Boot",
      "difficulty": "Intermedio",
      "features": ["Email interception", "Request interception", "Companion de WebGoat"],
      "companion": "WebGoat",
      "lastChecked": "2024-03-14T15:00:00.000Z"
    }
  ],
  "totalApps": 4,
  "runningApps": 4,
  "stoppedApps": 0
}
Códigos de Error
Table
Código	HTTP Status	Descripción
MISSING_TARGET	400	Parámetro target faltante
INVALID_TARGET	400	Formato de URL objetivo inválido
TARGET_NOT_ALLOWED	403	Target fuera del alcance permitido (whitelist)
SCAN_NOT_FOUND	404	ID de escaneo no encontrado
REPORT_NOT_READY	404	Reporte aún no generado (escaneo en progreso)
SCAN_IN_PROGRESS	409	Ya existe un escaneo activo para este target
TOOL_NOT_AVAILABLE	503	Herramienta requerida no instalada
CIRCUIT_BREAKER_OPEN	503	Circuit Breaker abierto - servicio temporalmente no disponible
FILE_STABILIZER_TIMEOUT	504	Timeout esperando estabilización de archivo de salida
TARGET_VALIDATION_FAILED	502	Health-check TCP falló - target no alcanzable
SCAN_FAILED	500	Error interno en ejecución del escaneo
Perfiles de Escaneo Predefinidos
Table
Perfil	Fases Incluidas	Duración Estimada	Uso Recomendado
quick	whatweb → nmap (top 1000) → zap (spider only) → scoring → reporting	10-15 minutos	Reconocimiento rápido, CI/CD pipeline
standard	whatweb → nmap (all ports) → gobuster → zap → exploitdb → scoring → reporting	20-30 minutos	Auditoría de seguridad regular (default)
comprehensive	Todas las fases incluyendo metasploit (dry-run) + dns/vhost enumeration	30-60 minutos	Evaluación de riesgo completa
passive	whatweb → nmap (safe scripts) → gobuster → exploitdb → scoring → reporting	15-20 minutos	Entornos sensibles, mínimo impacto, sin active scanning
Características de Resiliencia
La API implementa varios patrones de resiliencia que se reflejan en las respuestas:
Circuit Breaker
Previene cascada de fallos cuando las herramientas no están disponibles. Estados:
CLOSED: Funcionamiento normal
OPEN: Servicio no disponible, rechazando peticiones
HALF_OPEN: Período de prueba antes de cerrar nuevamente
File Stabilizer
Espera que los archivos de salida estén completamente escritos antes de procesarlos (3 rondas consecutivas estables).
Target Validation
Health-check TCP antes de iniciar cualquier escaneo + whitelist estricto de targets permitidos.
Process Manager
Cleanup automático de procesos huérfanos ante señales SIGTERM/SIGINT.
Graceful Degradation
Continúa el escaneo si fases no críticas fallan (a menos que failFast: true).
Ejemplos con cURL
Escaneo rápido con perfil
bash
Copy
curl -X POST http://localhost:4000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://localhost:3001", "options": {"profile": "quick"}}'
Escaneo estándar con opciones personalizadas
bash
Copy
curl -X POST http://localhost:4000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3001",
    "options": {
      "profile": "standard",
      "failFast": false,
      "nmapOptions": {
        "timing": "T4",
        "scripts": "vuln,vulners"
      },
      "zapOptions": {
        "activeScan": {
          "enabled": true,
          "maxScanDuration": 60
        }
      }
    }
  }'
Consultar estado del escaneo
bash
Copy
curl http://localhost:4000/api/scan/scan_1710432000000_abc123/status
Obtener resultados filtrados por severidad
bash
Copy
curl "http://localhost:4000/api/scan/scan_1710432000000_abc123/results?severity=critical"
Descargar reporte PDF
bash
Copy
curl -o report.pdf "http://localhost:4000/api/scan/scan_1710432000000_abc123/report?format=pdf"
Descargar reporte SARIF (para GitHub/GitLab)
bash
Copy
curl -o results.sarif "http://localhost:4000/api/scan/scan_1710432000000_abc123/report?format=sarif"
Listar escaneos completados
bash
Copy
curl "http://localhost:4000/api/scans?status=completed&limit=5"
Verificar estado del laboratorio
bash
Copy
curl http://localhost:4000/api/lab/apps
Notas de Implementación
Webhooks (Futuro)
El sistema está preparado para soportar webhooks de notificación en futuras versiones:
JSON
Copy
{
  "options": {
    "webhook": {
      "url": "https://mi-sistema.com/webhook/scan",
      "events": ["scan.completed", "scan.failed", "phase.completed"],
      "secret": "webhook-secret-key"
    }
  }
}
Autenticación (Futuro)
La API actual es pública (entorno de laboratorio local). Para producción, se recomienda implementar:
JWT tokens
API keys
Rate limiting por IP/token
Límites de Recursos
Máximo escaneos concurrentes: 1 (por diseño para evitar sobrecarga)
Máximo duración de escaneo: 3600 segundos (1 hora)
Máximo tamaño de reporte: 100 MB
Máximo historial de escaneos: 100 (rotación automática)
API Reference - SecureScan Pro v3.0
Última actualización: Marzo 2026
Versión del documento: 3.0.0-refactorizado