# SecureScan Pro - API Reference

## Base URL

http://localhost:4000/api
plain
Copy

---

## Endpoints

### 1. Start Scan

**POST** `/api/scan`

Initiates a new security scan against the specified target.

#### Request Body

```json
{
  "target": "http://localhost:3001",
  "options": {
    "profile": "standard",
    "tools": ["whatweb", "nmap", "gobuster", "zap", "exploitdb", "scoring", "reporting"],
    "scanType": "standard",
    "nmapOptions": {
      "timing": "T4",
      "scripts": "vuln,vulners,safe",
      "osDetection": true,
      "traceroute": true
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
Request Fields
Table
Field	Type	Required	Description
target	string	Yes	Target URL or domain
options.profile	string	No	Predefined profile: "quick", "standard", "comprehensive", "passive"
options.tools	array	No	Tools to execute (default: all enabled)
options.scanType	string	No	Scan depth: "quick", "standard", "full"
options.nmapOptions	object	No	Nmap-specific configuration
options.gobusterOptions	object	No	Gobuster-specific configuration
options.zapOptions	object	No	ZAP-specific configuration
options.exploitdbOptions	object	No	ExploitDB search configuration
options.metasploitOptions	object	No	Metasploit integration settings
options.scoringOptions	object	No	CVSS/EPSS scoring engine options
options.reportingOptions	object	No	Report generation configuration
Response - 202 Accepted
JSON
Copy
{
  "success": true,
  "scanId": "scan_1710432000000_abc123",
  "message": "Scan started successfully",
  "status": "running",
  "target": "http://localhost:3001",
  "estimatedTime": "15-30 minutes",
  "statusUrl": "/api/scan/scan_1710432000000_abc123/status"
}
Response - 400 Bad Request
JSON
Copy
{
  "success": false,
  "error": "Target URL required",
  "code": "MISSING_TARGET"
}
Response - 403 Forbidden
JSON
Copy
{
  "success": false,
  "error": "Target not allowed. Only localhost or authorized domains permitted.",
  "code": "TARGET_NOT_ALLOWED"
}
Response - 409 Conflict
JSON
Copy
{
  "success": false,
  "error": "Scan already in progress for this target",
  "code": "SCAN_IN_PROGRESS"
}
2. Check Scan Status
GET /api/scan/:scanId/status
Retrieves the current status of a running or completed scan.
URL Parameters
Table
Parameter	Type	Description
scanId	string	Scan ID returned from POST /api/scan
Response - 200 OK (In Progress)
JSON
Copy
{
  "success": true,
  "scanId": "scan_1710432000000_abc123",
  "status": "running",
  "progress": {
    "overall": 45,
    "currentPhase": "zap",
    "completedPhases": ["whatweb", "nmap", "gobuster"],
    "pendingPhases": ["exploitdb", "scoring", "reporting"],
    "phaseProgress": {
      "whatweb": { "status": "completed", "progress": 100 },
      "nmap": { "status": "completed", "progress": 100 },
      "gobuster": { "status": "completed", "progress": 100 },
      "zap": { "status": "running", "progress": 60 },
      "exploitdb": { "status": "pending", "progress": 0 },
      "scoring": { "status": "pending", "progress": 0 },
      "reporting": { "status": "pending", "progress": 0 }
    }
  },
  "startedAt": "2024-03-14T15:00:00.000Z",
  "elapsedTime": "5m 23s",
  "circuitBreakers": {
    "nmap": { "state": "CLOSED", "failures": 0 },
    "zap": { "state": "CLOSED", "failures": 0 }
  }
}
Response - 200 OK (Completed)
JSON
Copy
{
  "success": true,
  "scanId": "scan_1710432000000_abc123",
  "status": "completed",
  "progress": {
    "overall": 100,
    "currentPhase": null,
    "completedPhases": [
      "whatweb",
      "nmap",
      "gobuster",
      "zap",
      "exploitdb",
      "scoring",
      "reporting"
    ]
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
    "phasesCompleted": 7
  },
  "validation": {
    "target": "http://localhost:3001",
    "hostname": "localhost",
    "port": 3001,
    "reachable": true,
    "checkedAt": "2024-03-14T15:00:00.000Z"
  },
  "reportUrl": "/api/scan/scan_1710432000000_abc123/report",
  "resultsUrl": "/api/scan/scan_1710432000000_abc123/results"
}
Response - 404 Not Found
JSON
Copy
{
  "success": false,
  "error": "Scan not found",
  "code": "SCAN_NOT_FOUND"
}
3. Get Scan Results
GET /api/scan/:scanId/results
Retrieves detailed scan results with findings and vulnerabilities.
URL Parameters
Table
Parameter	Type	Description
scanId	string	Scan ID
Query Parameters
Table
Parameter	Type	Description
phase	string	Filter by specific phase (whatweb, nmap, gobuster, zap, exploitdb)
severity	string	Filter by severity: critical, high, medium, low, info
tool	string	Alias for phase parameter
Response - 200 OK
JSON
Copy
{
  "success": true,
  "scanId": "scan_1710432000000_abc123",
  "target": "http://localhost:3001",
  "status": "completed",
  "duration": "1500.00",
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
          "confidence": 100
        },
        {
          "name": "Node.js",
          "version": "18.x",
          "category": "Programming languages",
          "confidence": 100
        }
      ]
    },
    "nmap": {
      "status": "completed",
      "duration": "45s",
      "host": {
        "ip": "127.0.0.1",
        "hostname": "localhost",
        "state": "up"
      },
      "ports": [
        {
          "port": 3001,
          "protocol": "tcp",
          "state": "open",
          "service": "http",
          "version": "Node.js Express framework",
          "scripts": []
        }
      ],
      "os": {
        "name": "Linux",
        "accuracy": 95
      },
      "vulnerabilities": []
    },
    "gobuster": {
      "status": "completed",
      "duration": "2m 15s",
      "directories": [
        { "path": "/api", "status": 200, "size": 1234 },
        { "path": "/admin", "status": 403, "size": 0 },
        { "path": "/login", "status": 200, "size": 5678 },
        { "path": "/assets", "status": 301, "size": 0 },
        { "path": "/.git", "status": 403, "size": 0 }
      ],
      "totalFound": 5,
      "interestingFindings": [
        { "path": "/admin", "reason": "Admin panel detected" },
        { "path": "/.git", "reason": "Possible Git exposure" }
      ]
    },
    "zap": {
      "status": "completed",
      "duration": "10m 45s",
      "alerts": [
        {
          "id": "10021",
          "name": "X-Content-Type-Options Header Missing",
          "risk": "Low",
          "confidence": "Medium",
          "description": "The Anti-MIME-Sniffing header X-Content-Type-Options was not set to 'nosniff'",
          "solution": "Ensure that the application/web server sets the Content-Type header appropriately",
          "reference": "https://owasp.org/www-community/Security_Headers",
          "instances": [{ "uri": "http://localhost:3001/", "method": "GET" }],
          "count": 1,
          "cweid": "693",
          "wascid": "15"
        },
        {
          "id": "10038",
          "name": "Content Security Policy (CSP) Header Not Set",
          "risk": "Medium",
          "confidence": "High",
          "description": "Content Security Policy header not implemented",
          "solution": "Ensure CSP header is configured correctly",
          "reference": "https://developer.mozilla.org/en-US/docs/Web/HTTP/CSP",
          "instances": [{ "uri": "http://localhost:3001/", "method": "GET" }],
          "count": 1,
          "cweid": "693",
          "wascid": "15"
        }
      ],
      "summary": {
        "high": 0,
        "medium": 1,
        "low": 1,
        "informational": 0
      },
      "spiderResults": {
        "urlsFound": 45,
        "urlsScanned": 45
      }
    },
    "exploitdb": {
      "status": "completed",
      "duration": "8s",
      "exploits": [
        {
          "title": "Express.js 4.x - Path Traversal",
          "edbId": "12345",
          "path": "webapps/12345.txt",
          "type": "webapps",
          "platform": "multiple",
          "searchedTerm": "express 4.18",
          "relevance": "high"
        }
      ],
      "totalExploitsFound": 1,
      "searchedTerms": ["express 4.18", "node.js 18"]
    },
    "metasploit": {
      "status": "completed",
      "duration": "0s",
      "enabled": false,
      "dryRun": true,
      "attempts": 0,
      "successful": 0,
      "sessions": []
    },
    "scoring": {
      "status": "completed",
      "duration": "2s",
      "overallScore": 65,
      "riskLevel": "MEDIUM",
      "breakdown": {
        "niktoScore": 70,
        "zapScore": 75,
        "exploitScore": 50,
        "configScore": 80
      },
      "stats": {
        "totalScored": 23,
        "bySeverity": {
          "critical": 2,
          "high": 5,
          "medium": 8,
          "low": 6,
          "info": 2
        }
      },
      "recommendations": [
        "Implementar headers de seguridad (CSP, X-Frame-Options, etc.)",
        "Configurar cookies con flags HttpOnly y Secure",
        "Actualizar dependencias con vulnerabilidades conocidas"
      ]
    },
    "reporting": {
      "status": "completed",
      "duration": "5s",
      "formats": [
        { "format": "html", "path": "/reports/scan_xxx.html", "size": 45234 },
        { "format": "pdf", "path": "/reports/scan_xxx.pdf", "size": 89201 },
        { "format": "sarif", "path": "/reports/scan_xxx.sarif", "size": 12345 },
        { "format": "json", "path": "/reports/scan_xxx.json", "size": 67890 }
      ]
    }
  },
  "circuitBreakers": {
    "whatweb": { "name": "whatweb", "state": "CLOSED", "failures": 0 },
    "nmap": { "name": "nmap", "state": "CLOSED", "failures": 0 },
    "gobuster": { "name": "gobuster", "state": "CLOSED", "failures": 0 },
    "zap": { "name": "zap", "state": "CLOSED", "failures": 0 },
    "exploitdb": { "name": "exploitdb", "state": "CLOSED", "failures": 0 }
  }
}
4. Download Report
GET /api/scan/:scanId/report
Downloads the generated scan report in the specified format.
URL Parameters
Table
Parameter	Type	Description
scanId	string	Scan ID
Query Parameters
Table
Parameter	Type	Default	Description
format	string	"html"	Format: "html", "pdf", "sarif", "json", "md"
Response - 200 OK
Returns the report file with appropriate headers:
plain
Copy
Content-Type: text/html (or application/pdf, application/json, text/markdown)
Content-Disposition: attachment; filename="securescan_report_scan_xxx.html"
5. List Scans
GET /api/scans
Lists all scans with pagination and filtering.
Query Parameters
Table
Parameter	Type	Default	Description
page	number	1	Results page
limit	number	10	Results per page (max 100)
status	string	-	Filter by status: running, completed, failed
sortBy	string	"createdAt"	Sort field
sortOrder	string	"desc"	Sort order: asc, desc
Response - 200 OK
JSON
Copy
{
  "success": true,
  "scans": [
    {
      "scanId": "scan_1710432000000_abc123",
      "target": "http://localhost:3001",
      "status": "completed",
      "createdAt": "2024-03-14T15:00:00.000Z",
      "completedAt": "2024-03-14T15:25:00.000Z",
      "summary": {
        "totalFindings": 23,
        "riskLevel": "HIGH",
        "overallScore": 35,
        "criticalCount": 2,
        "highCount": 5
      }
    }
  ],
  "pagination": {
    "page": 1,
    "limit": 10,
    "total": 25,
    "totalPages": 3
  }
}
6. Health Check
GET /api/health
Verifies API server and core dependencies status.
Response - 200 OK
JSON
Copy
{
  "success": true,
  "status": "healthy",
  "timestamp": "2024-03-14T15:00:00.000Z",
  "uptime": "2h 30m",
  "version": "3.0.0",
  "resilience": {
    "circuitBreakers": 5,
    "activeProcesses": 0,
    "fileStabilizer": "ready"
  }
}
7. Tools Status
GET /api/tools/status
Checks availability of all scanning tools.
Response - 200 OK
JSON
Copy
{
  "success": true,
  "tools": {
    "whatweb": {
      "installed": true,
      "version": "6.10.0",
      "path": "/usr/local/bin/wappalyzer"
    },
    "nmap": {
      "installed": true,
      "version": "7.94",
      "path": "/usr/bin/nmap"
    },
    "gobuster": {
      "installed": true,
      "version": "3.6",
      "path": "/usr/bin/gobuster"
    },
    "zap": {
      "installed": true,
      "version": "2.14.0",
      "path": "/usr/share/zaproxy/zap.sh"
    },
    "searchsploit": {
      "installed": true,
      "version": "ExploitDB - 2024-01",
      "path": "/usr/bin/searchsploit"
    }
  },
  "allInstalled": true,
  "missingTools": []
}
Error Codes
Table
Code	HTTP Status	Description
MISSING_TARGET	400	Target parameter missing
INVALID_TARGET	400	Invalid target URL format
TARGET_NOT_ALLOWED	403	Target not in allowed scope
SCAN_NOT_FOUND	404	Scan ID not found
SCAN_IN_PROGRESS	409	Active scan already running for target
TOOL_NOT_AVAILABLE	503	Required tool not installed
CIRCUIT_BREAKER_OPEN	503	Service temporarily unavailable (circuit breaker open)
SCAN_FAILED	500	Internal scan execution error
cURL Examples
Quick scan with profile
bash
Copy
curl -X POST http://localhost:4000/api/scan \
  -H "Content-Type: application/json" \
  -d '{"target": "http://localhost:3001", "options": {"profile": "quick"}}'
Standard scan with custom options
bash
Copy
curl -X POST http://localhost:4000/api/scan \
  -H "Content-Type: application/json" \
  -d '{
    "target": "http://localhost:3001",
    "options": {
      "scanType": "full",
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
Check scan status
bash
Copy
curl http://localhost:4000/api/scan/scan_1710432000000_abc123/status
Get results filtered by severity
bash
Copy
curl "http://localhost:4000/api/scan/scan_1710432000000_abc123/results?severity=critical"
Download PDF report
bash
Copy
curl -o report.pdf "http://localhost:4000/api/scan/scan_xxx/report?format=pdf"
List completed scans
bash
Copy
curl "http://localhost:4000/api/scans?status=completed&limit=5"
Scan Profiles
Table
Profile	Phases	Description
quick	whatweb, nmap, zap, scoring, reporting	Fast reconnaissance (10-15 min)
standard	whatweb, nmap, gobuster, zap, exploitdb, scoring, reporting	Balanced depth (15-30 min)
comprehensive	All phases including metasploit	Full assessment (30-60 min)
passive	whatweb, nmap, gobuster, exploitdb, scoring, reporting	No active exploitation
Resilience Features
The API implements several resilience patterns:
Circuit Breaker: Prevents cascade failures when tools are unavailable
File Stabilizer: Waits for output files to stabilize before processing
Target Validation: TCP health-check before scanning
Process Management: Automatic cleanup of orphaned processes
Graceful Degradation: Continues scan if non-critical phases fail
plain
Copy

```
