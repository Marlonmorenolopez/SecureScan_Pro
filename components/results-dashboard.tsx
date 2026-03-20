"use client";

import {
  Shield,
  Server,
  Folder,
  Bug,
  Code2,
  Download,
  AlertTriangle,
  AlertCircle,
  Info,
  ChevronRight,
} from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import { useScan } from "@/lib/scan-context";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";

function getSeverityColor(severity: string) {
  switch (severity.toLowerCase()) {
    case "critical":
      return "bg-destructive text-destructive-foreground";
    case "high":
      return "bg-destructive/80 text-destructive-foreground";
    case "medium":
      return "bg-warning text-warning-foreground";
    case "low":
      return "bg-accent text-accent-foreground";
    default:
      return "bg-muted text-muted-foreground";
  }
}

function getGradeColor(grade: string) {
  switch (grade) {
    case "A":
    case "A+":
      return "text-success";
    case "B":
      return "text-primary";
    case "C":
      return "text-warning";
    case "D":
      return "text-destructive/80";
    case "F":
      return "text-destructive";
    default:
      return "text-muted-foreground";
  }
}

function ScoreCard({ score }: { score: { total: number; grade: string; breakdown: Record<string, number> } }) {
  const circumference = 2 * Math.PI * 45;
  const strokeDashoffset = circumference - (score.total / 100) * circumference;

  return (
    <Card className="border-border bg-card">
      <CardHeader>
        <CardTitle className="flex items-center gap-2 text-foreground">
          <Shield className="h-5 w-5 text-primary" />
          Puntuacion de Seguridad
        </CardTitle>
        <CardDescription className="text-muted-foreground">
          Evaluacion general basada en todos los hallazgos
        </CardDescription>
      </CardHeader>
      <CardContent>
        <div className="flex flex-col md:flex-row items-center gap-8">
          <div className="relative">
            <svg className="w-32 h-32 transform -rotate-90">
              <circle
                cx="64"
                cy="64"
                r="45"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                className="text-secondary"
              />
              <circle
                cx="64"
                cy="64"
                r="45"
                fill="none"
                stroke="currentColor"
                strokeWidth="8"
                strokeDasharray={circumference}
                strokeDashoffset={strokeDashoffset}
                strokeLinecap="round"
                className={getGradeColor(score.grade)}
              />
            </svg>
            <div className="absolute inset-0 flex flex-col items-center justify-center">
              <span className={`text-3xl font-bold ${getGradeColor(score.grade)}`}>
                {score.grade}
              </span>
              <span className="text-sm text-muted-foreground">{score.total}/100</span>
            </div>
          </div>

          <div className="flex-1 space-y-3 w-full">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-destructive" />
                <span className="text-sm text-foreground">Critico</span>
              </div>
              <span className="font-medium text-foreground">{score.breakdown.critical}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-destructive/80" />
                <span className="text-sm text-foreground">Alto</span>
              </div>
              <span className="font-medium text-foreground">{score.breakdown.high}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-warning" />
                <span className="text-sm text-foreground">Medio</span>
              </div>
              <span className="font-medium text-foreground">{score.breakdown.medium}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-accent" />
                <span className="text-sm text-foreground">Bajo</span>
              </div>
              <span className="font-medium text-foreground">{score.breakdown.low}</span>
            </div>
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <div className="h-3 w-3 rounded-full bg-muted" />
                <span className="text-sm text-foreground">Info</span>
              </div>
              <span className="font-medium text-foreground">{score.breakdown.info}</span>
            </div>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

export function ResultsDashboard() {
  const { currentScan, downloadReport } = useScan();

  if (!currentScan || currentScan.status === "pending") {
    return null;
  }

  const hasResults =
    currentScan.technologies.length > 0 ||
    currentScan.ports.length > 0 ||
    currentScan.directories.length > 0 ||
    currentScan.vulnerabilities.length > 0 ||
    currentScan.exploits.length > 0;

  if (!hasResults && currentScan.status !== "completed") {
    return null;
  }

  return (
    <div className="space-y-6">
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-4">
        <div>
          <h2 className="text-2xl font-bold text-foreground">Resultados del Analisis</h2>
          <p className="text-muted-foreground">
            Objetivo: {currentScan.target} | Iniciado:{" "}
            {new Date(currentScan.startTime).toLocaleString("es-ES")}
          </p>
        </div>
        <DropdownMenu>
          <DropdownMenuTrigger asChild>
            <Button className="bg-primary text-primary-foreground hover:bg-primary/90">
              <Download className="mr-2 h-4 w-4" />
              Descargar Reporte
            </Button>
          </DropdownMenuTrigger>
          <DropdownMenuContent align="end">
            <DropdownMenuItem onClick={() => downloadReport(currentScan.id, "html")}>
              Formato HTML
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => downloadReport(currentScan.id, "pdf")}>
              Formato PDF
            </DropdownMenuItem>
            <DropdownMenuItem onClick={() => downloadReport(currentScan.id, "json")}>
              Formato JSON
            </DropdownMenuItem>
          </DropdownMenuContent>
        </DropdownMenu>
      </div>

      <ScoreCard score={currentScan.score} />

      <Tabs defaultValue="vulnerabilities" className="w-full">
        <TabsList className="grid w-full grid-cols-5 bg-secondary">
          <TabsTrigger value="vulnerabilities" className="flex items-center gap-1">
            <Bug className="h-4 w-4" />
            <span className="hidden sm:inline">Vulnerabilidades</span>
            <Badge variant="secondary" className="ml-1">
              {currentScan.vulnerabilities.length}
            </Badge>
          </TabsTrigger>
          <TabsTrigger value="technologies" className="flex items-center gap-1">
            <Code2 className="h-4 w-4" />
            <span className="hidden sm:inline">Tecnologias</span>
            <Badge variant="secondary" className="ml-1">
              {currentScan.technologies.length}
            </Badge>
          </TabsTrigger>
          <TabsTrigger value="ports" className="flex items-center gap-1">
            <Server className="h-4 w-4" />
            <span className="hidden sm:inline">Puertos</span>
            <Badge variant="secondary" className="ml-1">
              {currentScan.ports.length}
            </Badge>
          </TabsTrigger>
          <TabsTrigger value="directories" className="flex items-center gap-1">
            <Folder className="h-4 w-4" />
            <span className="hidden sm:inline">Directorios</span>
            <Badge variant="secondary" className="ml-1">
              {currentScan.directories.length}
            </Badge>
          </TabsTrigger>
          <TabsTrigger value="exploits" className="flex items-center gap-1">
            <AlertTriangle className="h-4 w-4" />
            <span className="hidden sm:inline">Exploits</span>
            <Badge variant="secondary" className="ml-1">
              {currentScan.exploits.length}
            </Badge>
          </TabsTrigger>
        </TabsList>

        <TabsContent value="vulnerabilities" className="mt-4">
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="text-foreground">Vulnerabilidades Detectadas</CardTitle>
              <CardDescription className="text-muted-foreground">
                Hallazgos de Nikto, OWASP ZAP y otras herramientas
              </CardDescription>
            </CardHeader>
            <CardContent>
              {currentScan.vulnerabilities.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <Info className="h-12 w-12 mb-4" />
                  <p>No se detectaron vulnerabilidades</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {currentScan.vulnerabilities.map((vuln) => (
                    <div
                      key={vuln.id}
                      className="p-4 rounded-lg border border-border bg-secondary/50 hover:bg-secondary transition-colors"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge className={getSeverityColor(vuln.severity)}>
                              {vuln.severity.toUpperCase()}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              via {vuln.tool}
                            </span>
                          </div>
                          <h4 className="font-medium text-foreground">{vuln.name}</h4>
                          <p className="text-sm text-muted-foreground mt-1">
                            {vuln.description}
                          </p>
                          {vuln.solution && (
                            <div className="mt-3 p-3 rounded bg-primary/10 border border-primary/20">
                              <p className="text-sm text-foreground">
                                <strong>Solucion:</strong> {vuln.solution}
                              </p>
                            </div>
                          )}
                        </div>
                        {vuln.cvss && (
                          <div className="text-center">
                            <div className="text-2xl font-bold text-foreground">
                              {vuln.cvss.toFixed(1)}
                            </div>
                            <div className="text-xs text-muted-foreground">CVSS</div>
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="technologies" className="mt-4">
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="text-foreground">Tecnologias Detectadas</CardTitle>
              <CardDescription className="text-muted-foreground">
                Stack tecnologico identificado por Wappalyzer
              </CardDescription>
            </CardHeader>
            <CardContent>
              {currentScan.technologies.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <Info className="h-12 w-12 mb-4" />
                  <p>No se detectaron tecnologias</p>
                </div>
              ) : (
                <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3">
                  {currentScan.technologies.map((tech, index) => (
                    <div
                      key={index}
                      className="flex items-center gap-3 p-3 rounded-lg border border-border bg-secondary/50"
                    >
                      <div className="flex h-10 w-10 items-center justify-center rounded-md bg-primary/10 text-primary font-bold">
                        {tech.name.charAt(0)}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="font-medium text-foreground truncate">
                          {tech.name}
                        </div>
                        <div className="text-xs text-muted-foreground">
                          {tech.version || "Version desconocida"} | {tech.category}
                        </div>
                      </div>
                      <Badge variant="outline" className="text-xs">
                        {tech.confidence}%
                      </Badge>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="ports" className="mt-4">
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="text-foreground">Puertos y Servicios</CardTitle>
              <CardDescription className="text-muted-foreground">
                Resultados del escaneo con Nmap
              </CardDescription>
            </CardHeader>
            <CardContent>
              {currentScan.ports.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <Info className="h-12 w-12 mb-4" />
                  <p>No se detectaron puertos abiertos</p>
                </div>
              ) : (
                <Table>
                  <TableHeader>
                    <TableRow className="border-border">
                      <TableHead className="text-muted-foreground">Puerto</TableHead>
                      <TableHead className="text-muted-foreground">Estado</TableHead>
                      <TableHead className="text-muted-foreground">Servicio</TableHead>
                      <TableHead className="text-muted-foreground">Producto</TableHead>
                      <TableHead className="text-muted-foreground">Version</TableHead>
                    </TableRow>
                  </TableHeader>
                  <TableBody>
                    {currentScan.ports.map((port) => (
                      <TableRow key={port.port} className="border-border">
                        <TableCell className="font-mono font-medium text-foreground">
                          {port.port}
                        </TableCell>
                        <TableCell>
                          <Badge
                            variant={port.state === "open" ? "default" : "secondary"}
                            className={
                              port.state === "open"
                                ? "bg-success text-success-foreground"
                                : ""
                            }
                          >
                            {port.state}
                          </Badge>
                        </TableCell>
                        <TableCell className="text-foreground">{port.service}</TableCell>
                        <TableCell className="text-muted-foreground">
                          {port.product || "-"}
                        </TableCell>
                        <TableCell className="font-mono text-muted-foreground">
                          {port.version || "-"}
                        </TableCell>
                      </TableRow>
                    ))}
                  </TableBody>
                </Table>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="directories" className="mt-4">
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="text-foreground">Directorios Descubiertos</CardTitle>
              <CardDescription className="text-muted-foreground">
                Rutas encontradas por Gobuster
              </CardDescription>
            </CardHeader>
            <CardContent>
              {currentScan.directories.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <Info className="h-12 w-12 mb-4" />
                  <p>No se descubrieron directorios</p>
                </div>
              ) : (
                <div className="space-y-2">
                  {currentScan.directories.map((dir, index) => (
                    <div
                      key={index}
                      className="flex items-center justify-between p-3 rounded-lg border border-border bg-secondary/50 hover:bg-secondary transition-colors"
                    >
                      <div className="flex items-center gap-3">
                        <Folder className="h-4 w-4 text-primary" />
                        <span className="font-mono text-foreground">{dir.path}</span>
                      </div>
                      <div className="flex items-center gap-3">
                        <Badge
                          variant="outline"
                          className={
                            dir.status >= 200 && dir.status < 300
                              ? "border-success text-success"
                              : dir.status >= 300 && dir.status < 400
                              ? "border-warning text-warning"
                              : "border-muted-foreground"
                          }
                        >
                          {dir.status}
                        </Badge>
                        {dir.size && (
                          <span className="text-xs text-muted-foreground">
                            {dir.size} bytes
                          </span>
                        )}
                        <ChevronRight className="h-4 w-4 text-muted-foreground" />
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        <TabsContent value="exploits" className="mt-4">
          <Card className="border-border bg-card">
            <CardHeader>
              <CardTitle className="flex items-center gap-2 text-foreground">
                <AlertCircle className="h-5 w-5 text-destructive" />
                Exploits Relacionados
              </CardTitle>
              <CardDescription className="text-muted-foreground">
                Vulnerabilidades conocidas de Exploit-DB (Searchsploit)
              </CardDescription>
            </CardHeader>
            <CardContent>
              {currentScan.exploits.length === 0 ? (
                <div className="flex flex-col items-center justify-center py-8 text-muted-foreground">
                  <Info className="h-12 w-12 mb-4" />
                  <p>No se encontraron exploits relacionados</p>
                </div>
              ) : (
                <div className="space-y-3">
                  {currentScan.exploits.map((exploit) => (
                    <div
                      key={exploit.id}
                      className="p-4 rounded-lg border border-destructive/30 bg-destructive/5 hover:bg-destructive/10 transition-colors"
                    >
                      <div className="flex items-start justify-between gap-4">
                        <div className="flex-1">
                          <div className="flex items-center gap-2 mb-2">
                            <Badge variant="destructive">EDB-{exploit.id}</Badge>
                            <Badge variant="outline">{exploit.type}</Badge>
                            <Badge variant="outline">{exploit.platform}</Badge>
                          </div>
                          <h4 className="font-medium text-foreground">{exploit.title}</h4>
                          <p className="text-sm text-muted-foreground mt-1 font-mono">
                            {exploit.path}
                          </p>
                          {exploit.relatedService && (
                            <p className="text-xs text-muted-foreground mt-2">
                              Relacionado con: {exploit.relatedService}
                            </p>
                          )}
                        </div>
                        {exploit.date && (
                          <div className="text-xs text-muted-foreground">
                            {exploit.date}
                          </div>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
