"use client";

import { useState, useEffect } from "react";
import {
  History,
  Search,
  Download,
  Trash2,
  Eye,
  Calendar,
  Target,
  Shield,
  Filter,
  Layers,
  Network,
  Search as SearchIcon,
  ShieldCheck,
  Database,
  Skull,
  Activity,
  FileText,
  CheckCircle,
  XCircle,
  Clock,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import {
  Table,
  TableBody,
  TableCell,
  TableHead,
  TableHeader,
  TableRow,
} from "@/components/ui/table";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Dialog,
  DialogContent,
  DialogDescription,
  DialogHeader,
  DialogTitle,
  DialogTrigger,
} from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import { Header } from "@/components/header";

// Tipos de herramientas del sistema actualizado
type ToolStatus = "pending" | "running" | "completed" | "failed" | "skipped";

interface ToolResult {
  name: string;
  icon: React.ReactNode;
  status: ToolStatus;
  duration?: string;
  findings?: number;
  details?: string;
}

interface ScanHistoryItem {
  id: string;
  target: string;
  date: string;
  duration: string;
  status: "completed" | "running" | "failed" | "cancelled";
  grade: "A+" | "A" | "B" | "C" | "D" | "F";
  score: number;
  vulnerabilities: {
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
    total: number;
  };
  tools: ToolResult[];
  reportFormats: string[];
  exploitCount: number;
  hasMetasploitSession: boolean;
}

// Datos mock actualizados con las nuevas herramientas
const mockHistory: ScanHistoryItem[] = [
  {
    id: "scan-1710234567890",
    target: "https://example.com",
    date: "2024-03-10T14:30:00Z",
    duration: "5m 32s",
    status: "completed",
    grade: "C",
    score: 6.8,
    vulnerabilities: { critical: 2, high: 5, medium: 8, low: 12, info: 3, total: 30 },
    tools: [
      { name: "WhatWeb", icon: <Layers className="h-4 w-4" />, status: "completed", duration: "15s", findings: 8, details: "WordPress 6.4, PHP 8.1, Apache 2.4" },
      { name: "Nmap", icon: <Network className="h-4 w-4" />, status: "completed", duration: "45s", findings: 3, details: "22/ssh, 80/http, 443/https" },
      { name: "Gobuster", icon: <SearchIcon className="h-4 w-4" />, status: "completed", duration: "2m 10s", findings: 24, details: "/admin, /api, /wp-content" },
      { name: "ZAP", icon: <ShieldCheck className="h-4 w-4" />, status: "completed", duration: "2m 30s", findings: 12, details: "XSS, SQLi, CSRF detectados" },
      { name: "ExploitDB", icon: <Database className="h-4 w-4" />, status: "completed", duration: "30s", findings: 5, details: "5 exploits públicos encontrados" },
      { name: "Metasploit", icon: <Skull className="h-4 w-4" />, status: "completed", duration: "1m 20s", findings: 2, details: "2 sesiones activas (dry-run)" },
      { name: "Scoring", icon: <Activity className="h-4 w-4" />, status: "completed", duration: "2s", findings: 30, details: "CVSS: 6.8, EPSS: 0.45" },
    ],
    reportFormats: ["html", "pdf", "json", "sarif"],
    exploitCount: 5,
    hasMetasploitSession: true,
  },
  {
    id: "scan-1710234123456",
    target: "http://localhost:3000",
    date: "2024-03-09T10:15:00Z",
    duration: "3m 45s",
    status: "completed",
    grade: "B",
    score: 4.2,
    vulnerabilities: { critical: 0, high: 2, medium: 5, low: 8, info: 2, total: 17 },
    tools: [
      { name: "WhatWeb", icon: <Layers className="h-4 w-4" />, status: "completed", duration: "8s", findings: 5, details: "Next.js 14, Node.js 20" },
      { name: "Nmap", icon: <Network className="h-4 w-4" />, status: "completed", duration: "30s", findings: 1, details: "3000/tcp" },
      { name: "Gobuster", icon: <SearchIcon className="h-4 w-4" />, status: "completed", duration: "1m 30s", findings: 12, details: "/api, /_next" },
      { name: "ZAP", icon: <ShieldCheck className="h-4 w-4" />, status: "completed", duration: "1m 45s", findings: 5, details: "CSP, HSTS issues" },
      { name: "ExploitDB", icon: <Database className="h-4 w-4" />, status: "completed", duration: "20s", findings: 0, details: "Sin exploits conocidos" },
      { name: "Metasploit", icon: <Skull className="h-4 w-4" />, status: "skipped", findings: 0, details: "No requerido" },
      { name: "Scoring", icon: <Activity className="h-4 w-4" />, status: "completed", duration: "2s", findings: 17, details: "CVSS: 4.2, EPSS: 0.15" },
    ],
    reportFormats: ["html", "pdf"],
    exploitCount: 0,
    hasMetasploitSession: false,
  },
  {
    id: "scan-1710233987654",
    target: "https://api.test-server.com",
    date: "2024-03-08T16:45:00Z",
    duration: "8m 12s",
    status: "completed",
    grade: "D",
    score: 8.5,
    vulnerabilities: { critical: 5, high: 8, medium: 12, low: 6, info: 4, total: 35 },
    tools: [
      { name: "WhatWeb", icon: <Layers className="h-4 w-4" />, status: "completed", duration: "12s", findings: 6, details: "Express.js, nginx 1.18" },
      { name: "Nmap", icon: <Network className="h-4 w-4" />, status: "completed", duration: "1m 20s", findings: 5, details: "22, 80, 443, 3306, 8080" },
      { name: "Gobuster", icon: <SearchIcon className="h-4 w-4" />, status: "completed", duration: "3m 30s", findings: 45, details: "/swagger, /api/v1, /admin" },
      { name: "ZAP", icon: <ShieldCheck className="h-4 w-4" />, status: "completed", duration: "3m 45s", findings: 22, details: "API vulnerabilities, IDOR" },
      { name: "ExploitDB", icon: <Database className="h-4 w-4" />, status: "completed", duration: "45s", findings: 12, details: "12 exploits públicos" },
      { name: "Metasploit", icon: <Skull className="h-4 w-4" />, status: "completed", duration: "2m 30s", findings: 3, details: "3 sesiones activas" },
      { name: "Scoring", icon: <Activity className="h-4 w-4" />, status: "completed", duration: "2s", findings: 35, details: "CVSS: 8.5, EPSS: 0.78" },
    ],
    reportFormats: ["html", "pdf", "json", "sarif", "csv"],
    exploitCount: 12,
    hasMetasploitSession: true,
  },
];

function getGradeColor(grade: string) {
  switch (grade) {
    case "A+":
    case "A":
      return "bg-emerald-500 text-white hover:bg-emerald-600";
    case "B":
      return "bg-blue-500 text-white hover:bg-blue-600";
    case "C":
      return "bg-yellow-500 text-black hover:bg-yellow-600";
    case "D":
      return "bg-orange-500 text-white hover:bg-orange-600";
    case "F":
      return "bg-red-600 text-white hover:bg-red-700";
    default:
      return "bg-gray-500 text-white hover:bg-gray-600";
  }
}

function getStatusIcon(status: ScanHistoryItem["status"]) {
  switch (status) {
    case "completed":
      return <CheckCircle className="h-5 w-5 text-emerald-500" />;
    case "running":
      return <Clock className="h-5 w-5 text-blue-500 animate-spin" />;
    case "failed":
      return <XCircle className="h-5 w-5 text-red-500" />;
    case "cancelled":
      return <XCircle className="h-5 w-5 text-gray-500" />;
  }
}

function getToolStatusBadge(status: ToolStatus) {
  switch (status) {
    case "completed":
      return <Badge variant="default" className="bg-emerald-500/10 text-emerald-500 border-emerald-500/20">Completado</Badge>;
    case "running":
      return <Badge variant="default" className="bg-blue-500/10 text-blue-500 border-blue-500/20 animate-pulse">Ejecutando</Badge>;
    case "failed":
      return <Badge variant="destructive">Fallido</Badge>;
    case "skipped":
      return <Badge variant="secondary">Omitido</Badge>;
    case "pending":
      return <Badge variant="outline">Pendiente</Badge>;
  }
}

export default function HistoryPage() {
  const [searchTerm, setSearchTerm] = useState("");
  const [gradeFilter, setGradeFilter] = useState<string>("all");
  const [statusFilter, setStatusFilter] = useState<string>("all");
  const [selectedScan, setSelectedScan] = useState<ScanHistoryItem | null>(null);
  const [history, setHistory] = useState<ScanHistoryItem[]>(mockHistory);
  const [isLoading, setIsLoading] = useState(false);

  // TODO: Conectar con API real
  // useEffect(() => {
  //   fetch('/api/scans/history')
  //     .then(res => res.json())
  //     .then(data => setHistory(data))
  //     .catch(err => console.error('Error cargando historial:', err));
  // }, []);

  const filteredHistory = history.filter((scan) => {
    const matchesSearch = scan.target.toLowerCase().includes(searchTerm.toLowerCase()) ||
                         scan.id.toLowerCase().includes(searchTerm.toLowerCase());
    const matchesGrade = gradeFilter === "all" || scan.grade === gradeFilter;
    const matchesStatus = statusFilter === "all" || scan.status === statusFilter;
    return matchesSearch && matchesGrade && matchesStatus;
  });

  const totalScans = history.length;
  const completedScans = history.filter(s => s.status === "completed").length;
  const avgVulnerabilities = Math.round(
    history.reduce((sum, scan) => sum + scan.vulnerabilities.total, 0) / totalScans || 0
  );
  const totalExploits = history.reduce((sum, scan) => sum + scan.exploitCount, 0);
  const activeSessions = history.filter(s => s.hasMetasploitSession).length;

  const handleDownloadReport = (scanId: string, format: string) => {
    // TODO: Implementar descarga real
    console.log(`Descargando reporte ${scanId} en formato ${format}`);
    // window.open(`/api/reports/${scanId}/download?format=${format}`);
  };

  const handleDeleteScan = (scanId: string) => {
    // TODO: Implementar eliminación real
    setHistory(prev => prev.filter(s => s.id !== scanId));
  };

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 py-8">
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-2">
            Historial de Escaneos
          </h1>
          <p className="text-muted-foreground">
            Consulta y gestiona los resultados de escaneos de seguridad
          </p>
        </div>

        {/* Stats Cards Actualizadas */}
        <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-5 mb-8">
          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Total Escaneos</CardTitle>
              <History className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{totalScans}</div>
              <p className="text-xs text-muted-foreground">
                {completedScans} completados
              </p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Vulnerabilidades</CardTitle>
              <Shield className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{avgVulnerabilities}</div>
              <p className="text-xs text-muted-foreground">Promedio por escaneo</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Exploits Encontrados</CardTitle>
              <Database className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{totalExploits}</div>
              <p className="text-xs text-muted-foreground">Desde ExploitDB</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Sesiones Metasploit</CardTitle>
              <Skull className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">{activeSessions}</div>
              <p className="text-xs text-muted-foreground">Escaneos con acceso</p>
            </CardContent>
          </Card>

          <Card>
            <CardHeader className="flex flex-row items-center justify-between space-y-0 pb-2">
              <CardTitle className="text-sm font-medium">Objetivos Únicos</CardTitle>
              <Target className="h-4 w-4 text-muted-foreground" />
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold">
                {new Set(history.map((s) => s.target)).size}
              </div>
              <p className="text-xs text-muted-foreground">Dominios/IP distintos</p>
            </CardContent>
          </Card>
        </div>

        {/* Filtros Mejorados */}
        <Card className="mb-6">
          <CardContent className="pt-6">
            <div className="flex flex-col sm:flex-row gap-4">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 h-4 w-4 -translate-y-1/2 text-muted-foreground" />
                <Input
                  placeholder="Buscar por URL o ID de escaneo..."
                  value={searchTerm}
                  onChange={(e) => setSearchTerm(e.target.value)}
                  className="pl-10"
                />
              </div>
              <div className="flex gap-2">
                <Select value={gradeFilter} onValueChange={setGradeFilter}>
                  <SelectTrigger className="w-40">
                    <Filter className="mr-2 h-4 w-4" />
                    <SelectValue placeholder="Grado" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todos los grados</SelectItem>
                    <SelectItem value="A">A (Excelente)</SelectItem>
                    <SelectItem value="B">B (Bueno)</SelectItem>
                    <SelectItem value="C">C (Regular)</SelectItem>
                    <SelectItem value="D">D (Deficiente)</SelectItem>
                    <SelectItem value="F">F (Crítico)</SelectItem>
                  </SelectContent>
                </Select>

                <Select value={statusFilter} onValueChange={setStatusFilter}>
                  <SelectTrigger className="w-40">
                    <Activity className="mr-2 h-4 w-4" />
                    <SelectValue placeholder="Estado" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">Todos los estados</SelectItem>
                    <SelectItem value="completed">Completado</SelectItem>
                    <SelectItem value="running">En ejecución</SelectItem>
                    <SelectItem value="failed">Fallido</SelectItem>
                    <SelectItem value="cancelled">Cancelado</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Tabla de Historial */}
        <Card>
          <CardHeader>
            <CardTitle>Escaneos Recientes</CardTitle>
            <CardDescription>
              {filteredHistory.length} de {history.length} escaneos
              {totalExploits > 0 && ` • ${totalExploits} exploits públicos identificados`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {filteredHistory.length === 0 ? (
              <div className="flex flex-col items-center justify-center py-12 text-muted-foreground">
                <History className="h-12 w-12 mb-4" />
                <p className="text-lg font-medium">No hay escaneos que mostrar</p>
                <p className="text-sm">
                  {searchTerm || gradeFilter !== "all" || statusFilter !== "all"
                    ? "Intenta con otros filtros de búsqueda"
                    : "Realiza tu primer escaneo para ver el historial"}
                </p>
              </div>
            ) : (
              <Table>
                <TableHeader>
                  <TableRow>
                    <TableHead>Estado</TableHead>
                    <TableHead>Objetivo</TableHead>
                    <TableHead>Fecha</TableHead>
                    <TableHead>Duración</TableHead>
                    <TableHead>Vulnerabilidades</TableHead>
                    <TableHead>Exploits</TableHead>
                    <TableHead>Grado</TableHead>
                    <TableHead className="text-right">Acciones</TableHead>
                  </TableRow>
                </TableHeader>
                <TableBody>
                  {filteredHistory.map((scan) => (
                    <TableRow key={scan.id}>
                      <TableCell>{getStatusIcon(scan.status)}</TableCell>
                      <TableCell>
                        <div className="font-mono text-sm">{scan.target}</div>
                        <div className="text-xs text-muted-foreground">{scan.id.slice(-8)}</div>
                      </TableCell>
                      <TableCell className="text-muted-foreground">
                        {new Date(scan.date).toLocaleDateString("es-ES", {
                          day: "2-digit",
                          month: "short",
                          year: "numeric",
                          hour: "2-digit",
                          minute: "2-digit",
                        })}
                      </TableCell>
                      <TableCell className="text-muted-foreground">{scan.duration}</TableCell>
                      <TableCell>
                        <div className="flex gap-1">
                          {scan.vulnerabilities.critical > 0 && (
                            <Badge variant="destructive">{scan.vulnerabilities.critical} C</Badge>
                          )}
                          {scan.vulnerabilities.high > 0 && (
                            <Badge className="bg-orange-500">{scan.vulnerabilities.high} H</Badge>
                          )}
                          <Badge variant="secondary">{scan.vulnerabilities.total} total</Badge>
                        </div>
                      </TableCell>
                      <TableCell>
                        {scan.exploitCount > 0 ? (
                          <Badge className="bg-purple-500/10 text-purple-500 border-purple-500/20">
                            <Database className="mr-1 h-3 w-3" />
                            {scan.exploitCount}
                          </Badge>
                        ) : (
                          <span className="text-muted-foreground text-sm">-</span>
                        )}
                      </TableCell>
                      <TableCell>
                        <Badge className={getGradeColor(scan.grade)}>{scan.grade}</Badge>
                      </TableCell>
                      <TableCell className="text-right">
                        <Dialog>
                          <DialogTrigger asChild>
                            <Button variant="ghost" size="sm" onClick={() => setSelectedScan(scan)}>
                              <Eye className="mr-2 h-4 w-4" />
                              Ver
                            </Button>
                          </DialogTrigger>
                          <DialogContent className="max-w-4xl max-h-[90vh] overflow-y-auto">
                            <DialogHeader>
                              <DialogTitle>Detalles del Escaneo</DialogTitle>
                              <DialogDescription>
                                {scan.target} • {scan.id}
                              </DialogDescription>
                            </DialogHeader>
                            
                            <Tabs defaultValue="tools" className="mt-4">
                              <TabsList className="grid w-full grid-cols-4">
                                <TabsTrigger value="tools">Herramientas</TabsTrigger>
                                <TabsTrigger value="vulnerabilities">Vulnerabilidades</TabsTrigger>
                                <TabsTrigger value="exploits">Exploits</TabsTrigger>
                                <TabsTrigger value="reports">Reportes</TabsTrigger>
                              </TabsList>

                              <TabsContent value="tools" className="space-y-4">
                                <div className="grid gap-4">
                                  {scan.tools.map((tool, idx) => (
                                    <Card key={idx}>
                                      <CardContent className="flex items-center justify-between p-4">
                                        <div className="flex items-center gap-3">
                                          <div className="p-2 bg-muted rounded-lg">
                                            {tool.icon}
                                          </div>
                                          <div>
                                            <p className="font-medium">{tool.name}</p>
                                            <p className="text-sm text-muted-foreground">
                                              {tool.details}
                                            </p>
                                          </div>
                                        </div>
                                        <div className="flex items-center gap-4">
                                          <span className="text-sm text-muted-foreground">
                                            {tool.duration}
                                          </span>
                                          {getToolStatusBadge(tool.status)}
                                          {tool.findings !== undefined && (
                                            <Badge variant="outline">{tool.findings} hallazgos</Badge>
                                          )}
                                        </div>
                                      </CardContent>
                                    </Card>
                                  ))}
                                </div>
                              </TabsContent>

                              <TabsContent value="vulnerabilities">
                                <div className="space-y-4">
                                  <div className="grid grid-cols-5 gap-4">
                                    {Object.entries(scan.vulnerabilities)
                                      .filter(([key]) => key !== 'total')
                                      .map(([severity, count]) => (
                                        <Card key={severity}>
                                          <CardContent className="p-4 text-center">
                                            <p className="text-2xl font-bold capitalize">{count}</p>
                                            <p className="text-xs text-muted-foreground uppercase">{severity}</p>
                                          </CardContent>
                                        </Card>
                                      ))}
                                  </div>
                                  <Card>
                                    <CardHeader>
                                      <CardTitle>Score de Riesgo</CardTitle>
                                    </CardHeader>
                                    <CardContent>
                                      <div className="space-y-2">
                                        <div className="flex justify-between">
                                          <span>CVSS Score</span>
                                          <span className="font-bold">{scan.score}/10</span>
                                        </div>
                                        <Progress value={scan.score * 10} className="h-2" />
                                        <p className="text-sm text-muted-foreground">
                                          Basado en CVSS v3.1, EPSS y análisis de contexto
                                        </p>
                                      </div>
                                    </CardContent>
                                  </Card>
                                </div>
                              </TabsContent>

                              <TabsContent value="exploits">
                                {scan.exploitCount > 0 ? (
                                  <div className="space-y-4">
                                    <Card className="border-purple-500/20">
                                      <CardHeader>
                                        <CardTitle className="flex items-center gap-2">
                                          <Database className="h-5 w-5 text-purple-500" />
                                          Exploits Públicos Disponibles
                                        </CardTitle>
                                      </CardHeader>
                                      <CardContent>
                                        <p className="text-muted-foreground mb-4">
                                          Se encontraron {scan.exploitCount} exploits públicos para los servicios
                                          detectados en este objetivo.
                                        </p>
                                        {scan.hasMetasploitSession && (
                                          <div className="flex items-center gap-2 p-3 bg-emerald-500/10 rounded-lg border border-em

erald-500/20">
                                            <CheckCircle className="h-5 w-5 text-emerald-500" />
                                            <span className="text-sm">
                                              Validación con Metasploit completada (dry-run)
                                            </span>
                                          </div>
                                        )}
                                      </CardContent>
                                    </Card>
                                  </div>
                                ) : (
                                  <div className="text-center py-8 text-muted-foreground">
                                    <Shield className="h-12 w-12 mx-auto mb-4" />
                                    <p>No se encontraron exploits públicos para este objetivo</p>
                                  </div>
                                )}
                              </TabsContent>

                              <TabsContent value="reports">
                                <div className="grid gap-4">
                                  {scan.reportFormats.map((format) => (
                                    <Card key={format}>
                                      <CardContent className="flex items-center justify-between p-4">
                                        <div className="flex items-center gap-3">
                                          <FileText className="h-5 w-5 text-muted-foreground" />
                                          <div>
                                            <p className="font-medium uppercase">{format}</p>
                                            <p className="text-sm text-muted-foreground">
                                              Reporte completo en formato {format.toUpperCase()}
                                            </p>
                                          </div>
                                        </div>
                                        <Button
                                          size="sm"
                                          onClick={() => handleDownloadReport(scan.id, format)}
                                        >
                                          <Download className="mr-2 h-4 w-4" />
                                          Descargar
                                        </Button>
                                      </CardContent>
                                    </Card>
                                  ))}
                                </div>
                              </TabsContent>
                            </Tabs>
                          </DialogContent>
                        </Dialog>

                        <DropdownMenu>
                          <DropdownMenuTrigger asChild>
                            <Button variant="ghost" size="sm">
                              Acciones
                            </Button>
                          </DropdownMenuTrigger>
                          <DropdownMenuContent align="end">
                            <DropdownMenuItem onClick={() => handleDownloadReport(scan.id, 'html')}>
                              <Download className="mr-2 h-4 w-4" />
                              Descargar HTML
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleDownloadReport(scan.id, 'pdf')}>
                              <Download className="mr-2 h-4 w-4" />
                              Descargar PDF
                            </DropdownMenuItem>
                            <DropdownMenuItem onClick={() => handleDownloadReport(scan.id, 'json')}>
                              <Download className="mr-2 h-4 w-4" />
                              Descargar JSON
                            </DropdownMenuItem>
                            <DropdownMenuItem
                              className="text-destructive"
                              onClick={() => handleDeleteScan(scan.id)}
                            >
                              <Trash2 className="mr-2 h-4 w-4" />
                              Eliminar
                            </DropdownMenuItem>
                          </DropdownMenuContent>
                        </DropdownMenu>
                      </TableCell>
                    </TableRow>
                  ))}
                </TableBody>
              </Table>
            )}
          </CardContent>
        </Card>
      </main>
    </div>
  );
}