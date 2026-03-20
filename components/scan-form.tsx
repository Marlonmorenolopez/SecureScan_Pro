import { useState } from "react";
import { 
  Globe, 
  Play, 
  Settings2, 
  AlertTriangle, 
  ChevronDown, 
  Layers, 
  Network, 
  Search, 
  Zap, 
  Database, 
  Skull,
  Shield,
  Clock,
  Target,
  CheckCircle2,
  Info
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Checkbox } from "@/components/ui/checkbox";
import { Label } from "@/components/ui/label";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { useScan, ScanOptions } from "@/lib/scan-context";
import { Spinner } from "@/components/ui/spinner";

// LABORATORIOS ACTUALIZADOS - Solo 3: Juice Shop, DVWA, WebGoat
const labTargets = [
  { 
    name: "Juice Shop", 
    url: "http://localhost:3001", 
    description: "Tienda moderna con vulnerabilidades OWASP Top 10",
    difficulty: "Principiante-Avanzado",
    icon: Target
  },
  { 
    name: "DVWA", 
    url: "http://localhost:3002", 
    description: "Damn Vulnerable Web Application - SQLi, XSS, CSRF",
    difficulty: "Principiante",
    icon: Shield
  },
  { 
    name: "WebGoat", 
    url: "http://localhost:3003", 
    description: "Tutoriales interactivos de seguridad OWASP",
    difficulty: "Intermedio",
    icon: Info
  },
];

// CONFIGURACIÓN DE HERRAMIENTAS ACTUALIZADA
interface ToolConfig {
  id: keyof ScanOptions["tools"];
  name: string;
  description: string;
  icon: React.ElementType;
  category: "recon" | "scanning" | "exploitation" | "intelligence";
  new?: boolean;
  updated?: boolean;
  replaces?: string;
}

const toolsConfig: ToolConfig[] = [
  {
    id: "whatweb",
    name: "WhatWeb",
    description: "Fingerprinting de tecnologías web (reemplaza Wappalyzer)",
    icon: Layers,
    category: "recon",
    new: true,
    replaces: "Wappalyzer"
  },
  {
    id: "nmap",
    name: "Nmap",
    description: "Escaneo de puertos, servicios y detección de OS",
    icon: Network,
    category: "scanning"
  },
  {
    id: "gobuster",
    name: "Gobuster",
    description: "Fuerza bruta de directorios, DNS y virtual hosts",
    icon: Search,
    category: "scanning"
  },
  {
    id: "zap",
    name: "OWASP ZAP",
    description: "DAST completo con Spider, Active Scan y AJAX (reemplaza Nikto)",
    icon: Zap,
    category: "scanning",
    updated: true,
    replaces: "Nikto"
  },
  {
    id: "exploitdb",
    name: "ExploitDB",
    description: "Inteligencia de exploits unificada con CVSS/EPSS",
    icon: Database,
    category: "intelligence",
    new: true
  },
  {
    id: "metasploit",
    name: "Metasploit",
    description: "Validación controlada de vulnerabilidades críticas",
    icon: Skull,
    category: "exploitation",
    new: true
  }
];

// Perfiles de intensidad mejorados
const intensityProfiles = [
  {
    value: "light",
    label: "Ligero",
    description: "Reconocimiento rápido - 2-5 minutos",
    tools: ["whatweb", "nmap", "zap"],
    timing: "T4",
    threads: 50
  },
  {
    value: "normal",
    label: "Normal",
    description: "Balance velocidad/cobertura - 10-15 minutos",
    tools: ["whatweb", "nmap", "gobuster", "zap", "exploitdb"],
    timing: "T3",
    threads: 100
  },
  {
    value: "aggressive",
    label: "Agresivo",
    description: "Escaneo completo - 20-30 minutos",
    tools: ["whatweb", "nmap", "gobuster", "zap", "exploitdb", "metasploit"],
    timing: "T3",
    threads: 150
  },
  {
    value: "comprehensive",
    label: "Completo (Pentest)",
    description: "Análisis exhaustivo con validación - 30-60 minutos",
    tools: ["whatweb", "nmap", "gobuster", "zap", "exploitdb", "metasploit"],
    timing: "T2",
    threads: 100,
    fullNmap: true
  }
] as const;

export function ScanForm() {
  const { startScan, isScanning } = useScan();
  const [target, setTarget] = useState("");
  const [showAdvanced, setShowAdvanced] = useState(false);
  const [selectedProfile, setSelectedProfile] = useState<string>("normal");
  
  // Estado inicial con nuevas herramientas
  const [options, setOptions] = useState<ScanOptions>({
    tools: {
      whatweb: true,
      nmap: true,
      gobuster: true,
      zap: true,
      exploitdb: true,
      metasploit: false, // Deshabilitado por defecto por seguridad
    },
    intensity: "normal",
    timeout: 1800, // 30 minutos default
  });

  // Aplicar perfil de escaneo
  const applyProfile = (profileValue: string) => {
    const profile = intensityProfiles.find(p => p.value === profileValue);
    if (!profile) return;

    setSelectedProfile(profileValue);
    setOptions(prev => ({
      ...prev,
      intensity: profileValue as ScanOptions["intensity"],
      tools: {
        whatweb: profile.tools.includes("whatweb"),
        nmap: profile.tools.includes("nmap"),
        gobuster: profile.tools.includes("gobuster"),
        zap: profile.tools.includes("zap"),
        exploitdb: profile.tools.includes("exploitdb"),
        metasploit: profile.tools.includes("metasploit"),
      }
    }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!target.trim()) return;
    
    // Validación adicional de seguridad
    if (options.tools.metasploit && !target.includes("localhost")) {
      const confirmed = window.confirm(
        "⚠️ ADVERTENCIA: Has habilitado Metasploit para un target externo. " +
        "Esto ejecutará exploits reales. ¿Estás seguro de que tienes autorización explícita?"
      );
      if (!confirmed) return;
    }
    
    await startScan(target, options);
  };

  const handleToolToggle = (tool: keyof ScanOptions["tools"]) => {
    setOptions((prev) => ({
      ...prev,
      tools: {
        ...prev.tools,
        [tool]: !prev.tools[tool],
      },
    }));
    // Resetear perfil personalizado
    setSelectedProfile("custom");
  };

  const handleQuickTarget = (url: string) => {
    setTarget(url);
  };

  const isValidTarget = (value: string) => {
    if (!value) return true;
    try {
      new URL(value);
      return true;
    } catch {
      // Permitir localhost:puerto y dominios simples
      return /^(localhost:\d+|[a-zA-Z0-9][a-zA-Z0-9-_.]*\.[a-zA-Z]{2,})$/.test(value);
    }
  };

  const getActiveToolsCount = () => {
    return Object.values(options.tools).filter(Boolean).length;
  };

  const getEstimatedTime = () => {
    const profile = intensityProfiles.find(p => p.value === selectedProfile);
    if (profile) return profile.description.match(/\d+-\d+ minutos?/)?.[0] || "10-15 minutos";
    return "Variable";
  };

  return (
    <TooltipProvider>
      <Card className="border-border bg-card shadow-lg">
        <CardHeader className="space-y-1">
          <div className="flex items-center justify-between">
            <CardTitle className="flex items-center gap-2 text-foreground text-xl">
              <Globe className="h-6 w-6 text-primary" />
              Iniciar Análisis de Seguridad v2.1
            </CardTitle>
            <Badge variant="outline" className="text-xs">
              {getActiveToolsCount()} herramientas activas
            </Badge>
          </div>
          <CardDescription className="text-muted-foreground">
            Orquestación automática: WhatWeb → Nmap → Gobuster → ZAP → ExploitDB → Metasploit
          </CardDescription>
        </CardHeader>
        
        <CardContent className="space-y-6">
          {/* Alerta Legal Mejorada */}
          <Alert className="border-warning/50 bg-warning/10 relative overflow-hidden">
            <div className="absolute inset-0 bg-warning/5 animate-pulse" />
            <AlertTriangle className="h-5 w-5 text-warning relative z-10" />
            <AlertTitle className="text-warning font-semibold relative z-10">
              ⚠️ Aviso Legal y Ético
            </AlertTitle>
            <AlertDescription className="text-warning/90 text-sm relative z-10">
              Solo escanea sistemas con <strong>autorización explícita por escrito</strong>. 
              El uso no autorizado viola leyes de ciberseguridad (Ley 1273 de 2009 en Colombia) 
              y puede resultar en sanciones legales severas.
            </AlertDescription>
          </Alert>

          <form onSubmit={handleSubmit} className="space-y-6">
            {/* Target Input Mejorado */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <Label htmlFor="target" className="text-foreground font-medium">
                  URL o Dominio Objetivo
                </Label>
                <Tooltip>
                  <TooltipTrigger asChild>
                    <Info className="h-4 w-4 text-muted-foreground cursor-help" />
                  </TooltipTrigger>
                  <TooltipContent>
                    <p className="max-w-xs text-xs">
                      Soporta: https://ejemplo.com, localhost:3001, 192.168.1.1
                    </p>
                  </TooltipContent>
                </Tooltip>
              </div>
              
              <div className="flex gap-2">
                <Input
                  id="target"
                  type="text"
                  placeholder="https://ejemplo.com o localhost:3001"
                  value={target}
                  onChange={(e) => setTarget(e.target.value)}
                  className={`flex-1 bg-input border-border text-foreground placeholder:text-muted-foreground h-11 ${
                    !isValidTarget(target) && target ? "border-destructive focus-visible:ring-destructive" : ""
                  }`}
                  disabled={isScanning}
                />
                <Button
                  type="submit"
                  disabled={isScanning || !target.trim() || !isValidTarget(target)}
                  className="bg-primary text-primary-foreground hover:bg-primary/90 h-11 px-6"
                  size="lg"
                >
                  {isScanning ? (
                    <>
                      <Spinner className="mr-2 h-4 w-4 animate-spin" />
                      <span className="hidden sm:inline">Escaneando...</span>
                      <span className="sm:hidden">...</span>
                    </>
                  ) : (
                    <>
                      <Play className="mr-2 h-4 w-4" />
                      <span className="hidden sm:inline">Iniciar Escaneo</span>
                      <span className="sm:hidden">Escanear</span>
                    </>
                  )}
                </Button>
              </div>
              
              {!isValidTarget(target) && target && (
                <p className="text-sm text-destructive flex items-center gap-1">
                  <AlertTriangle className="h-3 w-3" />
                  URL o dominio inválido. Ejemplos válidos: https://site.com, localhost:3001
                </p>
              )}
            </div>

            {/* Laboratorios Mejorados */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <Label className="text-sm font-medium text-foreground">
                  Laboratorios de Práctica (Docker)
                </Label>
                <span className="text-xs text-muted-foreground">
                  Click para seleccionar
                </span>
              </div>
              
              <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
                {labTargets.map((lab) => {
                  const Icon = lab.icon;
                  const isSelected = target === lab.url;
                  
                  return (
                    <Tooltip key={lab.url}>
                      <TooltipTrigger asChild>
                        <Button
                          type="button"
                          variant="outline"
                          className={`h-auto py-4 px-4 justify-start text-left border-2 transition-all ${
                            isSelected 
                              ? "border-primary bg-primary/10 shadow-md" 
                              : "border-border hover:border-primary/50 hover:bg-primary/5"
                          }`}
                          onClick={() => handleQuickTarget(lab.url)}
                          disabled={isScanning}
                        >
                          <div className="flex items-start gap-3 w-full">
                            <div className={`p-2 rounded-lg ${isSelected ? "bg-primary text-primary-foreground" : "bg-secondary text-muted-foreground"}`}>
                              <Icon className="h-4 w-4" />
                            </div>
                            <div className="flex-1 min-w-0">
                              <div className="font-semibold text-foreground text-sm truncate">
                                {lab.name}
                              </div>
                              <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                                {lab.description}
                              </div>
                              <Badge variant="secondary" className="mt-2 text-[10px]">
                                {lab.difficulty}
                              </Badge>
                            </div>
                            {isSelected && (
                              <CheckCircle2 className="h-4 w-4 text-primary shrink-0" />
                            )}
                          </div>
                        </Button>
                      </TooltipTrigger>
                      <TooltipContent side="bottom">
                        <p className="text-xs">Puerto: {lab.url.split(":")[2]}</p>
                      </TooltipContent>
                    </Tooltip>
                  );
                })}
              </div>
            </div>

            {/* Perfiles de Escaneo Rápido */}
            <div className="space-y-3">
              <Label className="text-sm font-medium text-foreground">
                Perfil de Escaneo Rápido
              </Label>
              <div className="grid grid-cols-2 lg:grid-cols-4 gap-2">
                {intensityProfiles.map((profile) => (
                  <Button
                    key={profile.value}
                    type="button"
                    variant={selectedProfile === profile.value ? "default" : "outline"}
                    size="sm"
                    className={`h-auto py-2 px-3 text-xs justify-start flex-col items-start ${
                      selectedProfile === profile.value 
                        ? "bg-primary text-primary-foreground" 
                        : "border-border hover:border-primary/50"
                    }`}
                    onClick={() => applyProfile(profile.value)}
                    disabled={isScanning}
                  >
                    <span className="font-semibold">{profile.label}</span>
                    <span className="text-[10px] opacity-80 font-normal truncate w-full">
                      {profile.description}
                    </span>
                  </Button>
                ))}
              </div>
              
              <div className="flex items-center gap-4 text-xs text-muted-foreground bg-secondary/50 p-2 rounded-lg">
                <div className="flex items-center gap-1">
                  <Clock className="h-3 w-3" />
                  Tiempo estimado: <span className="font-medium text-foreground">{getEstimatedTime()}</span>
                </div>
                <div className="h-3 w-px bg-border" />
                <div className="flex items-center gap-1">
                  <Target className="h-3 w-3" />
                  Intensidad: <span className="font-medium text-foreground uppercase">{options.intensity}</span>
                </div>
              </div>
            </div>

            {/* Opciones Avanzadas Mejoradas */}
            <Collapsible open={showAdvanced} onOpenChange={setShowAdvanced}>
              <CollapsibleTrigger asChild>
                <Button
                  type="button"
                  variant="ghost"
                  className="w-full justify-between text-muted-foreground hover:text-foreground border border-dashed border-border hover:border-primary/50 py-3"
                >
                  <span className="flex items-center gap-2">
                    <Settings2 className="h-4 w-4" />
                    Configuración Avanzada de Herramientas
                  </span>
                  <ChevronDown
                    className={`h-4 w-4 transition-transform duration-200 ${
                      showAdvanced ? "rotate-180" : ""
                    }`}
                  />
                </Button>
              </CollapsibleTrigger>
              
              <CollapsibleContent className="space-y-6 pt-4 animate-in slide-in-from-top-2">
                
                {/* Herramientas por Categoría */}
                <div className="space-y-4">
                  {["recon", "scanning", "intelligence", "exploitation"].map((category) => {
                    const categoryTools = toolsConfig.filter(t => t.category === category);
                    const categoryLabels = {
                      recon: "🔍 Reconocimiento",
                      scanning: "🌐 Escaneo",
                      intelligence: "🧠 Inteligencia",
                      exploitation: "⚔️ Explotación (Cuidado)"
                    };
                    
                    return (
                      <div key={category} className="space-y-3">
                        <Label className="text-xs font-bold text-muted-foreground uppercase tracking-wider">
                          {categoryLabels[category as keyof typeof categoryLabels]}
                        </Label>
                        <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                          {categoryTools.map((tool) => {
                            const Icon = tool.icon;
                            const isEnabled = options.tools[tool.id];
                            
                            return (
                              <Tooltip key={tool.id}>
                                <TooltipTrigger asChild>
                                  <div 
                                    className={`flex items-start gap-3 p-3 rounded-lg border-2 transition-all cursor-pointer ${
                                      isEnabled 
                                        ? "border-primary bg-primary/5" 
                                        : "border-border bg-card hover:border-primary/30"
                                    } ${isScanning ? "opacity-50 cursor-not-allowed" : ""}`}
                                    onClick={() => !isScanning && handleToolToggle(tool.id)}
                                  >
                                    <Checkbox
                                      id={tool.id}
                                      checked={isEnabled}
                                      disabled={isScanning}
                                      className="mt-0.5 data-[state=checked]:bg-primary data-[state=checked]:border-primary"
                                    />
                                    <div className="flex-1 min-w-0">
                                      <div className="flex items-center gap-2 flex-wrap">
                                        <Icon className={`h-4 w-4 ${isEnabled ? "text-primary" : "text-muted-foreground"}`} />
                                        <Label
                                          htmlFor={tool.id}
                                          className="text-sm font-semibold text-foreground cursor-pointer"
                                        >
                                          {tool.name}
                                        </Label>
                                        {tool.new && (
                                          <Badge className="bg-green-100 text-green-700 text-[10px] px-1.5 py-0">
                                            NUEVO
                                          </Badge>
                                        )}
                                        {tool.updated && (
                                          <Badge className="bg-blue-100 text-blue-700 text-[10px] px-1.5 py-0">
                                            ACT
                                          </Badge>
                                        )}
                                      </div>
                                      <p className="text-xs text-muted-foreground mt-1 leading-relaxed">
                                        {tool.description}
                                      </p>
                                      {tool.replaces && (
                                        <p className="text-[10px] text-primary/70 mt-1">
                                          Reemplaza: {tool.replaces}
                                        </p>
                                      )}
                                    </div>
                                  </div>
                                </TooltipTrigger>
                                <TooltipContent side="right" className="max-w-xs">
                                  <p className="text-xs">{tool.description}</p>
                                </TooltipContent>
                              </Tooltip>
                            );
                          })}
                        </div>
                      </div>
                    );
                  })}
                </div>

                {/* Timeout Config */}
                <div className="space-y-2 pt-4 border-t border-border">
                  <Label htmlFor="timeout" className="text-foreground text-sm">
                    Timeout Total del Escaneo
                  </Label>
                  <Select
                    value={options.timeout?.toString()}
                    onValueChange={(value) =>
                      setOptions((prev) => ({ ...prev, timeout: parseInt(value) }))
                    }
                    disabled={isScanning}
                  >
                    <SelectTrigger id="timeout" className="w-full sm:w-64 bg-input border-border">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="300">5 minutos (rápido)</SelectItem>
                      <SelectItem value="900">15 minutos</SelectItem>
                      <SelectItem value="1800">30 minutos (recomendado)</SelectItem>
                      <SelectItem value="3600">1 hora (completo)</SelectItem>
                      <SelectItem value="7200">2 horas (máximo)</SelectItem>
                    </SelectContent>
                  </Select>
                </div>

                {/* Resumen de Configuración */}
                <div className="bg-secondary/30 rounded-lg p-4 space-y-2">
                  <h4 className="text-sm font-semibold text-foreground">Resumen del Escaneo</h4>
                  <div className="text-xs text-muted-foreground space-y-1">
                    <p>• Secuencia: {Object.entries(options.tools)
                      .filter(([,v]) => v)
                      .map(([k]) => toolsConfig.find(t => t.id === k)?.name)
                      .join(" → ")}</p>
                    <p>• Intensidad: {options.intensity} ({intensityProfiles.find(p => p.value === options.intensity)?.timing})</p>
                    <p>• Timeout: {Math.floor((options.timeout || 1800) / 60)} minutos</p>
                    {options.tools.metasploit && (
                      <p className="text-orange-600 font-medium">⚠️ Metasploit habilitado - Se ejecutarán exploits reales</p>
                    )}
                  </div>
                </div>
              </CollapsibleContent>
            </Collapsible>
          </form>
        </CardContent>
      </Card>
    </TooltipProvider>
  );
}