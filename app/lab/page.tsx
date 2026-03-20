"use client";

import { useState, useEffect, useCallback } from "react";
import {
  Play,
  Square,
  RefreshCw,
  CheckCircle2,
  XCircle,
  AlertCircle,
  ExternalLink,
  Terminal,
  Copy,
  Check,
  Trash2,
  Loader2,
  Shield,
  Target,
  BookOpen,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Alert, AlertDescription, AlertTitle } from "@/components/ui/alert";
import { Header } from "@/components/header";
import { Spinner } from "@/components/ui/spinner";
import { Progress } from "@/components/ui/progress";
import { toast } from "sonner";

interface LabApp {
  id: string;
  name: string;
  port: number;
  description: string;
  image: string;
  status: "running" | "stopped" | "starting" | "stopping" | "error" | "unknown";
  url: string;
  category: "owasp" | "training" | "practice";
  difficulty: "beginner" | "intermediate" | "advanced";
}

const labApps: LabApp[] = [
  {
    id: "juice-shop",
    name: "OWASP Juice Shop",
    port: 3001,
    description: "Aplicación moderna con más de 100 vulnerabilidades OWASP Top 10. Incluye desafíos CTF, scoreboard y retroalimentación en tiempo real.",
    image: "bkimminich/juice-shop",
    status: "unknown",
    url: "http://localhost:3001",
    category: "owasp",
    difficulty: "intermediate",
  },
  {
    id: "dvwa",
    name: "DVWA",
    port: 3002,
    description: "Damn Vulnerable Web Application. La clásica para aprender inyección SQL, XSS, CSRF, File Upload y más con 3 niveles de dificultad.",
    image: "vulnerables/web-dvwa",
    status: "unknown",
    url: "http://localhost:3002",
    category: "training",
    difficulty: "beginner",
  },
  {
    id: "webgoat",
    name: "WebGoat",
    port: 3003,
    description: "Tutoriales interactivos de OWASP con lecciones guiadas. Ideal para aprender paso a paso sobre vulnerabilidades web comunes.",
    image: "webgoat/webgoat",
    status: "unknown",
    url: "http://localhost:8080/WebGoat",
    category: "training",
    difficulty: "beginner",
  },
];

const dockerCommands = {
  setup: `# Configurar e iniciar laboratorio
git clone https://github.com/tu-repo/securescan-pro.git 
cd securescan-pro/docker/lab
docker-compose up -d`,
  start: `# Iniciar todas las aplicaciones
docker-compose up -d`,
  stop: `# Detener todas las aplicaciones
docker-compose down`,
  startOne: (id: string) => `# Iniciar ${id}
docker-compose up -d ${id}`,
  stopOne: (id: string) => `# Detener ${id}
docker-compose stop ${id}`,
  remove: (id: string) => `# Eliminar ${id}
docker-compose rm -f ${id}`,
  logs: (id: string) => `# Ver logs de ${id}
docker-compose logs -f ${id}`,
};

function CopyButton({ text, label }: { text: string; label?: string }) {
  const [copied, setCopied] = useState(false);

  const handleCopy = async () => {
    await navigator.clipboard.writeText(text);
    setCopied(true);
    toast.success(label ? `${label} copiado` : "Comando copiado");
    setTimeout(() => setCopied(false), 2000);
  };

  return (
    <Button
      variant="ghost"
      size="icon"
      className="h-8 w-8 text-muted-foreground hover:text-foreground"
      onClick={handleCopy}
    >
      {copied ? <Check className="h-4 w-4" /> : <Copy className="h-4 w-4" />}
    </Button>
  );
}

function StatusBadge({ status }: { status: LabApp["status"] }) {
  const variants = {
    running: { class: "bg-emerald-500/10 text-emerald-500 border-emerald-500/20", icon: CheckCircle2, label: "Ejecutando" },
    stopped: { class: "bg-slate-500/10 text-slate-500 border-slate-500/20", icon: Square, label: "Detenido" },
    starting: { class: "bg-amber-500/10 text-amber-500 border-amber-500/20", icon: Loader2, label: "Iniciando" },
    stopping: { class: "bg-orange-500/10 text-orange-500 border-orange-500/20", icon: Loader2, label: "Deteniendo" },
    error: { class: "bg-red-500/10 text-red-500 border-red-500/20", icon: XCircle, label: "Error" },
    unknown: { class: "bg-slate-500/10 text-slate-500 border-slate-500/20", icon: AlertCircle, label: "Desconocido" },
  };

  const { class: badgeClass, icon: Icon, label } = variants[status];

  return (
    <Badge variant="outline" className={badgeClass}>
      <Icon className={`mr-1 h-3 w-3 ${status === "starting" || status === "stopping" ? "animate-spin" : ""}`} />
      {label}
    </Badge>
  );
}

function DifficultyBadge({ level }: { level: LabApp["difficulty"] }) {
  const colors = {
    beginner: "bg-green-500/10 text-green-500 border-green-500/20",
    intermediate: "bg-yellow-500/10 text-yellow-500 border-yellow-500/20",
    advanced: "bg-red-500/10 text-red-500 border-red-500/20",
  };

  const labels = {
    beginner: "Principiante",
    intermediate: "Intermedio",
    advanced: "Avanzado",
  };

  return (
    <Badge variant="outline" className={colors[level]}>
      {labels[level]}
    </Badge>
  );
}

function CategoryBadge({ category }: { category: LabApp["category"] }) {
  const icons = {
    owasp: Shield,
    training: BookOpen,
    practice: Target,
  };

  const Icon = icons[category];
  const labels = {
    owasp: "OWASP",
    training: "Entrenamiento",
    practice: "Práctica",
  };

  return (
    <Badge variant="secondary" className="capitalize">
      <Icon className="mr-1 h-3 w-3" />
      {labels[category]}
    </Badge>
  );
}

export default function LabPage() {
  const [apps, setApps] = useState<LabApp[]>(labApps);
  const [isLoading, setIsLoading] = useState(false);
  const [actionInProgress, setActionInProgress] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);

  // Verificar estado real de los contenedores via API
  const checkStatus = useCallback(async () => {
    setIsLoading(true);
    setProgress(0);

    try {
      // Simulación de progreso
      const interval = setInterval(() => {
        setProgress(p => Math.min(p + 20, 80));
      }, 200);

      // En producción: llamada real al backend
      // const response = await fetch('/api/lab/status');
      // const data = await response.json();

      // Simulación de verificación
      await new Promise(r => setTimeout(r, 1000));

      clearInterval(interval);
      setProgress(100);

      // Simular estados variados para demo
      const updatedApps = apps.map((app, i) => ({
        ...app,
        status: i === 0 ? "running" : i === 1 ? "stopped" : "unknown" as LabApp["status"],
      }));

      setApps(updatedApps);
      toast.success("Estado actualizado");
    } catch (error) {
      toast.error("Error al verificar estado");
    } finally {
      setIsLoading(false);
      setTimeout(() => setProgress(0), 500);
    }
  }, [apps]);

  // Control de contenedores
  const controlContainer = async (appId: string, action: "start" | "stop" | "restart") => {
    setActionInProgress(`${action}-${appId}`);
    
    try {
      // Actualizar estado optimista
      setApps(prev => prev.map(app => 
        app.id === appId 
          ? { ...app, status: action === "start" ? "starting" : action === "stop" ? "stopping" : "starting" }
          : app
      ));

      // En producción: llamada real al backend
      // await fetch(`/api/lab/${appId}/${action}`, { method: 'POST' });

      // Simulación
      await new Promise(r => setTimeout(r, 2000));

      // Actualizar estado final
      setApps(prev => prev.map(app => 
        app.id === appId 
          ? { ...app, status: action === "start" || action === "restart" ? "running" : "stopped" }
          : app
      ));

      toast.success(`${appId} ${action === "start" ? "iniciado" : action === "stop" ? "detenido" : "reiniciado"}`);
    } catch (error) {
      toast.error(`Error al ${action} ${appId}`);
      setApps(prev => prev.map(app => 
        app.id === appId ? { ...app, status: "error" } : app
      ));
    } finally {
      setActionInProgress(null);
    }
  };

  // Iniciar todos los laboratorios
  const startAll = async () => {
    setIsLoading(true);
    setProgress(0);

    for (let i = 0; i < apps.length; i++) {
      await controlContainer(apps[i].id, "start");
      setProgress(((i + 1) / apps.length) * 100);
    }

    setIsLoading(false);
    setProgress(0);
    toast.success("Todos los laboratorios iniciados");
  };

  // Detener todos los laboratorios
  const stopAll = async () => {
    setIsLoading(true);
    
    for (const app of apps) {
      if (app.status === "running") {
        await controlContainer(app.id, "stop");
      }
    }

    setIsLoading(false);
    toast.success("Todos los laboratorios detenidos");
  };

  useEffect(() => {
    checkStatus();
    // Verificación periódica cada 30 segundos
    const interval = setInterval(checkStatus, 30000);
    return () => clearInterval(interval);
  }, []);

  const runningCount = apps.filter((app) => app.status === "running").length;
  const stoppedCount = apps.filter((app) => app.status === "stopped").length;

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 py-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold text-foreground mb-2">
            Laboratorio de Práctica
          </h1>
          <p className="text-muted-foreground max-w-2xl">
            Entorno controlado con aplicaciones intencionalmente vulnerables para practicar 
            técnicas de pentesting de forma segura y legal.
          </p>
        </div>

        {/* Alerta Ética */}
        <Alert className="mb-8 border-amber-500/50 bg-amber-500/10">
          <AlertCircle className="h-4 w-4 text-amber-500" />
          <AlertTitle className="text-amber-500">Uso Ético Obligatorio</AlertTitle>
          <AlertDescription className="text-amber-500/80">
            Estas aplicaciones contienen vulnerabilidades reales. Úsalas SOLO en este entorno 
            aislado. Nunca pruebes estas técnicas en sistemas sin autorización explícita.
          </AlertDescription>
        </Alert>

        {/* Controles Globales */}
        <Card className="mb-8 border-border bg-card">
          <CardHeader>
            <CardTitle className="text-foreground">Control del Laboratorio</CardTitle>
            <CardDescription className="text-muted-foreground">
              Gestiona todos los contenedores Docker desde aquí
            </CardDescription>
          </CardHeader>
          <CardContent>
            <div className="flex flex-wrap gap-3">
              <Button 
                onClick={startAll} 
                disabled={isLoading || runningCount === apps.length}
                className="bg-emerald-600 hover:bg-emerald-700"
              >
                <Play className="mr-2 h-4 w-4" />
                Iniciar Todo
              </Button>
              <Button 
                variant="outline" 
                onClick={stopAll}
                disabled={isLoading || runningCount === 0}
              >
                <Square className="mr-2 h-4 w-4" />
                Detener Todo
              </Button>
              <Button 
                variant="secondary" 
                onClick={checkStatus}
                disabled={isLoading}
              >
                {isLoading ? <Spinner className="mr-2 h-4 w-4" /> : <RefreshCw className="mr-2 h-4 w-4" />}
                Actualizar Estado
              </Button>
            </div>
            
            {progress > 0 && (
              <div className="mt-4">
                <Progress value={progress} className="h-2" />
                <p className="text-xs text-muted-foreground mt-1">
                  {progress < 100 ? "Procesando..." : "Completado"}
                </p>
              </div>
            )}
          </CardContent>
        </Card>

        {/* Estadísticas */}
        <div className="grid gap-4 md:grid-cols-4 mb-8">
          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Laboratorios
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-foreground">{apps.length}</div>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Ejecutando
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-emerald-500">{runningCount}</div>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Detenidos
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-slate-500">{stoppedCount}</div>
            </CardContent>
          </Card>
          <Card className="border-border bg-card">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm font-medium text-muted-foreground">
                Puerto Base
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="text-2xl font-bold text-primary">3001</div>
            </CardContent>
          </Card>
        </div>

        {/* Grid de Laboratorios */}
        <div className="grid gap-6 lg:grid-cols-3 mb-8">
          {apps.map((app) => (
            <Card key={app.id} className="border-border bg-card flex flex-col">
              <CardHeader>
                <div className="flex items-start justify-between mb-2">
                  <div className="flex items-center gap-3">
                    <div className="flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10 text-primary font-mono text-sm font-bold">
                      :{app.port}
                    </div>
                    <div>
                      <CardTitle className="text-foreground text-lg">{app.name}</CardTitle>
                      <CardDescription className="text-xs text-muted-foreground">
                        {app.image}
                      </CardDescription>
                    </div>
                  </div>
                </div>
                <div className="flex gap-2 flex-wrap">
                  <StatusBadge status={app.status} />
                  <DifficultyBadge level={app.difficulty} />
                  <CategoryBadge category={app.category} />
                </div>
              </CardHeader>
              
              <CardContent className="flex-1 flex flex-col">
                <p className="text-sm text-muted-foreground mb-4 flex-1">
                  {app.description}
                </p>

                {/* Controles individuales */}
                <div className="space-y-3">
                  <div className="flex gap-2">
                    {app.status !== "running" ? (
                      <Button 
                        size="sm" 
                        className="flex-1 bg-emerald-600 hover:bg-emerald-700"
                        onClick={() => controlContainer(app.id, "start")}
                        disabled={actionInProgress === `start-${app.id}` || actionInProgress === `stop-${app.id}`}
                      >
                        {actionInProgress === `start-${app.id}` ? (
                          <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                        ) : (
                          <Play className="mr-2 h-4 w-4" />
                        )}
                        Iniciar
                      </Button>
                    ) : (
                      <>
                        <Button 
                          size="sm" 
                          variant="outline"
                          className="flex-1"
                          onClick={() => controlContainer(app.id, "stop")}
                          disabled={actionInProgress === `stop-${app.id}`}
                        >
                          {actionInProgress === `stop-${app.id}` ? (
                            <Loader2 className="mr-2 h-4 w-4 animate-spin" />
                          ) : (
                            <Square className="mr-2 h-4 w-4" />
                          )}
                          Detener
                        </Button>
                        <Button
                          size="icon"
                          variant="outline"
                          onClick={() => controlContainer(app.id, "restart")}
                          disabled={actionInProgress === `restart-${app.id}`}
                        >
                          <RefreshCw className={`h-4 w-4 ${actionInProgress === `restart-${app.id}` ? "animate-spin" : ""}`} />
                        </Button>
                      </>
                    )}
                  </div>

                  {/* URL y Acceso */}
                  <div className="flex items-center justify-between p-2 rounded bg-secondary/50">
                    <code className="text-xs font-mono text-muted-foreground truncate">
                      {app.url}
                    </code>
                    {app.status === "running" ? (
                      <Button variant="ghost" size="sm" asChild className="h-7 px-2">
                        <a href={app.url} target="_blank" rel="noopener noreferrer">
                          <ExternalLink className="h-3 w-3 mr-1" />
                          Abrir
                        </a>
                      </Button>
                    ) : (
                      <span className="text-xs text-muted-foreground px-2">Offline</span>
                    )}
                  </div>

                  {/* Comando rápido */}
                  <div className="flex items-center justify-between p-2 rounded bg-secondary/30">
                    <span className="text-xs text-muted-foreground">Docker</span>
                    <CopyButton 
                      text={dockerCommands.logs(app.id).split("\n")[1]} 
                      label="Comando"
                    />
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {/* Comandos Docker */}
        <Card className="border-border bg-card">
          <CardHeader>
            <CardTitle className="flex items-center gap-2 text-foreground">
              <Terminal className="h-5 w-5 text-primary" />
              Comandos de Referencia
            </CardTitle>
            <CardDescription className="text-muted-foreground">
              Comandos útiles para gestionar el laboratorio manualmente
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            {[
              { key: "setup", label: "Configuración Inicial", cmd: dockerCommands.setup },
              { key: "start", label: "Iniciar Todo", cmd: dockerCommands.start },
              { key: "stop", label: "Detener Todo", cmd: dockerCommands.stop },
            ].map(({ key, label, cmd }) => (
              <div key={key} className="space-y-2">
                <div className="flex items-center justify-between">
                  <h4 className="text-sm font-medium text-foreground">{label}</h4>
                  <CopyButton text={cmd.split("\n").filter(l => !l.startsWith("#")).join("\n")} />
                </div>
                <pre className="overflow-x-auto rounded-lg bg-secondary p-3 text-xs">
                  <code className="text-muted-foreground">{cmd}</code>
                </pre>
              </div>
            ))}
          </CardContent>
        </Card>

        {/* Guía Rápida */}
        <Card className="mt-8 border-border bg-card">
          <CardHeader>
            <CardTitle className="text-foreground">Guía de Inicio Rápido</CardTitle>
          </CardHeader>
          <CardContent>
            <ol className="space-y-4 text-muted-foreground">
              {[
                { title: "Iniciar el laboratorio", desc: "Haz clic en 'Iniciar Todo' o inicia laboratorios individuales según necesites." },
                { title: "Esperar la inicialización", desc: "Los contenedores pueden tardar 30-60 segundos en estar listos." },
                { title: "Verificar estado", desc: "El indicador cambiará a 'Ejecutando' cuando esté listo." },
                { title: "Acceder a la aplicación", desc: "Haz clic en 'Abrir' o visita la URL directamente." },
                { title: "Iniciar escaneo", desc: "Ve al escáner y selecciona el laboratorio como objetivo." },
              ].map((step, i) => (
                <li key={i} className="flex gap-3">
                  <span className="flex h-6 w-6 shrink-0 items-center justify-center rounded-full bg-primary text-xs font-bold text-primary-foreground">
                    {i + 1}
                  </span>
                  <div>
                    <strong className="text-foreground">{step.title}</strong>
                    <p className="text-sm">{step.desc}</p>
                  </div>
                </li>
              ))}
            </ol>
          </CardContent>
        </Card>
      </main>
    </div>
  );
}