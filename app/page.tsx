import {
  Shield,
  Scan,
  FileText,
  Server,
  Bug,
  Code2,
  ChevronRight,
  Terminal,
  Lock,
  Zap,
  Target,
  Activity,
  Layers,
  Database,
  Skull,
  Search,
  Globe,
  Network,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Header } from "@/components/header";
import Link from "next/link";

const features = [
  {
    icon: Scan,
    title: "Escaneo Automatizado",
    description:
      "Ejecuta múltiples herramientas de seguridad de forma orquestada y automática con un solo click. Secuencia optimizada: WhatWeb → Nmap → Gobuster → ZAP → ExploitDB.",
  },
  {
    icon: Bug,
    title: "Detección de Vulnerabilidades",
    description:
      "Identifica vulnerabilidades web usando OWASP ZAP (reemplaza a Nikto) y correlación automática con Exploit-DB para validación de exploits disponibles.",
  },
  {
    icon: Server,
    title: "Reconocimiento de Infraestructura",
    description:
      "Descubre puertos, servicios, versiones y sistemas operativos con Nmap + scripts NSE para detección de CVEs.",
  },
  {
    icon: Code2,
    title: "Fingerprinting de Tecnologías",
    description:
      "Detecta el stack tecnológico completo usando WhatWeb (reemplaza a Wappalyzer) con 1,800+ plugins de detección y análisis de riesgo por versión.",
  },
  {
    icon: Database,
    title: "Inteligencia de Exploits",
    description:
      "Búsqueda unificada en ExploitDB con enriquecimiento de CVSS desde NVD y cálculo de probabilidad de explotación (EPSS).",
  },
  {
    icon: FileText,
    title: "Reportes Profesionales",
    description:
      "Genera informes detallados tipo pentest con scoring CVSS v3.1/v4.0, EPSS, SSVC, priorización automática y recomendaciones de remediación.",
  },
  {
    icon: Skull,
    title: "Validación de Explotación",
    description:
      "Integración con Metasploit para confirmación controlada de vulnerabilidades críticas (modo dry-run disponible).",
  },
  {
    icon: Target,
    title: "Laboratorio Integrado",
    description:
      "Practica de forma segura con aplicaciones vulnerables preconfiguradas vía Docker.",
  },
];

// HERRAMIENTAS ACTUALIZADAS - Eliminadas: Nikto, Wappalyzer, Searchsploit (individual)
// Agregadas: WhatWeb, ExploitDB Unified, Metasploit, ZAP mejorado
const tools = [
  {
    name: "WhatWeb",
    description: "Fingerprinting de tecnologías web (reemplaza Wappalyzer)",
    color: "bg-blue-500",
    icon: Layers,
    new: true,
  },
  {
    name: "Nmap",
    description: "Escaneo de puertos, servicios y detección de OS",
    color: "bg-cyan-500",
    icon: Network,
  },
  {
    name: "Gobuster",
    description: "Fuerza bruta de directorios, DNS y virtual hosts",
    color: "bg-purple-500",
    icon: Search,
  },
  {
    name: "OWASP ZAP",
    description: "DAST completo - Spider, Active Scan, AJAX (reemplaza Nikto)",
    color: "bg-blue-600",
    icon: Zap,
    updated: true,
  },
  {
    name: "ExploitDB",
    description: "Inteligencia de exploits unificada con CVSS/EPSS",
    color: "bg-red-500",
    icon: Database,
    new: true,
  },
  {
    name: "Metasploit",
    description: "Validación controlada de exploits",
    color: "bg-orange-500",
    icon: Skull,
    new: true,
  },
];

const workflowSteps = [
  {
    step: 1,
    title: "Reconocimiento",
    desc: "WhatWeb detecta tecnologías",
    icon: Layers,
    tools: ["WhatWeb"],
  },
  {
    step: 2,
    title: "Infraestructura",
    desc: "Nmap escanea puertos y servicios",
    icon: Network,
    tools: ["Nmap"],
  },
  {
    step: 3,
    title: "Contenido",
    desc: "Gobuster descubre recursos ocultos",
    icon: Search,
    tools: ["Gobuster"],
  },
  {
    step: 4,
    title: "Vulnerabilidades",
    desc: "ZAP analiza seguridad web",
    icon: Zap,
    tools: ["OWASP ZAP"],
  },
  {
    step: 5,
    title: "Inteligencia",
    desc: "ExploitDB busca exploits",
    icon: Database,
    tools: ["ExploitDB"],
  },
  {
    step: 6,
    title: "Validación",
    desc: "Metasploit confirma (opcional)",
    icon: Skull,
    tools: ["Metasploit"],
  },
  {
    step: 7,
    title: "Reporte",
    desc: "Scoring y generación de informe",
    icon: FileText,
    tools: ["CVSS/EPSS/SSVC"],
  },
];

// LABORATORIOS ACTUALIZADOS - Solo 3: Juice Shop, DVWA, WebGoat
const labApps = [
  { 
    name: "OWASP Juice Shop", 
    port: 3001, 
    desc: "Aplicación moderna con vulnerabilidades OWASP Top 10 - Ideal para principiantes y avanzados" 
  },
  { 
    name: "DVWA", 
    port: 3002, 
    desc: "Damn Vulnerable Web Application - Clásica para practicar SQLi, XSS, CSRF y más" 
  },
  { 
    name: "WebGoat", 
    port: 3003, 
    desc: "Tutoriales interactivos de seguridad OWASP con lecciones guiadas" 
  },
];

export default function HomePage() {
  return (
    <div className="min-h-screen bg-background">
      <Header />

      {/* Hero Section */}
      <section className="relative overflow-hidden border-b border-border">
        <div className="absolute inset-0 bg-gradient-to-br from-primary/5 via-transparent to-accent/5" />
        <div className="container relative mx-auto px-4 py-24 md:py-32">
          <div className="mx-auto max-w-3xl text-center">
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-primary/30 bg-primary/10 px-4 py-2 text-sm text-primary">
              <Lock className="h-4 w-4" />
              Plataforma de Análisis de Seguridad v2.1
            </div>
            <h1 className="mb-6 text-4xl font-bold tracking-tight text-foreground md:text-6xl text-balance">
              Automatiza tu{" "}
              <span className="text-primary">Análisis de Seguridad</span>{" "}
              Web
            </h1>
            <p className="mb-8 text-lg text-muted-foreground md:text-xl text-pretty">
              Plataforma integral que orquesta herramientas profesionales de ciberseguridad:
              WhatWeb, Nmap, Gobuster, OWASP ZAP, ExploitDB y Metasploit. 
              Consolida resultados con scoring CVSS/EPSS y genera reportes tipo pentest.
            </p>
            <div className="flex flex-col gap-4 sm:flex-row sm:justify-center">
              <Button
                asChild
                size="lg"
                className="bg-primary text-primary-foreground hover:bg-primary/90"
              >
                <Link href="/scanner">
                  <Scan className="mr-2 h-5 w-5" />
                  Iniciar Escaneo
                </Link>
              </Button>
              <Button asChild variant="outline" size="lg" className="border-border">
                <Link href="/docs">
                  <FileText className="mr-2 h-5 w-5" />
                  Ver Documentación
                </Link>
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Features Section */}
      <section className="py-20 md:py-28">
        <div className="container mx-auto px-4">
          <div className="mx-auto mb-16 max-w-2xl text-center">
            <h2 className="mb-4 text-3xl font-bold text-foreground md:text-4xl">
              Funcionalidades Principales
            </h2>
            <p className="text-muted-foreground">
              Arquitectura actualizada con las mejores herramientas de ciberseguridad
            </p>
          </div>
          <div className="grid gap-6 md:grid-cols-2 lg:grid-cols-4">
            {features.map((feature) => (
              <Card
                key={feature.title}
                className="group border-border bg-card transition-all hover:border-primary/50 hover:shadow-lg hover:shadow-primary/5"
              >
                <CardHeader>
                  <div className="mb-2 flex h-12 w-12 items-center justify-center rounded-lg bg-primary/10 text-primary transition-colors group-hover:bg-primary group-hover:text-primary-foreground">
                    <feature.icon className="h-6 w-6" />
                  </div>
                  <CardTitle className="text-foreground text-lg">{feature.title}</CardTitle>
                </CardHeader>
                <CardContent>
                  <CardDescription className="text-muted-foreground text-sm">
                    {feature.description}
                  </CardDescription>
                </CardContent>
              </Card>
            ))}
          </div>
        </div>
      </section>

      {/* Tools Section - ACTUALIZADA */}
      <section className="border-y border-border bg-secondary/30 py-20 md:py-28">
        <div className="container mx-auto px-4">
          <div className="mx-auto mb-16 max-w-2xl text-center">
            <h2 className="mb-4 text-3xl font-bold text-foreground md:text-4xl">
              Stack de Herramientas v2.1
            </h2>
            <p className="text-muted-foreground">
              Herramientas actualizadas y optimizadas para máxima eficiencia
            </p>
            <div className="mt-4 flex flex-wrap justify-center gap-2">
              <span className="inline-flex items-center gap-1 rounded-full bg-green-100 px-3 py-1 text-xs font-medium text-green-700">
                <Layers className="h-3 w-3" /> WhatWeb → Reemplaza Wappalyzer
              </span>
              <span className="inline-flex items-center gap-1 rounded-full bg-blue-100 px-3 py-1 text-xs font-medium text-blue-700">
                <Zap className="h-3 w-3" /> ZAP Mejorado → Reemplaza Nikto
              </span>
              <span className="inline-flex items-center gap-1 rounded-full bg-purple-100 px-3 py-1 text-xs font-medium text-purple-700">
                <Database className="h-3 w-3" /> ExploitDB Unified
              </span>
            </div>
          </div>
          <div className="grid gap-4 sm:grid-cols-2 lg:grid-cols-3">
            {tools.map((tool) => (
              <div
                key={tool.name}
                className="group flex items-center gap-4 rounded-lg border border-border bg-card p-4 transition-all hover:border-primary/50 hover:shadow-md"
              >
                <div
                  className={`flex h-12 w-12 items-center justify-center rounded-lg ${tool.color} text-white transition-transform group-hover:scale-110`}
                >
                  <tool.icon className="h-6 w-6" />
                </div>
                <div className="flex-1">
                  <div className="flex items-center gap-2">
                    <h3 className="font-semibold text-foreground">{tool.name}</h3>
                    {tool.new && (
                      <span className="rounded-full bg-green-100 px-2 py-0.5 text-xs font-medium text-green-700">
                        NUEVO
                      </span>
                    )}
                    {tool.updated && (
                      <span className="rounded-full bg-blue-100 px-2 py-0.5 text-xs font-medium text-blue-700">
                        ACTUALIZADO
                      </span>
                    )}
                  </div>
                  <p className="text-sm text-muted-foreground">{tool.description}</p>
                </div>
              </div>
            ))}
          </div>
        </div>
      </section>

      {/* Workflow Section - ACTUALIZADA con 7 pasos */}
      <section className="py-20 md:py-28">
        <div className="container mx-auto px-4">
          <div className="mx-auto mb-16 max-w-2xl text-center">
            <h2 className="mb-4 text-3xl font-bold text-foreground md:text-4xl">
              Flujo de Escaneo Automatizado
            </h2>
            <p className="text-muted-foreground">
              Secuencia optimizada de 7 fases con orquestación inteligente
            </p>
          </div>
          <div className="mx-auto max-w-6xl">
            <div className="grid gap-6 md:grid-cols-7">
              {workflowSteps.map((item, index) => (
                <div key={item.step} className="relative text-center">
                  {index < 6 && (
                    <div className="absolute left-1/2 top-8 hidden h-0.5 w-full bg-gradient-to-r from-border to-primary/30 md:block" />
                  )}
                  <div className="relative mx-auto mb-4 flex h-14 w-14 items-center justify-center rounded-full border-2 border-primary bg-card text-primary shadow-sm">
                    <item.icon className="h-6 w-6" />
                    <span className="absolute -right-1 -top-1 flex h-5 w-5 items-center justify-center rounded-full bg-primary text-xs font-bold text-primary-foreground">
                      {item.step}
                    </span>
                  </div>
                  <h3 className="mb-1 font-semibold text-foreground text-sm">{item.title}</h3>
                  <p className="text-xs text-muted-foreground mb-2">{item.desc}</p>
                  <div className="flex flex-wrap justify-center gap-1">
                    {item.tools.map((tool) => (
                      <span key={tool} className="rounded bg-secondary px-1.5 py-0.5 text-[10px] text-muted-foreground">
                        {tool}
                      </span>
                    ))}
                  </div>
                </div>
              ))}
            </div>
          </div>
        </div>
      </section>

      {/* Lab Section - ACTUALIZADO: Solo 3 laboratorios */}
      <section className="border-y border-border bg-secondary/30 py-20 md:py-28">
        <div className="container mx-auto px-4">
          <div className="mx-auto mb-16 max-w-2xl text-center">
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-accent/30 bg-accent/10 px-4 py-2 text-sm text-accent">
              <Terminal className="h-4 w-4" />
              Laboratorio de Práctica
            </div>
            <h2 className="mb-4 text-3xl font-bold text-foreground md:text-4xl">
              Aplicaciones Vulnerables Incluidas
            </h2>
            <p className="text-muted-foreground">
              Practica de forma segura y legal con aplicaciones diseñadas para el aprendizaje
            </p>
          </div>
          <div className="mx-auto max-w-3xl space-y-4">
            {labApps.map((app) => (
              <div
                key={app.name}
                className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 rounded-lg border border-border bg-card p-4 transition-all hover:border-primary/50"
              >
                <div className="flex items-center gap-4">
                  <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-primary/10 text-primary font-mono text-sm">
                    :{app.port}
                  </div>
                  <div>
                    <h3 className="font-semibold text-foreground">{app.name}</h3>
                    <p className="text-sm text-muted-foreground">{app.desc}</p>
                  </div>
                </div>
                <div className="flex items-center gap-2">
                  <code className="rounded bg-secondary px-2 py-1 text-sm font-mono text-muted-foreground">
                    localhost:{app.port}
                  </code>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                </div>
              </div>
            ))}
          </div>
          <div className="mt-8 text-center">
            <Button asChild variant="outline" className="border-border">
              <Link href="/lab">
                <Zap className="mr-2 h-4 w-4" />
                Configurar Laboratorio
              </Link>
            </Button>
          </div>
        </div>
      </section>

      {/* CTA Section */}
      <section className="py-20 md:py-28">
        <div className="container mx-auto px-4">
          <div className="mx-auto max-w-3xl rounded-2xl border border-primary/30 bg-gradient-to-br from-primary/10 via-card to-accent/10 p-8 text-center md:p-12">
            <Shield className="mx-auto mb-6 h-16 w-16 text-primary" />
            <h2 className="mb-4 text-3xl font-bold text-foreground md:text-4xl">
              Comienza tu Análisis Ahora
            </h2>
            <p className="mb-8 text-muted-foreground">
              Ejecuta tu primer escaneo completo con el nuevo stack de herramientas v2.1.
              Detección de tecnologías, escaneo de red, análisis DAST y validación de exploits
              en una sola plataforma.
            </p>
            <div className="flex flex-col gap-3 sm:flex-row sm:justify-center">
              <Button
                asChild
                size="lg"
                className="bg-primary text-primary-foreground hover:bg-primary/90"
              >
                <Link href="/scanner">
                  <Scan className="mr-2 h-5 w-5" />
                  Nuevo Escaneo v2.1
                  <ChevronRight className="ml-2 h-5 w-5" />
                </Link>
              </Button>
              <Button asChild variant="outline" size="lg" className="border-border">
                <Link href="/reports">
                  <FileText className="mr-2 h-5 w-5" />
                  Ver Reportes Anteriores
                </Link>
              </Button>
            </div>
          </div>
        </div>
      </section>

      {/* Footer */}
      <footer className="border-t border-border bg-secondary/30 py-8">
        <div className="container mx-auto px-4">
          <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
            <div className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-primary" />
              <span className="font-semibold text-foreground">SecureScan Pro v2.1</span>
            </div>
            <p className="text-sm text-muted-foreground text-center">
              Proyecto Académico SENA - Stack: WhatWeb, Nmap, Gobuster, ZAP, ExploitDB, Metasploit
            </p>
            <p className="text-sm text-muted-foreground">
              Solo para uso ético y autorizado
            </p>
          </div>
        </div>
      </footer>
    </div>
  );
}