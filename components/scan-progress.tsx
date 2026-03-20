"use client";

import { CheckCircle2, Circle, Loader2, XCircle, Clock } from "lucide-react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Progress } from "@/components/ui/progress";
import { Button } from "@/components/ui/button";
import { useScan } from "@/lib/scan-context";

const toolIcons: Record<string, string> = {
  Wappalyzer: "W",
  Nmap: "N",
  Gobuster: "G",
  Nikto: "Ni",
  "OWASP ZAP": "Z",
  Searchsploit: "S",
};

function StepIcon({ status }: { status: string }) {
  switch (status) {
    case "completed":
      return <CheckCircle2 className="h-5 w-5 text-success" />;
    case "running":
      return <Loader2 className="h-5 w-5 text-primary animate-spin" />;
    case "error":
      return <XCircle className="h-5 w-5 text-destructive" />;
    default:
      return <Circle className="h-5 w-5 text-muted-foreground" />;
  }
}

function formatDuration(startTime?: number, endTime?: number): string {
  if (!startTime) return "--";
  const end = endTime || Date.now();
  const duration = Math.floor((end - startTime) / 1000);
  const minutes = Math.floor(duration / 60);
  const seconds = duration % 60;
  return minutes > 0 ? `${minutes}m ${seconds}s` : `${seconds}s`;
}

export function ScanProgress() {
  const { currentScan, isScanning, cancelScan } = useScan();

  if (!currentScan) {
    return null;
  }

  const completedSteps = currentScan.steps.filter(
    (step) => step.status === "completed"
  ).length;
  const totalSteps = currentScan.steps.length;
  const overallProgress = (completedSteps / totalSteps) * 100;

  return (
    <Card className="border-border bg-card">
      <CardHeader>
        <div className="flex items-center justify-between">
          <div>
            <CardTitle className="flex items-center gap-2 text-foreground">
              <Loader2
                className={`h-5 w-5 ${
                  isScanning ? "animate-spin text-primary" : "text-muted-foreground"
                }`}
              />
              Progreso del Escaneo
            </CardTitle>
            <CardDescription className="text-muted-foreground">
              Objetivo: {currentScan.target}
            </CardDescription>
          </div>
          {isScanning && (
            <Button
              variant="outline"
              size="sm"
              onClick={cancelScan}
              className="border-destructive text-destructive hover:bg-destructive/10"
            >
              Cancelar
            </Button>
          )}
        </div>
      </CardHeader>
      <CardContent className="space-y-6">
        <div className="space-y-2">
          <div className="flex justify-between text-sm">
            <span className="text-muted-foreground">Progreso General</span>
            <span className="font-medium text-foreground">
              {completedSteps} de {totalSteps} herramientas
            </span>
          </div>
          <Progress value={overallProgress} className="h-2" />
        </div>

        <div className="space-y-3">
          {currentScan.steps.map((step, index) => (
            <div
              key={step.name}
              className={`flex items-center gap-4 p-3 rounded-lg transition-colors ${
                step.status === "running"
                  ? "bg-primary/10 border border-primary/30"
                  : step.status === "completed"
                  ? "bg-success/5 border border-success/20"
                  : step.status === "error"
                  ? "bg-destructive/10 border border-destructive/30"
                  : "bg-secondary border border-border"
              }`}
            >
              <div
                className={`flex h-8 w-8 items-center justify-center rounded-md text-xs font-bold ${
                  step.status === "running"
                    ? "bg-primary text-primary-foreground"
                    : step.status === "completed"
                    ? "bg-success text-success-foreground"
                    : step.status === "error"
                    ? "bg-destructive text-destructive-foreground"
                    : "bg-muted text-muted-foreground"
                }`}
              >
                {toolIcons[step.name] || index + 1}
              </div>

              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-2">
                  <span className="font-medium text-foreground">{step.name}</span>
                  <StepIcon status={step.status} />
                </div>
                {step.message && (
                  <p className="text-sm text-muted-foreground truncate">
                    {step.message}
                  </p>
                )}
                {step.status === "running" && step.progress > 0 && (
                  <Progress value={step.progress} className="h-1 mt-2" />
                )}
              </div>

              <div className="flex items-center gap-1 text-xs text-muted-foreground">
                <Clock className="h-3 w-3" />
                {formatDuration(step.startTime, step.endTime)}
              </div>
            </div>
          ))}
        </div>

        {currentScan.status === "completed" && (
          <div className="flex items-center justify-center gap-2 py-4 text-success">
            <CheckCircle2 className="h-5 w-5" />
            <span className="font-medium">Escaneo completado exitosamente</span>
          </div>
        )}

        {currentScan.status === "error" && (
          <div className="flex items-center justify-center gap-2 py-4 text-destructive">
            <XCircle className="h-5 w-5" />
            <span className="font-medium">El escaneo encontro errores</span>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
