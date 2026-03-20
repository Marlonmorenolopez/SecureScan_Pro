"use client";

declare const process: {
  env: {
    NEXT_PUBLIC_API_URL?: string;
  };
};

import React, { createContext, useContext, useState, useCallback } from "react";

// Types for scan results
export interface Technology {
  name: string;
  version?: string;
  category: string;
  confidence: number;
}

export interface Port {
  port: number;
  state: string;
  service: string;
  version?: string;
  product?: string;
}

export interface Directory {
  path: string;
  status: number;
  size?: number;
}

export interface Vulnerability {
  id: string;
  name: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  solution?: string;
  reference?: string;
  tool: string;
  cvss?: number;
}

export interface Exploit {
  id: string;
  title: string;
  path: string;
  type: string;
  platform: string;
  date?: string;
  relatedService?: string;
}

export interface ScanStep {
  name: string;
  status: "pending" | "running" | "completed" | "error";
  progress: number;
  message?: string;
  startTime?: number;
  endTime?: number;
}

export interface ScanResult {
  id: string;
  target: string;
  startTime: string;
  endTime?: string;
  status: "pending" | "running" | "completed" | "error";
  steps: ScanStep[];
  technologies: Technology[];
  ports: Port[];
  directories: Directory[];
  vulnerabilities: Vulnerability[];
  exploits: Exploit[];
  score: {
    total: number;
    grade: string;
    breakdown: {
      critical: number;
      high: number;
      medium: number;
      low: number;
      info: number;
    };
  };
  rawResults?: Record<string, unknown>;
}

interface ScanContextType {
  currentScan: ScanResult | null;
  scanHistory: ScanResult[];
  isScanning: boolean;
  startScan: (target: string, options?: ScanOptions) => Promise<void>;
  cancelScan: () => void;
  clearHistory: () => void;
  downloadReport: (scanId: string, format: "html" | "pdf" | "json") => Promise<void>;
}

export interface ScanOptions {
  tools: {
    wappalyzer: boolean;
    nmap: boolean;
    gobuster: boolean;
    nikto: boolean;
    zap: boolean;
    searchsploit: boolean;
  };
  intensity: "light" | "normal" | "aggressive";
}

const defaultOptions: ScanOptions = {
  tools: {
    wappalyzer: true,
    nmap: true,
    gobuster: true,
    nikto: true,
    zap: true,
    searchsploit: true,
  },
  intensity: "normal",
};

const ScanContext = createContext<ScanContextType | undefined>(undefined);

// API base URL - in production this would be environment variable
const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:4000/api";

export function ScanProvider({ children }: { children: React.ReactNode }) {
  const [currentScan, setCurrentScan] = useState<ScanResult | null>(null);
  const [scanHistory, setScanHistory] = useState<ScanResult[]>([]);
  const [isScanning, setIsScanning] = useState(false);
  const [abortController, setAbortController] = useState<AbortController | null>(null);

  const startScan = useCallback(async (target: string, options: ScanOptions = defaultOptions) => {
    const controller = new AbortController();
    setAbortController(controller);
    setIsScanning(true);

    // Initialize scan state
    const initialScan: ScanResult = {
      id: `scan-${Date.now()}`,
      target,
      startTime: new Date().toISOString(),
      status: "running",
      steps: [
        { name: "Wappalyzer", status: "pending", progress: 0 },
        { name: "Nmap", status: "pending", progress: 0 },
        { name: "Gobuster", status: "pending", progress: 0 },
        { name: "Nikto", status: "pending", progress: 0 },
        { name: "OWASP ZAP", status: "pending", progress: 0 },
        { name: "Searchsploit", status: "pending", progress: 0 },
      ],
      technologies: [],
      ports: [],
      directories: [],
      vulnerabilities: [],
      exploits: [],
      score: {
        total: 0,
        grade: "A",
        breakdown: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      },
    };

    setCurrentScan(initialScan);

    try {
      // Start scan via API
      const response = await fetch(`${API_BASE}/scan`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ target, options }),
        signal: controller.signal,
      });

      if (!response.ok) {
        throw new Error(`Scan failed: ${response.statusText}`);
      }

      const { jobId } = await response.json();

      // Poll for status updates
      const pollStatus = async () => {
        try {
          const statusResponse = await fetch(`${API_BASE}/scan/${jobId}/status`, {
            signal: controller.signal,
          });

          if (!statusResponse.ok) {
            throw new Error("Failed to get scan status");
          }

          const status = await statusResponse.json();

          setCurrentScan((prev: ScanResult | null) => {
            if (!prev) return prev;
            return {
              ...prev,
              status: status.status,
              steps: status.steps || prev.steps,
              technologies: status.technologies || prev.technologies,
              ports: status.ports || prev.ports,
              directories: status.directories || prev.directories,
              vulnerabilities: status.vulnerabilities || prev.vulnerabilities,
              exploits: status.exploits || prev.exploits,
              score: status.score || prev.score,
              endTime: status.endTime,
            };
          });

          if (status.status === "running") {
            setTimeout(pollStatus, 2000);
          } else {
            setIsScanning(false);
            if (status.status === "completed") {
              const finalResult: ScanResult = {
                ...initialScan,
                ...status,
                endTime: new Date().toISOString(),
              };
              setScanHistory((prev: ScanResult[]) => [finalResult, ...prev]);
            }
          }
        } catch (error) {
          if ((error as Error).name !== "AbortError") {
            console.error("Polling error:", error);
            setIsScanning(false);
          }
        }
      };

      await pollStatus();
    } catch (error) {
      if ((error as Error).name !== "AbortError") {
        console.error("Scan error:", error);
        setCurrentScan((prev: ScanResult | null) =>
          prev
            ? {
                ...prev,
                status: "error",
                endTime: new Date().toISOString(),
              }
            : null
        );
      }
      setIsScanning(false);
    }
  }, []);

  const cancelScan = useCallback(() => {
    if (abortController) {
      abortController.abort();
      setAbortController(null);
    }
    setIsScanning(false);
    setCurrentScan((prev: ScanResult | null) =>
      prev
        ? {
            ...prev,
            status: "error",
            endTime: new Date().toISOString(),
          }
        : null
    );
  }, [abortController]);

  const clearHistory = useCallback(() => {
    setScanHistory([]);
  }, []);

  const downloadReport = useCallback(async (scanId: string, format: "html" | "pdf" | "json") => {
    try {
      const response = await fetch(`${API_BASE}/scan/${scanId}/report?format=${format}`);
      if (!response.ok) {
        throw new Error("Failed to download report");
      }

      const blob = await response.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement("a");
      a.href = url;
      a.download = `security-report-${scanId}.${format}`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (error) {
      console.error("Download error:", error);
    }
  }, []);

  return (
    <ScanContext.Provider
      value={{
        currentScan,
        scanHistory,
        isScanning,
        startScan,
        cancelScan,
        clearHistory,
        downloadReport,
      }}
    >
      {children}
    </ScanContext.Provider>
  );
}

export function useScan() {
  const context = useContext(ScanContext);
  if (context === undefined) {
    throw new Error("useScan must be used within a ScanProvider");
  }
  return context;
}
