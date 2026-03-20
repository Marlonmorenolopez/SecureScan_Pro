"use client";

import { Header } from "@/components/header";
import { ScanForm } from "@/components/scan-form";
import { ScanProgress } from "@/components/scan-progress";
import { ResultsDashboard } from "@/components/results-dashboard";
import { ScanProvider, useScan } from "@/lib/scan-context";

function ScannerContent() {
  const { currentScan } = useScan();

  return (
    <div className="min-h-screen bg-background">
      <Header />
      <main className="container mx-auto px-4 py-8 space-y-8">
        <div className="max-w-4xl mx-auto">
          <ScanForm />
        </div>

        {currentScan && (
          <div className="max-w-4xl mx-auto">
            <ScanProgress />
          </div>
        )}

        {currentScan && currentScan.status !== "pending" && (
          <ResultsDashboard />
        )}
      </main>
    </div>
  );
}

export default function ScannerPage() {
  return (
    <ScanProvider>
      <ScannerContent />
    </ScanProvider>
  );
}
