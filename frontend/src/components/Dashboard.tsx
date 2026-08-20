"use client";

/**
 * AegisAI — Main Security Dashboard
 *
 * Responsibilities:
 *  - Accept GitHub URL + Target URL to start a scan
 *  - Display real-time scan status (via polling / SSE)
 *  - Render vulnerability summary cards
 *  - Link out to detailed CodeDiffViewer for each finding
 *
 * NOTE: API integration stubs are marked with TODO comments.
 * Replace fetch calls with your real API client once the
 * backend /api/v1/scan/start endpoint is live.
 */

import React, { useState, useTransition } from "react";
import {
  Shield,
  GitBranch,
  Globe,
  Play,
  AlertTriangle,
  CheckCircle2,
  Clock,
  Loader2,
  BarChart3,
  Terminal,
  Cpu,
} from "lucide-react";
import type {
  ScanStartRequest,
  ScanReport,
  ScanSummary,
  Severity,
} from "@/types/schema";

// ── Severity colour map ────────────────────────────────────────
const SEVERITY_STYLES: Record<Severity, string> = {
  CRITICAL: "badge-critical",
  HIGH: "badge-high",
  MEDIUM: "badge-medium",
  LOW: "badge-low",
  INFO: "badge-info",
};

// ── Stat card ─────────────────────────────────────────────────
interface StatCardProps {
  label: string;
  value: string | number;
  icon: React.ReactNode;
  accent?: string;
}

function StatCard({ label, value, icon, accent = "text-aegis-400" }: StatCardProps) {
  return (
    <div className="card-glass p-5 flex items-center gap-4 animate-slide-up">
      <div className={`p-3 rounded-lg bg-white/5 ${accent}`}>{icon}</div>
      <div>
        <p className="text-2xl font-bold text-white">{value}</p>
        <p className="text-xs text-slate-400 mt-0.5">{label}</p>
      </div>
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────
export default function Dashboard() {
  const [githubUrl, setGithubUrl] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [isPending, startTransition] = useTransition();
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<
    "idle" | "scanning" | "done" | "error"
  >("idle");

  // TODO: Replace with real API call to POST /api/v1/scan/start
  async function handleStartScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setScanReport(null);

    startTransition(async () => {
      setScanStatus("scanning");

      try {
        const body: ScanStartRequest = {
          github_url: githubUrl,
          target_url: targetUrl,
          scan_modules: ["all"],
        };

        // TODO: Replace with process.env.NEXT_PUBLIC_API_URL
        const res = await fetch("http://localhost:8000/api/v1/scan/start", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });

        if (!res.ok) {
          throw new Error(`API error: ${res.status} ${res.statusText}`);
        }

        // TODO: Poll /api/v1/scan/{scan_id} until status === "completed"
        const data = await res.json();
        setScanReport(data as ScanReport);
        setScanStatus("done");
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error");
        setScanStatus("error");
      }
    });
  }

  const summary: ScanSummary | null = scanReport?.summary ?? null;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* ── Header ── */}
      <header className="flex items-center gap-3">
        <div className="p-2 rounded-xl bg-aegis-600/20 border border-aegis-500/30">
          <Shield className="w-8 h-8 text-aegis-400" aria-hidden="true" />
        </div>
        <div>
          <h1 className="text-3xl font-bold text-white tracking-tight">
            AegisAI
          </h1>
          <p className="text-sm text-slate-400">
            Autonomous Multi-Agent Security Platform
          </p>
        </div>
      </header>

      {/* ── Scan Form ── */}
      <section
        id="scan-form"
        aria-labelledby="scan-form-heading"
        className="card-glass p-6 space-y-5"
      >
        <h2
          id="scan-form-heading"
          className="text-lg font-semibold text-white flex items-center gap-2"
        >
          <Terminal className="w-5 h-5 text-aegis-400" />
          New Scan
        </h2>

        <form
          onSubmit={handleStartScan}
          className="grid grid-cols-1 md:grid-cols-2 gap-4"
        >
          {/* GitHub URL */}
          <div className="space-y-1.5">
            <label
              htmlFor="github-url"
              className="text-sm font-medium text-slate-300 flex items-center gap-1.5"
            >
              <GitBranch className="w-4 h-4" />
              GitHub Repository URL
            </label>
            <input
              id="github-url"
              type="url"
              required
              value={githubUrl}
              onChange={(e) => setGithubUrl(e.target.value)}
              placeholder="https://github.com/org/repo"
              className="w-full px-4 py-2.5 bg-slate-900 border border-slate-700
                         rounded-lg text-sm text-white placeholder:text-slate-500
                         focus:outline-none focus:ring-2 focus:ring-aegis-500
                         focus:border-transparent transition-all"
            />
          </div>

          {/* Target URL */}
          <div className="space-y-1.5">
            <label
              htmlFor="target-url"
              className="text-sm font-medium text-slate-300 flex items-center gap-1.5"
            >
              <Globe className="w-4 h-4" />
              Target Application URL
            </label>
            <input
              id="target-url"
              type="url"
              required
              value={targetUrl}
              onChange={(e) => setTargetUrl(e.target.value)}
              placeholder="http://localhost:3000"
              className="w-full px-4 py-2.5 bg-slate-900 border border-slate-700
                         rounded-lg text-sm text-white placeholder:text-slate-500
                         focus:outline-none focus:ring-2 focus:ring-aegis-500
                         focus:border-transparent transition-all"
            />
          </div>

          {/* Submit */}
          <div className="md:col-span-2 flex justify-end">
            <button
              id="start-scan-btn"
              type="submit"
              disabled={isPending || scanStatus === "scanning"}
              className="btn-primary"
            >
              {isPending || scanStatus === "scanning" ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Scanning…
                </>
              ) : (
                <>
                  <Play className="w-4 h-4" />
                  Start Scan
                </>
              )}
            </button>
          </div>
        </form>

        {/* Error */}
        {error && (
          <div
            role="alert"
            className="flex items-start gap-2 p-3 rounded-lg bg-red-500/10
                       border border-red-500/30 text-red-400 text-sm"
          >
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            {error}
          </div>
        )}
      </section>

      {/* ── Scan Status ── */}
      {scanStatus !== "idle" && (
        <section
          id="scan-status"
          aria-label="Scan status"
          className="grid grid-cols-2 sm:grid-cols-4 gap-4"
        >
          <StatCard
            label="Total Endpoints"
            value={summary?.total_endpoints ?? "—"}
            icon={<Globe className="w-5 h-5" />}
          />
          <StatCard
            label="AST Nodes"
            value={summary?.total_ast_nodes ?? "—"}
            icon={<BarChart3 className="w-5 h-5" />}
          />
          <StatCard
            label="Vulnerabilities"
            value={summary?.total_vulnerabilities ?? "—"}
            icon={<AlertTriangle className="w-5 h-5" />}
            accent="text-danger"
          />
          <StatCard
            label="Risk Score"
            value={summary ? `${summary.risk_score}/100` : "—"}
            icon={<Cpu className="w-5 h-5" />}
            accent={
              (summary?.risk_score ?? 0) > 70 ? "text-danger" : "text-success"
            }
          />
        </section>
      )}

      {/* ── Agent Activity ── */}
      {scanStatus === "scanning" && (
        <section
          id="agent-activity"
          aria-label="Agent activity"
          className="card-glass p-6 space-y-4"
        >
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <Loader2 className="w-5 h-5 text-aegis-400 animate-spin" />
            Agent Pipeline Running…
          </h2>
          {(["Recon Agent", "Reason Agent", "Verify Agent"] as const).map(
            (agent, i) => (
              <div
                key={agent}
                className="flex items-center gap-3 text-sm"
                style={{ animationDelay: `${i * 0.15}s` }}
              >
                <Clock className="w-4 h-4 text-slate-500 animate-pulse-slow" />
                <span className="text-slate-400">{agent}</span>
                <span className="ml-auto text-slate-600 text-xs">queued</span>
              </div>
            )
          )}
        </section>
      )}

      {/* ── Results ── */}
      {scanStatus === "done" && scanReport && (
        <section
          id="scan-results"
          aria-label="Scan results"
          className="card-glass p-6 space-y-4"
        >
          <h2 className="text-lg font-semibold text-white flex items-center gap-2">
            <CheckCircle2 className="w-5 h-5 text-success" />
            Scan Complete
          </h2>

          {scanReport.vulnerabilities.length === 0 ? (
            <p className="text-slate-400 text-sm">
              No vulnerabilities detected. 🎉
            </p>
          ) : (
            <ul className="divide-y divide-white/5">
              {scanReport.vulnerabilities.map((vuln) => (
                <li
                  key={vuln.id}
                  className="py-3 flex items-start gap-3 text-sm"
                >
                  <span className={SEVERITY_STYLES[vuln.severity]}>
                    {vuln.severity}
                  </span>
                  <div>
                    <p className="font-medium text-white">{vuln.title}</p>
                    <p className="text-slate-400 mt-0.5 text-xs">
                      {vuln.cwe_id && (
                        <span className="mr-2 font-mono">{vuln.cwe_id}</span>
                      )}
                      {vuln.owasp_category}
                    </p>
                  </div>
                </li>
              ))}
            </ul>
          )}
        </section>
      )}
    </div>
  );
}
