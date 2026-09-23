"use client";

/**
 * AegisAI — Main Security Dashboard
 *
 * Responsibilities:
 *  - Accept GitHub URL + Target URL to start a scan
 *  - Display real-time scan status (polling /status and /agent-state every 1.5s)
 *  - Render vulnerability summary cards
 *  - Open CodeDiffViewer modal on vulnerability click
 */

import React, { useState, useTransition, useEffect, useRef, useCallback } from "react";
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
  ChevronRight,
  X,
  Sliders,
  KeyRound,
  Zap,
  MousePointerClick,
} from "lucide-react";
import type {
  ScanStartRequest,
  ScanStartResponse,
  ScanReport,
  ScanSummary,
  Severity,
  DetectedVulnerability,
  AgentState,
  ApiResponse,
  DetectionMode,
} from "@/types/schema";
import CodeDiffViewer from "@/components/CodeDiffViewer";

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
    <div className="liquid-glass-subtle liquid-glass-interactive p-5 flex items-center gap-4 animate-slide-up">
      <div className={`p-3 rounded-xl bg-white/[0.04] border border-white/[0.07] backdrop-blur-md ${accent}`}>{icon}</div>
      <div>
        <p className="text-2xl font-bold tracking-tight text-white">{value}</p>
        <p className="text-xs text-slate-400 font-medium mt-0.5">{label}</p>
      </div>
    </div>
  );
}

// ── Dashboard ─────────────────────────────────────────────────
export default function Dashboard() {
  const [githubUrl, setGithubUrl] = useState("");
  const [targetUrl, setTargetUrl] = useState("");
  const [detectionMode, setDetectionMode] = useState<DetectionMode | null>(null);
  const [isPending, startTransition] = useTransition();
  const [scanReport, setScanReport] = useState<ScanReport | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [scanStatus, setScanStatus] = useState<
    "idle" | "scanning" | "done" | "error"
  >("idle");

  // Live scan tracking
  const [scanId, setScanId] = useState<string | null>(null);
  const [progress, setProgress] = useState(0);
  const [currentAgent, setCurrentAgent] = useState<string>("idle");
  const [reasoningTrace, setReasoningTrace] = useState<string[]>([]);
  const traceRef = useRef<HTMLDivElement>(null);
  const pollRef = useRef<NodeJS.Timeout | null>(null);

  // CodeDiffViewer modal
  const [selectedVuln, setSelectedVuln] = useState<DetectedVulnerability | null>(null);

  const API_BASE = process.env.NEXT_PUBLIC_API_URL || "http://localhost:8000";

  // ── Stop polling helper ───────────────────────────────────
  const stopPolling = useCallback(() => {
    if (pollRef.current) {
      clearInterval(pollRef.current);
      pollRef.current = null;
    }
  }, []);

  // ── Auto-scroll reasoning trace ──────────────────────────
  useEffect(() => {
    if (traceRef.current) {
      traceRef.current.scrollTop = traceRef.current.scrollHeight;
    }
  }, [reasoningTrace]);

  // ── Cleanup on unmount ────────────────────────────────────
  useEffect(() => () => stopPolling(), [stopPolling]);

  // ── Start live polling for status + agent-state ───────────
  const startPolling = useCallback((id: string) => {
    stopPolling();

    pollRef.current = setInterval(async () => {
      try {
        // Poll status
        const statusRes = await fetch(`${API_BASE}/api/v1/scan/${id}/status`);
        if (!statusRes.ok) return;
        const statusData: ApiResponse<{
          status: string;
          progress_pct: number;
          current_agent: string;
          message: string;
        }> = await statusRes.json();

        const { status, progress_pct, current_agent, message } = statusData.data;
        setProgress(progress_pct ?? 0);
        setCurrentAgent(current_agent ?? "idle");

        // Poll agent-state for reasoning trace
        const agentRes = await fetch(`${API_BASE}/api/v1/scan/${id}/agent-state`);
        if (agentRes.ok) {
          const agentData: ApiResponse<AgentState> = await agentRes.json();
          const newTrace = agentData.data.reasoning_trace ?? [];
          setReasoningTrace(newTrace);
        }

        // When done, fetch full report
        if (status === "completed" || status === "failed" || status === "cancelled") {
          stopPolling();
          if (status === "completed") {
            const reportRes = await fetch(`${API_BASE}/api/v1/scan/${id}/report`);
            if (reportRes.ok) {
              const reportData: ApiResponse<ScanReport> = await reportRes.json();
              setScanReport(reportData.data);
            }
            setScanStatus("done");
          } else {
            setError(message || `Scan ${status}.`);
            setScanStatus("error");
          }
          setProgress(100);
        }
      } catch (err) {
        // Network error during polling — keep polling
      }
    }, 1500);
  }, [API_BASE, stopPolling]);

  // ── Start scan ────────────────────────────────────────────
  async function handleStartScan(e: React.FormEvent) {
    e.preventDefault();
    setError(null);
    setScanReport(null);
    setReasoningTrace([]);
    setProgress(0);
    setCurrentAgent("idle");
    stopPolling();

    const hasGh = Boolean(githubUrl.trim());
    const hasTgt = Boolean(targetUrl.trim());

    if (!hasGh && !hasTgt) {
      setError("Please provide either a GitHub Repository URL (for SAST Code Audit), a Target Application URL (for DAST Live Scan), or both (for Hybrid Scan).");
      setScanStatus("error");
      return;
    }

    startTransition(async () => {
      setScanStatus("scanning");

      try {
        const body: ScanStartRequest = {
          github_url: hasGh ? githubUrl.trim() : null,
          target_url: hasTgt ? targetUrl.trim() : null,
          scan_modules: ["all"],
          detection_mode: detectionMode || "all",
        };

        const res = await fetch(`${API_BASE}/api/v1/scan/start`, {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify(body),
        });

        if (!res.ok) {
          throw new Error(`API error: ${res.status} ${res.statusText}`);
        }

        // Capture scan_id and begin live polling
        const data: ScanStartResponse = await res.json();
        setScanId(data.scan_id);
        startPolling(data.scan_id);
      } catch (err) {
        setError(err instanceof Error ? err.message : "Unknown error");
        setScanStatus("error");
        stopPolling();
      }
    });
  }

  const summary: ScanSummary | null = scanReport?.summary ?? null;

  return (
    <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8 py-10 space-y-10">
      {/* ── Header ── */}
      <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 pb-2 border-b border-white/[0.06]">
        <div className="flex items-center gap-3.5">
          <div className="relative p-2.5 rounded-2xl bg-gradient-to-br from-white/10 to-white/[0.02] border border-white/15 backdrop-blur-xl shadow-lg shadow-black/30">
            <Shield className="w-7 h-7 text-aegis-400" aria-hidden="true" />
            <div className="absolute inset-0 rounded-2xl border border-white/20 pointer-events-none" />
          </div>
          <div>
            <div className="flex items-center gap-2.5">
              <h1 className="text-2xl sm:text-3xl font-bold text-white tracking-tight">
                AegisAI
              </h1>
              <span className="text-[10px] font-mono uppercase tracking-widest px-2 py-0.5 rounded-full bg-white/[0.05] border border-white/10 text-slate-300">
                v2.4
              </span>
            </div>
            <p className="text-xs sm:text-sm text-slate-400">
              Autonomous Multi-Agent Security Platform
            </p>
          </div>
        </div>
        <div className="flex items-center gap-2 self-start sm:self-auto">
          <div className="flex items-center gap-2 px-3 py-1.5 rounded-full bg-white/[0.03] border border-white/[0.08] backdrop-blur-md text-xs text-slate-300">
            <span className="w-2 h-2 rounded-full bg-emerald-400/90" />
            <span className="font-mono text-[11px] text-slate-400">Core Engine:</span>
            <span className="font-semibold text-slate-200">Active</span>
          </div>
        </div>
      </header>

      {/* ── Scan Form ── */}
      <section
        id="scan-form"
        aria-labelledby="scan-form-heading"
        className="liquid-glass p-6 sm:p-7 space-y-6"
      >
        <div className="flex items-center justify-between border-b border-white/[0.07] pb-4">
          <h2
            id="scan-form-heading"
            className="text-base sm:text-lg font-semibold text-white flex items-center gap-2.5"
          >
            <div className="p-1.5 rounded-lg bg-white/[0.04] border border-white/[0.08] text-aegis-400">
              <Terminal className="w-4 h-4" />
            </div>
            New Security Scan
          </h2>
          <span className="text-xs text-slate-400 font-mono">
            {detectionMode === "general"
              ? "Focus: General DAST (Playwright Crawler Engine)"
              : detectionMode === "bola_idor"
              ? "Focus: BOLA / IDOR (AI Reasoning Model)"
              : detectionMode === "all"
              ? "Focus: Full Combined Audit"
              : "Step 1: Choose Vulnerability Focus"}
          </span>
        </div>

        {/* ── Step 1: Select Vulnerability Detection Focus ── */}
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              <span className="flex items-center justify-center w-5 h-5 rounded-full bg-white/[0.06] text-aegis-300 text-xs font-bold border border-white/10">
                1
              </span>
              <label className="text-sm font-semibold text-white flex items-center gap-2">
                <Sliders className="w-4 h-4 text-aegis-400" />
                Select Vulnerability Detection Focus
              </label>
            </div>
            <span className="text-xs text-slate-400">Click a card to configure target links</span>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Box 1: General Web Vulnerabilities (Burp & Acunetix) */}
            <div
              id="select-general-mode"
              role="button"
              tabIndex={0}
              onClick={() => setDetectionMode(detectionMode === "general" ? null : "general")}
              onKeyDown={(e) => e.key === "Enter" && setDetectionMode(detectionMode === "general" ? null : "general")}
              className={`cursor-pointer p-5 rounded-2xl transition-all duration-200 relative group ${
                detectionMode === "general"
                  ? "liquid-glass border-blue-400/35 ring-1 ring-blue-400/25"
                  : "liquid-glass-subtle liquid-glass-interactive border-white/[0.07] hover:border-white/15"
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className={`p-2.5 rounded-xl flex-shrink-0 mt-0.5 transition-colors border ${
                    detectionMode === "general" 
                      ? "bg-blue-500/10 border-blue-400/30 text-blue-300" 
                      : "bg-white/[0.03] border-white/[0.06] text-slate-400 group-hover:text-slate-200"
                  }`}>
                    <Shield className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold text-white">General Vulnerabilities</h3>
                      <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-md bg-blue-500/10 text-blue-300 border border-blue-500/20">
                        Playwright DAST Engine
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                      Executes direct browser DOM traversal, form extraction, and deterministic security analysis (Clickjacking, CSP, CORS wildcards, server banners, cookie security) via the Playwright crawler.
                    </p>
                  </div>
                </div>
                <div className={`w-5 h-5 rounded-full border flex items-center justify-center flex-shrink-0 transition-all ${
                  detectionMode === "general" ? "border-blue-400/60 bg-blue-500/20 text-blue-300" : "border-white/10 bg-white/[0.02]"
                }`}>
                  {detectionMode === "general" && <CheckCircle2 className="w-3.5 h-3.5 text-blue-300" />}
                </div>
              </div>
              <div className="mt-3.5 pt-3 border-t border-white/[0.06] flex flex-wrap gap-1.5">
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-white/[0.03] border border-white/[0.06] text-blue-300/90">CWE-1021 Clickjacking</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-white/[0.03] border border-white/[0.06] text-blue-300/90">CWE-693 CSP</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-white/[0.03] border border-white/[0.06] text-blue-300/90">CWE-942 CORS</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-white/[0.03] border border-white/[0.06] text-blue-300/90">CWE-200 Banner</span>
              </div>
            </div>

            {/* Box 2: BOLA / IDOR (API Security) */}
            <div
              id="select-bola-mode"
              role="button"
              tabIndex={0}
              onClick={() => setDetectionMode(detectionMode === "bola_idor" ? null : "bola_idor")}
              onKeyDown={(e) => e.key === "Enter" && setDetectionMode(detectionMode === "bola_idor" ? null : "bola_idor")}
              className={`cursor-pointer p-5 rounded-2xl transition-all duration-200 relative group ${
                detectionMode === "bola_idor"
                  ? "liquid-glass border-purple-400/35 ring-1 ring-purple-400/25"
                  : "liquid-glass-subtle liquid-glass-interactive border-white/[0.07] hover:border-white/15"
              }`}
            >
              <div className="flex items-start justify-between gap-3">
                <div className="flex items-start gap-3">
                  <div className={`p-2.5 rounded-xl flex-shrink-0 mt-0.5 transition-colors border ${
                    detectionMode === "bola_idor" 
                      ? "bg-purple-500/10 border-purple-400/30 text-purple-300" 
                      : "bg-white/[0.03] border-white/[0.06] text-slate-400 group-hover:text-slate-200"
                  }`}>
                    <KeyRound className="w-5 h-5" />
                  </div>
                  <div>
                    <div className="flex items-center gap-2">
                      <h3 className="text-sm font-semibold text-white">BOLA / IDOR Vulnerabilities</h3>
                      <span className="text-[10px] uppercase font-bold tracking-wider px-2 py-0.5 rounded-md bg-purple-500/10 text-purple-300 border border-purple-500/20">
                        AI Reasoning Model Active
                      </span>
                    </div>
                    <p className="text-xs text-slate-400 mt-1 leading-relaxed">
                      Activates the local Ollama AI model (Qwen2.5-Coder) with LangGraph multi-agent cognitive reasoning to detect Broken Object Level Authorization, missing tenant isolation, ID tampering, and horizontal privilege escalation.
                    </p>
                  </div>
                </div>
                <div className={`w-5 h-5 rounded-full border flex items-center justify-center flex-shrink-0 transition-all ${
                  detectionMode === "bola_idor" ? "border-purple-400/60 bg-purple-500/20 text-purple-300" : "border-white/10 bg-white/[0.02]"
                }`}>
                  {detectionMode === "bola_idor" && <CheckCircle2 className="w-3.5 h-3.5 text-purple-300" />}
                </div>
              </div>
              <div className="mt-3.5 pt-3 border-t border-white/[0.06] flex flex-wrap gap-1.5">
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-white/[0.03] border border-white/[0.06] text-purple-300/90">API1:2023 BOLA</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-white/[0.03] border border-white/[0.06] text-purple-300/90">CWE-639 IDOR</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-white/[0.03] border border-white/[0.06] text-purple-300/90">CWE-285 Auth</span>
                <span className="text-[11px] font-mono px-2 py-0.5 rounded-md bg-white/[0.03] border border-white/[0.06] text-purple-300/90">Tenant Isolation</span>
              </div>
            </div>
          </div>

          {/* Quick Combined Option Toggle */}
          <div className="flex items-center justify-end pt-1">
            <button
              type="button"
              onClick={() => setDetectionMode(detectionMode === "all" ? null : "all")}
              className={`text-xs px-3.5 py-1.5 rounded-xl border transition-all flex items-center gap-1.5 backdrop-blur-md ${
                detectionMode === "all"
                  ? "bg-emerald-500/10 text-emerald-300 border-emerald-400/35 ring-1 ring-emerald-400/20"
                  : "text-slate-400 hover:text-slate-200 border-white/[0.08] hover:border-white/15 bg-white/[0.02]"
              }`}
            >
              <Zap className="w-3.5 h-3.5 text-emerald-400" />
              {detectionMode === "all" ? "Combined Audit Enabled (Both Modes Active)" : "Enable Full Combined Audit (Both Modes)"}
            </button>
          </div>
        </div>

        {/* ── Step 2: Target Link Boxes (Given upon clicking either mode box) ── */}
        {detectionMode ? (
          <form
            onSubmit={handleStartScan}
            className="space-y-4 pt-3 border-t border-white/10 animate-slide-up"
          >
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                <span className="flex items-center justify-center w-5 h-5 rounded-full bg-white/[0.06] text-aegis-300 text-xs font-bold border border-white/10">
                  2
                </span>
                <h3 className="text-sm font-semibold text-white">
                  Enter Target Links for {detectionMode === "general" ? "General DAST Scan" : detectionMode === "bola_idor" ? "BOLA / IDOR API Scan" : "Combined Security Audit"}
                </h3>
              </div>
              <div className="flex items-center gap-2">
                {detectionMode === "general" && (
                  <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-blue-500/10 text-blue-300 border border-blue-500/25 flex items-center gap-1.5">
                    <Shield className="w-3.5 h-3.5 text-blue-400" /> Playwright DAST Engine
                  </span>
                )}
                {detectionMode === "bola_idor" && (
                  <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-purple-500/10 text-purple-300 border border-purple-500/25 flex items-center gap-1.5">
                    <KeyRound className="w-3.5 h-3.5 text-purple-400" /> AI Reasoning Model Active
                  </span>
                )}
                {detectionMode === "all" && (
                  <span className="text-xs font-semibold px-2.5 py-0.5 rounded-full bg-emerald-500/10 text-emerald-300 border border-emerald-500/25 flex items-center gap-1.5">
                    <Zap className="w-3.5 h-3.5 text-emerald-400" /> All Engines Active
                  </span>
                )}
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              {/* Link Box 1: GitHub URL */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="github-url"
                    className="text-sm font-medium text-slate-300 flex items-center gap-1.5"
                  >
                    <GitBranch className="w-4 h-4 text-slate-400" />
                    GitHub Repository URL
                  </label>
                  <span className={`text-xs px-2.5 py-0.5 rounded-full font-medium transition-all ${
                    githubUrl.trim() && targetUrl.trim()
                      ? "bg-purple-500/15 text-purple-300 border border-purple-500/25"
                      : githubUrl.trim()
                      ? "bg-aegis-500/15 text-aegis-300 border border-aegis-500/25"
                      : "bg-white/[0.03] text-slate-400 border border-white/[0.08]"
                  }`}>
                    {githubUrl.trim() && targetUrl.trim()
                      ? "Hybrid (SAST + DAST)"
                      : githubUrl.trim()
                      ? "Active · SAST Code Audit"
                      : "Optional · DAST-Only if blank"}
                  </span>
                </div>
                <input
                  id="github-url"
                  type="url"
                  value={githubUrl}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setGithubUrl(e.target.value)}
                  placeholder="https://github.com/org/repo (for SAST static code audit)"
                  className="liquid-input w-full px-4 py-2.5 rounded-xl text-sm placeholder:text-slate-500"
                />
              </div>

              {/* Link Box 2: Target Application URL */}
              <div className="space-y-1.5">
                <div className="flex items-center justify-between">
                  <label
                    htmlFor="target-url"
                    className="text-sm font-medium text-slate-300 flex items-center gap-1.5"
                  >
                    <Globe className="w-4 h-4 text-slate-400" />
                    Target Application URL
                  </label>
                  <span className={`text-xs px-2.5 py-0.5 rounded-full font-medium transition-all ${
                    githubUrl.trim() && targetUrl.trim()
                      ? "bg-purple-500/15 text-purple-300 border border-purple-500/25"
                      : targetUrl.trim()
                      ? "bg-blue-500/15 text-blue-300 border border-blue-500/25"
                      : githubUrl.trim()
                      ? "bg-white/[0.03] text-slate-400 border border-white/[0.08]"
                      : "bg-amber-500/10 text-amber-300 border border-amber-500/20"
                  }`}>
                    {githubUrl.trim() && targetUrl.trim()
                      ? "Hybrid (SAST + DAST)"
                      : targetUrl.trim()
                      ? "Active · DAST Live Scan"
                      : githubUrl.trim()
                      ? "Optional · SAST-Only Mode"
                      : "Provide GitHub or URL"}
                  </span>
                </div>
                <input
                  id="target-url"
                  type="url"
                  value={targetUrl}
                  onChange={(e: React.ChangeEvent<HTMLInputElement>) => setTargetUrl(e.target.value)}
                  placeholder={
                    detectionMode === "general"
                      ? "http://zero.webappsecurity.com (Optional — leave blank for SAST)"
                      : detectionMode === "bola_idor"
                      ? "http://localhost:3000 (Optional — leave blank for SAST)"
                      : "http://target-app.com (Optional — leave blank for SAST)"
                  }
                  className="liquid-input w-full px-4 py-2.5 rounded-xl text-sm placeholder:text-slate-500"
                />
              </div>
            </div>

            {/* Action Bar */}
            <div className="flex flex-col sm:flex-row items-center justify-between gap-3 pt-2">
              <p className="text-xs text-slate-400 leading-relaxed">
                {githubUrl.trim() && !targetUrl.trim()
                  ? "SAST-Only Mode: Deep code parsing with tree-sitter AST, identifying security flaws in source handlers."
                  : !githubUrl.trim() && targetUrl.trim()
                  ? (detectionMode === "general"
                      ? "DAST-Only Mode: Crawling DOM routes, inspecting live response headers (CSP, Clickjacking, CORS), and testing injection."
                      : detectionMode === "bola_idor"
                      ? "DAST-Only Mode: Auditing object IDs, user parameters, and testing cross-tenant authorization boundaries."
                      : "DAST-Only Mode: Running full comprehensive web crawler and live exploit verification.")
                  : githubUrl.trim() && targetUrl.trim()
                  ? "Hybrid Mode: Correlating AST source code nodes with live dynamic crawler findings and patch synthesis."
                  : "Provide either a GitHub Repository (SAST), a Target URL (DAST), or both for combined analysis."}
              </p>
              <button
                id="start-scan-btn"
                type="submit"
                disabled={isPending || scanStatus === "scanning"}
                className={`btn-primary flex-shrink-0 px-6 py-2.5 rounded-xl font-semibold shadow-lg ${
                  detectionMode === "bola_idor"
                    ? "!from-purple-600/80 !to-indigo-600/80 hover:!from-purple-500 hover:!to-indigo-500"
                    : detectionMode === "all"
                    ? "!from-emerald-600/80 !to-teal-600/80 hover:!from-emerald-500 hover:!to-teal-500"
                    : "!from-aegis-600/90 !to-sky-600/90 hover:!from-aegis-500 hover:!to-sky-500"
                }`}
              >
                {isPending || scanStatus === "scanning" ? (
                  <>
                    <Loader2 className="w-4 h-4 animate-spin" />
                    Scanning…
                  </>
                ) : (
                  <>
                    <Play className="w-4 h-4" />
                    {(() => {
                      const isHybrid = Boolean(githubUrl.trim() && targetUrl.trim());
                      const isSastOnly = Boolean(githubUrl.trim() && !targetUrl.trim());

                      if (detectionMode === "general") {
                        if (isSastOnly) return "Start General SAST Code Audit";
                        if (isHybrid) return "Start General Hybrid Scan";
                        return "Start General DAST Scan (Playwright Engine)";
                      } else if (detectionMode === "bola_idor") {
                        if (isSastOnly) return "Start BOLA / IDOR Code Audit (SAST)";
                        if (isHybrid) return "Start BOLA / IDOR Hybrid Scan";
                        return "Start BOLA / IDOR Scan (AI Model Active)";
                      } else {
                        if (isSastOnly) return "Start Full SAST Code Audit";
                        if (isHybrid) return "Start Combined Hybrid Audit";
                        return "Start Full Combined DAST Audit";
                      }
                    })()}
                  </>
                )}
              </button>
            </div>
          </form>
        ) : (
          <div className="p-8 rounded-2xl border border-dashed border-white/[0.09] bg-white/[0.015] backdrop-blur-md text-center space-y-2.5">
            <div className="inline-flex p-3 rounded-2xl bg-white/[0.04] border border-white/[0.08] text-aegis-400">
              <MousePointerClick className="w-5 h-5 animate-bounce" />
            </div>
            <p className="text-sm font-semibold text-slate-200">
              Select a Vulnerability Detection Focus Above
            </p>
            <p className="text-xs text-slate-400 max-w-md mx-auto leading-relaxed">
              Click <strong>General Vulnerabilities</strong> to configure target links for Burp Suite & Acunetix style DAST, or click <strong>BOLA / IDOR Vulnerabilities</strong> to configure target links for API authorization testing.
            </p>
          </div>
        )}

        {/* Error */}
        {error && (
          <div
            role="alert"
            className="flex items-start gap-2.5 p-3.5 rounded-xl bg-red-500/10
                       border border-red-500/25 text-red-400 text-sm backdrop-blur-md"
          >
            <AlertTriangle className="w-4 h-4 mt-0.5 flex-shrink-0" />
            {error}
          </div>
        )}
      </section>

      {/* ── Scan Failed Error Section ── */}
      {scanStatus === "error" && (
        <section
          id="scan-failed-banner"
          aria-label="Scan error"
          className="p-6 rounded-2xl liquid-glass border-red-500/25 text-red-200 shadow-xl space-y-3"
        >
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-red-500/10 text-red-400 border border-red-500/25">
              <AlertTriangle className="w-6 h-6" />
            </div>
            <div>
              <h3 className="text-base font-bold text-white tracking-wide">
                Scan Aborted: Input Verification Failed
              </h3>
              <p className="text-xs text-red-300/80">
                The scanner could not locate or connect to the specified target. Detection was stopped immediately to prevent false reports.
              </p>
            </div>
          </div>
          <div className="p-3.5 rounded-xl bg-black/40 border border-red-500/20 text-xs font-mono text-red-300 leading-relaxed">
            {error || "The repository URL or target URL does not exist or is unreachable."}
          </div>
        </section>
      )}

      {/* ── Scan Status ── */}
      {scanStatus !== "idle" && scanStatus !== "error" && (
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

      {/* ── Agent Activity with live trace ── */}
      {scanStatus === "scanning" && (
        <section
          id="agent-activity"
          aria-label="Agent activity"
          className="liquid-glass p-6 sm:p-7 space-y-4"
        >
          <div className="flex items-center justify-between">
            <h2 className="text-base sm:text-lg font-semibold text-white flex items-center gap-2.5">
              <Loader2 className="w-4 h-4 text-aegis-400 animate-spin" />
              Agent Pipeline Running…
            </h2>
            <span className="text-xs font-mono px-2.5 py-1 rounded-full bg-white/[0.04] border border-white/[0.08] text-aegis-300">{progress}%</span>
          </div>

          {/* Progress bar */}
          <div className="w-full h-1.5 bg-black/40 border border-white/[0.06] rounded-full overflow-hidden">
            <div
              className="h-full bg-gradient-to-r from-aegis-500 to-sky-400 transition-all duration-700 ease-out rounded-full"
              style={{ width: `${progress}%` }}
            />
          </div>

          {/* Agent stages */}
          <div className="grid grid-cols-1 sm:grid-cols-3 gap-2.5 pt-1">
            {(["recon", "reason", "verify"] as const).map((agent) => {
              const labels: Record<string, string> = {
                recon: detectionMode === "general" ? "Playwright Crawler" : "Recon Agent",
                reason: detectionMode === "general" ? "DAST Security Engine" : detectionMode === "bola_idor" ? "AI Reasoning Model (Active)" : "Reason Agent",
                verify: detectionMode === "general" ? "Deterministic Verifier" : "Verify Agent",
              };
              const isActive = currentAgent === agent;
              const isDone =
                (currentAgent === "reason" && agent === "recon") ||
                (currentAgent === "verify" && (agent === "recon" || agent === "reason")) ||
                currentAgent === "done";
              return (
                <div
                  key={agent}
                  className={`flex items-center gap-2.5 p-3 rounded-xl border transition-all ${
                    isActive 
                      ? "liquid-glass border-aegis-400/30 text-white" 
                      : isDone
                      ? "bg-white/[0.02] border-emerald-500/20 text-slate-300"
                      : "bg-white/[0.01] border-white/[0.05] text-slate-500"
                  }`}
                >
                  {isActive ? (
                    <Loader2 className="w-3.5 h-3.5 text-aegis-400 animate-spin flex-shrink-0" />
                  ) : isDone ? (
                    <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400 flex-shrink-0" />
                  ) : (
                    <Clock className="w-3.5 h-3.5 text-slate-500 flex-shrink-0" />
                  )}
                  <span className="text-xs font-medium">
                    {labels[agent]}
                  </span>
                  {isActive && (
                    <span className="ml-auto text-[10px] font-mono px-1.5 py-0.5 rounded bg-aegis-500/15 text-aegis-300 border border-aegis-500/20 animate-pulse">active</span>
                  )}
                </div>
              );
            })}
          </div>

          {/* Reasoning trace terminal */}
          {reasoningTrace.length > 0 && (
            <div
              ref={traceRef}
              className="mt-2 bg-[#040711]/90 border border-white/[0.08] rounded-xl p-3.5
                         font-mono text-xs text-slate-300 max-h-44 overflow-y-auto
                         space-y-1 backdrop-blur-md shadow-inner"
            >
              {reasoningTrace.map((entry, i) => (
                <p key={i} className="leading-relaxed flex items-start gap-2">
                  <span className="text-aegis-400 select-none">›</span>
                  <span className="text-slate-300">{entry}</span>
                </p>
              ))}
            </div>
          )}
        </section>
      )}

      {/* ── Results ── */}
      {scanStatus === "done" && scanReport && (
        <section
          id="scan-results"
          aria-label="Scan results"
          className="liquid-glass p-6 sm:p-7 space-y-4"
        >
          <div className="flex items-center justify-between border-b border-white/[0.06] pb-3">
            <h2 className="text-base sm:text-lg font-semibold text-white flex items-center gap-2">
              <CheckCircle2 className="w-5 h-5 text-emerald-400" />
              Scan Complete
            </h2>
            <span className="text-xs font-mono text-slate-400">
              {scanReport.vulnerabilities.length} {scanReport.vulnerabilities.length === 1 ? "vulnerability" : "vulnerabilities"} identified
            </span>
          </div>

          {scanReport.vulnerabilities.length === 0 ? (
            <p className="text-slate-400 text-sm py-4 text-center">
              No vulnerabilities detected. 🎉
            </p>
          ) : (
            <ul className="divide-y divide-white/[0.05]">
              {scanReport.vulnerabilities.map((vuln: DetectedVulnerability) => (
                <li
                  key={vuln.id}
                  className="py-3 px-3 -mx-1.5 flex items-start gap-3.5 text-sm cursor-pointer
                             hover:bg-white/[0.04] border border-transparent hover:border-white/[0.06] rounded-xl transition-all
                             group backdrop-blur-sm"
                  onClick={() => setSelectedVuln(vuln)}
                  role="button"
                  tabIndex={0}
                  onKeyDown={(e) => e.key === "Enter" && setSelectedVuln(vuln)}
                >
                  <span className={SEVERITY_STYLES[vuln.severity]}>
                    {vuln.severity}
                  </span>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <p className="font-semibold text-white group-hover:text-aegis-300 transition-colors">{vuln.title}</p>
                      {(vuln.cwe_id === "CWE-639" || vuln.owasp_category?.includes("API1") || vuln.title.toLowerCase().includes("bola") || vuln.title.toLowerCase().includes("idor")) ? (
                        <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-purple-500/10 text-purple-300 border border-purple-500/20">
                          BOLA / IDOR
                        </span>
                      ) : (
                        <span className="px-2 py-0.5 rounded text-[10px] uppercase font-bold tracking-wider bg-blue-500/10 text-blue-300 border border-blue-500/20">
                          General DAST
                        </span>
                      )}
                    </div>
                    <p className="text-slate-400 mt-1 text-xs flex items-center gap-2">
                      {vuln.cwe_id && (
                        <span className="font-mono text-slate-300 bg-white/[0.04] px-1.5 py-0.5 rounded border border-white/[0.06]">{vuln.cwe_id}</span>
                      )}
                      <span>{vuln.owasp_category}</span>
                    </p>
                  </div>
                  <ChevronRight className="w-4 h-4 text-slate-500 group-hover:text-aegis-300
                                          group-hover:translate-x-0.5 transition-all flex-shrink-0 mt-1" />
                </li>
              ))}
            </ul>
          )}
        </section>
      )}

      {/* ── CodeDiffViewer Modal ── */}
      {selectedVuln && (
        <div
          className="fixed inset-0 z-50 flex items-start justify-end"
          role="dialog"
          aria-modal="true"
        >
          {/* Backdrop */}
          <div
            className="absolute inset-0 bg-black/70 backdrop-blur-md transition-opacity"
            onClick={() => setSelectedVuln(null)}
          />
          {/* Drawer (spacious, trendy, responsive width) */}
          <div className="relative w-full max-w-4xl lg:max-w-5xl xl:max-w-6xl h-full bg-[#050813]/95 backdrop-blur-2xl shadow-2xl border-l border-white/[0.09] overflow-hidden z-10">
            <CodeDiffViewer
              vulnerability={selectedVuln}
              originalCode={selectedVuln.original_code}
              patchedCode={selectedVuln.patched_code}
              filePath={selectedVuln.file_path || selectedVuln.remediation?.match(/Source:\s*([^\n:]+)/)?.[1]}
              lineNumber={selectedVuln.line_number || Number(selectedVuln.remediation?.match(/:([0-9]+)/)?.[1] ?? 0) || undefined}
              onClose={() => setSelectedVuln(null)}
            />
          </div>
        </div>
      )}
    </div>
  );
}
