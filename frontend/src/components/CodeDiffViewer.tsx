"use client";

/**
 * AegisAI — CodeDiffViewer Component
 *
 * Displays a side-by-side diff of vulnerable vs. remediated code,
 * alongside full vulnerability metadata for a single finding.
 *
 * Props:
 *  - `vulnerability`  : The detected vulnerability object
 *  - `originalCode`   : Raw vulnerable code snippet
 *  - `patchedCode`    : Remediated code snippet (from AI suggestion)
 *  - `onClose`        : Callback to dismiss/navigate away
 *
 * TODO: Wire up to /api/v1/scan/{scan_id}/finding/{vuln_id}
 *       to fetch original + patched code from the backend.
 */

import React from "react";
import ReactDiffViewer, { DiffMethod } from "react-diff-viewer-continued";
import {
  X,
  AlertTriangle,
  Shield,
  BookOpen,
  ExternalLink,
  Hash,
  FileCode2,
} from "lucide-react";
import type { DetectedVulnerability, Severity } from "@/types/schema";

// ── Types ─────────────────────────────────────────────────────
interface CodeDiffViewerProps {
  vulnerability: DetectedVulnerability;
  originalCode: string;
  patchedCode: string;
  filePath?: string;
  lineNumber?: number;
  onClose: () => void;
}

// ── Severity colour utils ─────────────────────────────────────
const severityBorderMap: Record<Severity, string> = {
  CRITICAL: "border-red-500/50",
  HIGH: "border-orange-500/50",
  MEDIUM: "border-yellow-500/50",
  LOW: "border-blue-500/50",
  INFO: "border-slate-500/50",
};

const severityTextMap: Record<Severity, string> = {
  CRITICAL: "text-red-400",
  HIGH: "text-orange-400",
  MEDIUM: "text-yellow-400",
  LOW: "text-blue-400",
  INFO: "text-slate-400",
};

// ── Custom diff styles (dark theme) ──────────────────────────
const diffStyles = {
  variables: {
    dark: {
      diffViewerBackground: "#0f172a",
      diffViewerColor: "#e2e8f0",
      addedBackground: "#14532d33",
      addedColor: "#86efac",
      removedBackground: "#7f1d1d33",
      removedColor: "#fca5a5",
      wordAddedBackground: "#15803d55",
      wordRemovedBackground: "#b9182555",
      addedGutterBackground: "#14532d55",
      removedGutterBackground: "#7f1d1d55",
      gutterBackground: "#1e293b",
      gutterBackgroundDark: "#0f172a",
      highlightBackground: "#1e3a5f",
      highlightGutterBackground: "#1e3a5f",
      codeFoldBackground: "#1e293b",
      emptyLineBackground: "#0f172a",
      gutterColor: "#475569",
      codeFoldContentColor: "#94a3b8",
      diffViewerTitleBackground: "#1e293b",
      diffViewerTitleColor: "#e2e8f0",
      diffViewerTitleBorderColor: "#334155",
    },
  },
};

// ── Component ─────────────────────────────────────────────────
export default function CodeDiffViewer({
  vulnerability,
  originalCode,
  patchedCode,
  filePath,
  lineNumber,
  onClose,
}: CodeDiffViewerProps) {
  const borderClass = severityBorderMap[vulnerability.severity];
  const textClass = severityTextMap[vulnerability.severity];

  return (
    <div
      id={`diff-viewer-${vulnerability.id}`}
      role="dialog"
      aria-modal="true"
      aria-labelledby="diff-viewer-title"
      className={`flex flex-col h-full bg-slate-950 border-l ${borderClass} overflow-hidden`}
    >
      {/* ── Header ── */}
      <header className="flex items-start justify-between p-4 border-b border-white/10 flex-shrink-0">
        <div className="space-y-1">
          <h2
            id="diff-viewer-title"
            className="font-semibold text-white text-base"
          >
            {vulnerability.title}
          </h2>

          <div className="flex flex-wrap items-center gap-2 text-xs">
            {/* CWE */}
            {vulnerability.cwe_id && (
              <span className="flex items-center gap-1 font-mono text-slate-400">
                <Hash className="w-3 h-3" />
                {vulnerability.cwe_id}
              </span>
            )}
            {/* OWASP */}
            {vulnerability.owasp_category && (
              <span className="flex items-center gap-1 text-slate-400">
                <Shield className="w-3 h-3" />
                {vulnerability.owasp_category}
              </span>
            )}
            {/* Severity */}
            <span className={`font-semibold uppercase ${textClass}`}>
              {vulnerability.severity}
            </span>
            {/* Confidence */}
            <span className="text-slate-500">
              Confidence:{" "}
              <span className="text-slate-300">
                {Math.round(vulnerability.confidence * 100)}%
              </span>
            </span>
          </div>

          {/* File path */}
          {filePath && (
            <p className="flex items-center gap-1 text-xs text-slate-500 font-mono">
              <FileCode2 className="w-3 h-3" />
              {filePath}
              {lineNumber != null && (
                <span className="text-aegis-500">:{lineNumber}</span>
              )}
            </p>
          )}
        </div>

        <button
          id="close-diff-viewer-btn"
          onClick={onClose}
          aria-label="Close diff viewer"
          className="p-1.5 rounded-lg text-slate-400 hover:text-white
                     hover:bg-white/10 transition-colors flex-shrink-0"
        >
          <X className="w-5 h-5" />
        </button>
      </header>

      {/* ── Description ── */}
      <div className="p-4 border-b border-white/10 flex-shrink-0">
        <p className="text-sm text-slate-300">{vulnerability.description}</p>
      </div>

      {/* ── Code Diff ── */}
      <div className="flex-1 overflow-auto text-xs">
        <ReactDiffViewer
          oldValue={originalCode}
          newValue={patchedCode}
          splitView={true}
          compareMethod={DiffMethod.WORDS}
          useDarkTheme
          styles={diffStyles}
          leftTitle="Vulnerable Code"
          rightTitle="AI-Suggested Patch"
        />
      </div>

      {/* ── Remediation ── */}
      {vulnerability.remediation && (
        <section className="p-4 border-t border-white/10 flex-shrink-0 space-y-2">
          <h3 className="text-sm font-semibold text-white flex items-center gap-1.5">
            <BookOpen className="w-4 h-4 text-aegis-400" />
            Remediation
          </h3>
          <p className="text-sm text-slate-400">{vulnerability.remediation}</p>
        </section>
      )}

      {/* ── References ── */}
      {vulnerability.references && vulnerability.references.length > 0 && (
        <section className="px-4 pb-4 space-y-1.5 flex-shrink-0">
          <h3 className="text-xs font-semibold text-slate-500 uppercase tracking-wider">
            References
          </h3>
          <ul className="space-y-1">
            {vulnerability.references.map((ref) => (
              <li key={ref}>
                <a
                  href={ref}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="flex items-center gap-1 text-xs text-aegis-400
                             hover:text-aegis-300 transition-colors"
                >
                  <ExternalLink className="w-3 h-3" />
                  {ref}
                </a>
              </li>
            ))}
          </ul>
        </section>
      )}

      {/* ── Exploit Payload ── */}
      {vulnerability.exploit_payload && (
        <section className="px-4 pb-4 space-y-1.5 flex-shrink-0">
          <h3 className="text-xs font-semibold text-red-400 uppercase tracking-wider flex items-center gap-1.5">
            <AlertTriangle className="w-3.5 h-3.5" />
            AI Exploit Payload
          </h3>
          <pre className="code-block text-red-300 text-xs max-h-40 overflow-y-auto">
            {vulnerability.exploit_payload}
          </pre>
        </section>
      )}
    </div>
  );
}
