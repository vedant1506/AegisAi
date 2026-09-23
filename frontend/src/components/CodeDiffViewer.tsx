"use client";

/**
 * AegisAI — Modern CodeDiffViewer Component
 *
 * Displays a sleek, cyber-security grade code diff viewer:
 *  - Split (side-by-side) vs Unified (inline) view toggles
 *  - Clear syntax-like line rendering with preserved whitespace
 *  - Quick "Copy Security Patch" button
 *  - Structured tabs for Diff, Exploit Payload, and Remediation Guide
 *  - Severity glow indicators and clickable source breadcrumbs
 */

import React, { useState, useMemo } from "react";
import ReactDiffViewer, { DiffMethod } from "react-diff-viewer-continued";
import {
  X,
  AlertTriangle,
  Shield,
  BookOpen,
  ExternalLink,
  Hash,
  FileCode2,
  Copy,
  Check,
  Columns,
  AlignLeft,
  Sparkles,
  Terminal,
  ShieldAlert,
  ShieldCheck,
  CheckCircle2,
  Layers,
} from "lucide-react";
import type { DetectedVulnerability, Severity } from "@/types/schema";

interface CodeDiffViewerProps {
  vulnerability: DetectedVulnerability;
  originalCode?: string | null;
  patchedCode?: string | null;
  filePath?: string;
  lineNumber?: number;
  onClose: () => void;
}

/**
 * Aligns original code and security patch so that ONLY the specific changeable /
 * vulnerable code line is highlighted in red (-) and green (+), preserving
 * surrounding function signatures, decorators, and context as unchanged code.
 */
function alignDiffSnippets(
  orig: string,
  patch: string,
  vuln?: DetectedVulnerability
): { alignedOriginal: string; alignedPatched: string } {
  if (!orig || !patch) {
    return { alignedOriginal: orig || "", alignedPatched: patch || "" };
  }

  const origClean = orig.trimEnd();
  const patchClean = patch.trimEnd();

  const origLines = origClean.split("\n");
  const patchLines = patchClean.split("\n");

  const trimmedOrig = origLines.map((l) => l.trim()).filter(Boolean);
  const trimmedPatch = new Set(patchLines.map((l) => l.trim()).filter(Boolean));
  let commonCount = 0;
  for (const l of trimmedOrig) {
    if (trimmedPatch.has(l)) commonCount++;
  }

  // Already well-aligned if they share at least 2 non-empty lines
  if (commonCount >= 2 || (origLines.length <= 2 && patchLines.length <= 2)) {
    return { alignedOriginal: origClean, alignedPatched: patchClean };
  }

  // Identify vulnerable / changeable target line in orig
  let targetIdx = -1;
  let isReplacement = false;

  const cwe = (vuln?.cwe_id || "").toUpperCase();
  const title = (vuln?.title || "").toLowerCase();

  for (let i = 0; i < origLines.length; i++) {
    const l = origLines[i].toLowerCase();

    // SQL Injection targets (CWE-89)
    if (
      l.includes("db.query") ||
      l.includes("executequery") ||
      l.includes("cursor.execute") ||
      l.includes("session.query") ||
      l.includes("db.session") ||
      l.includes("execute(") ||
      l.includes("raw(") ||
      ((l.includes("select ") || l.includes("from ") || l.includes("where ")) &&
        (l.includes("%") || l.includes("+") || l.includes('f"') || l.includes(".format(")))
    ) {
      targetIdx = i;
      isReplacement = true;
      break;
    }

    // Deserialization / eval / template injection (CWE-502, CWE-1336, CWE-94)
    if (
      l.includes("yaml.load") ||
      l.includes("pickle.load") ||
      l.includes("pickle.loads") ||
      l.includes("render_template_string") ||
      l.includes("eval(") ||
      l.includes("exec(")
    ) {
      targetIdx = i;
      isReplacement = true;
      break;
    }

    // Weak crypto / broken token (CWE-327, CWE-287)
    if (
      l.includes("hashlib.md5") ||
      l.includes("md5(") ||
      l.includes("sha1(") ||
      l.includes("verify=false") ||
      l.includes("verify = false")
    ) {
      targetIdx = i;
      isReplacement = true;
      break;
    }

    // BOLA / IDOR resource query (CWE-639)
    if (
      (cwe.includes("639") || title.includes("bola") || title.includes("idor")) &&
      (l.includes("findbypk") ||
        l.includes("filter_by") ||
        l.includes("findbyid") ||
        l.includes("query.get") ||
        l.includes("findone"))
    ) {
      targetIdx = i;
      isReplacement = true;
      break;
    }
  }

  // If no specific vulnerability pattern matched, check for explicit "// Vulnerable" or "# Vulnerable" comments
  if (targetIdx === -1) {
    for (let i = 0; i < origLines.length; i++) {
      const l = origLines[i].toLowerCase();
      if (l.includes("vulnerable") || l.includes("todo: fix") || l.includes("fixme")) {
        targetIdx = i;
        isReplacement = true;
        break;
      }
    }
  }

  // Fallback: locate function signature insertion point
  if (targetIdx === -1) {
    for (let i = 0; i < origLines.length; i++) {
      const line = origLines[i];
      if (
        (line.includes("def ") ||
          line.includes("function") ||
          line.includes("=>") ||
          line.includes("class ") ||
          line.includes("func ")) &&
        !line.trim().startsWith("@")
      ) {
        let idx = i;
        while (
          idx < origLines.length &&
          !origLines[idx].trim().endsWith(":") &&
          !origLines[idx].includes("{")
        ) {
          idx++;
        }
        targetIdx = idx;
        isReplacement = false;
        // Skip docstring if immediately following
        if (targetIdx + 1 < origLines.length && origLines[targetIdx + 1].includes('"""')) {
          targetIdx++;
          while (targetIdx + 1 < origLines.length && !origLines[targetIdx + 1].includes('"""')) {
            targetIdx++;
          }
          targetIdx++;
        }
        break;
      }
    }
  }

  if (targetIdx !== -1) {
    const refLine = origLines[targetIdx] || "";
    const matchIndent = refLine.match(/^\s*/);
    const baseIndent = matchIndent && matchIndent[0] ? matchIndent[0] : "    ";

    const formattedPatch = patchLines.map((pl) =>
      pl.trim() ? `${baseIndent}${pl.trim()}` : ""
    );

    if (isReplacement) {
      const newPatchLines = [
        ...origLines.slice(0, targetIdx),
        ...formattedPatch,
        ...origLines.slice(targetIdx + 1),
      ];
      return {
        alignedOriginal: origLines.join("\n"),
        alignedPatched: newPatchLines.join("\n"),
      };
    } else {
      const newPatchLines = [
        ...origLines.slice(0, targetIdx + 1),
        ...formattedPatch,
        ...origLines.slice(targetIdx + 1),
      ];
      return {
        alignedOriginal: origLines.join("\n"),
        alignedPatched: newPatchLines.join("\n"),
      };
    }
  }

  return { alignedOriginal: origClean, alignedPatched: patchClean };
}

const severityConfig: Record<
  Severity,
  { border: string; bg: string; text: string; glow: string }
> = {
  CRITICAL: {
    border: "border-red-500/30",
    bg: "bg-red-500/10",
    text: "text-red-400",
    glow: "shadow-none",
  },
  HIGH: {
    border: "border-orange-500/30",
    bg: "bg-orange-500/10",
    text: "text-orange-400",
    glow: "shadow-none",
  },
  MEDIUM: {
    border: "border-amber-500/30",
    bg: "bg-amber-500/10",
    text: "text-amber-400",
    glow: "shadow-none",
  },
  LOW: {
    border: "border-sky-500/30",
    bg: "bg-sky-500/10",
    text: "text-sky-400",
    glow: "shadow-none",
  },
  INFO: {
    border: "border-slate-500/30",
    bg: "bg-slate-500/10",
    text: "text-slate-400",
    glow: "shadow-none",
  },
};

// Sleek modern dark theme diff styles
const modernDiffStyles = {
  variables: {
    dark: {
      diffViewerBackground: "#060914",
      diffViewerColor: "#cbd5e1",
      addedBackground: "#062e1b",
      addedColor: "#4ade80",
      removedBackground: "#380d12",
      removedColor: "#f87171",
      wordAddedBackground: "#14532d",
      wordRemovedBackground: "#7f1d1d",
      addedGutterBackground: "#063d27",
      removedGutterBackground: "#581216",
      gutterBackground: "#090e1f",
      gutterBackgroundDark: "#060914",
      highlightBackground: "#1e293b",
      highlightGutterBackground: "#1e293b",
      codeFoldBackground: "#090e1f",
      emptyLineBackground: "#060914",
      gutterColor: "#64748b",
      codeFoldContentColor: "#94a3b8",
      diffViewerTitleBackground: "#090e1f",
      diffViewerTitleColor: "#e2e8f0",
      diffViewerTitleBorderColor: "rgba(255,255,255,0.08)",
    },
  },
  line: {
    fontFamily:
      "'JetBrains Mono', 'Fira Code', 'Cascadia Code', Consolas, monospace",
    fontSize: "12.5px",
    lineHeight: "20px",
  },
};

export default function CodeDiffViewer({
  vulnerability,
  originalCode,
  patchedCode,
  filePath,
  lineNumber,
  onClose,
}: CodeDiffViewerProps) {
  const [splitView, setSplitView] = useState<boolean>(true);
  const [activeTab, setActiveTab] = useState<"diff" | "exploit" | "guide">("diff");
  const [copiedPatch, setCopiedPatch] = useState<boolean>(false);

  const sev = severityConfig[vulnerability.severity] || severityConfig.HIGH;

  // For DAST-only scans, extract endpoint/route or title rather than defaulting to app.py
  const rawFile =
    filePath ||
    vulnerability.file_path ||
    vulnerability.remediation?.match(/Source:\s*([^\n:]+)/)?.[1] ||
    "";

  const isUrl = rawFile.startsWith("http://") || rawFile.startsWith("https://");
  const extractedPath = isUrl
    ? (() => {
        try {
          const u = new URL(rawFile);
          return u.pathname + (u.search ? u.search : "");
        } catch {
          return rawFile;
        }
      })()
    : rawFile;

  const extractedFromTitle =
    vulnerability.title.match(/([a-zA-Z0-9_\-./]+\.(?:aspx|asp|php|jsp|html|json|\w+)(\?[^\s]+)?)/i)?.[1] ||
    vulnerability.title.match(/in\s+([^\s]+)/)?.[1];

  const displayFile =
    extractedPath ||
    extractedFromTitle ||
    (vulnerability.file_path ? vulnerability.file_path : "Live DAST Target");

  const rawLine =
    lineNumber ??
    vulnerability.line_number ??
    (vulnerability.remediation?.match(/:([0-9]+)/)?.[1]
      ? Number(vulnerability.remediation.match(/:([0-9]+)/)?.[1])
      : null);

  const displayLine = rawLine && rawLine > 0 ? rawLine : null;

  const isJsTs =
    displayFile.toLowerCase().endsWith(".ts") ||
    displayFile.toLowerCase().endsWith(".js") ||
    displayFile.toLowerCase().endsWith(".tsx") ||
    displayFile.toLowerCase().endsWith(".jsx");

  // Clean fallback snippet if none provided
  const targetRoute =
    vulnerability.title.match(/in\s+([^\s]+)/)?.[1] || "/api/Users/:id";

  const cleanOriginal =
    originalCode && !originalCode.includes("# Exploit: {")
      ? originalCode
      : isJsTs
      ? `// Vulnerable Express Route Handler (${displayFile})
app.route('${targetRoute}')
  .get(security.isAuthorized(), async (req: any, res: any) => {
    // Vulnerable: Returns record without verifying that requesting user matches :id
    const user = await models.User.findByPk(req.params.id);
    if (!user) return res.status(404).json({ error: "User not found" });
    res.json(user);
  });`
      : `@app.get("${targetRoute}")
async def get_resource_data(item_id: int, current_user: dict = Depends(get_current_user)):
    # Vulnerable: Missing authorization check on requested object id
    record = db.query(Resource).filter_by(id=item_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Item not found")
    return record`;

  const cleanPatched =
    patchedCode && !patchedCode.includes("# Fix: Validate")
      ? patchedCode
      : isJsTs
      ? `// AegisAI Security-Hardened Route Handler (CWE-639 / BOLA Fix)
app.route('${targetRoute}')
  .get(
    security.isAuthorized(),
    // AegisAI Security Fix: Verify caller ownership before accessing resource
    (req: any, res: any, next: any) => {
      if (req.user?.id != req.params.id && req.user?.role !== "admin") {
        return res.status(403).json({ error: "Access forbidden: cross-user access denied" });
      }
      next();
    },
    async (req: any, res: any) => {
      const user = await models.User.findByPk(req.params.id);
      if (!user) return res.status(404).json({ error: "User not found" });
      res.json(user);
    }
  );`
      : `@app.get("${targetRoute}")
async def get_resource_data(item_id: int, current_user: dict = Depends(get_current_user)):
    # AegisAI Security Fix: Verify ownership before returning sensitive data (CWE-639)
    if current_user.get("user_id") != item_id and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Forbidden: cross-tenant access denied")

    record = db.query(Resource).filter_by(id=item_id).first()
    if not record:
        raise HTTPException(status_code=404, detail="Item not found")
    return record`;

  const { alignedOriginal, alignedPatched } = useMemo(() => {
    return alignDiffSnippets(cleanOriginal, cleanPatched, vulnerability);
  }, [cleanOriginal, cleanPatched, vulnerability]);

  const handleCopyPatch = () => {
    navigator.clipboard.writeText(alignedPatched);
    setCopiedPatch(true);
    setTimeout(() => setCopiedPatch(false), 2000);
  };

  return (
    <div
      id={`diff-viewer-${vulnerability.id}`}
      role="dialog"
      aria-modal="true"
      className="flex flex-col h-full bg-[#050813] text-slate-200 border-l border-white/[0.08] shadow-none overflow-hidden"
    >
      {/* ── Top Bar / Header ── */}
      <header className="p-5 border-b border-white/[0.07] bg-[#070b18]/90 backdrop-blur-xl flex-shrink-0 space-y-3">
        <div className="flex items-start justify-between gap-4">
          <div className="space-y-1.5 flex-1 min-w-0">
            <div className="flex items-center gap-2 flex-wrap">
              {/* Severity badge */}
              <span
                className={`inline-flex items-center gap-1 px-2.5 py-0.5 rounded-full text-[11px] font-bold tracking-wider uppercase border ${sev.border} ${sev.bg} ${sev.text}`}
              >
                <ShieldAlert className="w-3 h-3" />
                {vulnerability.severity}
              </span>

              {/* CWE Badge */}
              {vulnerability.cwe_id && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] font-mono bg-white/[0.04] border border-white/[0.08] text-slate-300">
                  <Hash className="w-3 h-3 text-slate-400" />
                  {vulnerability.cwe_id}
                </span>
              )}

              {/* OWASP Badge */}
              {vulnerability.owasp_category && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded-md text-[11px] bg-aegis-500/10 border border-aegis-500/20 text-aegis-400">
                  <Shield className="w-3 h-3" />
                  {vulnerability.owasp_category.split("-")[0].trim()}
                </span>
              )}

              {/* Confidence */}
              <span className="text-[11px] text-slate-400 bg-white/[0.03] px-2 py-0.5 rounded-md border border-white/[0.06]">
                Confidence:{" "}
                <span className="text-emerald-400 font-semibold">
                  {Math.round(vulnerability.confidence * 100)}%
                </span>
              </span>
            </div>

            <h2 className="text-lg font-bold text-white tracking-tight leading-snug truncate">
              {vulnerability.title}
            </h2>

            {/* File & Line breadcrumb */}
            <div className="flex items-center gap-2 text-xs text-slate-400 font-mono">
              <FileCode2 className="w-3.5 h-3.5 text-aegis-400" />
              <span className="text-slate-300">{displayFile}</span>
              {displayLine !== null && (
                <span className="text-aegis-400 font-bold">:{displayLine}</span>
              )}
            </div>
          </div>

          {/* Close button */}
          <button
            onClick={onClose}
            aria-label="Close diff viewer"
            className="p-2 rounded-xl text-slate-400 hover:text-white hover:bg-white/[0.08] transition-colors border border-transparent hover:border-white/10 flex-shrink-0"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Action Toolbar & Navigation Tabs */}
        <div className="flex items-center justify-between gap-3 pt-2 border-t border-white/[0.06] flex-wrap">
          {/* Tabs */}
          <div className="flex items-center gap-1 p-1 rounded-xl bg-black/40 border border-white/[0.07] backdrop-blur-md">
            <button
              onClick={() => setActiveTab("diff")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === "diff"
                  ? "bg-white/[0.10] text-white shadow-sm border border-white/10"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <FileCode2 className="w-3.5 h-3.5 text-aegis-400" />
              Code Diff
            </button>
            <button
              onClick={() => setActiveTab("exploit")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === "exploit"
                  ? "bg-white/[0.10] text-white shadow-sm border border-white/10"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <Terminal className="w-3.5 h-3.5 text-amber-400" />
              Exploit PoC
            </button>
            <button
              onClick={() => setActiveTab("guide")}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-lg text-xs font-medium transition-all ${
                activeTab === "guide"
                  ? "bg-white/[0.10] text-white shadow-sm border border-white/10"
                  : "text-slate-400 hover:text-white"
              }`}
            >
              <BookOpen className="w-3.5 h-3.5 text-emerald-400" />
              Remediation
            </button>
          </div>

          {/* Right Toolbar Actions */}
          <div className="flex items-center gap-2">
            {activeTab === "diff" && (
              <div className="flex items-center rounded-xl bg-black/40 border border-white/[0.08] p-0.5 text-xs backdrop-blur-md">
                <button
                  onClick={() => setSplitView(true)}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors ${
                    splitView
                      ? "bg-white/[0.12] text-white font-semibold shadow-sm"
                      : "text-slate-400 hover:text-white"
                  }`}
                  title="Side-by-side split comparison"
                >
                  <Columns className="w-3.5 h-3.5" />
                  Split
                </button>
                <button
                  onClick={() => setSplitView(false)}
                  className={`flex items-center gap-1 px-2.5 py-1 rounded-lg transition-colors ${
                    !splitView
                      ? "bg-white/[0.12] text-white font-semibold shadow-sm"
                      : "text-slate-400 hover:text-white"
                  }`}
                  title="Unified single column diff"
                >
                  <AlignLeft className="w-3.5 h-3.5" />
                  Unified
                </button>
              </div>
            )}

            <button
              onClick={handleCopyPatch}
              className="flex items-center gap-1.5 px-3.5 py-1.5 rounded-xl text-xs font-semibold bg-emerald-500/10 border border-emerald-500/25 text-emerald-300 hover:bg-emerald-500/20 transition-all shadow-sm backdrop-blur-md"
            >
              {copiedPatch ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-400" />
                  Copied Patch!
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5" />
                  Copy Secure Fix
                </>
              )}
            </button>
          </div>
        </div>
      </header>

      {/* ── Content Area ── */}
      <div className="flex-1 overflow-y-auto">
        {/* Tab 1: Code Diff */}
        {activeTab === "diff" && (
          <div className="p-4 space-y-4">
            {/* Description Card */}
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.07] text-xs text-slate-300 leading-relaxed backdrop-blur-md">
              <span className="font-semibold text-white">Vulnerability Impact: </span>
              {vulnerability.description}
            </div>

            {/* Diff Container */}
            <div className="rounded-xl border border-white/[0.08] overflow-hidden shadow-2xl bg-[#060914]">
              {/* Custom Header labels for Diff columns */}
              <div className="grid grid-cols-2 text-xs font-mono font-semibold border-b border-white/[0.08] bg-[#090e1f]/90 backdrop-blur-md">
                <div className="px-4 py-2 text-red-400 flex items-center gap-2 border-r border-white/[0.08]">
                  <span className="w-2 h-2 rounded-full bg-red-400/90" />
                  Vulnerable Code (Before)
                </div>
                <div className="px-4 py-2 text-emerald-400 flex items-center gap-2">
                  <span className="w-2 h-2 rounded-full bg-emerald-400/90" />
                  AI-Secured Patch (After)
                </div>
              </div>

              <div className="overflow-x-auto">
                <ReactDiffViewer
                  oldValue={alignedOriginal}
                  newValue={alignedPatched}
                  splitView={splitView}
                  compareMethod={DiffMethod.WORDS}
                  useDarkTheme
                  styles={modernDiffStyles}
                  leftTitle=""
                  rightTitle=""
                />
              </div>
            </div>
          </div>
        )}

        {/* Tab 2: Exploit PoC Payload */}
        {activeTab === "exploit" && (
          <div className="p-5 space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="text-xs font-bold uppercase tracking-wider text-red-400 flex items-center gap-2">
                <AlertTriangle className="w-4 h-4" />
                Dynamic Exploit Verification Payload
              </h3>
              <span className="text-[11px] text-slate-400">
                Method: <span className="text-white font-mono">GET/POST</span>
              </span>
            </div>

            <p className="text-xs text-slate-400 leading-relaxed">
              The automated reasoning agent constructed the following probe to
              verify cross-tenant authorization leakage:
            </p>

            <pre className="p-4 rounded-xl bg-[#060914] border border-red-500/20 text-red-300 font-mono text-xs overflow-x-auto leading-relaxed shadow-inner backdrop-blur-md">
              {vulnerability.exploit_payload ||
                JSON.stringify(
                  {
                    target_url: `http://127.0.0.1:8081${targetRoute}`,
                    vulnerability: "CWE-639 Broken Object Level Authorization",
                    status: "Confirmed unauthorized object traversal",
                  },
                  null,
                  2
                )}
            </pre>
          </div>
        )}

        {/* Tab 3: Remediation Guide & References */}
        {activeTab === "guide" && (
          <div className="p-6 space-y-6 max-w-5xl mx-auto">
            {/* Header Banner */}
            <div className="p-4 rounded-xl bg-gradient-to-r from-aegis-950/40 via-white/[0.02] to-transparent border border-aegis-500/20 shadow-lg flex items-start gap-3 backdrop-blur-md">
              <div className="p-2 rounded-lg bg-aegis-500/10 border border-aegis-500/30 text-aegis-400 mt-0.5">
                <ShieldCheck className="w-5 h-5" />
              </div>
              <div className="flex-1 min-w-0">
                <h3 className="text-sm font-bold text-white tracking-wide">
                  Enterprise Remediation & Hardening Runbook
                </h3>
                <p className="text-xs text-slate-400 mt-0.5">
                  Actionable engineering specifications to eliminate Broken Object Level Authorization (CWE-639) and enforce zero-trust tenant boundary controls.
                </p>
              </div>
            </div>

            {/* Section 1: Root Cause Analysis */}
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.07] space-y-2 backdrop-blur-md">
              <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-amber-400">
                <AlertTriangle className="w-4 h-4" />
                Root Cause Analysis (Why this flaw exists)
              </div>
              <p className="text-xs text-slate-300 leading-relaxed">
                The endpoint accepts an arbitrary resource identifier (such as an integer database primary key or UUID) from the client via the URL path or payload, and queries the database record without validating that the authenticated session (<code className="text-aegis-300 font-mono bg-white/5 px-1 py-0.5 rounded">current_user</code>) owns or possesses explicit tenant permissions to access that object. Because access control is decoupled from data retrieval, an attacker can trivially iterate or modify the ID to read, modify, or delete records belonging to any other user in the system.
              </p>
            </div>

            {/* Target-Specific Diagnostic Findings */}
            {vulnerability.remediation && (
              <div className="p-4 rounded-xl bg-aegis-950/25 border border-aegis-500/20 space-y-2 backdrop-blur-md">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-aegis-400">
                  <Sparkles className="w-4 h-4" />
                  Target-Specific Diagnostic Findings
                </div>
                <div className="text-xs text-slate-300 font-mono whitespace-pre-wrap leading-relaxed bg-black/40 p-3 rounded-lg border border-white/5">
                  {vulnerability.remediation.replace(/📁 Source:[\s\S]*$/, "").trim()}
                </div>
              </div>
            )}

            {/* Section 2: 4-Step Engineering Mitigation Plan */}
            <div className="space-y-3">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Layers className="w-4 h-4 text-aegis-400" />
                4-Step Engineering Mitigation Plan
              </h4>

              <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                {/* Step 1 */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.07] space-y-2 hover:border-aegis-500/30 transition-colors backdrop-blur-md">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-aegis-500/15 text-aegis-300 font-bold text-[11px] flex items-center justify-center border border-aegis-500/30">
                      1
                    </span>
                    <h5 className="text-xs font-semibold text-white">
                      Cryptographic Session Binding
                    </h5>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Never trust client-supplied identity parameters in request parameters or JSON bodies. Always extract caller credentials (<code className="text-slate-300 font-mono text-[11px]">user_id</code> and <code className="text-slate-300 font-mono text-[11px]">tenant_id</code>) exclusively from validated server-side session cookies or verified JWT claims.
                  </p>
                </div>

                {/* Step 2 */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.07] space-y-2 hover:border-aegis-500/30 transition-colors backdrop-blur-md">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-aegis-500/15 text-aegis-300 font-bold text-[11px] flex items-center justify-center border border-aegis-500/30">
                      2
                    </span>
                    <h5 className="text-xs font-semibold text-white">
                      Direct Database Tenant Scoping
                    </h5>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Never fetch by primary key alone. Enforce compound SQL/ORM filters: <code className="text-emerald-400 font-mono text-[11px]">.filter_by(id=target_id, tenant_id=current_user.tenant_id)</code>. This ensures cross-tenant queries return zero records directly at the database layer.
                  </p>
                </div>

                {/* Step 3 */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.07] space-y-2 hover:border-aegis-500/30 transition-colors backdrop-blur-md">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-aegis-500/15 text-aegis-300 font-bold text-[11px] flex items-center justify-center border border-aegis-500/30">
                      3
                    </span>
                    <h5 className="text-xs font-semibold text-white">
                      Declarative Dependency Guards
                    </h5>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Centralize authorization checks into reusable FastAPI security dependencies (<code className="text-slate-300 font-mono text-[11px]">Depends(verify_ownership)</code>). Decouple route business logic from access enforcement to guarantee uniform application across all CRUD routes.
                  </p>
                </div>

                {/* Step 4 */}
                <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.07] space-y-2 hover:border-aegis-500/30 transition-colors backdrop-blur-md">
                  <div className="flex items-center gap-2">
                    <span className="w-5 h-5 rounded-full bg-aegis-500/15 text-aegis-300 font-bold text-[11px] flex items-center justify-center border border-aegis-500/30">
                      4
                    </span>
                    <h5 className="text-xs font-semibold text-white">
                      Non-Enumerable Identifiers
                    </h5>
                  </div>
                  <p className="text-xs text-slate-400 leading-relaxed">
                    Migrate from predictable auto-increment integers (<code className="text-slate-300 font-mono text-[11px]">id: 1, 2, 3...</code>) to cryptographically random UUIDv4 or KSUIDs. This completely prevents automated scanning and ID harvesting attacks.
                  </p>
                </div>
              </div>
            </div>

            {/* Section 3: Production Code Implementation Architecture */}
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.07] space-y-3 backdrop-blur-md">
              <div className="flex items-center justify-between">
                <div className="flex items-center gap-2 text-xs font-bold uppercase tracking-wider text-slate-200">
                  <FileCode2 className="w-4 h-4 text-emerald-400" />
                  Production Guard Architecture Pattern (FastAPI)
                </div>
                <button
                  onClick={() => {
                    const guardSnippet = `# app/security/guards.py
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session
from app.core.auth import get_current_user
from app.db.session import get_db

async def verify_resource_ownership(
    item_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Enforce BOLA / IDOR protection with tenant scoping."""
    record = db.query(Resource).filter(
        Resource.id == item_id,
        Resource.tenant_id == current_user.get("tenant_id")
    ).first()

    if not record:
        # Return 404 to avoid leaking object existence across tenants
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Resource not found or unauthorized"
        )
    return record`;
                    navigator.clipboard.writeText(guardSnippet);
                    setCopiedPatch(true);
                    setTimeout(() => setCopiedPatch(false), 2000);
                  }}
                  className="flex items-center gap-1.5 px-2.5 py-1 rounded-md text-[11px] font-medium bg-white/5 hover:bg-white/10 text-slate-300 border border-white/10 transition-colors"
                >
                  <Copy className="w-3 h-3" />
                  Copy Guard Code
                </button>
              </div>

              <pre className="p-3.5 rounded-lg bg-[#060914] border border-white/[0.06] font-mono text-[11.5px] text-emerald-300/90 overflow-x-auto leading-relaxed">
{`# app/security/guards.py — Reusable Ownership Dependency
from fastapi import Depends, HTTPException, status
from sqlalchemy.orm import Session

async def verify_resource_ownership(
    item_id: int,
    current_user: dict = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    # Enforce database tenant filter
    record = db.query(Resource).filter(
        Resource.id == item_id,
        Resource.tenant_id == current_user.get("tenant_id")
    ).first()

    if not record:
        raise HTTPException(status_code=404, detail="Resource not found")
    return record`}
              </pre>
            </div>

            {/* Section 4: Defense-in-Depth Verification Checklist */}
            <div className="p-4 rounded-xl bg-white/[0.02] border border-white/[0.07] space-y-3 backdrop-blur-md">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-300 flex items-center gap-2">
                <Shield className="w-4 h-4 text-emerald-400" />
                Defense-in-Depth Verification Checklist
              </h4>
              <div className="space-y-2 text-xs">
                <div className="flex items-start gap-2.5 text-slate-300">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                  <span>
                    <strong className="text-white">Multi-Tenant Integration Tests:</strong> Add automated test cases in Pytest verifying that attempting to access a resource with an unauthorized token yields HTTP 403 or 404.
                  </span>
                </div>
                <div className="flex items-start gap-2.5 text-slate-300">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                  <span>
                    <strong className="text-white">Audit Logging & Alerting:</strong> Emit structured security telemetry whenever an unauthorized object access attempt occurs, capturing client IP, user ID, and requested object.
                  </span>
                </div>
                <div className="flex items-start gap-2.5 text-slate-300">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                  <span>
                    <strong className="text-white">API Gateway Rate Limiting:</strong> Configure burst-limiting on parameterized resource routes to thwart automated integer enumeration.
                  </span>
                </div>
                <div className="flex items-start gap-2.5 text-slate-300">
                  <CheckCircle2 className="w-4 h-4 text-emerald-400 flex-shrink-0 mt-0.5" />
                  <span>
                    <strong className="text-white">CI/CD AST Verification:</strong> Run AegisAI AST and DAST correlation checks in continuous integration pipelines to prevent authorization regression.
                  </span>
                </div>
              </div>
            </div>

            {/* Section 5: Security Standards & Compliance References */}
            <div className="space-y-2">
              <h4 className="text-xs font-bold uppercase tracking-wider text-slate-400">
                Security Compliance & Framework Cross-Reference
              </h4>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-2">
                <a
                  href="https://owasp.org/API-Security/editions/2023/en/0xa1-broken-object-level-authorization/"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] hover:border-aegis-500/30 text-xs text-slate-300 hover:text-white flex flex-col justify-between transition-colors group backdrop-blur-md"
                >
                  <div className="flex items-center justify-between text-aegis-400 font-semibold mb-1">
                    <span>OWASP API1:2023</span>
                    <ExternalLink className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <span className="text-[11px] text-slate-400">
                    Broken Object Level Authorization standard specification and mitigation guide.
                  </span>
                </a>

                <a
                  href="https://cwe.mitre.org/data/definitions/639.html"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] hover:border-aegis-500/30 text-xs text-slate-300 hover:text-white flex flex-col justify-between transition-colors group backdrop-blur-md"
                >
                  <div className="flex items-center justify-between text-amber-400 font-semibold mb-1">
                    <span>MITRE CWE-639</span>
                    <ExternalLink className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <span className="text-[11px] text-slate-400">
                    Authorization Bypass Through User-Controlled Key taxonomy & vulnerability patterns.
                  </span>
                </a>

                <a
                  href="https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="p-3 rounded-xl bg-white/[0.02] border border-white/[0.06] hover:border-aegis-500/30 text-xs text-slate-300 hover:text-white flex flex-col justify-between transition-colors group backdrop-blur-md"
                >
                  <div className="flex items-center justify-between text-sky-400 font-semibold mb-1">
                    <span>NIST SP 800-53 (AC-3)</span>
                    <ExternalLink className="w-3.5 h-3.5 group-hover:translate-x-0.5 transition-transform" />
                  </div>
                  <span className="text-[11px] text-slate-400">
                    Federal Access Enforcement & Least Privilege security control specifications.
                  </span>
                </a>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}
