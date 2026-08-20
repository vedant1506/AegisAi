// =============================================================
// AegisAI — Shared TypeScript Schema Definitions
// Mirror of backend/app/schemas/io_models.py (Pydantic ↔ TS)
// =============================================================

// ── Severity ──────────────────────────────────────────────────
export type Severity = "CRITICAL" | "HIGH" | "MEDIUM" | "LOW" | "INFO";

// ── Scan Status ───────────────────────────────────────────────
export type ScanStatus =
  | "pending"
  | "running"
  | "completed"
  | "failed"
  | "cancelled";

// ── Endpoint Schema ──────────────────────────────────────────
/**
 * Represents a discovered API endpoint from crawler or SAST analysis.
 * Mirrors: EndpointSchema in io_models.py
 */
export interface EndpointSchema {
  url: string;
  method: "GET" | "POST" | "PUT" | "PATCH" | "DELETE" | "OPTIONS" | "HEAD";
  headers: Record<string, string>;
  /** Auth tokens associated with the endpoint (JWT, session, API key) */
  tokens: AuthTokens;
  body_schema?: Record<string, unknown> | null;
  discovered_at: string; // ISO 8601
}

export interface AuthTokens {
  jwt?: string | null;
  session_cookie?: string | null;
  api_key?: string | null;
  csrf_token?: string | null;
}

// ── AST Schema ────────────────────────────────────────────────
/**
 * Represents a route/symbol node extracted from static AST analysis.
 * Mirrors: ASTSchema in io_models.py
 */
export interface ASTSchema {
  route_path: string;
  file_path: string;
  line_number: number;
  language: "python" | "javascript" | "typescript" | "java" | "go" | "rust";
  function_name?: string | null;
  /** Raw source snippet around the route definition */
  source_snippet?: string | null;
  vulnerabilities?: DetectedVulnerability[];
}

// ── Vulnerability ─────────────────────────────────────────────
export interface DetectedVulnerability {
  id: string; // e.g. "VULN-2024-001"
  cwe_id?: string | null; // e.g. "CWE-89"
  owasp_category?: string | null; // e.g. "A03:2021"
  title: string;
  description: string;
  severity: Severity;
  confidence: number; // 0.0 – 1.0
  exploit_payload?: string | null;
  remediation?: string | null;
  references?: string[];
}

// ── Scan Request / Response ───────────────────────────────────
export interface ScanStartRequest {
  github_url: string;
  target_url: string;
  /** Branch to analyse; defaults to 'main' */
  branch?: string;
  scan_modules?: ScanModule[];
}

export type ScanModule = "sast" | "dast" | "ai_exploit" | "all";

export interface ScanStartResponse {
  scan_id: string;
  status: ScanStatus;
  message: string;
  created_at: string;
}

export interface ScanReport {
  scan_id: string;
  status: ScanStatus;
  github_url: string;
  target_url: string;
  started_at: string;
  completed_at?: string | null;
  duration_seconds?: number | null;
  ast_findings: ASTSchema[];
  endpoint_findings: EndpointSchema[];
  vulnerabilities: DetectedVulnerability[];
  summary: ScanSummary;
}

export interface ScanSummary {
  total_endpoints: number;
  total_ast_nodes: number;
  total_vulnerabilities: number;
  by_severity: Record<Severity, number>;
  risk_score: number; // 0 – 100
}

// ── Agent State (mirrors LangGraph state_graph.py) ────────────
export interface AgentState {
  scan_id: string;
  ast_data: ASTSchema[];
  crawler_data: EndpointSchema[];
  ai_exploit_payload?: string | null;
  reasoning_trace?: string[] | null;
  current_agent: "recon" | "reason" | "verify" | "done";
}

// ── Utility Types ─────────────────────────────────────────────
export type ApiResponse<T> = {
  data: T;
  success: boolean;
  error?: string | null;
};
