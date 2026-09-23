"""
AegisAI — Pydantic I/O Models (API Contract)
==============================================
Single source of truth for all request/response schemas.
These models are used by FastAPI for automatic validation,
serialisation, and OpenAPI schema generation.

TypeScript equivalents live in: frontend/src/types/schema.ts
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Generic, TypeVar
from uuid import UUID, uuid4

from pydantic import BaseModel, Field, HttpUrl, field_validator, model_validator


# ── Enums ─────────────────────────────────────────────────────

class Severity(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH     = "HIGH"
    MEDIUM   = "MEDIUM"
    LOW      = "LOW"
    INFO     = "INFO"


class ScanStatus(str, Enum):
    PENDING   = "pending"
    RUNNING   = "running"
    COMPLETED = "completed"
    FAILED    = "failed"
    CANCELLED = "cancelled"


class ScanModule(str, Enum):
    SAST       = "sast"
    DAST       = "dast"
    AI_EXPLOIT = "ai_exploit"
    ALL        = "all"


class ProgrammingLanguage(str, Enum):
    PYTHON     = "python"
    JAVASCRIPT = "javascript"
    TYPESCRIPT = "typescript"
    JAVA       = "java"
    GO         = "go"
    RUST       = "rust"
    PHP        = "php"
    RUBY       = "ruby"
    CSHARP     = "csharp"


# ── Auth Tokens ───────────────────────────────────────────────

class AuthTokens(BaseModel):
    """Authentication credentials discovered during crawling."""

    jwt: str | None = Field(
        default=None,
        description="JSON Web Token extracted from auth flow.",
    )
    session_cookie: str | None = Field(
        default=None,
        description="Session cookie value (e.g. connect.sid, PHPSESSID).",
    )
    api_key: str | None = Field(
        default=None,
        description="API key found in request headers.",
    )
    csrf_token: str | None = Field(
        default=None,
        description="CSRF token required for state-mutating requests.",
    )


# ── Endpoint Schema ───────────────────────────────────────────

class EndpointSchema(BaseModel):
    """
    Represents a discovered API endpoint from DAST crawling.

    Captured by the Playwright bot and enriched by the token manager
    before being passed into the AI reasoning pipeline.
    """

    url: str = Field(..., description="Full URL of the endpoint.")
    method: str = Field(
        ...,
        pattern="^(GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD)$",
        description="HTTP method used to reach this endpoint.",
    )
    headers: dict[str, str] = Field(
        default_factory=dict,
        description="Request headers observed or required by this endpoint.",
    )
    tokens: AuthTokens = Field(
        default_factory=AuthTokens,
        description="Auth credentials associated with this endpoint.",
    )
    body_schema: dict[str, Any] | None = Field(
        default=None,
        description="JSON body schema inferred from the request payload.",
    )
    discovered_at: datetime = Field(
        default_factory=datetime.utcnow,
        description="UTC timestamp when this endpoint was first discovered.",
    )

    model_config = {"json_schema_extra": {
        "example": {
            "url": "http://localhost:3000/api/user/login",
            "method": "POST",
            "headers": {"Content-Type": "application/json"},
            "tokens": {"jwt": None, "session_cookie": "abc123"},
            "body_schema": {"email": "string", "password": "string"},
            "discovered_at": "2024-01-15T10:30:00Z",
        }
    }}


# ── AST Schema ────────────────────────────────────────────────

class ASTSchema(BaseModel):
    """
    Represents a route or code symbol node extracted from SAST analysis.

    Produced by tree_sitter_engine.py and consumed by the AI Reason Agent
    to correlate static findings with dynamic crawler results.
    """

    route_path: str = Field(
        ...,
        description="The URL route pattern defined at this location (e.g. '/api/user/<id>').",
        examples=["/api/user/<id>", "/admin/settings"],
    )
    file_path: str = Field(
        ...,
        description="Repository-relative path to the source file.",
        examples=["backend/app/api/users.py"],
    )
    line_number: int = Field(
        ...,
        ge=1,
        description="Line number where the route/function is defined (1-indexed).",
    )
    language: ProgrammingLanguage = Field(
        ...,
        description="Programming language of the source file.",
    )
    function_name: str | None = Field(
        default=None,
        description="Name of the handler function if resolvable.",
    )
    source_snippet: str | None = Field(
        default=None,
        description="Raw source code surrounding the route definition (for AI context).",
    )
    vulnerabilities: list["DetectedVulnerability"] = Field(
        default_factory=list,
        description="Vulnerabilities identified at this AST node.",
    )

    model_config = {"json_schema_extra": {
        "example": {
            "route_path": "/api/user/<id>",
            "file_path": "backend/app/api/users.py",
            "line_number": 42,
            "language": "python",
            "function_name": "get_user",
            "source_snippet": "@app.get('/api/user/{id}')\nasync def get_user(id: int): ...",
            "vulnerabilities": [],
        }
    }}


# ── Detected Vulnerability ────────────────────────────────────

class DetectedVulnerability(BaseModel):
    """A single vulnerability finding produced by SAST, DAST, or the AI agent."""

    id: str = Field(
        default_factory=lambda: f"VULN-{uuid4().hex[:8].upper()}",
        description="Unique vulnerability identifier.",
    )
    cwe_id: str | None = Field(
        default=None,
        description="CWE identifier (e.g. 'CWE-89' for SQL Injection).",
        examples=["CWE-89", "CWE-79", "CWE-22"],
    )
    owasp_category: str | None = Field(
        default=None,
        description="OWASP Top 10 category (e.g. 'A03:2021').",
    )
    title: str = Field(..., description="Short, human-readable vulnerability title.")
    description: str = Field(..., description="Detailed description of the vulnerability.")
    severity: Severity = Field(..., description="Severity rating.")
    confidence: float = Field(
        ...,
        ge=0.0,
        le=1.0,
        description="Model confidence score between 0.0 and 1.0.",
    )
    exploit_payload: str | None = Field(
        default=None,
        description="AI-generated exploit payload demonstrating the vulnerability.",
    )
    remediation: str | None = Field(
        default=None,
        description="Recommended remediation steps.",
    )
    references: list[str] = Field(
        default_factory=list,
        description="External references (NVD, CWE, OWASP links).",
    )
    original_code: str | None = Field(
        default=None,
        description="Vulnerable code snippet from the repository.",
    )
    patched_code: str | None = Field(
        default=None,
        description="Remediated code snippet generated by the AI reasoning engine.",
    )
    file_path: str | None = Field(
        default=None,
        description="Target source file path.",
    )
    line_number: int | None = Field(
        default=None,
        description="Line number where the vulnerable handler is located.",
    )
    route_path: str | None = Field(
        default=None,
        description="Endpoint route path where the vulnerability is exposed.",
    )


# ── Scan Request / Response ───────────────────────────────────

class ScanStartRequest(BaseModel):
    """Request body for POST /api/v1/scan/start."""

    github_url: str | None = Field(
        default=None,
        description="Public or private GitHub repository URL to clone and analyse. Optional for DAST-only scans.",
        examples=["https://github.com/juice-shop/juice-shop"],
    )
    target_url: str | None = Field(
        default=None,
        description="Base URL of the running target application for DAST. Optional for SAST-only scans.",
        examples=["http://localhost:3000"],
    )
    branch: str = Field(
        default="main",
        description="Git branch to check out for SAST analysis.",
    )
    scan_modules: list[ScanModule] = Field(
        default=[ScanModule.ALL],
        description="Which scan modules to run.",
    )
    detection_mode: str = Field(
        default="all",
        description="Vulnerability detection focus: 'general' (Burp/Acunetix DAST style), 'bola_idor' (BOLA / IDOR API security), or 'all' (Both).",
    )

    @field_validator("github_url")
    @classmethod
    def validate_github_url(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        v = v.strip()
        import os
        if v.startswith(("https://github.com/", "git@github.com:", "https://", "http://")) or os.path.exists(v) or (len(v) > 2 and v[1] == ":"):
            return v
        raise ValueError("github_url must be a valid GitHub repository URL or existing directory path.")

    @field_validator("target_url")
    @classmethod
    def validate_target_url(cls, v: str | None) -> str | None:
        if v is None or not v.strip():
            return None
        v = v.strip()
        if not v.startswith(("http://", "https://")):
            raise ValueError("target_url must start with http:// or https://")
        return v

    @model_validator(mode="after")
    def check_at_least_one_target(self) -> "ScanStartRequest":
        if not self.github_url and not self.target_url:
            raise ValueError("At least one of github_url (for SAST) or target_url (for DAST) must be provided.")
        return self


class ScanStartResponse(BaseModel):
    """Response for POST /api/v1/scan/start."""

    scan_id: str = Field(..., description="Unique scan job identifier (UUID).")
    status: ScanStatus = Field(default=ScanStatus.PENDING)
    message: str = Field(default="Scan queued successfully.")
    created_at: datetime = Field(default_factory=datetime.utcnow)


class ScanSummary(BaseModel):
    """Aggregated metrics for a completed scan."""

    total_endpoints: int = 0
    total_ast_nodes: int = 0
    total_vulnerabilities: int = 0
    by_severity: dict[Severity, int] = Field(default_factory=dict)
    risk_score: float = Field(
        default=0.0,
        ge=0.0,
        le=100.0,
        description="Composite risk score from 0 (safe) to 100 (critical).",
    )


class ScanReport(BaseModel):
    """Full report returned by GET /api/v1/scan/{scan_id}/report."""

    scan_id: str
    status: ScanStatus
    github_url: str | None = None
    target_url: str | None = None
    started_at: datetime
    completed_at: datetime | None = None
    duration_seconds: float | None = None
    ast_findings: list[ASTSchema] = Field(default_factory=list)
    endpoint_findings: list[EndpointSchema] = Field(default_factory=list)
    vulnerabilities: list[DetectedVulnerability] = Field(default_factory=list)
    summary: ScanSummary = Field(default_factory=ScanSummary)


# ── Agent State (mirrors LangGraph state_graph.py) ────────────

class AgentStateSchema(BaseModel):
    """Serialisable snapshot of LangGraph agent state for API responses."""

    scan_id: str
    ast_data: list[ASTSchema] = Field(default_factory=list)
    crawler_data: list[EndpointSchema] = Field(default_factory=list)
    ai_exploit_payload: str | None = None
    reasoning_trace: list[str] = Field(default_factory=list)
    current_agent: str = Field(
        default="recon",
        description="Which agent node is currently executing.",
    )


# ── Generic API Response wrapper ─────────────────────────────

T = TypeVar("T")


class ApiResponse(BaseModel, Generic[T]):
    """Generic success/error envelope for all API responses."""

    data: T
    success: bool = True
    error: str | None = None

