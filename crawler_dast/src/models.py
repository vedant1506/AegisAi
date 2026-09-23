"""
AegisAI — DAST Reconnaissance & Verification Data Contracts
============================================================
Strongly-typed Pydantic models for the DAST crawler, test runner,
verification engine, and false-positive filter.

Full interoperability with backend/app/schemas/io_models.py (EndpointSchema, AuthTokens)
and ai_engine/multi_agent/state_graph.py.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any
from uuid import uuid4

from pydantic import BaseModel, Field


# ── Verification Status Enum ──────────────────────────────────

class VerificationStatus(str, Enum):
    VERIFIED = "VERIFIED"
    LIKELY = "LIKELY"
    INCONCLUSIVE = "INCONCLUSIVE"
    FALSE_POSITIVE = "FALSE_POSITIVE"
    ERROR = "ERROR"


# ── Target Metadata ───────────────────────────────────────────

class TargetInfo(BaseModel):
    """Information about the scanned target host."""
    base_url: str
    host: str = ""
    port: int = 80
    scheme: str = "http"
    is_reachable: bool = False
    response_time_ms: float = 0.0
    server_banner: str | None = None
    detected_framework: str | None = None
    technologies: list[str] = Field(default_factory=list)


# ── Reconnaissance Items ──────────────────────────────────────

class DiscoveredRoute(BaseModel):
    """A web page or SPA view route discovered by the browser."""
    path: str
    full_url: str
    method: str = "GET"
    status_code: int | None = None
    content_type: str | None = None
    page_title: str | None = None
    is_spa_route: bool = False
    headers: dict[str, str] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class DiscoveredParameter(BaseModel):
    """A dynamic parameter found in forms, URL queries, or API payloads."""
    name: str
    location: str = "query"  # "query", "body", "path", "header"
    endpoint_url: str
    method: str = "GET"
    sample_value: Any = None


class DiscoveredForm(BaseModel):
    """HTML / DOM form identified during crawling."""
    action_url: str
    method: str = "POST"
    page_url: str
    inputs: list[dict[str, Any]] = Field(default_factory=list)
    has_csrf: bool = False


class DiscoveredAPI(BaseModel):
    """An intercepted API / XHR / Fetch network request."""
    url: str
    method: str
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, str] = Field(default_factory=dict)
    body_sample: str | None = None
    response_status: int | None = None
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_time_ms: float = 0.0
    content_type: str = "application/json"
    tokens: dict[str, str | None] = Field(default_factory=dict)
    discovered_at: datetime = Field(default_factory=datetime.utcnow)


class AuthMetadata(BaseModel):
    """Safe metadata regarding acquired authentication state (no raw secrets)."""
    has_jwt: bool = False
    jwt_subject: str | None = None
    jwt_roles: list[str] = Field(default_factory=list)
    jwt_expired: bool = False
    has_session_cookie: bool = False
    cookie_names: list[str] = Field(default_factory=list)
    has_csrf_token: bool = False
    has_api_key: bool = False
    active_sessions: list[str] = Field(default_factory=lambda: ["default"])


class Observation(BaseModel):
    """Security or operational observation made during recon."""
    category: str  # e.g., "auth", "cors", "info_leak", "waf"
    message: str
    severity: str = "INFO"
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class CrawlError(BaseModel):
    """Non-fatal or fatal error encountered during crawling."""
    phase: str
    url: str = ""
    error_type: str
    message: str
    timestamp: datetime = Field(default_factory=datetime.utcnow)


# ── Full DAST Recon Output Contract (Phase 5) ─────────────────

class DASTReconOutput(BaseModel):
    """
    Comprehensive machine-readable DAST reconnaissance output.
    Consumed by the AI reasoning engine and backend correlation pipeline.
    """
    scan_id: str = Field(default_factory=lambda: str(uuid4()))
    target: TargetInfo
    started_at: datetime = Field(default_factory=datetime.utcnow)
    completed_at: datetime | None = None
    duration_seconds: float = 0.0
    routes: list[DiscoveredRoute] = Field(default_factory=list)
    apis: list[DiscoveredAPI] = Field(default_factory=list)
    forms: list[DiscoveredForm] = Field(default_factory=list)
    parameters: list[DiscoveredParameter] = Field(default_factory=list)
    authentication: AuthMetadata = Field(default_factory=AuthMetadata)
    observations: list[Observation] = Field(default_factory=list)
    errors: list[CrawlError] = Field(default_factory=list)

    def to_endpoint_schemas(self) -> list[dict[str, Any]]:
        """
        Export in format 100% compatible with backend.app.schemas.io_models.EndpointSchema.
        Includes intercepted APIs, HTML forms, and discovered web routes.
        """
        endpoints: list[dict[str, Any]] = []
        seen_keys: set[str] = set()

        detected_fw = getattr(self.target, "detected_framework", None) or "generic"
        server_ban = getattr(self.target, "server_banner", None) or ""

        # 1. Intercepted APIs (XHR / Fetch)
        for api in self.apis:
            key = f"{api.method.upper()}:{api.url.split('?')[0]}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            endpoints.append({
                "url": api.url,
                "method": api.method.upper(),
                "headers": api.headers,
                "detected_framework": detected_fw,
                "server_banner": server_ban,
                "tokens": {
                    "jwt": api.tokens.get("jwt"),
                    "session_cookie": api.tokens.get("session_cookie"),
                    "api_key": api.tokens.get("api_key"),
                    "csrf_token": api.tokens.get("csrf_token"),
                },
                "body_schema": {"sample": api.body_sample} if api.body_sample else None,
                "discovered_at": api.discovered_at.isoformat(),
            })

        # 2. Discovered Forms (POST / GET action endpoints with input params)
        for form in self.forms:
            form_url = form.action_url or form.page_url
            if not form_url:
                continue

            inputs_schema = {}
            query_parts = []
            for i, inp in enumerate(form.inputs):
                if isinstance(inp, dict):
                    name = inp.get("name") or inp.get("id")
                    if name:
                        inputs_schema[name] = inp.get("type", "string")
                        val = inp.get("value") or "test"
                        query_parts.append(f"{name}={val}")

            actual_url = form_url
            if form.method.upper() == "GET" and query_parts and "?" not in form_url:
                actual_url = f"{form_url}?{'&'.join(query_parts)}"

            key = f"{form.method.upper()}:{actual_url}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            endpoints.append({
                "url": actual_url,
                "method": form.method.upper(),
                "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                "detected_framework": detected_fw,
                "server_banner": server_ban,
                "tokens": {},
                "body_schema": inputs_schema if inputs_schema else None,
                "discovered_at": datetime.utcnow().isoformat(),
            })

        # 3. Discovered Web Routes & View Pages
        for route in self.routes:
            route_url = route.full_url
            if not route_url:
                continue
            key = f"{route.method.upper()}:{route_url.split('?')[0]}"
            if key in seen_keys:
                continue
            seen_keys.add(key)

            endpoints.append({
                "url": route_url,
                "method": route.method.upper(),
                "headers": route.headers or {},
                "detected_framework": detected_fw,
                "server_banner": server_ban,
                "tokens": {},
                "body_schema": None,
                "discovered_at": route.discovered_at.isoformat(),
            })

        return endpoints

    def to_ai_context(self) -> dict[str, Any]:
        """Format summary suitable for AI Reason Agent prompt injection."""
        return {
            "scan_id": self.scan_id,
            "target_base_url": self.target.base_url,
            "total_routes": len(self.routes),
            "total_apis": len(self.apis),
            "total_forms": len(self.forms),
            "total_parameters": len(self.parameters),
            "authenticated": self.authentication.has_jwt or self.authentication.has_session_cookie,
            "apis_sample": [
                {
                    "url": api.url,
                    "method": api.method,
                    "params": api.query_params,
                    "has_body": bool(api.body_sample),
                }
                for api in self.apis[:30]
            ],
            "observations": [obs.message for obs in self.observations],
        }


# ── Test Specification Contract (Phase 6) ─────────────────────

class TestSpecification(BaseModel):
    """
    Structured test specification received from the AI reasoning engine.
    Instructs ExploitRunner precisely what HTTP probe to execute.
    """
    __test__ = False
    test_id: str = Field(default_factory=lambda: f"TEST-{uuid4().hex[:8].upper()}")
    scan_id: str
    vulnerability_type: str  # e.g. "BOLA", "IDOR", "SQLI", "XSS", "AUTH_BYPASS"
    target_url: str
    method: str = "GET"
    headers: dict[str, str] = Field(default_factory=dict)
    query_params: dict[str, Any] = Field(default_factory=dict)
    body: Any | None = None
    payload: str = ""
    inject_in: str = "body"  # "body", "query", "header", "path"
    param_name: str | None = None
    auth_session: str = "default"  # "default", "attacker", "victim", "unauthenticated"
    expected_indicator: str | None = None
    baseline_context: dict[str, Any] | None = None
    timeout_seconds: float = 15.0


# ── Exploit Evidence & Verification Results (Phase 7 & 8) ──────

class ExploitEvidence(BaseModel):
    """Raw HTTP evidence captured during test execution."""
    request_url: str
    request_method: str
    request_headers: dict[str, str] = Field(default_factory=dict)
    request_body: str | None = None
    response_status: int
    response_body: str
    response_headers: dict[str, str] = Field(default_factory=dict)
    duration_ms: float
    dom_evidence: dict[str, Any] | None = None
    timestamp: datetime = Field(default_factory=datetime.utcnow)


class VerificationResult(BaseModel):
    """
    Final deterministic evaluation of an exploit probe.
    Produced by Verifier and FalsePositiveFilter.
    """
    test_id: str
    scan_id: str
    vulnerability_type: str
    status: VerificationStatus
    confidence: float = Field(default=0.0, ge=0.0, le=1.0)
    is_confirmed: bool = False
    evidence: ExploitEvidence | None = None
    expected_behavior: str = ""
    observed_behavior: str = ""
    reason: str = ""
    false_positive_reason: str | None = None
    remediation_hint: str | None = None
    duration_ms: float = 0.0
    timestamp: datetime = Field(default_factory=datetime.utcnow)

    def to_detected_vulnerability(self) -> dict[str, Any] | None:
        """Export to backend DetectedVulnerability format if verified or likely."""
        if self.status not in (VerificationStatus.VERIFIED, VerificationStatus.LIKELY):
            return None

        severity_map = {
            "SQLI": "CRITICAL",
            "BOLA": "HIGH",
            "IDOR": "HIGH",
            "AUTH_BYPASS": "CRITICAL",
            "XSS": "MEDIUM",
        }
        severity = severity_map.get(self.vulnerability_type.upper(), "MEDIUM")

        return {
            "id": f"VULN-{self.test_id}",
            "title": f"Verified {self.vulnerability_type} at {self.evidence.request_url if self.evidence else 'target'}",
            "description": self.reason,
            "severity": severity,
            "confidence": self.confidence,
            "exploit_payload": self.evidence.request_body if self.evidence else None,
            "remediation": self.remediation_hint or "Implement strict server-side validation and authorization checks.",
            "references": [],
        }
