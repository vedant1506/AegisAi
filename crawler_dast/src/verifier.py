"""
AegisAI — Deterministic Verification Engine
============================================
Evaluates captured HTTP evidence to deterministically confirm or refute
vulnerability hypotheses without relying exclusively on LLM calls or naive
HTTP 200 checks.

Verification Standards:
  - SQL Injection: Error signatures, query syntax leaks, or boolean response diffs.
  - BOLA / IDOR: Cross-tenant data exposure (victim tokens/data returned to attacker)
    vs. expected 401/403 authorization denial.
  - XSS: Raw payload execution reflection in rendered text/html responses.
  - Auth Bypass: Unauthenticated access to restricted endpoints returning functional state.
"""

from __future__ import annotations

import re
from typing import Any

import structlog

from models import ExploitEvidence, TestSpecification, VerificationResult, VerificationStatus

logger = structlog.get_logger(__name__)

# Common database syntax error signatures
SQL_ERROR_SIGNATURES = [
    r"SQL syntax.*MySQL",
    r"Warning.*mysql_.*",
    r"valid MySQL result",
    r"MySqlClient\.",
    r"PostgreSQL.*ERROR",
    r"warning.*pg_.*",
    r"valid PostgreSQL result",
    r"Npgsql\.",
    r"Driver.*SQL[-_ ]*Server",
    r"OLE DB.*SQL Server",
    r"SQLServer JDBC Driver",
    r"SqlException",
    r"Oracle error",
    r"Oracle.*Driver",
    r"Warning.*oci_.*",
    r"Warning.*ora_.*",
    r"SQLite/JDBCDriver",
    r"SQLite.Exception",
    r"System.Data.SQLite.SQLiteException",
    r"sqlite3\.OperationalError",
    r"SQLITE_ERROR",
    r"near ['\"].*?['\"]: syntax error",
    r"syntax error",
    r"SQLSTATE\[\d+\]",
    r"unclosed quotation mark after the character string",
]

COMPILED_SQL_REGEX = [re.compile(sig, re.IGNORECASE) for sig in SQL_ERROR_SIGNATURES]


class VerificationEngine:
    """
    Evaluates evidence against vulnerability-specific deterministic rules.
    """

    def verify(
        self,
        spec: TestSpecification,
        evidence: ExploitEvidence,
        baseline_evidence: ExploitEvidence | None = None,
    ) -> VerificationResult:
        """
        Verify an exploit probe outcome based on vulnerability type and observed behavior.
        Supports baseline_evidence for differential testing and anomaly detection.
        """
        vtype = spec.vulnerability_type.upper()

        if evidence.response_status == 0:
            return VerificationResult(
                test_id=spec.test_id,
                scan_id=spec.scan_id,
                vulnerability_type=spec.vulnerability_type,
                status=VerificationStatus.ERROR,
                confidence=0.0,
                is_confirmed=False,
                evidence=evidence,
                expected_behavior="Target should respond with a valid HTTP status code.",
                observed_behavior="Connection failed or timed out.",
                reason="Target unreachable or network timeout.",
                duration_ms=evidence.duration_ms,
            )

        if vtype in ("SQLI", "SQL_INJECTION"):
            return self._verify_sqli(spec, evidence, baseline_evidence=baseline_evidence)
        elif vtype in ("BOLA", "IDOR", "BROKEN_OBJECT_LEVEL_AUTH"):
            return self._verify_bola(spec, evidence)
        elif vtype in ("XSS", "REFLECTED_XSS", "STORED_XSS", "DOM_XSS"):
            return self._verify_xss(spec, evidence, baseline_evidence=baseline_evidence)
        elif vtype in ("AUTH_BYPASS", "BROKEN_AUTHENTICATION", "PRIVILEGE_ESCALATION", "BROKEN_AUTH"):
            return self._verify_auth_bypass(spec, evidence, baseline_evidence=baseline_evidence)
        else:
            return self._verify_generic(spec, evidence)

    # ── Vulnerability Verifiers ───────────────────────────────

    def _verify_sqli(
        self,
        spec: TestSpecification,
        evidence: ExploitEvidence,
        baseline_evidence: ExploitEvidence | None = None,
    ) -> VerificationResult:
        body = evidence.response_body

        # 1. Error-Signature Detection
        for regex in COMPILED_SQL_REGEX:
            match = regex.search(body)
            if match:
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.VERIFIED,
                    confidence=0.95,
                    is_confirmed=True,
                    evidence=evidence,
                    expected_behavior="Parameterized query with safe input handling.",
                    observed_behavior=f"Database syntax error leaked: '{match.group(0)}'",
                    reason=f"Server returned SQL dialect error signature matching '{match.group(0)}'.",
                    remediation_hint="Use prepared statements or parameterized queries.",
                    duration_ms=evidence.duration_ms,
                )

        # 2. Syntax Breakout 500 Anomaly
        syntax_chars = ("'", '"', "''", "')", "'))", "';", "')))", "'''")
        if evidence.response_status == 500 and any(sc in spec.payload for sc in syntax_chars):
            return VerificationResult(
                test_id=spec.test_id,
                scan_id=spec.scan_id,
                vulnerability_type=spec.vulnerability_type,
                status=VerificationStatus.LIKELY,
                confidence=0.80,
                is_confirmed=True,
                evidence=evidence,
                expected_behavior="Handled request returning 400 or normal validation message.",
                observed_behavior=f"Server crashed with 500 Internal Server Error upon syntax injection: '{spec.payload}'",
                reason="Unhandled exception on payload injection indicates SQL syntax failure.",
                remediation_hint="Ensure input is safely escaped or parameterized before query execution.",
                duration_ms=evidence.duration_ms,
            )

        # 3. Boolean Differential & Response Anomaly Testing
        if baseline_evidence is not None:
            true_len = len(evidence.response_body)
            base_len = len(baseline_evidence.response_body)
            len_diff = abs(true_len - base_len)
            ratio = true_len / max(base_len, 1)

            payload_upper = spec.payload.upper()
            is_boolean = any(
                kw in payload_upper
                for kw in ("OR 1=1", "AND 1=2", "OR '1'='1", "AND '1'='2'", "OR TRUE", "AND FALSE")
            )
            is_union = any(kw in payload_upper for kw in ("UNION SELECT", "UNION ALL SELECT"))

            if is_boolean and evidence.response_status == 200:
                if (ratio >= 2.0 and len_diff >= 100) or (ratio <= 0.5 and len_diff >= 100):
                    return VerificationResult(
                        test_id=spec.test_id,
                        scan_id=spec.scan_id,
                        vulnerability_type=spec.vulnerability_type,
                        status=VerificationStatus.VERIFIED,
                        confidence=0.92,
                        is_confirmed=True,
                        evidence=evidence,
                        expected_behavior="Identical or handled response across boolean conditions.",
                        observed_behavior=f"Significant differential: TRUE condition yielded {true_len} bytes vs FALSE/baseline {base_len} bytes (ratio {ratio:.1f}x).",
                        reason=f"Boolean differential SQL injection confirmed: response altered significantly by logical expression (ratio: {ratio:.1f}x, diff: {len_diff}B).",
                        remediation_hint="Use prepared statements or parameterized queries.",
                        duration_ms=evidence.duration_ms,
                    )

            if is_union and evidence.response_status == 200:
                if ratio >= 1.5 and true_len >= 500:
                    return VerificationResult(
                        test_id=spec.test_id,
                        scan_id=spec.scan_id,
                        vulnerability_type=spec.vulnerability_type,
                        status=VerificationStatus.VERIFIED,
                        confidence=0.90,
                        is_confirmed=True,
                        evidence=evidence,
                        expected_behavior="Query returns only intended schema entities.",
                        observed_behavior=f"Response body expanded from {base_len} to {true_len} bytes ({ratio:.1f}x) on UNION payload.",
                        reason=f"UNION-based SQL injection confirmed: payload induced a {ratio:.1f}x response body expansion with additional leaked records.",
                        remediation_hint="Use prepared statements or parameterized queries.",
                        duration_ms=evidence.duration_ms,
                    )

            # 4. Time-Based Verification (Safe Bounds: 2s - 10s)
            is_time_based = any(
                kw in payload_upper
                for kw in ("SLEEP", "PG_SLEEP", "WAITFOR", "BENCHMARK", "RANDOMBLOB")
            )
            if is_time_based:
                time_diff = evidence.duration_ms - baseline_evidence.duration_ms
                if time_diff >= 2000.0 and evidence.duration_ms <= 10000.0:
                    return VerificationResult(
                        test_id=spec.test_id,
                        scan_id=spec.scan_id,
                        vulnerability_type=spec.vulnerability_type,
                        status=VerificationStatus.VERIFIED,
                        confidence=0.88,
                        is_confirmed=True,
                        evidence=evidence,
                        expected_behavior="Query latency unaffected by payload.",
                        observed_behavior=f"Injected probe delayed response by {time_diff:.0f}ms (total: {evidence.duration_ms:.0f}ms vs baseline: {baseline_evidence.duration_ms:.0f}ms).",
                        reason=f"Time-based blind SQL injection confirmed: query latency delayed by {time_diff:.0f}ms.",
                        remediation_hint="Use prepared statements and enforce strict server-side query timeouts.",
                        duration_ms=evidence.duration_ms,
                    )

        # 5. Fallback: No detectable vulnerability
        return VerificationResult(
            test_id=spec.test_id,
            scan_id=spec.scan_id,
            vulnerability_type=spec.vulnerability_type,
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.10,
            is_confirmed=False,
            evidence=evidence,
            expected_behavior="SQL error, boolean divergence, or response anomaly.",
            observed_behavior=f"Status {evidence.response_status} with no detectable SQL injection signals.",
            reason="Payload did not trigger detectable database error, boolean divergence, or response anomaly.",
            duration_ms=evidence.duration_ms,
        )

    def _verify_bola(
        self, spec: TestSpecification, evidence: ExploitEvidence
    ) -> VerificationResult:
        """
        Verify Broken Object Level Authorization (BOLA/IDOR).
        Requires positive access to victim object AND lack of proper 401/403 rejection.
        """
        status = evidence.response_status

        # If properly rejected with 401/403/404, authorization is enforced
        if status in (401, 403):
            return VerificationResult(
                test_id=spec.test_id,
                scan_id=spec.scan_id,
                vulnerability_type=spec.vulnerability_type,
                status=VerificationStatus.FALSE_POSITIVE,
                confidence=0.0,
                is_confirmed=False,
                evidence=evidence,
                expected_behavior="Access denied by authorization controls.",
                observed_behavior=f"Server returned HTTP {status} (Authorization properly enforced).",
                reason="Authorization check correctly rejected cross-tenant access.",
                duration_ms=evidence.duration_ms,
            )

        # If 200 OK, check whether victim-specific data is present in response
        if status == 200:
            # Check for victim data leakage in attacker session
            leaked_identifiers = []
            if spec.baseline_context and "victim_identifiers" in spec.baseline_context:
                expected_ids = spec.baseline_context["victim_identifiers"]
                for v_id in expected_ids:
                    if str(v_id) in evidence.response_body:
                        leaked_identifiers.append(str(v_id))

            if leaked_identifiers:
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.VERIFIED,
                    confidence=0.95,
                    is_confirmed=True,
                    evidence=evidence,
                    expected_behavior="Access denied (403 Forbidden) for unauthorized tenant.",
                    observed_behavior=f"HTTP 200 OK leaking victim attributes: {leaked_identifiers}",
                    reason=f"Cross-tenant IDOR confirmed: victim attributes {leaked_identifiers} exposed.",
                    remediation_hint="Validate current session ownership of object ID before returning data.",
                    duration_ms=evidence.duration_ms,
                )

            # If expected indicator was specified and found
            if spec.expected_indicator and spec.expected_indicator in evidence.response_body:
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.VERIFIED,
                    confidence=0.90,
                    is_confirmed=True,
                    evidence=evidence,
                    expected_behavior="Denial of cross-tenant resource access.",
                    observed_behavior=f"Expected sensitive victim indicator found: '{spec.expected_indicator}'",
                    reason="Target returned protected resource data to unauthorized session.",
                    duration_ms=evidence.duration_ms,
                )

            # 200 OK without victim indicators might simply be a public endpoint or soft-404
            return VerificationResult(
                test_id=spec.test_id,
                scan_id=spec.scan_id,
                vulnerability_type=spec.vulnerability_type,
                status=VerificationStatus.INCONCLUSIVE,
                confidence=0.40,
                is_confirmed=False,
                evidence=evidence,
                expected_behavior="Victim data or 403 Forbidden.",
                observed_behavior=f"HTTP 200 OK but no specific victim identifiers observed.",
                reason="Response returned 200 OK without definitive proof of private data leakage.",
                duration_ms=evidence.duration_ms,
            )

        return VerificationResult(
            test_id=spec.test_id,
            scan_id=spec.scan_id,
            vulnerability_type=spec.vulnerability_type,
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.10,
            is_confirmed=False,
            evidence=evidence,
            expected_behavior="Victim data leak.",
            observed_behavior=f"Server returned HTTP status {status}.",
            reason="Endpoint did not return protected data.",
            duration_ms=evidence.duration_ms,
        )

    def _verify_xss(
        self,
        spec: TestSpecification,
        evidence: ExploitEvidence,
        baseline_evidence: ExploitEvidence | None = None,
    ) -> VerificationResult:
        # 1. Browser DOM Evidence
        if evidence.dom_evidence and evidence.dom_evidence.get("rendered_in_dom"):
            elements = evidence.dom_evidence.get("elements_found", [])
            cnt = evidence.dom_evidence.get("element_count", 0)
            if cnt > 0 or elements:
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.VERIFIED,
                    confidence=0.95,
                    is_confirmed=True,
                    evidence=evidence,
                    expected_behavior="Client-side routing sanitizes or escapes user parameters before DOM insertion.",
                    observed_behavior=f"Browser rendered active unescaped DOM elements: {elements}",
                    reason=f"DOM-based XSS confirmed: browser DOM inspection verified active injection of {elements} into rendered page tree.",
                    remediation_hint="Contextually encode or sanitize parameters in client-side SPA routing before innerHTML insertion.",
                    duration_ms=evidence.duration_ms,
                )

        # 2. Reflected HTTP Response Evidence
        body = evidence.response_body
        payload = spec.payload
        content_type = evidence.response_headers.get("content-type", "").lower()
        is_renderable = "html" in content_type or "xml" in content_type or not content_type

        # Check if safely entity-encoded (e.g. &lt;script&gt; or &quot;)
        if payload and ("<" in payload or ">" in payload):
            encoded_lt_gt = payload.replace("<", "&lt;").replace(">", "&gt;")
            if encoded_lt_gt in body:
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.FALSE_POSITIVE,
                    confidence=0.05,
                    is_confirmed=False,
                    evidence=evidence,
                    expected_behavior="Payload safely entity-encoded.",
                    observed_behavior="Payload was reflected but safely HTML entity-encoded (&lt;...&gt;).",
                    reason="Input was safely HTML entity-encoded by server.",
                    duration_ms=evidence.duration_ms,
                )

        if payload and payload in body:
            if is_renderable:
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.VERIFIED,
                    confidence=0.90,
                    is_confirmed=True,
                    evidence=evidence,
                    expected_behavior="Payload encoded/escaped (e.g. &lt;script&gt;) or rejected.",
                    observed_behavior="Unescaped payload reflected directly in HTML body.",
                    reason=f"Reflected XSS: unencoded payload '{payload[:30]}' returned in renderable context.",
                    remediation_hint="Contextually HTML-encode user inputs before rendering.",
                    duration_ms=evidence.duration_ms,
                )
            else:
                # Reflected in JSON without HTML context
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.INCONCLUSIVE,
                    confidence=0.35,
                    is_confirmed=False,
                    evidence=evidence,
                    expected_behavior="Payload sanitized.",
                    observed_behavior=f"Payload reflected in {content_type} (non-HTML context).",
                    reason="Payload stored or reflected, but Content-Type is not directly executable HTML.",
                    duration_ms=evidence.duration_ms,
                )

        return VerificationResult(
            test_id=spec.test_id,
            scan_id=spec.scan_id,
            vulnerability_type=spec.vulnerability_type,
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.05,
            is_confirmed=False,
            evidence=evidence,
            expected_behavior="Payload reflection in DOM or HTML response.",
            observed_behavior="Payload not found in response body or rendered DOM.",
            reason="Input was sanitized, filtered, or not reflected in DOM or response.",
            duration_ms=evidence.duration_ms,
        )

    def _verify_auth_bypass(
        self,
        spec: TestSpecification,
        evidence: ExploitEvidence,
        baseline_evidence: ExploitEvidence | None = None,
    ) -> VerificationResult:
        # 1. Negative Control: Proper Rejection (401 / 403)
        if evidence.response_status in (401, 403):
            return VerificationResult(
                test_id=spec.test_id,
                scan_id=spec.scan_id,
                vulnerability_type=spec.vulnerability_type,
                status=VerificationStatus.FALSE_POSITIVE,
                confidence=0.0,
                is_confirmed=False,
                evidence=evidence,
                expected_behavior="Protected resource denies access.",
                observed_behavior=f"Server returned HTTP status {evidence.response_status}.",
                reason="Authentication / authorization properly enforced: request was rejected.",
                duration_ms=evidence.duration_ms,
            )

        # 2. Privilege Escalation / Admin Registration Bypass
        if evidence.response_status in (200, 201):
            body_lower = evidence.response_body.lower()
            is_priv_escalation = False
            role_requested = "admin"

            if isinstance(spec.body, dict):
                is_priv_escalation = "role" in spec.body
                role_requested = str(spec.body.get("role", "admin"))
            elif isinstance(spec.body, str):
                is_priv_escalation = "role" in spec.body

            body_no_spaces = evidence.response_body.replace(" ", "").replace("'", '"').lower()
            role_confirmed_in_body = f'"role":"{role_requested.lower()}"' in body_no_spaces

            followup_verified = False
            followup_details = ""
            if spec.baseline_context:
                followup_verified = bool(spec.baseline_context.get("privilege_verified"))
                followup_details = str(spec.baseline_context.get("privilege_details", ""))

            if is_priv_escalation and (role_confirmed_in_body or followup_verified):
                conf = 0.95 if followup_verified else 0.88
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.VERIFIED,
                    confidence=conf,
                    is_confirmed=True,
                    evidence=evidence,
                    expected_behavior="Client-supplied role rejected or overridden with default non-privileged role.",
                    observed_behavior=f"HTTP {evidence.response_status} with elevated role '{role_requested}' granted" + (f"; follow-up session: {followup_details}" if followup_details else "."),
                    reason=f"Improper authentication / privilege escalation: user successfully registered with elevated '{role_requested}' role" + (f" and verified in authenticated session ({followup_details})" if followup_details else "."),
                    remediation_hint="Validate user roles server-side and prevent client-controlled role assignment during registration.",
                    duration_ms=evidence.duration_ms,
                )

            # 3. Unauthenticated Access to Protected Resource
            if spec.auth_session == "unauthenticated":
                # Check if explicitly public
                if spec.baseline_context and spec.baseline_context.get("is_public"):
                    return VerificationResult(
                        test_id=spec.test_id,
                        scan_id=spec.scan_id,
                        vulnerability_type=spec.vulnerability_type,
                        status=VerificationStatus.FALSE_POSITIVE,
                        confidence=0.0,
                        is_confirmed=False,
                        evidence=evidence,
                        expected_behavior="Public resource accessible without authentication.",
                        observed_behavior=f"HTTP {evidence.response_status} on public endpoint.",
                        reason="Endpoint is intentionally public by design; unauthenticated access is expected.",
                        duration_ms=evidence.duration_ms,
                    )
                if any(term in body_lower for term in ("admin", "dashboard", "users", "success")):
                    return VerificationResult(
                        test_id=spec.test_id,
                        scan_id=spec.scan_id,
                        vulnerability_type=spec.vulnerability_type,
                        status=VerificationStatus.VERIFIED,
                        confidence=0.88,
                        is_confirmed=True,
                        evidence=evidence,
                        expected_behavior="Rejection with HTTP 401 Unauthorized or 403 Forbidden.",
                        observed_behavior=f"HTTP {evidence.response_status} granted without authentication credentials.",
                        reason="Protected administrative or sensitive resource accessible anonymously.",
                        remediation_hint="Enforce authentication middleware on all protected routes.",
                        duration_ms=evidence.duration_ms,
                    )

            # 4. Function-Level Access Control Bypass (Unprivileged Principal Accessing Admin Endpoint)
            if spec.baseline_context and spec.baseline_context.get("admin_operation"):
                if spec.expected_indicator and spec.expected_indicator in evidence.response_body:
                    return VerificationResult(
                        test_id=spec.test_id,
                        scan_id=spec.scan_id,
                        vulnerability_type=spec.vulnerability_type,
                        status=VerificationStatus.VERIFIED,
                        confidence=0.92,
                        is_confirmed=True,
                        evidence=evidence,
                        expected_behavior="HTTP 401 or 403 Forbidden for non-administrative principal.",
                        observed_behavior=f"HTTP {evidence.response_status} granting administrative function '{spec.target_url}'.",
                        reason=f"Function-level access control bypass: unprivileged user granted administrative function (found indicator '{spec.expected_indicator}').",
                        remediation_hint="Enforce strict role-based access control checks at the endpoint level.",
                        duration_ms=evidence.duration_ms,
                    )

            # 5. Token Revocation / Broken Session Management (CWE-613)
            if spec.baseline_context and spec.baseline_context.get("token_revocation_test"):
                if "token" in body_lower or "jwt" in body_lower or (spec.expected_indicator and spec.expected_indicator in evidence.response_body):
                    return VerificationResult(
                        test_id=spec.test_id,
                        scan_id=spec.scan_id,
                        vulnerability_type=spec.vulnerability_type,
                        status=VerificationStatus.VERIFIED,
                        confidence=0.95,
                        is_confirmed=True,
                        evidence=evidence,
                        expected_behavior="HTTP 401 Unauthorized rejecting invalidated/revoked refresh token.",
                        observed_behavior=f"HTTP {evidence.response_status} issuing active session token from revoked refresh token.",
                        reason="Broken authentication / token revocation failure: revoked refresh token continues to issue valid sessions.",
                        remediation_hint="Maintain a persistent token revocation blocklist and invalidate active sessions upon logout.",
                        duration_ms=evidence.duration_ms,
                    )

            # 6. Expected Indicator Confirmation (Generic Auth Bypass)
            if spec.expected_indicator and spec.expected_indicator in evidence.response_body:
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.VERIFIED,
                    confidence=0.90,
                    is_confirmed=True,
                    evidence=evidence,
                    expected_behavior="Rejection with HTTP 401 or 403 Forbidden.",
                    observed_behavior=f"HTTP {evidence.response_status} with expected exploit indicator '{spec.expected_indicator}'.",
                    reason=f"Authentication bypass verified: observed indicator '{spec.expected_indicator}' in response body.",
                    remediation_hint="Ensure all protected operations validate identity and authorization boundaries.",
                    duration_ms=evidence.duration_ms,
                )

        # 7. Lack of Rate Limiting / Excessive Authentication Attempts (CWE-307)
        if spec.baseline_context and spec.baseline_context.get("rate_limiting_test"):
            attempts = spec.baseline_context.get("attempts_count", 0)
            statuses = spec.baseline_context.get("response_statuses", [])
            rate_limited = any(s in (429, 503) for s in statuses)
            if attempts >= 10 and not rate_limited:
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.VERIFIED,
                    confidence=0.95,
                    is_confirmed=True,
                    evidence=evidence,
                    expected_behavior="Server should enforce rate limiting or lockout after excessive attempts (HTTP 429/503).",
                    observed_behavior=f"Server processed {attempts} consecutive invalid attempts without rate limiting or lockout (statuses: {statuses[:5]}...).",
                    reason=f"Broken Authentication (CWE-307): OTP verification lacks rate limiting or account lockout across {attempts} attempts.",
                    remediation_hint="Implement rate limiting and temporary account lockout on OTP verification endpoints.",
                    duration_ms=evidence.duration_ms,
                )

        # 5. Fallback
        return VerificationResult(
            test_id=spec.test_id,
            scan_id=spec.scan_id,
            vulnerability_type=spec.vulnerability_type,
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.10,
            is_confirmed=False,
            evidence=evidence,
            expected_behavior="Authentication bypass.",
            observed_behavior=f"Server returned status {evidence.response_status}.",
            reason="Protected resource not exposed anonymously.",
            duration_ms=evidence.duration_ms,
        )

    def _verify_generic(
        self, spec: TestSpecification, evidence: ExploitEvidence
    ) -> VerificationResult:
        if spec.expected_indicator and spec.expected_indicator in evidence.response_body:
            return VerificationResult(
                test_id=spec.test_id,
                scan_id=spec.scan_id,
                vulnerability_type=spec.vulnerability_type,
                status=VerificationStatus.LIKELY,
                confidence=0.75,
                is_confirmed=True,
                evidence=evidence,
                expected_behavior="Expected response indicator present.",
                observed_behavior=f"Found expected indicator: '{spec.expected_indicator}'",
                reason=f"Evidence contains the expected exploit signature '{spec.expected_indicator}'.",
                duration_ms=evidence.duration_ms,
            )

        return VerificationResult(
            test_id=spec.test_id,
            scan_id=spec.scan_id,
            vulnerability_type=spec.vulnerability_type,
            status=VerificationStatus.INCONCLUSIVE,
            confidence=0.30,
            is_confirmed=False,
            evidence=evidence,
            expected_behavior="Significant exploit divergence.",
            observed_behavior=f"Status {evidence.response_status}.",
            reason="Insufficient evidence to confirm generic vulnerability hypothesis.",
            duration_ms=evidence.duration_ms,
        )


# ── Pipeline Convenience Function ─────────────────────────────

async def execute_and_verify(
    spec: TestSpecification,
    runner: Any,
    verifier: VerificationEngine | None = None,
    filter_engine: Any | None = None,
    baseline_spec: TestSpecification | None = None,
) -> VerificationResult:
    """
    Convenience function combining probe execution, deterministic verification,
    and false-positive filtering into a single async step.
    """
    from false_positive_filter import FalsePositiveFilter

    engine = verifier or VerificationEngine()
    fp_filter = filter_engine or FalsePositiveFilter()

    # 1. Execute probe
    evidence = await runner.execute_test(spec)

    # 2. Execute baseline probe if requested
    baseline_evidence = None
    if baseline_spec:
        try:
            baseline_evidence = await runner.execute_test(baseline_spec)
        except Exception:
            pass

    # 3. Deterministic verification with baseline differential support
    initial_result = engine.verify(spec, evidence, baseline_evidence=baseline_evidence)

    # 4. Filter false positives
    return fp_filter.filter_result(initial_result, spec, baseline_evidence)
