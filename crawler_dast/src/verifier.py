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
    ) -> VerificationResult:
        """
        Verify an exploit probe outcome based on vulnerability type and observed behavior.
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
            return self._verify_sqli(spec, evidence)
        elif vtype in ("BOLA", "IDOR", "BROKEN_OBJECT_LEVEL_AUTH"):
            return self._verify_bola(spec, evidence)
        elif vtype in ("XSS", "REFLECTED_XSS", "STORED_XSS"):
            return self._verify_xss(spec, evidence)
        elif vtype in ("AUTH_BYPASS", "BROKEN_AUTHENTICATION"):
            return self._verify_auth_bypass(spec, evidence)
        else:
            return self._verify_generic(spec, evidence)

    # ── Vulnerability Verifiers ───────────────────────────────

    def _verify_sqli(
        self, spec: TestSpecification, evidence: ExploitEvidence
    ) -> VerificationResult:
        body = evidence.response_body

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

        # Check for error indicator or unexpected 500 error
        if evidence.response_status == 500 and spec.payload in ("'", '"', "''"):
            return VerificationResult(
                test_id=spec.test_id,
                scan_id=spec.scan_id,
                vulnerability_type=spec.vulnerability_type,
                status=VerificationStatus.LIKELY,
                confidence=0.75,
                is_confirmed=True,
                evidence=evidence,
                expected_behavior="Handled request returning 400 or normal validation message.",
                observed_behavior="Server crashed with 500 Internal Server Error upon quote injection.",
                reason="Unhandled exception on payload injection suggests SQL syntax failure.",
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
            expected_behavior="SQL error or differential response.",
            observed_behavior=f"Status {evidence.response_status} with no SQL error signatures.",
            reason="Payload did not trigger detectable database error or syntax leak.",
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
                expected_behavior="Server rejects unauthorized access with 401/403.",
                observed_behavior=f"Server correctly returned {status} Forbidden/Unauthorized.",
                reason="Authorization check correctly rejected cross-tenant access.",
                duration_ms=evidence.duration_ms,
            )

        # If 200 OK, check whether victim-specific data is present in response
        if status == 200:
            baseline = spec.baseline_context or {}
            victim_identifiers = baseline.get("victim_identifiers", [])

            leaked_identifiers = [
                ident for ident in victim_identifiers if ident and ident in evidence.response_body
            ]

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
        self, spec: TestSpecification, evidence: ExploitEvidence
    ) -> VerificationResult:
        body = evidence.response_body
        payload = spec.payload
        content_type = evidence.response_headers.get("content-type", "").lower()

        # XSS requires an HTML or XML response context
        is_renderable = "html" in content_type or "xml" in content_type or not content_type

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
                    confidence=0.40,
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
            expected_behavior="Payload reflection.",
            observed_behavior="Payload not found in response body.",
            reason="Input was sanitized, filtered, or not reflected.",
            duration_ms=evidence.duration_ms,
        )

    def _verify_auth_bypass(
        self, spec: TestSpecification, evidence: ExploitEvidence
    ) -> VerificationResult:
        if evidence.response_status == 200:
            body = evidence.response_body.lower()
            if any(term in body for term in ("admin", "dashboard", "users", "role", "success")):
                return VerificationResult(
                    test_id=spec.test_id,
                    scan_id=spec.scan_id,
                    vulnerability_type=spec.vulnerability_type,
                    status=VerificationStatus.VERIFIED,
                    confidence=0.88,
                    is_confirmed=True,
                    evidence=evidence,
                    expected_behavior="Rejection with HTTP 401 Unauthorized or 403 Forbidden.",
                    observed_behavior="HTTP 200 OK granted without authentication credentials.",
                    reason="Protected administrative or sensitive resource accessible anonymously.",
                    remediation_hint="Enforce authentication middleware on all protected routes.",
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

    # 3. Deterministic verification
    initial_result = engine.verify(spec, evidence)

    # 4. Filter false positives
    return fp_filter.filter_result(initial_result, spec, baseline_evidence)

