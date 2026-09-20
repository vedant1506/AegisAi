"""
Unit tests for VerificationEngine and FalsePositiveFilter.
"""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from false_positive_filter import FalsePositiveFilter
from models import ExploitEvidence, TestSpecification, VerificationResult, VerificationStatus
from verifier import VerificationEngine


@pytest.fixture
def verifier():
    return VerificationEngine()


@pytest.fixture
def fp_filter():
    return FalsePositiveFilter()


# ── SQL Injection Verification Tests ─────────────────────────

def test_sqli_verification_detected_dialect_error(verifier):
    spec = TestSpecification(
        scan_id="scan-1",
        vulnerability_type="SQLI",
        target_url="http://localhost:3000/rest/products/search",
        payload="')) UNION SELECT * FROM users--",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/rest/products/search?q=test",
        request_method="GET",
        response_status=500,
        response_body="SQLITE_ERROR: near 'UNION': syntax error in SQL query",
        duration_ms=45.0,
    )

    result = verifier.verify(spec, evidence)
    assert result.status == VerificationStatus.VERIFIED
    assert result.is_confirmed is True
    assert result.confidence >= 0.90
    assert "SQL" in result.reason


def test_sqli_verification_false_positive(verifier):
    spec = TestSpecification(
        scan_id="scan-1",
        vulnerability_type="SQLI",
        target_url="http://localhost:3000/rest/products/search",
        payload="' OR 1=1--",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/rest/products/search?q=test",
        request_method="GET",
        response_status=200,
        response_body="<html><body>Normal page content without SQL errors</body></html>",
        duration_ms=30.0,
    )

    result = verifier.verify(spec, evidence)
    assert result.status == VerificationStatus.FALSE_POSITIVE
    assert result.is_confirmed is False


# ── BOLA / IDOR Verification Tests ───────────────────────────

def test_bola_verification_confirmed_with_victim_leak(verifier):
    spec = TestSpecification(
        scan_id="scan-1",
        vulnerability_type="BOLA",
        target_url="http://localhost:3000/rest/basket/2",
        auth_session="attacker",
        baseline_context={"victim_identifiers": ["victim@juice-sh.op", "order_id_9876"]},
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/rest/basket/2",
        request_method="GET",
        response_status=200,
        response_body='{"status":"success","data":{"user":"victim@juice-sh.op","items":["Apple"]}}',
        duration_ms=40.0,
    )

    result = verifier.verify(spec, evidence)
    assert result.status == VerificationStatus.VERIFIED
    assert result.is_confirmed is True
    assert "victim@juice-sh.op" in result.reason


def test_bola_verification_properly_rejected_403(verifier):
    spec = TestSpecification(
        scan_id="scan-1",
        vulnerability_type="BOLA",
        target_url="http://localhost:3000/rest/basket/2",
        auth_session="attacker",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/rest/basket/2",
        request_method="GET",
        response_status=403,
        response_body="Access denied: You are not authorized to view this basket.",
        duration_ms=25.0,
    )

    result = verifier.verify(spec, evidence)
    assert result.status == VerificationStatus.FALSE_POSITIVE
    assert result.is_confirmed is False


# ── XSS Verification Tests ───────────────────────────────────

def test_xss_verification_reflected_in_html(verifier):
    probe_payload = "<script>alert('aegis_xss')</script>"
    spec = TestSpecification(
        scan_id="scan-1",
        vulnerability_type="XSS",
        target_url="http://localhost:3000/#/search",
        payload=probe_payload,
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/#/search?q=" + probe_payload,
        request_method="GET",
        response_status=200,
        response_headers={"content-type": "text/html; charset=utf-8"},
        response_body=f"<div>Results for: {probe_payload}</div>",
        duration_ms=30.0,
    )

    result = verifier.verify(spec, evidence)
    assert result.status == VerificationStatus.VERIFIED
    assert result.is_confirmed is True


# ── False-Positive Filter Tests ──────────────────────────────

def test_false_positive_filter_soft_404(fp_filter):
    spec = TestSpecification(
        scan_id="scan-1",
        vulnerability_type="BOLA",
        target_url="http://localhost:3000/api/users/9999",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/api/users/9999",
        request_method="GET",
        response_status=200,
        response_body="<html><body><h1>Error: 404</h1><p>Resource not found</p></body></html>",
        duration_ms=20.0,
    )
    raw_result = VerificationResult(
        test_id=spec.test_id,
        scan_id=spec.scan_id,
        vulnerability_type="BOLA",
        status=VerificationStatus.INCONCLUSIVE,
        confidence=0.4,
        is_confirmed=False,
        evidence=evidence,
    )

    filtered = fp_filter.filter_result(raw_result, spec)
    assert filtered.status == VerificationStatus.FALSE_POSITIVE
    assert "Soft 404" in filtered.false_positive_reason


def test_false_positive_filter_static_asset(fp_filter):
    spec = TestSpecification(
        scan_id="scan-1",
        vulnerability_type="IDOR",
        target_url="http://localhost:3000/assets/public/logo.png",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/assets/public/logo.png",
        request_method="GET",
        response_status=200,
        response_body="[binary png content]",
        duration_ms=10.0,
    )
    raw_result = VerificationResult(
        test_id=spec.test_id,
        scan_id=spec.scan_id,
        vulnerability_type="IDOR",
        status=VerificationStatus.LIKELY,
        confidence=0.7,
        is_confirmed=True,
        evidence=evidence,
    )

    filtered = fp_filter.filter_result(raw_result, spec)
    assert filtered.status == VerificationStatus.FALSE_POSITIVE
    assert "static" in filtered.reason.lower()


def test_false_positive_filter_identical_baseline(fp_filter):
    spec = TestSpecification(
        scan_id="scan-1",
        vulnerability_type="SQLI",
        target_url="http://localhost:3000/products",
        payload="' OR 1=1--",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/products",
        request_method="GET",
        response_status=200,
        response_body='{"products":[{"id":1,"name":"Apple"}]}',
        duration_ms=20.0,
    )
    baseline_evidence = ExploitEvidence(
        request_url="http://localhost:3000/products",
        request_method="GET",
        response_status=200,
        response_body='{"products":[{"id":1,"name":"Apple"}]}',
        duration_ms=20.0,
    )
    raw_result = VerificationResult(
        test_id=spec.test_id,
        scan_id=spec.scan_id,
        vulnerability_type="SQLI",
        status=VerificationStatus.LIKELY,
        confidence=0.6,
        is_confirmed=True,
        evidence=evidence,
    )

    filtered = fp_filter.filter_result(raw_result, spec, baseline_evidence=baseline_evidence)
    assert filtered.status == VerificationStatus.FALSE_POSITIVE
    summary_text = (filtered.reason + " " + (filtered.false_positive_reason or "") + " " + filtered.observed_behavior).lower()
    assert "identical" in summary_text


# ── Phase 4B Detection Improvement Tests ─────────────────────

def test_sqli_boolean_differential_verification(verifier):
    spec = TestSpecification(
        scan_id="scan-4b",
        vulnerability_type="SQLI",
        target_url="http://localhost:3000/rest/products/search",
        payload="apple')) OR 1=1--",
        inject_in="query",
        param_name="q",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/rest/products/search?q=apple%27%29%29%20OR%201=1--",
        request_method="GET",
        response_status=200,
        response_body='{"status":"success","data":[' + ','.join(['{"id":' + str(i) + '}' for i in range(50)]) + ']}',
        duration_ms=45.0,
    )
    baseline_evidence = ExploitEvidence(
        request_url="http://localhost:3000/rest/products/search?q=apple%27%29%29%20AND%201=2--",
        request_method="GET",
        response_status=200,
        response_body='{"status":"success","data":[]}',
        duration_ms=25.0,
    )

    result = verifier.verify(spec, evidence, baseline_evidence=baseline_evidence)
    assert result.status == VerificationStatus.VERIFIED
    assert result.is_confirmed is True
    assert result.confidence >= 0.90
    assert "differential" in result.reason.lower() or "boolean" in result.reason.lower()


def test_xss_dom_evidence_verification(verifier):
    spec = TestSpecification(
        scan_id="scan-4b",
        vulnerability_type="XSS",
        target_url="http://localhost:3000/#/search",
        payload="<iframe src=\"javascript:alert(1)\">",
        inject_in="spa_dom",
        param_name="q",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/#/search?q=<iframe src=\"javascript:alert(1)\">",
        request_method="GET",
        response_status=200,
        response_headers={"content-type": "text/html"},
        response_body="<html><head></head><body><app-root></app-root></body></html>",
        duration_ms=850.0,
        dom_evidence={
            "rendered_in_dom": True,
            "elements_found": ["iframe[src='javascript:alert(1)']"],
            "element_count": 1,
            "iframe_count": 1,
            "marker_count": 0,
        },
    )

    result = verifier.verify(spec, evidence)
    assert result.status == VerificationStatus.VERIFIED
    assert result.is_confirmed is True
    assert result.confidence >= 0.90
    assert "dom" in result.reason.lower()


def test_xss_safely_encoded_negative_control(verifier):
    spec = TestSpecification(
        scan_id="scan-4b",
        vulnerability_type="XSS",
        target_url="http://localhost:3000/#/search",
        payload="<script>alert(1)</script>",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/#/search?q=test",
        request_method="GET",
        response_status=200,
        response_headers={"content-type": "text/html"},
        response_body="<div>Search query: &lt;script&gt;alert(1)&lt;/script&gt;</div>",
        duration_ms=35.0,
    )

    result = verifier.verify(spec, evidence)
    assert result.status == VerificationStatus.FALSE_POSITIVE
    assert result.is_confirmed is False
    assert "encoded" in result.reason.lower() or "escaped" in result.reason.lower()


def test_auth_bypass_admin_registration(verifier):
    spec = TestSpecification(
        scan_id="scan-4b",
        vulnerability_type="AUTH_BYPASS",
        target_url="http://localhost:3000/api/Users",
        method="POST",
        body={
            "email": "attacker_admin@test.com",
            "password": "Password123!",
            "role": "admin",
        },
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/api/Users",
        request_method="POST",
        response_status=201,
        response_body='{"status":"success","data":{"id":15,"email":"attacker_admin@test.com","role":"admin"}}',
        duration_ms=50.0,
    )

    result = verifier.verify(spec, evidence)
    assert result.status == VerificationStatus.VERIFIED
    assert result.is_confirmed is True
    assert "admin" in result.reason.lower()


def test_auth_bypass_401_rejection_negative_control(verifier):
    spec = TestSpecification(
        scan_id="scan-4b",
        vulnerability_type="AUTH_BYPASS",
        target_url="http://localhost:3000/rest/user/change-password",
        method="GET",
    )
    evidence = ExploitEvidence(
        request_url="http://localhost:3000/rest/user/change-password",
        request_method="GET",
        response_status=401,
        response_body='{"error":"Unauthorized"}',
        duration_ms=20.0,
    )

    result = verifier.verify(spec, evidence)
    assert result.status == VerificationStatus.FALSE_POSITIVE
    assert result.is_confirmed is False

