"""
AegisAI — False Positive Filter
=================================
Screens potential vulnerability findings to eliminate false alarms before
they are presented in final reports or passed to the correlation pipeline.

Filtering Criteria:
  1. Soft-404 detection (endpoints returning 200 OK for missing resources).
  2. Public asset / static content detection (rejects IDOR claims on public assets).
  3. Baseline similarity: if exploit response is identical to the baseline response,
     the payload had no causal effect.
  4. Response length anomalies and status code misinterpretations.
"""

from __future__ import annotations

import difflib
from typing import Any

import structlog

from models import ExploitEvidence, TestSpecification, VerificationResult, VerificationStatus

logger = structlog.get_logger(__name__)

SOFT_404_INDICATORS = [
    "page not found",
    "404 not found",
    "cannot find",
    "does not exist",
    "item not found",
    "no results found",
    "resource not found",
    "page not available",
    "error: 404",
]

PUBLIC_STATIC_EXTENSIONS = (
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".js",
    ".ico", ".woff", ".woff2", ".ttf", ".map",
)


class FalsePositiveFilter:
    """
    Applies heuristic and baseline evidence filters to verification results.
    """

    def filter_result(
        self,
        result: VerificationResult,
        spec: TestSpecification,
        baseline_evidence: ExploitEvidence | None = None,
    ) -> VerificationResult:
        """
        Evaluate and potentially downgrade or reject a finding if it matches
        false-positive criteria.
        """
        # Already rejected or errored findings require no filtering
        if result.status in (VerificationStatus.FALSE_POSITIVE, VerificationStatus.ERROR):
            return result

        evidence = result.evidence
        if not evidence:
            return result

        body_lower = evidence.response_body.lower()

        # ── 1. Soft-404 Detection ─────────────────────────────
        if evidence.response_status == 200:
            for phrase in SOFT_404_INDICATORS:
                if phrase in body_lower and len(evidence.response_body) < 1500:
                    logger.info(
                        "fp_filter.soft_404_detected",
                        test_id=spec.test_id,
                        phrase=phrase,
                    )
                    return VerificationResult(
                        test_id=result.test_id,
                        scan_id=result.scan_id,
                        vulnerability_type=result.vulnerability_type,
                        status=VerificationStatus.FALSE_POSITIVE,
                        confidence=0.0,
                        is_confirmed=False,
                        evidence=evidence,
                        expected_behavior=result.expected_behavior,
                        observed_behavior=result.observed_behavior,
                        reason=f"Soft 404: Endpoint returned HTTP 200 but body contains '{phrase}'.",
                        false_positive_reason=f"Soft 404: '{phrase}' detected in response body.",
                        duration_ms=result.duration_ms,
                    )

        # ── 2. Public Static Asset Check for BOLA/IDOR ────────
        if spec.vulnerability_type.upper() in ("BOLA", "IDOR"):
            req_path = spec.target_url.lower()
            if any(req_path.endswith(ext) for ext in PUBLIC_STATIC_EXTENSIONS):
                logger.info(
                    "fp_filter.static_asset_idor_rejected",
                    test_id=spec.test_id,
                    url=spec.target_url,
                )
                return VerificationResult(
                    test_id=result.test_id,
                    scan_id=result.scan_id,
                    vulnerability_type=result.vulnerability_type,
                    status=VerificationStatus.FALSE_POSITIVE,
                    confidence=0.0,
                    is_confirmed=False,
                    evidence=evidence,
                    expected_behavior=result.expected_behavior,
                    observed_behavior=result.observed_behavior,
                    reason="Target is a public static file, not a protected user-specific resource.",
                    false_positive_reason="Public static asset path requested.",
                    duration_ms=result.duration_ms,
                )

        # ── 3. Baseline Comparison ────────────────────────────
        if baseline_evidence is not None:
            similarity = self._calculate_body_similarity(
                evidence.response_body, baseline_evidence.response_body
            )

            # If response is virtually identical (>98% similarity) to normal un-payloaded baseline
            if similarity >= 0.98 and evidence.response_status == baseline_evidence.response_status:
                logger.info(
                    "fp_filter.identical_baseline",
                    test_id=spec.test_id,
                    similarity=round(similarity, 3),
                )
                return VerificationResult(
                    test_id=result.test_id,
                    scan_id=result.scan_id,
                    vulnerability_type=result.vulnerability_type,
                    status=VerificationStatus.FALSE_POSITIVE,
                    confidence=0.05,
                    is_confirmed=False,
                    evidence=evidence,
                    expected_behavior="Payload induces anomalous state or data divergence.",
                    observed_behavior=f"Response identical to baseline ({similarity:.1%} similarity).",
                    reason="Payload produced no distinguishable divergence from the baseline request.",
                    false_positive_reason="Identical response to baseline request.",
                    duration_ms=result.duration_ms,
                )

        # ── 4. Empty / Zero Content Filter ────────────────────
        if len(evidence.response_body.strip()) == 0 and evidence.response_status == 200:
            if spec.vulnerability_type.upper() in ("BOLA", "IDOR", "SQLI"):
                return VerificationResult(
                    test_id=result.test_id,
                    scan_id=result.scan_id,
                    vulnerability_type=result.vulnerability_type,
                    status=VerificationStatus.FALSE_POSITIVE,
                    confidence=0.0,
                    is_confirmed=False,
                    evidence=evidence,
                    expected_behavior="Leaked resource content.",
                    observed_behavior="Empty 200 OK body.",
                    reason="Server returned empty body with no data leakage.",
                    false_positive_reason="Empty response body.",
                    duration_ms=result.duration_ms,
                )

        # Passes all filters
        return result

    @staticmethod
    def _calculate_body_similarity(a: str, b: str) -> float:
        """Compute SequenceMatcher similarity ratio between two response texts."""
        if not a and not b:
            return 1.0
        if not a or not b:
            return 0.0
        # Cap string size for fast comparison
        sample_a = a[:4096]
        sample_b = b[:4096]
        return difflib.SequenceMatcher(None, sample_a, sample_b).ratio()
