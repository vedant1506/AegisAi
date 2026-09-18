"""
AegisAI — Empirical Benchmark Evaluation Harness
=================================================
Evaluates AegisAI dynamic testing, reconnaissance, and verification accuracy
against standard ground-truth vulnerability testbeds (OWASP Juice Shop,
OWASP crAPI, and the Custom 10 Ground-Truth Authorization Testbed).

Computes:
  - Precision = TP / (TP + FP)
  - Recall = TP / (TP + FN)
  - F1 Score = 2 * (Precision * Recall) / (Precision + Recall)
  - Detection Rate = TP / Total Ground Truth
  - Scan latency, discovered attack surface metrics
Saves raw JSON benchmark artifacts for reproducible research and academic defense.
"""

from __future__ import annotations

import json
import os
import sys
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any

# Ensure crawler_dast/src and benchmarks are on path
BENCHMARK_DIR = Path(__file__).resolve().parent
SRC_DIR = BENCHMARK_DIR.parent / "src"
sys.path.insert(0, str(SRC_DIR))
sys.path.insert(0, str(BENCHMARK_DIR))

from ground_truth_testbed import (
    CUSTOM_AUTH_GROUND_TRUTH,
    JUICE_SHOP_GROUND_TRUTH,
    get_ground_truth_catalog,
)
from models import VerificationResult, VerificationStatus


@dataclass
class BenchmarkMetrics:
    """Quantitative empirical evaluation metrics."""
    testbed_name: str
    target_url: str
    timestamp: str
    duration_seconds: float
    total_ground_truth: int
    detected_vulnerabilities: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float
    recall: float
    f1_score: float
    detection_rate: float
    routes_discovered: int = 0
    apis_discovered: int = 0
    tests_executed: int = 0
    findings_detail: list[dict[str, Any]] = field(default_factory=list)


class BenchmarkHarness:
    """
    Evaluates scan results against ground-truth catalogs and produces raw data.
    """

    def __init__(self, output_dir: Path | None = None) -> None:
        self.output_dir = output_dir or (BENCHMARK_DIR / "results")
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def evaluate_findings(
        self,
        testbed_name: str,
        target_url: str,
        results: list[VerificationResult],
        routes_count: int = 0,
        apis_count: int = 0,
        duration_seconds: float = 0.0,
    ) -> BenchmarkMetrics:
        """
        Compare dynamic verification findings against ground-truth catalogs.
        """
        ground_truth = get_ground_truth_catalog(testbed_name)
        total_gt = len(ground_truth)

        # Filter for confirmed findings
        confirmed_findings = [
            r for r in results if r.status in (VerificationStatus.VERIFIED, VerificationStatus.LIKELY)
        ]

        # Match findings to ground truth
        matched_gt_ids: set[str] = set()
        matched_results: set[str] = set()
        tp = 0

        for r in confirmed_findings:
            req_url = r.evidence.request_url if r.evidence else ""
            vuln_type = r.vulnerability_type.upper()

            # Find matching ground truth entry
            for gt in ground_truth:
                gt_type = gt.get("vulnerability_type", "").upper()
                gt_endpoint = gt.get("endpoint", "")
                clean_endpoint = gt_endpoint.split("{")[0].rstrip("/")

                if vuln_type == gt_type or (vuln_type in ("BOLA", "IDOR") and gt_type in ("BOLA", "IDOR")):
                    if clean_endpoint in req_url or gt_endpoint in req_url:
                        if gt["id"] not in matched_gt_ids:
                            matched_gt_ids.add(gt["id"])
                            matched_results.add(r.test_id)
                            tp += 1
                            break

        fp = len(confirmed_findings) - len(matched_results)
        fn = total_gt - tp

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = (
            (2.0 * precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        detection_rate = (tp / total_gt) if total_gt > 0 else 0.0

        metrics = BenchmarkMetrics(
            testbed_name=testbed_name,
            target_url=target_url,
            timestamp=datetime.now().isoformat(),
            duration_seconds=round(duration_seconds, 2),
            total_ground_truth=total_gt,
            detected_vulnerabilities=len(confirmed_findings),
            true_positives=tp,
            false_positives=fp,
            false_negatives=fn,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            detection_rate=round(detection_rate, 4),
            routes_discovered=routes_count,
            apis_discovered=apis_count,
            tests_executed=len(results),
            findings_detail=[
                {
                    "test_id": r.test_id,
                    "vuln_type": r.vulnerability_type,
                    "status": r.status.value,
                    "confidence": r.confidence,
                    "url": r.evidence.request_url if r.evidence else "",
                    "reason": r.reason,
                }
                for r in results
            ],
        )

        return metrics

    def save_benchmark_report(self, metrics: BenchmarkMetrics) -> Path:
        """Serialize benchmark metrics to raw JSON artifact."""
        safe_name = metrics.testbed_name.lower().replace(" ", "_")
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"benchmark_{safe_name}_{timestamp_str}.json"
        target_path = self.output_dir / filename

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(asdict(metrics), f, indent=2)

        return target_path

    def print_summary_table(self, metrics: BenchmarkMetrics) -> None:
        """Print formatted benchmark evaluation table in console."""
        print("\n" + "=" * 64)
        print(f"  AegisAI Benchmark Evaluation: {metrics.testbed_name}")
        print("=" * 64)
        print(f"  Target URL:           {metrics.target_url}")
        print(f"  Timestamp:            {metrics.timestamp}")
        print(f"  Scan Duration:        {metrics.duration_seconds}s")
        print(f"  Discovered Routes:    {metrics.routes_discovered}")
        print(f"  Discovered APIs:      {metrics.apis_discovered}")
        print(f"  Tests Executed:       {metrics.tests_executed}")
        print("-" * 64)
        print(f"  Ground Truth Vulns:   {metrics.total_ground_truth}")
        print(f"  Detected Vulns:       {metrics.detected_vulnerabilities}")
        print(f"  True Positives (TP):  {metrics.true_positives}")
        print(f"  False Positives (FP): {metrics.false_positives}")
        print(f"  False Negatives (FN): {metrics.false_negatives}")
        print("-" * 64)
        print(f"  Precision:            {metrics.precision * 100:.2f}%")
        print(f"  Recall:               {metrics.recall * 100:.2f}%")
        print(f"  F1 Score:             {metrics.f1_score * 100:.2f}%")
        print(f"  Detection Rate:       {metrics.detection_rate * 100:.2f}%")
        print("=" * 64 + "\n")


# ── Benchmark Self-Run Demo ───────────────────────────────────

def run_sample_benchmark() -> None:
    """Simulate a benchmark evaluation across the custom 10 ground-truth testbed."""
    harness = BenchmarkHarness()

    sample_results = [
        VerificationResult(
            test_id="TEST-001",
            scan_id="bench-01",
            vulnerability_type="BOLA",
            status=VerificationStatus.VERIFIED,
            confidence=0.95,
            is_confirmed=True,
            evidence=None,
            reason="Leaked victim billing data",
        ),
        VerificationResult(
            test_id="TEST-002",
            scan_id="bench-01",
            vulnerability_type="BOLA",
            status=VerificationStatus.VERIFIED,
            confidence=0.92,
            is_confirmed=True,
            evidence=None,
            reason="Leaked document payload",
        ),
        VerificationResult(
            test_id="TEST-003",
            scan_id="bench-01",
            vulnerability_type="SQLI",
            status=VerificationStatus.FALSE_POSITIVE,
            confidence=0.0,
            is_confirmed=False,
            evidence=None,
            reason="Payload sanitized",
        ),
    ]

    # Assign URLs matching ground truth
    from models import ExploitEvidence
    sample_results[0].evidence = ExploitEvidence(
        request_url="http://localhost:3000/api/v1/users/42/billing",
        request_method="GET",
        response_status=200,
        response_body="{}",
        duration_ms=25.0,
    )
    sample_results[1].evidence = ExploitEvidence(
        request_url="http://localhost:3000/api/v1/documents/doc_123",
        request_method="GET",
        response_status=200,
        response_body="{}",
        duration_ms=22.0,
    )
    sample_results[2].evidence = ExploitEvidence(
        request_url="http://localhost:3000/api/v1/search",
        request_method="GET",
        response_status=200,
        response_body="{}",
        duration_ms=18.0,
    )

    metrics = harness.evaluate_findings(
        testbed_name="Custom Ground-Truth Authorization Testbed",
        target_url="http://localhost:3000",
        results=sample_results,
        routes_count=14,
        apis_count=10,
        duration_seconds=12.4,
    )

    harness.print_summary_table(metrics)
    saved_file = harness.save_benchmark_report(metrics)
    print(f"[+] Raw benchmark results saved to: {saved_file}")


if __name__ == "__main__":
    run_sample_benchmark()
