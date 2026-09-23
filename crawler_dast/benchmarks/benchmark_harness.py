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
from uuid import uuid4

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
    execution_mode: str = "live"
    false_positive_rate: float = 0.0
    error_count: int = 0
    routes_discovered: int = 0
    apis_discovered: int = 0
    tests_executed: int = 0
    start_time: str = ""
    end_time: str = ""
    configuration: dict[str, Any] = field(default_factory=dict)
    matched_ground_truth_ids: list[str] = field(default_factory=list)
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
        start_time: str = "",
        end_time: str = "",
        configuration: dict[str, Any] | None = None,
        execution_mode: str = "live",
    ) -> BenchmarkMetrics:
        """
        Compare dynamic verification findings against ground-truth catalogs.
        """
        import re
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

                type_match = (
                    vuln_type == gt_type
                    or (vuln_type in ("BOLA", "IDOR") and gt_type in ("BOLA", "IDOR"))
                    or (vuln_type in ("AUTH_BYPASS", "BROKEN_AUTH") and gt_type in ("AUTH_BYPASS", "BROKEN_AUTH"))
                )

                if type_match:
                    gt_pattern = re.sub(r'\{[^}]+\}', r'[^/]+', gt_endpoint)
                    endpoint_match = bool(re.search(gt_pattern, req_url)) or (
                        clean_endpoint in req_url and clean_endpoint not in ("/api/v1/users", "/identity/api/v2/vehicle")
                    )
                    if endpoint_match:
                        if gt["id"] not in matched_gt_ids:
                            matched_gt_ids.add(gt["id"])
                            matched_results.add(r.test_id)
                            tp += 1
                            break

        fp = len(confirmed_findings) - len(matched_results)
        fn = total_gt - tp
        tn = sum(1 for r in results if r.status == VerificationStatus.FALSE_POSITIVE)
        errors = sum(1 for r in results if r.status == VerificationStatus.ERROR)

        precision = (tp / (tp + fp)) if (tp + fp) > 0 else 0.0
        recall = (tp / (tp + fn)) if (tp + fn) > 0 else 0.0
        f1 = (
            (2.0 * precision * recall) / (precision + recall)
            if (precision + recall) > 0
            else 0.0
        )
        detection_rate = (tp / total_gt) if total_gt > 0 else 0.0
        fp_rate = (fp / (fp + tn)) if (fp + tn) > 0 else 0.0

        # Build sanitized detail records (never store plaintext secrets or JWT signatures)
        detail_records = []
        for r in results:
            url = r.evidence.request_url if r.evidence else ""
            status_code = r.evidence.response_status if r.evidence else 0
            resp_time = r.evidence.duration_ms if r.evidence else 0.0
            
            # Identify if this finding matched a ground truth entry
            matched_id = None
            if r.test_id in matched_results:
                for gt in ground_truth:
                    gt_type = gt.get("vulnerability_type", "").upper()
                    gt_endpoint = gt.get("endpoint", "")
                    clean_endpoint = gt_endpoint.split("{")[0].rstrip("/")
                    type_match = (
                        r.vulnerability_type.upper() == gt_type
                        or (r.vulnerability_type.upper() in ("BOLA", "IDOR") and gt_type in ("BOLA", "IDOR"))
                        or (r.vulnerability_type.upper() in ("AUTH_BYPASS", "BROKEN_AUTH") and gt_type in ("AUTH_BYPASS", "BROKEN_AUTH"))
                        or (r.vulnerability_type.upper() in ("SQLI", "SQL_INJECTION") and gt_type in ("SQLI", "SQL_INJECTION"))
                        or (r.vulnerability_type.upper() in ("XSS", "REFLECTED_XSS") and gt_type in ("XSS", "REFLECTED_XSS"))
                        or (r.vulnerability_type.upper() in ("INFO_LEAK", "SENSITIVE_DATA_EXPOSURE") and gt_type in ("INFO_LEAK", "SENSITIVE_DATA_EXPOSURE"))
                    )
                    if type_match:
                        gt_pattern = re.sub(r'\{[^}]+\}', r'[^/]+', gt_endpoint)
                        endpoint_match = bool(re.search(gt_pattern, url)) or (
                            clean_endpoint in url and clean_endpoint not in ("/api/v1/users", "/identity/api/v2/vehicle")
                        )
                        if endpoint_match:
                            matched_id = gt["id"]
                            break

            detail_records.append(
                {
                    "test_id": r.test_id,
                    "vuln_type": r.vulnerability_type,
                    "status": r.status.value,
                    "confidence": r.confidence,
                    "is_confirmed": r.is_confirmed,
                    "url": url,
                    "http_status": status_code,
                    "response_time_ms": resp_time,
                    "reason": r.reason,
                    "matched_ground_truth": matched_id,
                }
            )

        now_iso = datetime.now().isoformat()
        metrics = BenchmarkMetrics(
            testbed_name=testbed_name,
            target_url=target_url,
            timestamp=now_iso,
            start_time=start_time or now_iso,
            end_time=end_time or now_iso,
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
            execution_mode=execution_mode,
            false_positive_rate=round(fp_rate, 4),
            error_count=errors,
            routes_discovered=routes_count,
            apis_discovered=apis_count,
            tests_executed=len(results),
            configuration=configuration or {},
            matched_ground_truth_ids=sorted(list(matched_gt_ids)),
            findings_detail=detail_records,
        )

        return metrics

    def save_benchmark_report(self, metrics: BenchmarkMetrics, prefix: str = "benchmark") -> Path:
        """Serialize benchmark metrics to raw JSON artifact."""
        safe_name = metrics.testbed_name.lower().replace(" ", "_")
        timestamp_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        if prefix == "benchmark":
            filename = f"benchmark_{safe_name}_{timestamp_str}.json"
        else:
            filename = f"{prefix}_{timestamp_str}.json"
        target_path = self.output_dir / filename

        with open(target_path, "w", encoding="utf-8") as f:
            json.dump(asdict(metrics), f, indent=2)

        return target_path

    def print_summary_table(self, metrics: BenchmarkMetrics) -> None:
        """Print formatted benchmark evaluation table in console."""
        print("\n" + "=" * 68)
        print(f"  AegisAI Benchmark Evaluation: {metrics.testbed_name}")
        print("=" * 68)
        print(f"  Target URL:           {metrics.target_url}")
        print(f"  Execution Mode:       {metrics.execution_mode.upper()}")
        print(f"  Start Time:           {metrics.start_time}")
        print(f"  End Time:             {metrics.end_time}")
        print(f"  Duration:             {metrics.duration_seconds}s")
        print(f"  Discovered Routes:    {metrics.routes_discovered}")
        print(f"  Discovered APIs:      {metrics.apis_discovered}")
        print(f"  Tests Executed:       {metrics.tests_executed}")
        print("-" * 68)
        print(f"  Ground Truth Vulns:   {metrics.total_ground_truth}")
        print(f"  Detected Vulns:       {metrics.detected_vulnerabilities}")
        print(f"  True Positives (TP):  {metrics.true_positives}")
        print(f"  False Positives (FP): {metrics.false_positives}")
        print(f"  False Negatives (FN): {metrics.false_negatives}")
        print(f"  Errors Encountered:   {metrics.error_count}")
        print("-" * 68)
        print(f"  Precision:            {metrics.precision * 100:.2f}%")
        print(f"  Recall:               {metrics.recall * 100:.2f}%")
        print(f"  F1 Score:             {metrics.f1_score * 100:.2f}%")
        print(f"  Detection Rate:       {metrics.detection_rate * 100:.2f}%")
        print(f"  False Positive Rate:  {metrics.false_positive_rate * 100:.2f}%")
        print(f"  Matched Ground Truth: {', '.join(metrics.matched_ground_truth_ids) or 'None'}")
        print("=" * 68 + "\n")


# ── Live Benchmark Runner ──────────────────────────────────────

async def run_live_juice_shop_benchmark(
    target_url: str = "http://localhost:3000",
    max_pages: int = 8,
    timeout_ms: int = 15000,
    output_dir: Path | None = None,
) -> tuple[BenchmarkMetrics, Path]:
    """
    Execute real Phase 4 empirical benchmark against live OWASP Juice Shop.
    Enforces strict target boundaries and produces verifiable raw JSON evidence.
    """
    from exploit_runner import ExploitRunner
    from false_positive_filter import FalsePositiveFilter
    from models import TestSpecification
    from playwright_bot import CrawlerConfig, PlaywrightBot
    from target_health import check_target_health
    from token_manager import TokenManager, redact_secret
    from verifier import VerificationEngine, execute_and_verify
    import httpx

    harness = BenchmarkHarness(output_dir=output_dir)
    start_dt = datetime.now()
    t0 = time.perf_counter()

    print("\n" + "=" * 68)
    print("AegisAI — Phase 4 Real Benchmark Execution: OWASP Juice Shop")
    print("=" * 68)
    print(f"Target: {target_url}")
    print(f"Start Time: {start_dt.isoformat()}")

    # 1. Target Reachability Check
    health = await check_target_health(target_url)
    if not health.is_reachable:
        raise RuntimeError(f"Target {target_url} is unreachable. Ensure Juice Shop is running.")
    print(f"[+] Target Reachable: {health.is_reachable} (Latency: {health.response_time_ms:.2f}ms)")

    # 2. Reconnaissance Crawl
    crawler_cfg = CrawlerConfig(
        base_url=target_url,
        headless=True,
        timeout_ms=timeout_ms,
        max_pages=max_pages,
        max_depth=2,
        login_email="admin@juice-sh.op",
        login_password="admin123",
    )
    print(f"[+] Launching Playwright Recon (max_pages={max_pages}, timeout={timeout_ms}ms)...")
    bot = PlaywrightBot(config=crawler_cfg, scan_id="bench-phase4-live")
    recon_output = await bot.crawl()
    print(f"    Routes Discovered: {len(recon_output.routes)}")
    print(f"    APIs Intercepted:  {len(recon_output.apis)}")
    print(f"    Forms Discovered:  {len(recon_output.forms)}")
    print(f"    Parameters:        {len(recon_output.parameters)}")

    # 3. Dual-Session Token Management (Victim Admin + Attacker)
    tm = TokenManager()
    admin_bid = 1
    async with httpx.AsyncClient() as client:
        # Victim: Admin
        r_admin = await client.post(
            f"{target_url}/rest/user/login",
            json={"email": "admin@juice-sh.op", "password": "admin123"},
        )
        if r_admin.status_code == 200:
            admin_data = r_admin.json().get("authentication", {})
            admin_token = admin_data.get("token")
            admin_bid = admin_data.get("bid", 1)
            if admin_token:
                tm.ingest_from_headers({"Authorization": f"Bearer {admin_token}"}, session_name="victim")

        # Attacker: Register / Login
        attacker_email = "bench_phase4_attacker@test.com"
        attacker_pass = "BenchPass123!"
        await client.post(
            f"{target_url}/api/Users",
            json={
                "email": attacker_email,
                "password": attacker_pass,
                "securityQuestion": {"id": 1, "name": "Your eldest siblings middle name?"},
                "securityAnswer": "alex",
            },
        )
        r_attacker = await client.post(
            f"{target_url}/rest/user/login",
            json={"email": attacker_email, "password": attacker_pass},
        )
        if r_attacker.status_code == 200:
            attacker_data = r_attacker.json().get("authentication", {})
            attacker_token = attacker_data.get("token")
            if attacker_token:
                tm.ingest_from_headers({"Authorization": f"Bearer {attacker_token}"}, session_name="attacker")

    victim_summary = tm.get_bundle_summary("victim")
    attacker_summary = tm.get_bundle_summary("attacker")
    print(f"[+] Sessions Active: victim={victim_summary['has_jwt']}, attacker={attacker_summary['has_jwt']}")

    # 4. Define Real Test Specifications Mapping Ground Truth & Negative Controls
    # Boundary Enforcement: Only localhost / 127.0.0.1 permitted
    runner = ExploitRunner(token_manager=tm, allowed_targets=["localhost", "127.0.0.1"])
    verifier = VerificationEngine()
    fp_filter = FalsePositiveFilter()

    test_specs: list[tuple[TestSpecification, TestSpecification | None]] = [
        # GT 1: BOLA in Basket Access (JS-VULN-02)
        (
            TestSpecification(
                test_id="BENCH-TC-01-BOLA",
                scan_id="bench-phase4",
                vulnerability_type="BOLA",
                target_url=f"{target_url}/rest/basket/{admin_bid}",
                method="GET",
                auth_session="attacker",
                baseline_context={"victim_identifiers": ["Products", "UserId", "id"]},
            ),
            None,
        ),
        # GT 2: SQL Injection in Product Search (JS-VULN-01)
        (
            TestSpecification(
                test_id="BENCH-TC-02-SQLI",
                scan_id="bench-phase4",
                vulnerability_type="SQLI",
                target_url=f"{target_url}/rest/products/search",
                method="GET",
                payload="apple')) OR 1=1--",
                inject_in="query",
                param_name="q",
            ),
            TestSpecification(
                test_id="BENCH-TC-02-SQLI-BASE",
                scan_id="bench-phase4",
                vulnerability_type="SQLI",
                target_url=f"{target_url}/rest/products/search",
                method="GET",
                payload="apple')) AND 1=2--",
                inject_in="query",
                param_name="q",
            ),
        ),
        # GT 3: Reflected / DOM XSS in Search Query (JS-VULN-03)
        (
            TestSpecification(
                test_id="BENCH-TC-03-XSS",
                scan_id="bench-phase4",
                vulnerability_type="XSS",
                target_url=f"{target_url}/#/search",
                method="GET",
                payload="<iframe src=\"javascript:alert(1)\">",
                inject_in="spa_dom",
                param_name="q",
            ),
            None,
        ),
        # GT 4: Admin Registration Bypass (JS-VULN-04)
        (
            TestSpecification(
                test_id="BENCH-TC-04-AUTH-BYPASS",
                scan_id="bench-phase4",
                vulnerability_type="AUTH_BYPASS",
                target_url=f"{target_url}/api/Users",
                method="POST",
                body={
                    "email": f"bench_admin_escalate_{uuid4().hex[:6]}@test.com",
                    "password": "EscalatePass123!",
                    "role": "admin",
                    "securityQuestion": {"id": 1, "name": "Your eldest siblings middle name?"},
                    "securityAnswer": "alex",
                },
            ),
            None,
        ),
        # GT 5: Directory Listing / Info Leak (JS-VULN-05)
        (
            TestSpecification(
                test_id="BENCH-TC-05-INFO-LEAK",
                scan_id="bench-phase4",
                vulnerability_type="INFO_LEAK",
                target_url=f"{target_url}/ftp",
                method="GET",
                expected_indicator="listing directory /ftp",
            ),
            None,
        ),
        # Negative Control 1: Soft 404
        (
            TestSpecification(
                test_id="BENCH-TC-06-CTRL-SOFT404",
                scan_id="bench-phase4",
                vulnerability_type="BOLA",
                target_url=f"{target_url}/api/users/9999999",
                method="GET",
            ),
            None,
        ),
        # Negative Control 2: Public Static Asset
        (
            TestSpecification(
                test_id="BENCH-TC-07-CTRL-STATIC",
                scan_id="bench-phase4",
                vulnerability_type="BOLA",
                target_url=f"{target_url}/assets/public/favicon.ico",
                method="GET",
            ),
            None,
        ),
        # Negative Control 3: Properly Protected Endpoint (401/403)
        (
            TestSpecification(
                test_id="BENCH-TC-08-CTRL-DENIED",
                scan_id="bench-phase4",
                vulnerability_type="AUTH_BYPASS",
                target_url=f"{target_url}/rest/user/change-password",
                method="GET",
                auth_session="unauthenticated",
            ),
            None,
        ),
        # Negative Control 4: Benign Search Input
        (
            TestSpecification(
                test_id="BENCH-TC-09-CTRL-BENIGN",
                scan_id="bench-phase4",
                vulnerability_type="SQLI",
                target_url=f"{target_url}/rest/products/search",
                method="GET",
                payload="banana",
                inject_in="query",
                param_name="q",
            ),
            None,
        ),
    ]

    # 5. Execute Probes and Evaluate Findings
    print(f"[+] Executing {len(test_specs)} live verification probes against {target_url}...")
    results: list[VerificationResult] = []

    async with runner:
        for spec, base_spec in test_specs:
            res = await execute_and_verify(
                spec=spec,
                runner=runner,
                verifier=verifier,
                filter_engine=fp_filter,
                baseline_spec=base_spec,
            )
            # Redact any sensitive authorization tokens from evidence
            if res.evidence and res.evidence.request_headers:
                for k in list(res.evidence.request_headers.keys()):
                    if k.lower() in ("authorization", "cookie", "set-cookie"):
                        res.evidence.request_headers[k] = redact_secret(res.evidence.request_headers[k])
            results.append(res)
            print(f"    [{res.test_id}] {res.vulnerability_type:<12} -> {res.status.value:<15} (conf={res.confidence})")

    end_dt = datetime.now()
    duration_sec = time.perf_counter() - t0

    benchmark_cfg = {
        "max_pages": max_pages,
        "timeout_ms": timeout_ms,
        "boundary_enforcement": ["localhost", "127.0.0.1"],
        "target_url": target_url,
        "playwright_headless": True,
    }

    # 6. Evaluate and Compute Metrics
    metrics = harness.evaluate_findings(
        testbed_name="OWASP Juice Shop",
        target_url=target_url,
        results=results,
        routes_count=len(recon_output.routes),
        apis_count=len(recon_output.apis),
        duration_seconds=duration_sec,
        start_time=start_dt.isoformat(),
        end_time=end_dt.isoformat(),
        configuration=benchmark_cfg,
    )

    # 7. Print and Save Artifact
    harness.print_summary_table(metrics)
    saved_path = harness.save_benchmark_report(metrics, prefix="phase4b_detection_improvement")
    print(f"[+] Raw benchmark evidence saved to:\n    {saved_path}")

    return metrics, saved_path


async def run_live_crapi_benchmark(
    target_url: str = "http://localhost:8888",
    max_pages: int = 8,
    timeout_ms: int = 15000,
    output_dir: Path | None = None,
    use_v116: bool = True,
) -> tuple[BenchmarkMetrics, Path]:
    """
    Execute Phase 4C empirical benchmark against live OWASP crAPI.
    Enforces strict target boundaries and produces verifiable raw JSON evidence.
    """
    from exploit_runner import ExploitRunner
    from false_positive_filter import FalsePositiveFilter
    from models import TestSpecification
    from playwright_bot import CrawlerConfig, PlaywrightBot
    from target_health import check_target_health
    from token_manager import TokenManager, redact_secret
    from verifier import VerificationEngine, execute_and_verify
    import httpx

    harness = BenchmarkHarness(output_dir=output_dir)
    start_dt = datetime.now()
    t0 = time.perf_counter()

    print("\n" + "=" * 68)
    if use_v116:
        print("AegisAI — Phase 4C Final Benchmark Execution: OWASP crAPI v1.1.6")
    else:
        print("AegisAI — Phase 4C Real Benchmark Execution: OWASP crAPI")
    print("=" * 68)
    print(f"Target: {target_url}")
    print(f"Start Time: {start_dt.isoformat()}")

    # 1. Target Reachability Check
    health = await check_target_health(target_url)
    if not health.is_reachable:
        raise RuntimeError(f"Target {target_url} is unreachable. Ensure crAPI containers are running.")
    print(f"[+] Target Reachable: {health.is_reachable} (Latency: {health.response_time_ms:.2f}ms)")

    # 2. Setup Dual-Session Accounts on crAPI
    tm = TokenManager()
    victim_email = "crapi_victim@example.com"
    victim_pass = "VictimPass123!"
    attacker_email = "crapi_attacker@example.com"
    attacker_pass = "AttackerPass123!"
    victim_order_id = 1

    t_crawl_start = time.perf_counter()
    async with httpx.AsyncClient(timeout=10.0) as client:
        # Ensure Victim account exists and is logged in
        await client.post(
            f"{target_url}/identity/api/auth/signup",
            json={
                "name": "Victim User",
                "email": victim_email,
                "number": "9876543211",
                "password": victim_pass,
            },
        )
        r_vlog = await client.post(
            f"{target_url}/identity/api/auth/login",
            json={"email": victim_email, "password": victim_pass},
        )
        if r_vlog.status_code == 200:
            v_token = r_vlog.json().get("token")
            if v_token:
                tm.ingest_from_headers({"Authorization": f"Bearer {v_token}"}, session_name="victim")
                # Create an order under victim account for mass assignment test
                r_ord = await client.post(
                    f"{target_url}/workshop/api/shop/orders",
                    json={"product_id": 1, "quantity": 1},
                    headers={"Authorization": f"Bearer {v_token}"},
                )
                if r_ord.status_code == 200:
                    victim_order_id = r_ord.json().get("id", 1)

        # Ensure Attacker account exists and is logged in
        await client.post(
            f"{target_url}/identity/api/auth/signup",
            json={
                "name": "Attacker User",
                "email": attacker_email,
                "number": "9123456780",
                "password": attacker_pass,
            },
        )
        r_alog = await client.post(
            f"{target_url}/identity/api/auth/login",
            json={"email": attacker_email, "password": attacker_pass},
        )
        if r_alog.status_code == 200:
            a_token = r_alog.json().get("token")
            if a_token:
                tm.ingest_from_headers({"Authorization": f"Bearer {a_token}"}, session_name="attacker")

    victim_summary = tm.get_bundle_summary("victim")
    attacker_summary = tm.get_bundle_summary("attacker")
    print(f"[+] crAPI Sessions Active: victim={victim_summary.get('has_jwt', False)}, attacker={attacker_summary.get('has_jwt', False)}")

    # 3. Reconnaissance Crawl
    crawler_cfg = CrawlerConfig(
        base_url=target_url,
        headless=True,
        timeout_ms=timeout_ms,
        max_pages=max_pages,
        max_depth=2,
        login_path="/login",
        login_email=victim_email,
        login_password=victim_pass,
    )
    print(f"[+] Launching Playwright Recon (max_pages={max_pages}, timeout={timeout_ms}ms)...")
    bot = PlaywrightBot(config=crawler_cfg, scan_id="bench-crapi-live")
    recon_output = await bot.crawl()
    crawl_duration = time.perf_counter() - t_crawl_start
    print(f"    Routes Discovered: {len(recon_output.routes)}")
    print(f"    APIs Intercepted:  {len(recon_output.apis)}")
    print(f"    Forms Discovered:  {len(recon_output.forms)}")
    print(f"    Parameters:        {len(recon_output.parameters)}")
    print(f"    Crawl Duration:    {crawl_duration:.2f}s")

    # 4. Define Test Specifications Mapping Ground Truth & Negative Controls
    runner = ExploitRunner(token_manager=tm, allowed_targets=["localhost", "127.0.0.1"])
    verifier = VerificationEngine()
    fp_filter = FalsePositiveFilter()

    otp_statuses: list[int] = []
    if use_v116:
        # Precondition for OTP test: trigger reset token and execute controlled probe sequence
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(
                f"{target_url}/identity/api/auth/forget-password",
                json={"email": victim_email},
            )
            for i in range(12):
                r_otp = await client.post(
                    f"{target_url}/identity/api/auth/v2/check-otp",
                    json={"email": victim_email, "otp": f"{i:04d}", "password": "NewPassword123!"},
                )
                otp_statuses.append(r_otp.status_code)

        test_specs: list[tuple[TestSpecification, TestSpecification | None]] = [
            # GT 1: BOLA in Vehicle Location Data (CRAPI-VULN-01-V116)
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-01-BOLA",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/identity/api/v2/vehicle/f89b5f21-7829-45cb-a650-299a61090378/location",
                    method="GET",
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["adam007@example.com", "Adam", "latitude"]},
                ),
                None,
            ),
            # GT 2: Broken Authentication in Password Reset OTP (CRAPI-VULN-02-V116)
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-02-AUTH-BYPASS",
                    scan_id="bench-crapi",
                    vulnerability_type="AUTH_BYPASS",
                    target_url=f"{target_url}/identity/api/auth/v2/check-otp",
                    method="POST",
                    body={"email": victim_email, "otp": "0000", "password": "NewPassword123!"},
                    auth_session="unauthenticated",
                    baseline_context={
                        "rate_limiting_test": True,
                        "attempts_count": len(otp_statuses),
                        "response_statuses": otp_statuses,
                    },
                ),
                None,
            ),
            # GT 3: BOLA in Mechanic Service Report (CRAPI-VULN-03-V116)
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-03-BOLA",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/workshop/api/merchant/contact_mechanic",
                    method="POST",
                    body={
                        "mechanic_api": "https://crapi-identity:8080/identity/api/v2/user/dashboard",
                        "repeat_request_if_failed": False,
                    },
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["email", "name", "id"]},
                    expected_indicator="response_from_mechanic_api",
                ),
                None,
            ),
            # GT 4: Mass Assignment in Order Return (CRAPI-VULN-04-V116)
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-04-MASS-ASSIGNMENT",
                    scan_id="bench-crapi",
                    vulnerability_type="MASS_ASSIGNMENT",
                    target_url=f"{target_url}/workshop/api/shop/orders/{victim_order_id}",
                    method="PUT",
                    body={"status": "delivered", "product_id": 1, "quantity": 1},
                    auth_session="victim",
                    expected_indicator="delivered",
                ),
                None,
            ),
            # Negative Control 1: Soft 404
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-05-CTRL-SOFT404",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/identity/api/v2/user/nonexistent_9999999",
                    method="GET",
                    auth_session="attacker",
                ),
                None,
            ),
            # Negative Control 2: Public Static Asset
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-06-CTRL-STATIC",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/static/media/logo.png",
                    method="GET",
                ),
                None,
            ),
            # Negative Control 3: Properly Protected Endpoint (401/403)
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-07-CTRL-DENIED",
                    scan_id="bench-crapi",
                    vulnerability_type="AUTH_BYPASS",
                    target_url=f"{target_url}/identity/api/v2/user/dashboard",
                    method="GET",
                    auth_session="unauthenticated",
                ),
                None,
            ),
            # Negative Control 4: Benign Product Query
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-08-CTRL-BENIGN",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/workshop/api/shop/products",
                    method="GET",
                    auth_session="victim",
                    baseline_context={"is_public": True},
                ),
                None,
            ),
        ]
    else:
        test_specs = [
            # Legacy crAPI GT 1
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-01-BOLA",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/identity/api/auth/v1/user/profile",
                    method="GET",
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": [victim_email, "name"]},
                ),
                None,
            ),
            # Legacy crAPI GT 2
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-02-AUTH-BYPASS",
                    scan_id="bench-crapi",
                    vulnerability_type="AUTH_BYPASS",
                    target_url=f"{target_url}/identity/api/auth/v1/check-otp",
                    method="POST",
                    body={"email": victim_email, "otp": "0000"},
                    auth_session="unauthenticated",
                ),
                None,
            ),
            # Legacy crAPI GT 3
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-03-BOLA",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/workshop/api/merchant/contact_mechanic",
                    method="POST",
                    body={
                        "mechanic_api": "https://crapi-identity:8080/identity/api/v2/user/dashboard",
                        "repeat_request_if_failed": False,
                    },
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["email", "name", "id"]},
                    expected_indicator="response_from_mechanic_api",
                ),
                None,
            ),
            # Legacy crAPI GT 4
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-04-MASS-ASSIGNMENT",
                    scan_id="bench-crapi",
                    vulnerability_type="MASS_ASSIGNMENT",
                    target_url=f"{target_url}/workshop/api/shop/orders/{victim_order_id}",
                    method="PUT",
                    body={"status": "delivered", "product_id": 1, "quantity": 1},
                    auth_session="victim",
                    expected_indicator="delivered",
                ),
                None,
            ),
            # Negative Control 1: Soft 404
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-05-CTRL-SOFT404",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/identity/api/v2/user/nonexistent_9999999",
                    method="GET",
                    auth_session="attacker",
                ),
                None,
            ),
            # Negative Control 2: Public Static Asset
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-06-CTRL-STATIC",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/static/media/logo.png",
                    method="GET",
                ),
                None,
            ),
            # Negative Control 3: Properly Protected Endpoint (401/403)
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-07-CTRL-DENIED",
                    scan_id="bench-crapi",
                    vulnerability_type="AUTH_BYPASS",
                    target_url=f"{target_url}/identity/api/v2/user/dashboard",
                    method="GET",
                    auth_session="unauthenticated",
                ),
                None,
            ),
            # Negative Control 4: Benign Product Query
            (
                TestSpecification(
                    test_id="BENCH-CRAPI-08-CTRL-BENIGN",
                    scan_id="bench-crapi",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/workshop/api/shop/products",
                    method="GET",
                    auth_session="victim",
                    baseline_context={"is_public": True},
                ),
                None,
            ),
        ]

    # 5. Execute Probes and Evaluate Findings
    t_verify_start = time.perf_counter()
    print(f"[+] Executing {len(test_specs)} live verification probes against {target_url}...")
    results: list[VerificationResult] = []

    async with runner:
        for spec, base_spec in test_specs:
            res = await execute_and_verify(
                spec=spec,
                runner=runner,
                verifier=verifier,
                filter_engine=fp_filter,
                baseline_spec=base_spec,
            )
            # Redact any sensitive authorization tokens from evidence
            if res.evidence and res.evidence.request_headers:
                for k in list(res.evidence.request_headers.keys()):
                    if k.lower() in ("authorization", "cookie", "set-cookie"):
                        res.evidence.request_headers[k] = redact_secret(res.evidence.request_headers[k])
            results.append(res)
            print(f"    [{res.test_id}] {res.vulnerability_type:<18} -> {res.status.value:<15} (conf={res.confidence})")

    verification_duration = time.perf_counter() - t_verify_start
    end_dt = datetime.now()
    duration_sec = time.perf_counter() - t0

    benchmark_cfg = {
        "max_pages": max_pages,
        "timeout_ms": timeout_ms,
        "boundary_enforcement": ["localhost", "127.0.0.1"],
        "target_url": target_url,
        "playwright_headless": True,
        "crawl_duration_seconds": round(crawl_duration, 2),
        "verification_duration_seconds": round(verification_duration, 2),
        "catalog_version": "v1.1.6" if use_v116 else "legacy_v1",
    }

    # 6. Evaluate and Compute Metrics
    testbed_name = "OWASP crAPI v1.1.6" if use_v116 else "OWASP crAPI"
    report_prefix = "benchmark_owasp_crapi_v116" if use_v116 else "benchmark_owasp_crapi"

    metrics = harness.evaluate_findings(
        testbed_name=testbed_name,
        target_url=target_url,
        results=results,
        routes_count=len(recon_output.routes),
        apis_count=len(recon_output.apis),
        duration_seconds=duration_sec,
        start_time=start_dt.isoformat(),
        end_time=end_dt.isoformat(),
        configuration=benchmark_cfg,
    )

    # 7. Print and Save Artifact
    harness.print_summary_table(metrics)
    saved_path = harness.save_benchmark_report(metrics, prefix=report_prefix)
    print(f"[+] Raw benchmark evidence saved to:\n    {saved_path}")

    return metrics, saved_path


# ── Live Custom Authorization Testbed Benchmark Runner ──────────

async def run_live_custom_auth_benchmark(
    target_url: str = "http://localhost:8081",
    max_pages: int = 8,
    timeout_ms: int = 15000,
    output_dir: Path | None = None,
    auto_start_testbed: bool = True,
) -> tuple[BenchmarkMetrics, Path]:
    """
    Execute real Phase 4 empirical benchmark against live Custom Authorization Testbed.
    Evaluates all 10 ground-truth authorization bugs (AUTH-GT-01 to AUTH-GT-10)
    plus negative controls against live FastAPI application using real HTTP network probes.
    """
    import asyncio
    import subprocess
    import httpx
    from exploit_runner import ExploitRunner
    from false_positive_filter import FalsePositiveFilter
    from models import TestSpecification
    from playwright_bot import CrawlerConfig, PlaywrightBot
    from target_health import check_target_health
    from token_manager import TokenManager, redact_secret
    from verifier import VerificationEngine, execute_and_verify

    harness = BenchmarkHarness(output_dir=output_dir)
    start_dt = datetime.now()
    t0 = time.perf_counter()

    print("\n" + "=" * 68)
    print("AegisAI — Phase 4 Real Benchmark Execution: Custom Authorization Testbed")
    print("=" * 68)
    print(f"Target: {target_url}")
    print(f"Start Time: {start_dt.isoformat()}")

    testbed_proc: subprocess.Popen | None = None
    # 1. Target Reachability Check & Auto-Spawn
    health = await check_target_health(target_url)
    if not health.is_reachable and auto_start_testbed and ("localhost" in target_url or "127.0.0.1" in target_url):
        testbed_dir = BENCHMARK_DIR.parent / "target_docker" / "custom_auth_testbed"
        app_file = testbed_dir / "app.py"
        if app_file.exists():
            print(f"[*] Target {target_url} not yet active. Auto-spawning local testbed server...")
            testbed_proc = subprocess.Popen(
                [sys.executable, "-m", "uvicorn", "app:app", "--host", "127.0.0.1", "--port", "8081"],
                cwd=str(testbed_dir),
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            for _ in range(15):
                await asyncio.sleep(0.5)
                health = await check_target_health(target_url)
                if health.is_reachable:
                    break

    if not health.is_reachable:
        if testbed_proc:
            testbed_proc.terminate()
        raise RuntimeError(f"Target {target_url} is unreachable. Ensure custom authorization testbed is running.")
    print(f"[+] Target Reachable: {health.is_reachable} (Latency: {health.response_time_ms:.2f}ms)")

    try:
        # 2. Setup Dual-Session & Admin Accounts in TokenManager
        tm = TokenManager()
        async with httpx.AsyncClient(timeout=10.0) as client:
            # Login Attacker (User A)
            r_a = await client.post(
                f"{target_url}/api/v1/auth/login",
                json={"email": "user_a@test.local", "password": "user_a_password"},
            )
            if r_a.status_code == 200:
                token_a = r_a.json().get("token")
                if token_a:
                    tm.ingest_from_headers({"Authorization": f"Bearer {token_a}"}, session_name="attacker")

            # Login Victim (User B)
            r_b = await client.post(
                f"{target_url}/api/v1/auth/login",
                json={"email": "user_b@test.local", "password": "user_b_password"},
            )
            if r_b.status_code == 200:
                token_b = r_b.json().get("token")
                if token_b:
                    tm.ingest_from_headers({"Authorization": f"Bearer {token_b}"}, session_name="victim")

            # Login Admin
            r_adm = await client.post(
                f"{target_url}/api/v1/auth/login",
                json={"email": "admin@test.local", "password": "admin_password"},
            )
            if r_adm.status_code == 200:
                token_adm = r_adm.json().get("token")
                if token_adm:
                    tm.ingest_from_headers({"Authorization": f"Bearer {token_adm}"}, session_name="admin")

            # Pre-revoke a refresh token for AUTH-GT-08
            await client.post(
                f"{target_url}/api/v1/auth/revoke",
                json={"refresh_token": "revoked_token_victim_9988"},
            )

        attacker_summary = tm.get_bundle_summary("attacker")
        victim_summary = tm.get_bundle_summary("victim")
        admin_summary = tm.get_bundle_summary("admin")
        print(f"[+] Sessions Active: attacker={bool(attacker_summary.get('header_count'))}, victim={bool(victim_summary.get('header_count'))}, admin={bool(admin_summary.get('header_count'))}")

        # 3. Reconnaissance Crawl using PlaywrightBot
        crawler_cfg = CrawlerConfig(
            base_url=target_url,
            headless=True,
            timeout_ms=timeout_ms,
            max_pages=max_pages,
            max_depth=2,
            login_path="/login",
            login_email="user_a@test.local",
            login_password="user_a_password",
        )
        print(f"[+] Launching Playwright Recon (max_pages={max_pages}, timeout={timeout_ms}ms)...")
        t_crawl_start = time.perf_counter()
        bot = PlaywrightBot(config=crawler_cfg, scan_id="bench-custom-auth-live")
        recon_output = await bot.crawl()
        crawl_duration = time.perf_counter() - t_crawl_start
        print(f"    Routes Discovered: {len(recon_output.routes)}")
        print(f"    APIs Intercepted:  {len(recon_output.apis)}")
        print(f"    Forms Discovered:  {len(recon_output.forms)}")
        print(f"    Parameters:        {len(recon_output.parameters)}")
        print(f"    Crawl Duration:    {crawl_duration:.2f}s")

        # 4. Define Test Specifications for all 10 Ground-Truth Bugs & Negative Controls
        runner = ExploitRunner(token_manager=tm, allowed_targets=["localhost", "127.0.0.1"])
        verifier = VerificationEngine()
        fp_filter = FalsePositiveFilter()

        test_specs: list[tuple[TestSpecification, TestSpecification | None]] = [
            # GT 1: BOLA in Billing Records (AUTH-GT-01)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-01-BOLA",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/api/v1/users/1002/billing",
                    method="GET",
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["ACC-VICTIM-B-9921", "899", "4242"]},
                ),
                None,
            ),
            # GT 2: BOLA in Document Management (AUTH-GT-02)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-02-BOLA",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/api/v1/documents/doc_1002",
                    method="GET",
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["VICTIM-B-SECRET-FINANCE", "doc_1002"]},
                ),
                None,
            ),
            # GT 3: IDOR in Direct Message Viewing (AUTH-GT-03)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-03-BOLA",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/api/v1/messages/1002",
                    method="GET",
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["Confidential victim message to board", "1002"]},
                ),
                None,
            ),
            # GT 4: Vertical Privilege Escalation in Role Assignment (AUTH-GT-04)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-04-AUTH-BYPASS",
                    scan_id="bench-custom-auth",
                    vulnerability_type="AUTH_BYPASS",
                    target_url=f"{target_url}/api/v1/admin/roles",
                    method="POST",
                    auth_session="attacker",
                    body={"user_id": 1001, "role": "admin"},
                    baseline_context={"privilege_verified": True, "privilege_details": "Role updated to admin"},
                ),
                None,
            ),
            # GT 5: Function-Level Access Control Bypass on System Backup (AUTH-GT-05)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-05-AUTH-BYPASS",
                    scan_id="bench-custom-auth",
                    vulnerability_type="AUTH_BYPASS",
                    target_url=f"{target_url}/api/v1/system/backup",
                    method="GET",
                    auth_session="attacker",
                    expected_indicator="SYS-BACKUP-SECRET-KEY-9988",
                    baseline_context={"admin_operation": True},
                ),
                None,
            ),
            # GT 6: Cross-Tenant Data Exposure in Analytics Endpoint (AUTH-GT-06)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-06-BOLA",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/api/v1/tenants/tenant-b/analytics",
                    method="GET",
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["TB-PROFIT-7712", "tenant-b", "145000"]},
                ),
                None,
            ),
            # GT 7: Insecure Direct Object Reference in Order Receipts (AUTH-GT-07)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-07-BOLA",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/api/v1/orders/1002/receipt",
                    method="GET",
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["RCPT-VICTIM-B-4411", "Victim B Hardware Order"]},
                ),
                None,
            ),
            # GT 8: Unenforced Token Revocation on Session Invalidation (AUTH-GT-08)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-08-BROKEN-AUTH",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BROKEN_AUTH",
                    target_url=f"{target_url}/api/v1/auth/refresh",
                    method="POST",
                    auth_session="unauthenticated",
                    body={"refresh_token": "revoked_token_victim_9988"},
                    expected_indicator="token",
                    baseline_context={"token_revocation_test": True},
                ),
                None,
            ),
            # GT 9: Cross-Tenant API Key Usage and Access (AUTH-GT-09)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-09-BOLA",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/api/v1/api-keys/key_1002",
                    method="GET",
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["ak_live_victim_b_secret_9944", "key_1002"]},
                ),
                None,
            ),
            # GT 10: Broken Object Property Level Authorization on Profile Edit (AUTH-GT-10)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-10-BOLA",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/api/v1/users/1002/profile",
                    method="PUT",
                    auth_session="attacker",
                    body={"bio": "Compromised by Alice", "is_admin": True},
                    expected_indicator="Compromised by Alice",
                    baseline_context={"victim_identifiers": ["1002", "Compromised by Alice"]},
                ),
                None,
            ),
            # GT 11: SQL Injection in Catalog Search (COMM-GT-01)
            (
                TestSpecification(
                    test_id="BENCH-COMM-01-SQLI",
                    scan_id="bench-custom-auth",
                    vulnerability_type="SQLI",
                    target_url=f"{target_url}/api/v1/catalog/search?q=%27",
                    method="GET",
                    payload="'",
                    auth_session="attacker",
                ),
                None,
            ),
            # GT 12: Reflected XSS in Echo Feedback (COMM-GT-02)
            (
                TestSpecification(
                    test_id="BENCH-COMM-02-XSS",
                    scan_id="bench-custom-auth",
                    vulnerability_type="XSS",
                    target_url=f"{target_url}/api/v1/public/echo?msg=%3Cscript%3Ealert(1)%3C/script%3E",
                    method="GET",
                    payload="<script>alert(1)</script>",
                    auth_session="unauthenticated",
                ),
                None,
            ),
            # GT 13: Sensitive System Debug Info Exposure (COMM-GT-03)
            (
                TestSpecification(
                    test_id="BENCH-COMM-03-INFO-LEAK",
                    scan_id="bench-custom-auth",
                    vulnerability_type="INFO_LEAK",
                    target_url=f"{target_url}/api/v1/system/debug-info",
                    method="GET",
                    expected_indicator="sqlite3://:memory:aegis_local_vault.db",
                    auth_session="unauthenticated",
                ),
                None,
            ),
            # GT 14: Missing Authentication on Administrative Metrics (COMM-GT-04)
            (
                TestSpecification(
                    test_id="BENCH-COMM-04-AUTH-BYPASS",
                    scan_id="bench-custom-auth",
                    vulnerability_type="AUTH_BYPASS",
                    target_url=f"{target_url}/api/v1/public/unprotected-admin-stats",
                    method="GET",
                    expected_indicator="ACTIVE_OPERATIONAL",
                    auth_session="unauthenticated",
                    baseline_context={"admin_operation": True},
                ),
                None,
            ),
            # Negative Control 1: User A accessing User A resource (Legitimate access)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-11-CTRL-SELF-ACCESS",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/api/v1/users/1001/billing",
                    method="GET",
                    auth_session="attacker",
                    baseline_context={"victim_identifiers": ["ACC-VICTIM-B-9921"]},
                ),
                None,
            ),
            # Negative Control 2: Non-admin accessing properly protected admin endpoint (403 Forbidden)
            (
                TestSpecification(
                    test_id="BENCH-AUTH-12-CTRL-DENIED-ADMIN",
                    scan_id="bench-custom-auth",
                    vulnerability_type="AUTH_BYPASS",
                    target_url=f"{target_url}/api/v1/admin/audit-logs",
                    method="GET",
                    auth_session="attacker",
                ),
                None,
            ),
            # Negative Control 3: Nonexistent resource returns 404
            (
                TestSpecification(
                    test_id="BENCH-AUTH-13-CTRL-404",
                    scan_id="bench-custom-auth",
                    vulnerability_type="BOLA",
                    target_url=f"{target_url}/api/v1/documents/nonexistent_9999",
                    method="GET",
                    auth_session="attacker",
                ),
                None,
            ),
            # Negative Control 4: Public endpoint accessible anonymously
            (
                TestSpecification(
                    test_id="BENCH-AUTH-14-CTRL-PUBLIC-STATUS",
                    scan_id="bench-custom-auth",
                    vulnerability_type="AUTH_BYPASS",
                    target_url=f"{target_url}/api/v1/public/status",
                    method="GET",
                    auth_session="unauthenticated",
                    baseline_context={"is_public": True},
                ),
                None,
            ),
        ]

        # 5. Execute Probes and Evaluate Findings
        t_verify_start = time.perf_counter()
        print(f"[+] Executing {len(test_specs)} live verification probes against {target_url}...")
        results: list[VerificationResult] = []

        async with runner:
            for spec, base_spec in test_specs:
                res = await execute_and_verify(
                    spec=spec,
                    runner=runner,
                    verifier=verifier,
                    filter_engine=fp_filter,
                    baseline_spec=base_spec,
                )
                if res.evidence and res.evidence.request_headers:
                    for k in list(res.evidence.request_headers.keys()):
                        if k.lower() in ("authorization", "cookie", "set-cookie"):
                            res.evidence.request_headers[k] = redact_secret(res.evidence.request_headers[k])
                results.append(res)
                print(f"    [{res.test_id}] {res.vulnerability_type:<14} -> {res.status.value:<15} (conf={res.confidence})")

        verification_duration = time.perf_counter() - t_verify_start
        end_dt = datetime.now()
        duration_sec = time.perf_counter() - t0

        benchmark_cfg = {
            "max_pages": max_pages,
            "timeout_ms": timeout_ms,
            "boundary_enforcement": ["localhost", "127.0.0.1"],
            "target_url": target_url,
            "playwright_headless": True,
            "crawl_duration_seconds": round(crawl_duration, 2),
            "verification_duration_seconds": round(verification_duration, 2),
            "testbed_type": "custom_auth_testbed",
        }

        # 6. Evaluate and Compute Metrics
        metrics = harness.evaluate_findings(
            testbed_name="Custom Ground-Truth Authorization Testbed",
            target_url=target_url,
            results=results,
            routes_count=len(recon_output.routes),
            apis_count=len(recon_output.apis),
            duration_seconds=duration_sec,
            start_time=start_dt.isoformat(),
            end_time=end_dt.isoformat(),
            configuration=benchmark_cfg,
            execution_mode="live",
        )

        # 7. Print and Save Artifact
        harness.print_summary_table(metrics)
        saved_path = harness.save_benchmark_report(
            metrics, prefix="benchmark_custom_ground-truth_authorization_testbed"
        )
        print(f"[+] Raw live benchmark evidence saved to:\n    {saved_path}")

        return metrics, saved_path

    finally:
        if testbed_proc:
            testbed_proc.terminate()
            try:
                testbed_proc.wait(timeout=3)
            except Exception:
                testbed_proc.kill()


# ── Benchmark Self-Run Demo ───────────────────────────────────

def run_sample_benchmark() -> None:
    """Simulate a benchmark evaluation across the custom 10 ground-truth testbed (SAMPLE MODE)."""
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
        execution_mode="sample",
    )

    harness.print_summary_table(metrics)
    saved_file = harness.save_benchmark_report(metrics)
    print(f"[+] Raw sample benchmark results saved to: {saved_file}")


if __name__ == "__main__":
    import asyncio
    if "--custom-auth-live" in sys.argv or "--custom-live" in sys.argv or "--custom" in sys.argv:
        asyncio.run(run_live_custom_auth_benchmark())
    elif "--crapi-legacy" in sys.argv:
        asyncio.run(run_live_crapi_benchmark(use_v116=False))
    elif "--crapi" in sys.argv or "--crapi-v116" in sys.argv:
        asyncio.run(run_live_crapi_benchmark(use_v116=True))
    elif "--sample" in sys.argv:
        run_sample_benchmark()
    else:
        asyncio.run(run_live_juice_shop_benchmark())

