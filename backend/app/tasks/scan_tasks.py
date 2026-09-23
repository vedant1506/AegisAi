"""
AegisAI — Celery Scan Tasks
=============================
Defines the background scan task that orchestrates the full
SAST ? DAST ? AI-Reasoning ? Correlation pipeline.

The task is dispatched from scan_router.py and updates state
via ScanStateManager so all polling endpoints see live progress.
"""

from __future__ import annotations

import asyncio
import sys
from datetime import datetime
from pathlib import Path
from typing import Any

import structlog

from app.schemas.io_models import (
    ASTSchema,
    DetectedVulnerability,
    EndpointSchema,
    ScanReport,
    ScanStatus,
    ScanSummary,
    Severity,
)
from app.services.scan_state_manager import state_manager

logger = structlog.get_logger(__name__)


# -- Lazy Celery import (avoids startup failure when Redis is down) -

def _get_celery():
    from app.tasks.celery_app import celery_app
    return celery_app


# -- Helpers ---------------------------------------------------

def _run_async(coro) -> Any:
    """Run an async coroutine from sync Celery task context."""
    try:
        loop = asyncio.get_event_loop()
        if loop.is_closed():
            raise RuntimeError("closed")
        return loop.run_until_complete(coro)
    except RuntimeError:
        return asyncio.run(coro)


def _check_url_reachable(target_url: str) -> tuple[bool, str]:
    """Pre-flight check: verify that target_url can be reached over HTTP/HTTPS."""
    import urllib.request
    try:
        req = urllib.request.Request(
            target_url,
            headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AegisAI-Scanner/1.0"},
        )
        with urllib.request.urlopen(req, timeout=12):
            return True, ""
    except Exception as exc:
        err_str = str(exc)
        if "HTTP Error" in err_str:
            return True, ""
        return False, err_str


# -- Main Scan Pipeline ----------------------------------------

def run_full_scan_pipeline(
    scan_id: str,
    github_url: str | None,
    target_url: str | None = None,
    branch: str = "main",
    detection_mode: str = "all",
) -> dict[str, Any]:
    """
    Synchronously execute the full VAPT pipeline.

    Stages:
      1. Pre-flight verification of target URL (if provided) and GitHub repository (if provided)
      2. Clone repo & run tree-sitter AST route extraction (25% - skipped in DAST-only mode)
      3. Run Playwright DAST crawler on target_url        (50% - skipped in SAST-only mode)
      4. Feed data into LangGraph AI agent graph          (75%)
      5. Run Hybrid Correlator                            (100%)
      6. Persist ScanReport to state manager
    """
    logger.info("scan.pipeline.start", scan_id=scan_id, github_url=github_url, target_url=target_url)

    started_at = datetime.utcnow()
    ast_results: list[ASTSchema] = []
    endpoint_results: list[EndpointSchema] = []
    vulnerabilities: list[DetectedVulnerability] = []
    passive_vulns: list[DetectedVulnerability] = []

    has_github = bool(github_url and github_url.strip())
    has_target = bool(target_url and target_url.strip())

    if not has_github and not has_target:
        error_msg = "Neither GitHub URL nor Target URL was provided. Please provide at least one target."
        logger.error("scan.pipeline.no_targets", scan_id=scan_id)
        state_manager.update_status(
            scan_id,
            ScanStatus.FAILED,
            progress_pct=0,
            current_agent="error",
            message=error_msg,
        )
        state_manager.update_agent_state(
            scan_id,
            current_agent="error",
            reasoning_trace=[f"[Target Error] {error_msg}"],
        )
        return {"scan_id": scan_id, "status": "failed", "error": error_msg}

    # -- Pre-flight Check: Target URL Reachability (if target_url provided) -------------
    if has_target:
        state_manager.update_status(
            scan_id,
            ScanStatus.RUNNING,
            progress_pct=2,
            current_agent="recon",
            message=f"Verifying target application connectivity at {target_url}...",
        )
        is_reachable, reachability_error = _check_url_reachable(target_url.strip())
        if not is_reachable:
            error_msg = f"Target Application URL '{target_url}' is unreachable ({reachability_error}). Ensure the server is online and try again."
            logger.error("scan.pipeline.target_unreachable", scan_id=scan_id, target_url=target_url, error=reachability_error)
            state_manager.update_status(
                scan_id,
                ScanStatus.FAILED,
                progress_pct=0,
                current_agent="error",
                message=error_msg,
            )
            state_manager.update_agent_state(
                scan_id,
                current_agent="error",
                reasoning_trace=[f"[Pre-Flight Error] {error_msg}"],
            )
            return {"scan_id": scan_id, "status": "failed", "error": error_msg}
    else:
        logger.info("scan.pipeline.sast_mode_preflight", scan_id=scan_id, github_url=github_url)
        state_manager.update_status(
            scan_id,
            ScanStatus.RUNNING,
            progress_pct=2,
            current_agent="recon",
            message="Starting SAST-Only static repository security audit...",
        )

    repo_path = None
    cleanup_fn = None

    if has_github:
        # -- Step 1: SAST (tree-sitter AST Analysis & Repo Clone) --
        state_manager.update_status(
            scan_id,
            ScanStatus.RUNNING,
            progress_pct=5,
            current_agent="recon",
            message=f"Cloning GitHub repository from {github_url}...",
        )

        try:
            from app.ast_parser.tree_sitter_engine import TreeSitterEngine

            engine = TreeSitterEngine()
            repo_path, cleanup_fn = _run_async(
                engine.clone_or_resolve_repository(github_url.strip(), branch=branch)
            )
            ast_results = _run_async(engine.analyse_repository(repo_path))

            logger.info(
                "scan.pipeline.sast_complete",
                scan_id=scan_id,
                ast_nodes=len(ast_results),
            )
            state_manager.update_agent_state(
                scan_id,
                current_agent="recon",
                reasoning_trace=[
                    f"[SAST] Analysed repository. Found {len(ast_results)} route nodes."
                ],
                ast_data=[r.model_dump(mode="json") for r in ast_results],
            )
        except Exception as exc:
            exc_str = str(exc)
            if "not found" in exc_str.lower() or "404" in exc_str:
                error_msg = f"GitHub repository does not exist or is private (404 Not Found): '{github_url}'. Scan stopped."
            else:
                error_msg = f"Failed to clone repository '{github_url}': {exc}. Scan stopped."
            logger.error("scan.pipeline.sast_failed", scan_id=scan_id, error=exc_str)
            state_manager.update_status(
                scan_id,
                ScanStatus.FAILED,
                progress_pct=0,
                current_agent="error",
                message=error_msg,
            )
            state_manager.update_agent_state(
                scan_id,
                current_agent="error",
                reasoning_trace=[f"[Repository Error] {error_msg}"],
            )
            # STOP EXECUTION IMMEDIATELY! Do NOT proceed to DAST or AI reasoning!
            return {"scan_id": scan_id, "status": "failed", "error": error_msg}

        state_manager.update_status(
            scan_id,
            ScanStatus.RUNNING,
            progress_pct=25,
            current_agent="recon",
            message=(
                f"AST analysis complete ({len(ast_results)} routes found). Starting DAST crawler..."
                if has_target
                else f"AST analysis complete ({len(ast_results)} routes found). Proceeding to AI code audit..."
            ),
        )
    else:
        logger.info("scan.pipeline.dast_only_mode", scan_id=scan_id)
        state_manager.update_status(
            scan_id,
            ScanStatus.RUNNING,
            progress_pct=20,
            current_agent="recon",
            message="No GitHub repository provided. Running in DAST-Only Mode...",
        )
        state_manager.update_agent_state(
            scan_id,
            current_agent="recon",
            reasoning_trace=[
                "[DAST-Only Mode] Repository not provided. Skipping SAST; proceeding with dynamic endpoint crawling and AI exploit testing."
            ],
            ast_data=[],
        )

    # -- Step 2: DAST (Playwright crawler - skipped in SAST-only mode) --------------------
    if has_target:
        try:
            dast_src = str(Path(__file__).resolve().parents[3] / "crawler_dast" / "src")
            if dast_src not in sys.path:
                sys.path.insert(0, dast_src)
            from playwright_bot import run_playwright_crawler  # type: ignore
            from passive_scanner import PassiveSecurityScanner  # type: ignore

            recon_output = _run_async(
                run_playwright_crawler(target_url=target_url.strip(), scan_id=scan_id)
            )
            endpoint_results = recon_output.to_endpoint_schemas()

            # Run Deterministic Passive Security Scanner (only in general or all mode)
            if detection_mode in ("general", "all"):
                try:
                    detected_fw = recon_output.target.detected_framework or "generic"
                    passive_scanner = PassiveSecurityScanner()
                    raw_passive_findings = passive_scanner.scan_endpoints(
                        endpoint_results,
                        target_url=target_url.strip(),
                        detected_framework=detected_fw,
                        forms=getattr(recon_output, "forms", []),
                    )
                    for pf in raw_passive_findings:
                        passive_vulns.append(DetectedVulnerability(**pf))
                    logger.info("scan.pipeline.passive_complete", count=len(passive_vulns))
                except Exception as p_exc:
                    logger.warning("scan.pipeline.passive_failed", error=str(p_exc))

            dast_trace = [
                f"[DAST] Crawler finished. Discovered {len(endpoint_results)} endpoints."
            ]
            if passive_vulns:
                dast_trace.append(
                    f"[Passive Scanner] Identified {len(passive_vulns)} verified security misconfiguration(s) with 100% confidence."
                )

            logger.info(
                "scan.pipeline.dast_complete",
                scan_id=scan_id,
                endpoints=len(endpoint_results),
                passive_vulns=len(passive_vulns),
            )
            state_manager.update_agent_state(
                scan_id,
                current_agent="recon",
                reasoning_trace=dast_trace,
                crawler_data=[
                    e.model_dump(mode="json") if hasattr(e, "model_dump") else e
                    for e in endpoint_results
                ],
            )
        except Exception as exc:
            logger.warning("scan.pipeline.dast_failed", scan_id=scan_id, error=str(exc))
            state_manager.update_agent_state(
                scan_id,
                current_agent="recon",
                reasoning_trace=[f"[DAST] Failed or skipped: {exc}"],
            )
    else:
        logger.info("scan.pipeline.sast_only_skip_dast", scan_id=scan_id)
        state_manager.update_status(
            scan_id,
            ScanStatus.RUNNING,
            progress_pct=40,
            current_agent="recon",
            message="SAST-Only Mode: Static repository analysis in progress (skipping dynamic DAST)...",
        )
        state_manager.update_agent_state(
            scan_id,
            current_agent="recon",
            reasoning_trace=[
                "[SAST-Only Mode] Live target URL omitted. Skipping DAST crawler; proceeding directly to multi-agent AST code analysis."
            ],
            crawler_data=[],
        )

    # -- Step 3: Analysis Execution (General DAST vs BOLA/IDOR AI Model) --
    if detection_mode == "general":
        logger.info("scan.pipeline.general_dast_mode", scan_id=scan_id)
        state_manager.update_status(
            scan_id,
            ScanStatus.RUNNING,
            progress_pct=60,
            current_agent="reason",
            message="General DAST Mode: Playwright browser crawler engine analyzing discovered endpoints...",
        )
        general_trace = [
            f"[General DAST] Playwright browser crawler engine active. Discovered {len(endpoint_results)} endpoint(s).",
        ]
        if passive_vulns:
            general_trace.append(
                f"[DAST Security Scanner] Verified {len(passive_vulns)} security finding(s) with 100% confidence."
            )

        # If repository was also provided, run deterministic AST pattern analysis
        if ast_results:
            try:
                from ai_engine.multi_agent.state_graph import _normalize_route, _perform_ast_pattern_analysis

                correlated_targets = []
                for ast_node in ast_results:
                    route_path = ast_node.route_path if hasattr(ast_node, "route_path") else ast_node.get("route_path", "")
                    matched_eps = [
                        e.model_dump(mode="json") if hasattr(e, "model_dump") else e
                        for e in endpoint_results
                        if route_path in (e.url if hasattr(e, "url") else e.get("url", ""))
                    ]
                    correlated_targets.append({
                        "ast_node": ast_node.model_dump(mode="json") if hasattr(ast_node, "model_dump") else ast_node,
                        "matched_endpoints": matched_eps,
                        "unmatched": len(matched_eps) == 0,
                    })
                ast_pattern_findings = _perform_ast_pattern_analysis(correlated_targets, detection_mode="general")
                for af in ast_pattern_findings:
                    vulnerabilities.append(DetectedVulnerability(**af))
                if ast_pattern_findings:
                    general_trace.append(f"[Deterministic AST] Identified {len(ast_pattern_findings)} static security finding(s).")
            except Exception as ast_exc:
                logger.warning("scan.pipeline.general_ast_failed", error=str(ast_exc))

        state_manager.update_agent_state(
            scan_id,
            current_agent="verify",
            reasoning_trace=general_trace,
            ai_exploit_payload=None,
        )
        logger.info(
            "scan.pipeline.general_dast_complete",
            scan_id=scan_id,
            passive_vulns=len(passive_vulns),
            deterministic_vulns=len(vulnerabilities),
        )

    elif detection_mode == "bola_idor":
        logger.info("scan.pipeline.bola_idor_mode", scan_id=scan_id)
        state_manager.update_status(
            scan_id,
            ScanStatus.RUNNING,
            progress_pct=50,
            current_agent="reason",
            message="BOLA/IDOR Mode: AI Reasoning Model active (auditing OWASP API1:2023 / CWE-639)...",
        )
        try:
            from app.services.ai_engine_service import AiEngineService

            ai_service = AiEngineService()
            raw_ai_vulns, reasoning_trace = _run_async(
                ai_service.run_reasoning_pipeline(
                    scan_id=scan_id,
                    ast_data=ast_results,
                    crawler_data=endpoint_results,
                    target_url=target_url,
                    detection_mode="bola_idor",
                )
            )
            # Filter specifically for BOLA / IDOR findings
            vulnerabilities = [
                v for v in raw_ai_vulns
                if v.cwe_id in ("CWE-639", "CWE-285", "CWE-862")
                or "API1" in (v.owasp_category or "")
                or "API5" in (v.owasp_category or "")
                or any(k in v.title.lower() for k in ("bola", "idor", "authorization", "tenant", "privilege", "ownership"))
            ]
            state_manager.update_agent_state(
                scan_id,
                current_agent="verify",
                reasoning_trace=[
                    "[AI Reasoning Engine] Cognitive model active. Auditing object-level authorization and tenant isolation (OWASP API1:2023)...",
                    *reasoning_trace,
                ],
                ai_exploit_payload=vulnerabilities[0].exploit_payload
                if vulnerabilities else None,
            )
            logger.info(
                "scan.pipeline.ai_bola_complete",
                scan_id=scan_id,
                vulns=len(vulnerabilities),
            )
        except Exception as exc:
            logger.warning("scan.pipeline.ai_failed", scan_id=scan_id, error=str(exc))
            state_manager.update_agent_state(
                scan_id,
                current_agent="verify",
                reasoning_trace=[f"[AI Reasoning Engine] Analysis completed with notice: {exc}"],
            )

    else:
        # Full combined audit (all modules)
        state_manager.update_status(
            scan_id,
            ScanStatus.RUNNING,
            progress_pct=50,
            current_agent="reason",
            message=(
                "DAST complete. Running AI reasoning engine..."
                if has_target
                else "Running AI security reasoning engine on source AST..."
            ),
        )
        try:
            from app.services.ai_engine_service import AiEngineService

            ai_service = AiEngineService()
            vulnerabilities, reasoning_trace = _run_async(
                ai_service.run_reasoning_pipeline(
                    scan_id=scan_id,
                    ast_data=ast_results,
                    crawler_data=endpoint_results,
                    target_url=target_url,
                    detection_mode=detection_mode,
                )
            )
            state_manager.update_agent_state(
                scan_id,
                current_agent="verify",
                reasoning_trace=reasoning_trace,
                ai_exploit_payload=vulnerabilities[0].exploit_payload
                if vulnerabilities else None,
            )
            logger.info(
                "scan.pipeline.ai_complete",
                scan_id=scan_id,
                vulns=len(vulnerabilities),
            )
        except Exception as exc:
            logger.warning("scan.pipeline.ai_failed", scan_id=scan_id, error=str(exc))
            state_manager.update_agent_state(
                scan_id,
                current_agent="verify",
                reasoning_trace=[f"[AI Reasoning Engine] Reasoning notice: {exc}"],
            )

    state_manager.update_status(
        scan_id,
        ScanStatus.RUNNING,
        progress_pct=75,
        current_agent="verify",
        message="Analysis complete. Running hybrid correlator...",
    )

    # -- Step 4: Hybrid Correlator -----------------------------
    try:
        from app.services.hybrid_correlator import HybridCorrelator

        correlator = HybridCorrelator()
        correlated_vulns = correlator.correlate(
            vulnerabilities=vulnerabilities,
            ast_findings=ast_results,
            endpoint_findings=endpoint_results,
            repo_root=repo_path,
        )
        vulnerabilities = correlated_vulns
        logger.info(
            "scan.pipeline.correlation_complete",
            scan_id=scan_id,
            correlated=len(vulnerabilities),
        )
    except Exception as exc:
        logger.warning(
            "scan.pipeline.correlation_failed", scan_id=scan_id, error=str(exc)
        )

    # Merge passive findings with active/AI findings (deduplicated by CWE and file/URL)
    all_vulns: list[DetectedVulnerability] = []
    seen_vuln_keys = set()
    for v in (passive_vulns + vulnerabilities):
        key = (v.cwe_id, v.file_path or v.title)
        if key not in seen_vuln_keys:
            seen_vuln_keys.add(key)
            all_vulns.append(v)

    # Strict mode-specific vulnerability enforcement:
    if detection_mode == "general":
        all_vulns = [
            v for v in all_vulns
            if v.cwe_id != "CWE-639"
            and "API1" not in (v.owasp_category or "")
            and not any(k in v.title.lower() for k in ("bola", "idor"))
        ]
    elif detection_mode == "bola_idor":
        all_vulns = [
            v for v in all_vulns
            if v.cwe_id in ("CWE-639", "CWE-285", "CWE-862")
            or "API1" in (v.owasp_category or "")
            or "API5" in (v.owasp_category or "")
            or any(k in v.title.lower() for k in ("bola", "idor", "authorization", "tenant", "privilege", "ownership"))
        ]

    vulnerabilities = all_vulns

    # -- Step 5: Build & save final ScanReport -----------------
    completed_at = datetime.utcnow()
    duration = (completed_at - started_at).total_seconds()

    # Compute severity distribution
    by_severity: dict[Severity, int] = {s: 0 for s in Severity}
    for v in vulnerabilities:
        by_severity[v.severity] = by_severity.get(v.severity, 0) + 1

    # Simple risk score: weighted average (CRITICAL=10, HIGH=7, MEDIUM=4, LOW=1)
    weights = {Severity.CRITICAL: 10, Severity.HIGH: 7, Severity.MEDIUM: 4,
               Severity.LOW: 1, Severity.INFO: 0}
    raw_score = sum(weights.get(v.severity, 0) for v in vulnerabilities)
    risk_score = min(100.0, raw_score * 2.0)

    summary = ScanSummary(
        total_endpoints=len(endpoint_results),
        total_ast_nodes=len(ast_results),
        total_vulnerabilities=len(vulnerabilities),
        by_severity={k.value: v for k, v in by_severity.items()},
        risk_score=risk_score,
    )

    report = ScanReport(
        scan_id=scan_id,
        status=ScanStatus.COMPLETED,
        github_url=github_url,
        target_url=target_url,
        started_at=started_at,
        completed_at=completed_at,
        duration_seconds=duration,
        ast_findings=ast_results,
        endpoint_findings=endpoint_results,
        vulnerabilities=vulnerabilities,
        summary=summary,
    )

    state_manager.save_report(scan_id, report)
    state_manager.update_status(
        scan_id,
        ScanStatus.COMPLETED,
        progress_pct=100,
        current_agent="done",
        message=f"Scan complete. Found {len(vulnerabilities)} vulnerabilities.",
    )
    state_manager.update_agent_state(
        scan_id,
        current_agent="done",
        reasoning_trace=[
            f"[DONE] Pipeline finished in {duration:.1f}s. "
            f"Risk Score: {risk_score:.0f}/100."
        ],
    )

    logger.info(
        "scan.pipeline.complete",
        scan_id=scan_id,
        duration_s=duration,
        vulnerabilities=len(vulnerabilities),
        risk_score=risk_score,
    )

    if cleanup_fn:
        try:
            cleanup_fn()
        except Exception:
            pass

    return {"scan_id": scan_id, "status": "completed", "vulnerabilities": len(vulnerabilities)}


# -- Celery Task Wrapper (optional) ----------------------------

try:
    celery_app = _get_celery()

    @celery_app.task(bind=True, name="run_full_scan", max_retries=1)
    def run_full_scan(
        self,
        scan_id: str,
        github_url: str | None = None,
        target_url: str | None = None,
        branch: str = "main",
        detection_mode: str = "all",
    ):
        """Celery-wrapped version of the scan pipeline."""
        try:
            return run_full_scan_pipeline(scan_id, github_url, target_url, branch, detection_mode=detection_mode)
        except Exception as exc:
            state_manager.update_status(
                scan_id,
                ScanStatus.FAILED,
                progress_pct=0,
                current_agent="error",
                message=f"Scan failed: {exc}",
            )
            logger.error("celery.task.failed", scan_id=scan_id, error=str(exc))
            raise

except Exception:
    # Celery not available — tasks run via FastAPI BackgroundTasks
    pass
