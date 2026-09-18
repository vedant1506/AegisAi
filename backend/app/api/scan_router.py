"""
AegisAI — Scan API Router
==========================
Provides all scan-related HTTP endpoints:

  POST  /api/v1/scan/start              → Start a new scan job
  GET   /api/v1/scan/{scan_id}/status   → Poll job status
  GET   /api/v1/scan/{scan_id}/report   → Retrieve full report
  DELETE /api/v1/scan/{scan_id}         → Cancel a running scan

All heavy work is dispatched asynchronously (Celery / background task).
"""

from __future__ import annotations

import uuid
from datetime import datetime

import structlog
from fastapi import APIRouter, BackgroundTasks, HTTPException, Response, status

from app.schemas.io_models import (
    AgentStateSchema,
    ApiResponse,
    ScanReport,
    ScanStartRequest,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
)

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])


# ── POST /api/v1/scan/start ───────────────────────────────────

@router.post(
    "/start",
    response_model=ScanStartResponse,
    status_code=status.HTTP_202_ACCEPTED,
    summary="Start a new VAPT scan",
    description=(
        "Accepts a GitHub repository URL and a target application URL, then "
        "enqueues a full SAST + DAST + AI exploit-reasoning scan. "
        "Returns a scan_id that can be polled for status."
    ),
)
async def start_scan(
    request: ScanStartRequest,
    background_tasks: BackgroundTasks,
) -> ScanStartResponse:
    """
    Kick off an autonomous scan pipeline.

    Steps (orchestrated asynchronously):
      1. Clone GitHub repo → run tree-sitter SAST
      2. Launch Playwright crawler against target_url
      3. Feed SAST + crawler data into LangGraph agent graph
      4. Persist findings to DB
    """
    scan_id = str(uuid.uuid4())

    logger.info(
        "scan.start",
        scan_id=scan_id,
        github_url=request.github_url,
        target_url=request.target_url,
        modules=[m.value for m in request.scan_modules],
    )

    # TODO: Replace with Celery task dispatch:
    # from app.tasks.scan_tasks import run_full_scan
    # run_full_scan.apply_async(args=[scan_id, request.model_dump()])

    # For now, register a FastAPI background task (single-worker, non-distributed)
    background_tasks.add_task(
        _run_scan_pipeline,
        scan_id=scan_id,
        github_url=request.github_url,
        target_url=request.target_url,
    )

    return ScanStartResponse(
        scan_id=scan_id,
        status=ScanStatus.PENDING,
        message=f"Scan {scan_id} queued. Poll /api/v1/scan/{scan_id}/status for updates.",
        created_at=datetime.utcnow(),
    )


# ── GET /api/v1/scan/{scan_id}/status ────────────────────────

@router.get(
    "/{scan_id}/status",
    response_model=ApiResponse[dict],
    summary="Get scan status",
)
async def get_scan_status(scan_id: str) -> ApiResponse[dict]:
    """
    Returns the current status of a scan job.

    TODO: Fetch real status from Redis/DB instead of stub response.
    """
    # TODO: Look up scan_id in Redis / DB
    stub_status = {
        "scan_id": scan_id,
        "status": ScanStatus.RUNNING,
        "current_agent": "recon",
        "progress_pct": 25,
    }
    return ApiResponse(data=stub_status)


# ── GET /api/v1/scan/{scan_id}/report ────────────────────────

@router.get(
    "/{scan_id}/report",
    response_model=ApiResponse[ScanReport],
    summary="Get full scan report",
)
async def get_scan_report(scan_id: str) -> ApiResponse[ScanReport]:
    """
    Returns the full vulnerability report for a completed scan.

    TODO: Fetch real report from DB using scan_id.
    Raises 404 if scan not found, 425 if scan still running.
    """
    # TODO: Replace stub with DB query
    # report = await db.get_scan_report(scan_id)
    # if not report:
    #     raise HTTPException(status_code=404, detail="Scan not found")

    stub_report = ScanReport(
        scan_id=scan_id,
        status=ScanStatus.COMPLETED,
        github_url="https://github.com/example/app",
        target_url="http://localhost:3000",
        started_at=datetime.utcnow(),
        completed_at=datetime.utcnow(),
        duration_seconds=0.0,
        summary=ScanSummary(),
    )
    return ApiResponse(data=stub_report)


# ── GET /api/v1/scan/{scan_id}/agent-state ───────────────────

@router.get(
    "/{scan_id}/agent-state",
    response_model=ApiResponse[AgentStateSchema],
    summary="Get live agent pipeline state",
)
async def get_agent_state(scan_id: str) -> ApiResponse[AgentStateSchema]:
    """
    Returns the current LangGraph agent state for a running scan.
    Useful for streaming agent progress to the frontend.

    TODO: Fetch real state snapshot from Redis.
    """
    stub_state = AgentStateSchema(
        scan_id=scan_id,
        current_agent="recon",
        reasoning_trace=["Starting reconnaissance…"],
    )
    return ApiResponse(data=stub_state)


# ── DELETE /api/v1/scan/{scan_id} ────────────────────────────

@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Cancel a running scan",
)
async def cancel_scan(scan_id: str) -> Response:
    """
    Cancels a pending or running scan.

    TODO: Revoke the Celery task and update DB status to CANCELLED.
    """
    logger.info("scan.cancel", scan_id=scan_id)
    # TODO: celery_app.control.revoke(task_id, terminate=True)
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── Internal: background scan pipeline stub ───────────────────

async def _run_scan_pipeline(
    scan_id: str,
    github_url: str,
    target_url: str,
) -> None:
    """
    Placeholder for the full async scan pipeline.
    In production this will be replaced by a Celery task.

    Workflow:
      1. Clone repo (GitPython)
      2. Run tree-sitter AST analysis (tree_sitter_engine.py)
      3. Launch Playwright DAST crawler (playwright_bot.py)
      4. Feed data into LangGraph graph (state_graph.py)
      5. Persist findings to PostgreSQL
    """
    logger.info("scan.pipeline.start", scan_id=scan_id)

    # TODO: Step 1 — Clone
    # repo_path = await clone_repository(github_url)

    # TODO: Step 2 — SAST
    # ast_results = await run_ast_analysis(repo_path)

    # ── Step 3: DAST Reconnaissance Crawler (Shahad) ──────────
    endpoint_results = []
    try:
        import sys
        from pathlib import Path
        dast_src = str(Path(__file__).resolve().parents[3] / "crawler_dast" / "src")
        if dast_src not in sys.path:
            sys.path.insert(0, dast_src)
        from playwright_bot import run_playwright_crawler
        recon_output = await run_playwright_crawler(target_url=target_url, scan_id=scan_id)
        endpoint_results = recon_output.to_endpoint_schemas()
        logger.info(
            "scan.pipeline.dast_complete",
            scan_id=scan_id,
            endpoints_discovered=len(endpoint_results),
        )
    except Exception as exc:
        logger.warning("scan.pipeline.dast_failed", scan_id=scan_id, error=str(exc))

    # TODO: Step 4 — AI Agent Graph
    # from ai_engine.multi_agent.state_graph import build_graph
    # graph = build_graph()
    # final_state = await graph.ainvoke({...})

    # TODO: Step 5 — Persist
    # await db.save_report(scan_id, final_state)

    logger.info("scan.pipeline.complete", scan_id=scan_id)
