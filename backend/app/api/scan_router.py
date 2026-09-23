"""
AegisAI — Scan API Router
==========================
Provides all scan-related HTTP endpoints:

  POST   /api/v1/scan/start             → Start a new scan job
  GET    /api/v1/scan/{scan_id}/status  → Poll job status (live)
  GET    /api/v1/scan/{scan_id}/report  → Retrieve full report
  GET    /api/v1/scan/{scan_id}/agent-state → Live agent pipeline state
  DELETE /api/v1/scan/{scan_id}         → Cancel a running scan

All heavy work is dispatched asynchronously.
Priority: Celery (when Redis is available) → FastAPI BackgroundTasks.
"""

from __future__ import annotations

import asyncio
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
from app.core.config import settings
from app.services.scan_state_manager import state_manager

logger = structlog.get_logger(__name__)

router = APIRouter(prefix="/scan", tags=["scan"])


def _dispatch_scan(
    scan_id: str,
    github_url: str | None,
    target_url: str | None = None,
    branch: str = "main",
    background_tasks: BackgroundTasks = None,
    detection_mode: str = "all",
) -> None:
    """Dispatch via Celery if Redis is connected, else FastAPI BackgroundTasks."""
    # Dispatch via Celery if configured and available, else in-process BackgroundTasks
    celery_broker = getattr(settings, "celery_broker_url", None)
    if celery_broker:
        try:
            from app.tasks.scan_tasks import run_full_scan  # type: ignore

            run_full_scan.apply_async(
                kwargs={
                    "scan_id": scan_id,
                    "github_url": github_url,
                    "target_url": target_url,
                    "branch": branch,
                    "detection_mode": detection_mode,
                },
                queue="aegis_scans",
            )
            logger.info("scan.dispatch.celery", scan_id=scan_id, detection_mode=detection_mode)
            return
        except Exception as celery_exc:
            logger.warning(
                "scan.dispatch.celery_unavailable",
                scan_id=scan_id,
                error=str(celery_exc),
                fallback="BackgroundTasks",
            )

    # In-process background task (instant dispatch, no Redis blocking)
    from app.tasks.scan_tasks import run_full_scan_pipeline

    background_tasks.add_task(
        run_full_scan_pipeline,
        scan_id=scan_id,
        github_url=github_url,
        target_url=target_url,
        branch=branch,
        detection_mode=detection_mode,
    )


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
      4. Run Hybrid Correlator to map vulns to source lines
      5. Persist findings via ScanStateManager
    """
    scan_id = str(uuid.uuid4())
    branch = getattr(request, "branch", "main") or "main"

    detection_mode = getattr(request, "detection_mode", "all") or "all"

    logger.info(
        "scan.start",
        scan_id=scan_id,
        github_url=request.github_url,
        target_url=request.target_url,
        modules=[m.value for m in request.scan_modules],
        detection_mode=detection_mode,
    )

    # Initialise scan state immediately so /status endpoint returns 'pending'
    state_manager.init_scan(
        scan_id=scan_id,
        github_url=request.github_url,
        target_url=request.target_url,
        branch=branch,
    )

    # Dispatch: Celery → BackgroundTasks fallback
    _dispatch_scan(
        scan_id=scan_id,
        github_url=request.github_url,
        target_url=request.target_url,
        branch=branch,
        background_tasks=background_tasks,
        detection_mode=detection_mode,
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
    """Returns the current status of a scan job (live from state manager)."""
    scan_status = state_manager.get_status(scan_id)
    if scan_status is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )
    return ApiResponse(data=scan_status)


# ── GET /api/v1/scan/{scan_id}/report ────────────────────────

@router.get(
    "/{scan_id}/report",
    response_model=ApiResponse[ScanReport],
    summary="Get full scan report",
)
async def get_scan_report(scan_id: str) -> ApiResponse[ScanReport]:
    """Returns the full vulnerability report for a completed scan."""
    # Check scan exists
    scan_status = state_manager.get_status(scan_id)
    if scan_status is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )

    # Check if still running
    current_status = scan_status.get("status", "")
    if current_status in (ScanStatus.PENDING.value, ScanStatus.RUNNING.value):
        raise HTTPException(
            status_code=status.HTTP_425_TOO_EARLY,
            detail=f"Scan '{scan_id}' is still {current_status}. Check /status.",
        )

    report_data = state_manager.get_report(scan_id)
    if report_data is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Report for scan '{scan_id}' not available yet.",
        )

    report = ScanReport.model_validate(report_data)
    return ApiResponse(data=report)


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
    """
    if not state_manager.scan_exists(scan_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )

    agent_data = state_manager.get_agent_state(scan_id) or {}
    agent_state = AgentStateSchema(
        scan_id=scan_id,
        ast_data=agent_data.get("ast_data", []),
        crawler_data=agent_data.get("crawler_data", []),
        ai_exploit_payload=agent_data.get("ai_exploit_payload"),
        reasoning_trace=agent_data.get("reasoning_trace", []),
        current_agent=agent_data.get("current_agent", "idle"),
    )
    return ApiResponse(data=agent_state)


# ── DELETE /api/v1/scan/{scan_id} ────────────────────────────

@router.delete(
    "/{scan_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    response_class=Response,
    summary="Cancel a running scan",
)
async def cancel_scan(scan_id: str) -> Response:
    """Cancels a pending or running scan."""
    if not state_manager.scan_exists(scan_id):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"Scan '{scan_id}' not found.",
        )

    logger.info("scan.cancel", scan_id=scan_id)

    # Attempt Celery task revocation
    try:
        from app.tasks.celery_app import celery_app

        celery_app.control.revoke(scan_id, terminate=True)
        logger.info("scan.cancel.celery_revoked", scan_id=scan_id)
    except Exception as exc:
        logger.debug("scan.cancel.celery_unavailable", error=str(exc))

    state_manager.update_status(
        scan_id,
        ScanStatus.CANCELLED,
        progress_pct=0,
        current_agent="idle",
        message="Scan cancelled by user.",
    )
    return Response(status_code=status.HTTP_204_NO_CONTENT)


# ── (Legacy stub removed — pipeline now lives in app/tasks/scan_tasks.py) ─
