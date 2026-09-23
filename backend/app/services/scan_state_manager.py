"""
AegisAI — Scan State Manager
==============================
Centralised store for real-time scan state.  Supports two backends:
  * Redis  — used in Docker / production (full persistence, atomic ops)
  * Memory — used for local dev / tests when Redis is unavailable

All endpoints (GET /status, /agent-state, /report) read from this store
so they always return live data instead of static stubs.

Usage:
    from app.services.scan_state_manager import state_manager
    state_manager.init_scan(scan_id, github_url, target_url, branch)
    state_manager.update_status(scan_id, ScanStatus.RUNNING, progress=25)
"""

from __future__ import annotations

import json
from datetime import datetime
from typing import Any

import structlog

from app.schemas.io_models import (
    AgentStateSchema,
    ScanReport,
    ScanStartResponse,
    ScanStatus,
    ScanSummary,
)

logger = structlog.get_logger(__name__)


# -- In-memory fallback store ----------------------------------

_scan_store: dict[str, dict[str, Any]] = {}


def _now_iso() -> str:
    return datetime.utcnow().isoformat() + "Z"


class ScanStateManager:
    """
    Manages per-scan state with optional Redis backend.

    Falls back to an in-process dict when Redis is unavailable
    (local development, CI, single-worker deployments).
    """

    def __init__(self) -> None:
        self._redis: Any = None
        self._try_connect_redis()

    def _try_connect_redis(self) -> None:
        """Attempt to connect to Redis; silently degrade to memory if unavailable."""
        try:
            import redis  # type: ignore

            from app.core.config import settings

            client = redis.Redis.from_url(
                settings.redis_url,
                decode_responses=True,
                socket_connect_timeout=1,
                socket_timeout=1,
            )
            client.ping()
            self._redis = client
            logger.info("state_manager.redis.connected", url=settings.redis_url)
        except Exception as exc:
            logger.warning(
                "state_manager.redis.unavailable",
                error=str(exc),
                fallback="in-memory store",
            )
            self._redis = None

    # -- Key helpers -------------------------------------------

    @staticmethod
    def _key(scan_id: str, suffix: str) -> str:
        return f"aegisai:scan:{scan_id}:{suffix}"

    def _set(self, key: str, value: dict[str, Any], ttl_seconds: int = 86400) -> None:
        """Write a JSON value to Redis or memory."""
        serialised = json.dumps(value, default=str)
        if self._redis:
            try:
                self._redis.setex(key, ttl_seconds, serialised)
                return
            except Exception as exc:
                logger.warning("state_manager.redis.write_failed", key=key, error=str(exc))
        # Memory fallback
        _scan_store[key] = value

    def _get(self, key: str) -> dict[str, Any] | None:
        """Read a JSON value from Redis or memory."""
        if self._redis:
            try:
                raw = self._redis.get(key)
                if raw is not None:
                    return json.loads(raw)
            except Exception as exc:
                logger.warning("state_manager.redis.read_failed", key=key, error=str(exc))
        return _scan_store.get(key)

    # -- Public API --------------------------------------------

    def init_scan(
        self,
        scan_id: str,
        github_url: str | None,
        target_url: str | None = None,
        branch: str = "main",
    ) -> None:
        """Initialise state for a new scan job."""
        now = _now_iso()

        status_payload: dict[str, Any] = {
            "scan_id": scan_id,
            "status": ScanStatus.PENDING.value,
            "progress_pct": 0,
            "current_agent": "idle",
            "message": "Scan queued.",
            "started_at": now,
            "github_url": github_url,
            "target_url": target_url,
            "branch": branch,
        }

        agent_payload: dict[str, Any] = {
            "scan_id": scan_id,
            "ast_data": [],
            "crawler_data": [],
            "ai_exploit_payload": None,
            "reasoning_trace": [],
            "current_agent": "idle",
        }

        self._set(self._key(scan_id, "status"), status_payload)
        self._set(self._key(scan_id, "agent"), agent_payload)
        logger.info("state_manager.init", scan_id=scan_id)

    def update_status(
        self,
        scan_id: str,
        status: ScanStatus,
        progress_pct: int = 0,
        current_agent: str = "idle",
        message: str = "",
    ) -> None:
        """Update scan job status & progress."""
        existing = self._get(self._key(scan_id, "status")) or {}
        existing.update(
            {
                "status": status.value,
                "progress_pct": progress_pct,
                "current_agent": current_agent,
                "message": message,
            }
        )
        if status in (ScanStatus.COMPLETED, ScanStatus.FAILED):
            existing["completed_at"] = _now_iso()

        self._set(self._key(scan_id, "status"), existing)
        logger.debug(
            "state_manager.status_updated",
            scan_id=scan_id,
            status=status.value,
            progress=progress_pct,
        )

    def update_agent_state(
        self,
        scan_id: str,
        current_agent: str,
        reasoning_trace: list[str] | None = None,
        ast_data: list[dict] | None = None,
        crawler_data: list[dict] | None = None,
        ai_exploit_payload: str | None = None,
    ) -> None:
        """Update the live agent pipeline state (streamed to frontend)."""
        existing = self._get(self._key(scan_id, "agent")) or {}
        existing["current_agent"] = current_agent

        if reasoning_trace is not None:
            existing.setdefault("reasoning_trace", [])
            existing["reasoning_trace"].extend(reasoning_trace)

        if ast_data is not None:
            existing["ast_data"] = ast_data

        if crawler_data is not None:
            existing["crawler_data"] = crawler_data

        if ai_exploit_payload is not None:
            existing["ai_exploit_payload"] = ai_exploit_payload

        self._set(self._key(scan_id, "agent"), existing)

    def save_report(self, scan_id: str, report: ScanReport) -> None:
        """Persist the final scan report."""
        self._set(self._key(scan_id, "report"), report.model_dump(mode="json"))
        logger.info("state_manager.report_saved", scan_id=scan_id)

    def get_status(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve current scan status dict."""
        return self._get(self._key(scan_id, "status"))

    def get_agent_state(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve current agent pipeline state."""
        return self._get(self._key(scan_id, "agent"))

    def get_report(self, scan_id: str) -> dict[str, Any] | None:
        """Retrieve final scan report dict."""
        return self._get(self._key(scan_id, "report"))

    def scan_exists(self, scan_id: str) -> bool:
        """Check if a scan ID is known."""
        return self._get(self._key(scan_id, "status")) is not None


# Singleton instance used throughout the application
state_manager = ScanStateManager()
