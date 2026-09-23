"""
AegisAI — AI Engine Service
=============================
Bridge between the FastAPI/Celery scan pipeline and Divy's
LangGraph multi-agent state graph.

Responsibilities:
  - Format ASTSchema + EndpointSchema into AgentState-compatible dicts
  - Invoke the LangGraph graph asynchronously
  - Stream agent transitions to ScanStateManager
  - Handle graceful fallback if Ollama / LangGraph is unavailable

Usage:
    service = AiEngineService()
    vulns, trace = await service.run_reasoning_pipeline(
        scan_id, ast_data, crawler_data
    )
"""

from __future__ import annotations

from typing import Any

import structlog

from app.schemas.io_models import (
    ASTSchema,
    DetectedVulnerability,
    EndpointSchema,
    Severity,
)
from app.services.scan_state_manager import state_manager

logger = structlog.get_logger(__name__)


class AiEngineService:
    """Wraps the LangGraph multi-agent graph for use inside the scan pipeline."""

    async def run_reasoning_pipeline(
        self,
        scan_id: str,
        ast_data: list[ASTSchema],
        crawler_data: list[EndpointSchema],
        target_url: str | None = None,
        detection_mode: str = "all",
        model_name: str = "qwen2.5-coder:7b",
        ollama_base_url: str = "http://localhost:11434",
    ) -> tuple[list[DetectedVulnerability], list[str]]:
        """
        Run the full LangGraph reasoning pipeline.

        Returns:
            (vulnerabilities, reasoning_trace) tuple.
            Falls back to empty results if LangGraph is unavailable.
        """
        # -- Format input -------------------------------------
        ast_dicts = [a.model_dump(mode="json") if hasattr(a, "model_dump") else a for a in ast_data]
        crawler_dicts = [e.model_dump(mode="json") if hasattr(e, "model_dump") else e for e in crawler_data]

        # -- Dynamically detect installed Ollama model if default is missing --
        resolved_model = model_name
        try:
            import urllib.request, json
            with urllib.request.urlopen(f"{ollama_base_url}/api/tags", timeout=2.0) as resp:
                tags_data = json.loads(resp.read().decode())
                installed_names = [m.get("name", "") for m in tags_data.get("models", [])]
                if model_name not in installed_names and installed_names:
                    # Prefer llama3.1:8b or llama3:latest if qwen is not installed
                    preferred = [m for m in installed_names if "llama3" in m or "coder" in m]
                    resolved_model = preferred[0] if preferred else installed_names[0]
                    logger.info("ai_engine.model_auto_resolved", requested=model_name, using=resolved_model)
        except Exception as detect_err:
            logger.debug("ai_engine.model_detect_fallback", error=str(detect_err))

        try:
            return await self._run_langgraph(
                scan_id=scan_id,
                ast_dicts=ast_dicts,
                crawler_dicts=crawler_dicts,
                target_url=target_url,
                detection_mode=detection_mode,
                model_name=resolved_model,
                ollama_base_url=ollama_base_url,
            )
        except Exception as exc:
            logger.warning(
                "ai_engine.langgraph.unavailable",
                scan_id=scan_id,
                error=str(exc),
                hint="Ensure Ollama is running with the correct model pulled.",
            )
            return [], [f"[AI] LangGraph unavailable: {exc}"]

    async def _run_langgraph(
        self,
        scan_id: str,
        ast_dicts: list[dict[str, Any]],
        crawler_dicts: list[dict[str, Any]],
        target_url: str | None,
        detection_mode: str,
        model_name: str,
        ollama_base_url: str,
    ) -> tuple[list[DetectedVulnerability], list[str]]:
        """Invoke Divy's LangGraph state machine."""
        import sys
        from pathlib import Path

        # Add AegisAi project root and ai_engine to path (monorepo structure)
        aegis_root = str(Path(__file__).resolve().parents[3])
        ai_engine_root = str(Path(__file__).resolve().parents[3] / "ai_engine")
        for p in (aegis_root, ai_engine_root):
            if p not in sys.path:
                sys.path.insert(0, p)

        try:
            from ai_engine.multi_agent.state_graph import build_graph  # type: ignore
        except ImportError:
            from multi_agent.state_graph import build_graph  # type: ignore

        graph = build_graph()

        initial_state = {
            "scan_id": scan_id,
            "target_url": target_url,
            "detection_mode": detection_mode,
            "ast_data": ast_dicts,
            "crawler_data": crawler_dicts,
            "model_name": model_name,
            "ollama_base_url": ollama_base_url,
            "correlated_targets": [],
            "ai_exploit_payload": None,
            "exploit_results": [],
            "reasoning_trace": [],
            "vulnerabilities": [],
            "current_agent": "recon",
            "error": None,
        }

        # Stream agent state transitions
        reasoning_trace: list[str] = []
        final_state: dict[str, Any] = {}

        async for state_update in graph.astream(initial_state):
            # state_update keys are node names
            for node_name, node_state in state_update.items():
                agent = node_state.get("current_agent", node_name)
                trace_entries = node_state.get("reasoning_trace", [])
                new_entries = [
                    e for e in trace_entries if e not in reasoning_trace
                ]
                reasoning_trace.extend(new_entries)

                state_manager.update_agent_state(
                    scan_id,
                    current_agent=agent,
                    reasoning_trace=new_entries,
                    ai_exploit_payload=node_state.get("ai_exploit_payload"),
                )
                final_state = node_state

        # -- Convert raw vulnerability dicts ? Pydantic models -
        raw_vulns: list[dict[str, Any]] = final_state.get("vulnerabilities", [])
        vulnerabilities: list[DetectedVulnerability] = []

        for raw in raw_vulns:
            try:
                # Normalise severity
                severity_str = str(raw.get("severity", "MEDIUM")).upper()
                valid_severities = {s.value for s in Severity}
                if severity_str not in valid_severities:
                    severity_str = "MEDIUM"

                vuln = DetectedVulnerability(
                    cwe_id=raw.get("cwe_id"),
                    owasp_category=raw.get("owasp_category"),
                    title=raw.get("title", "Unnamed Vulnerability"),
                    description=raw.get("description", ""),
                    severity=Severity(severity_str),
                    confidence=float(raw.get("confidence", 0.7)),
                    exploit_payload=raw.get("exploit_payload"),
                    remediation=raw.get("remediation"),
                    references=raw.get("references", []),
                    original_code=raw.get("original_code"),
                    patched_code=raw.get("patched_code"),
                    file_path=raw.get("file_path"),
                    line_number=raw.get("line_number"),
                    route_path=raw.get("route_path"),
                )
                vulnerabilities.append(vuln)
            except Exception as e:
                logger.warning("ai_engine.vuln_parse_failed", error=str(e), raw=raw)

        logger.info(
            "ai_engine.pipeline_complete",
            scan_id=scan_id,
            vulnerabilities=len(vulnerabilities),
            trace_entries=len(reasoning_trace),
        )

        return vulnerabilities, reasoning_trace
