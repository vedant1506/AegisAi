"""
AegisAI — LangGraph Multi-Agent State Graph
=============================================
Defines the orchestration graph for the autonomous security pipeline.

Agents:
  1. ReconAgent   — Gathers AST findings + crawler endpoints, correlates routes
  2. ReasonAgent  — Feeds correlated data to the LLM for vulnerability reasoning
  3. VerifyAgent  — Dispatches exploit probes, confirms/refutes hypotheses

State flows:
  START → recon_agent → reason_agent → verify_agent → END

The TypedDict AgentState serves as the shared memory passed between nodes.

Usage:
    from ai_engine.multi_agent.state_graph import build_graph

    graph = build_graph()
    result = await graph.ainvoke({
        "scan_id": "abc-123",
        "ast_data": [...],
        "crawler_data": [...],
    })
"""

from __future__ import annotations

import asyncio
from typing import Annotated, Any, TypedDict

import structlog
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

logger = structlog.get_logger(__name__)


# ── Agent State Definition ────────────────────────────────────

class AgentState(TypedDict, total=False):
    """
    Shared state passed between all nodes in the AegisAI agent graph.

    Fields:
        scan_id             : Unique identifier for this scan job.
        ast_data            : List of ASTSchema-compatible dicts from SAST.
        crawler_data        : List of EndpointSchema-compatible dicts from DAST.
        correlated_targets  : Routes matched between SAST and DAST findings.
        ai_exploit_payload  : Raw exploit string produced by the Reason Agent.
        exploit_results     : Verification outcomes from the Verify Agent.
        reasoning_trace     : Human-readable log of LLM reasoning steps.
        vulnerabilities     : Final list of confirmed DetectedVulnerability dicts.
        current_agent       : Name of the currently executing agent node.
        error               : Set if a node encounters an unrecoverable error.
    """

    # ── Input data ────────────────────────────────────────────
    scan_id: str
    ast_data: list[dict[str, Any]]
    crawler_data: list[dict[str, Any]]

    # ── Pipeline state ────────────────────────────────────────
    correlated_targets: list[dict[str, Any]]
    ai_exploit_payload: str | None
    exploit_results: list[dict[str, Any]]

    # ── Observability ─────────────────────────────────────────
    reasoning_trace: Annotated[list[str], add_messages]
    vulnerabilities: list[dict[str, Any]]
    current_agent: str
    error: str | None


# ── Agent Node: Recon ─────────────────────────────────────────

async def recon_agent(state: AgentState) -> AgentState:
    """
    Reconnaissance Agent.

    Responsibilities:
      1. Cross-reference AST routes with crawler-discovered endpoints
      2. Identify unprotected or sensitive routes
      3. Enrich targets with auth context from crawler tokens
      4. Produce `correlated_targets` list for the Reason Agent

    TODO: Implement actual correlation logic using route-matching heuristics.
    """
    scan_id = state.get("scan_id", "unknown")
    logger.info("agent.recon.start", scan_id=scan_id)

    ast_data: list[dict] = state.get("ast_data", [])
    crawler_data: list[dict] = state.get("crawler_data", [])

    # ── Correlation stub ──────────────────────────────────────
    # TODO: Replace with semantic route matching:
    #   - Normalise URL paths from both sources
    #   - Match on method + path template similarity
    #   - Flag routes only visible in AST (missed by crawler) → hidden attack surface
    correlated: list[dict] = []
    crawler_urls = {ep.get("url", "") for ep in crawler_data}

    for ast_node in ast_data:
        route_path = ast_node.get("route_path", "")
        # Naive prefix match — replace with proper URL template matching
        matched_endpoints = [
            ep for ep in crawler_data if route_path in ep.get("url", "")
        ]
        correlated.append({
            "ast_node": ast_node,
            "matched_endpoints": matched_endpoints,
            "unmatched": len(matched_endpoints) == 0,
        })

    logger.info(
        "agent.recon.complete",
        scan_id=scan_id,
        ast_nodes=len(ast_data),
        crawler_endpoints=len(crawler_data),
        correlated=len(correlated),
    )

    return {
        **state,
        "correlated_targets": correlated,
        "current_agent": "reason",
        "reasoning_trace": [
            f"[Recon] Correlated {len(ast_data)} AST nodes with "
            f"{len(crawler_data)} crawler endpoints. "
            f"Found {len(correlated)} target candidates."
        ],
    }


# ── Agent Node: Reason ────────────────────────────────────────

async def reason_agent(state: AgentState) -> AgentState:
    """
    Reasoning Agent (LLM-powered).

    Responsibilities:
      1. Format correlated targets into a structured prompt
      2. Query the LLM (via Ollama / fine-tuned model) for vulnerability analysis
      3. Parse LLM output into DetectedVulnerability structures
      4. Generate an exploit payload hypothesis

    TODO: Integrate with LangChain LLM chain:
      from langchain_ollama import OllamaLLM
      from ai_engine.multi_agent.prompts import build_reason_prompt
      llm = OllamaLLM(model="aegisai-security:7b", base_url=settings.OLLAMA_API_BASE)
      response = await llm.ainvoke(build_reason_prompt(state["correlated_targets"]))
    """
    scan_id = state.get("scan_id", "unknown")
    logger.info("agent.reason.start", scan_id=scan_id)

    targets = state.get("correlated_targets", [])

    # ── LLM call placeholder ──────────────────────────────────
    stub_payload = "' OR 1=1 UNION SELECT username, password, NULL FROM users--"
    stub_vulnerabilities = [
        {
            "id": "VULN-STUB-001",
            "title": "[STUB] Potential SQL Injection",
            "description": "LLM reasoning not yet connected. This is a placeholder.",
            "severity": "HIGH",
            "confidence": 0.0,
            "cwe_id": "CWE-89",
            "owasp_category": "A03:2021",
            "exploit_payload": stub_payload,
            "remediation": "Use parameterised queries.",
        }
    ] if targets else []

    logger.info(
        "agent.reason.complete",
        scan_id=scan_id,
        vulnerabilities_found=len(stub_vulnerabilities),
    )

    return {
        **state,
        "ai_exploit_payload": stub_payload,
        "vulnerabilities": stub_vulnerabilities,
        "current_agent": "verify",
        "reasoning_trace": [
            f"[Reason] Analysed {len(targets)} targets. "
            f"Generated {len(stub_vulnerabilities)} vulnerability hypotheses. "
            "(LLM stub — wire up Ollama to replace this output.)"
        ],
    }


# ── Agent Node: Verify ────────────────────────────────────────

async def verify_agent(state: AgentState) -> AgentState:
    """
    Verification Agent.

    Responsibilities:
      1. Take exploit payloads from Reason Agent
      2. Dispatch them via ExploitRunner (httpx)
      3. Assess responses to confirm/refute vulnerability hypotheses
      4. Update vulnerability confidence scores
      5. Filter out false positives

    TODO: Integrate with ExploitRunner:
      from crawler_dast.src.exploit_runner import ExploitRunner
      async with ExploitRunner(token_manager=...) as runner:
          results = await runner.run_batch(probes)
    """
    scan_id = state.get("scan_id", "unknown")
    logger.info("agent.verify.start", scan_id=scan_id)

    payload = state.get("ai_exploit_payload")
    vulnerabilities = state.get("vulnerabilities", [])

    # ── ExploitRunner stub ────────────────────────────────────
    exploit_results: list[dict] = []
    if payload:
        exploit_results.append({
            "payload": payload,
            "is_confirmed": False,       # stub
            "confidence": 0.0,           # stub
            "notes": "Verification stub — wire up ExploitRunner.",
        })

    logger.info(
        "agent.verify.complete",
        scan_id=scan_id,
        probes_fired=len(exploit_results),
    )

    return {
        **state,
        "exploit_results": exploit_results,
        "current_agent": "done",
        "reasoning_trace": [
            f"[Verify] Fired {len(exploit_results)} probe(s). "
            "ExploitRunner not yet connected — all results are stubs."
        ],
    }


# ── Conditional routing ───────────────────────────────────────

def should_continue(state: AgentState) -> str:
    """
    Routing function: decides whether to proceed or halt on error.
    Extend this to add retry logic, human-in-the-loop checkpoints, etc.
    """
    if state.get("error"):
        logger.warning("agent.graph.routing_to_end_on_error", error=state["error"])
        return END
    current = state.get("current_agent", "recon")
    return current  # node name acts as the routing key


# ── Graph Builder ─────────────────────────────────────────────

def build_graph() -> StateGraph:
    """
    Construct and compile the AegisAI LangGraph agent graph.

    Returns a compiled graph ready for .invoke() or .ainvoke().

    Graph topology:
        START → recon_agent → reason_agent → verify_agent → END
    """
    builder = StateGraph(AgentState)

    # ── Register nodes ────────────────────────────────────────
    builder.add_node("recon", recon_agent)
    builder.add_node("reason", reason_agent)
    builder.add_node("verify", verify_agent)

    # ── Define edges ──────────────────────────────────────────
    builder.add_edge(START, "recon")
    builder.add_edge("recon", "reason")
    builder.add_edge("reason", "verify")
    builder.add_edge("verify", END)

    # ── Compile ───────────────────────────────────────────────
    graph = builder.compile()
    logger.info("agent.graph.compiled", nodes=["recon", "reason", "verify"])
    return graph


# ── Standalone runner ─────────────────────────────────────────

async def _main() -> None:
    """Quick smoke test of the compiled graph with stub data."""
    graph = build_graph()

    initial_state: AgentState = {
        "scan_id": "test-001",
        "ast_data": [
            {
                "route_path": "/api/user",
                "file_path": "app/api/users.py",
                "line_number": 42,
                "language": "python",
                "source_snippet": "cursor.execute(f'SELECT * FROM users WHERE id = {user_id}')",
            }
        ],
        "crawler_data": [
            {
                "url": "http://localhost:3000/api/user",
                "method": "GET",
                "headers": {},
            }
        ],
    }

    print("\n🛡️  AegisAI Agent Graph — Smoke Test\n" + "─" * 50)
    result = await graph.ainvoke(initial_state)

    print(f"\n✅ Scan complete — agent: {result.get('current_agent')}")
    print(f"📋 Reasoning trace:")
    for step in result.get("reasoning_trace", []):
        print(f"   {step}")
    print(f"\n🔴 Vulnerabilities: {len(result.get('vulnerabilities', []))}")


if __name__ == "__main__":
    asyncio.run(_main())
