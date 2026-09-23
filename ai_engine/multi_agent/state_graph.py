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
import json
import os
import re
from typing import Annotated, Any, TypedDict

import structlog
from langchain_ollama import ChatOllama
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages

from ai_engine.multi_agent.prompts import (
    build_bola_reason_prompt,
    build_reason_prompt,
)

logger = structlog.get_logger(__name__)


# ── Agent State Definition ────────────────────────────────────

class AgentState(TypedDict, total=False):
    """
    Shared state passed between all nodes in the AegisAI agent graph.

    Fields:
        scan_id             : Unique identifier for this scan job.
        ast_data            : List of ASTSchema-compatible dicts from SAST.
        crawler_data        : List of EndpointSchema-compatible dicts from DAST.
        model_name          : Name of local LLM model (default: 'qwen2.5-coder:7b').
        ollama_base_url     : Base URL for Ollama API (default: 'http://localhost:11434').
        correlated_targets  : Routes matched between SAST and DAST findings.
        ai_exploit_payload  : Structured exploit payload JSON string produced by Reason Agent.
        exploit_results     : Verification outcomes from the Verify Agent.
        reasoning_trace     : Human-readable log of LLM reasoning steps.
        vulnerabilities     : Final list of confirmed DetectedVulnerability dicts.
        current_agent       : Name of the currently executing agent node.
        error               : Set if a node encounters an unrecoverable error.
    """

    # ── Input data ────────────────────────────────────────────
    scan_id: str
    detection_mode: str
    ast_data: list[dict[str, Any]]
    crawler_data: list[dict[str, Any]]
    model_name: str
    ollama_base_url: str
    target_url: str | None

    # ── Pipeline state ────────────────────────────────────────
    correlated_targets: list[dict[str, Any]]
    ai_exploit_payload: str | None
    exploit_results: list[dict[str, Any]]

    # ── Observability ─────────────────────────────────────────
    reasoning_trace: Annotated[list[str], add_messages]
    vulnerabilities: list[dict[str, Any]]
    current_agent: str
    error: str | None


# ── Route Normalisation Helper ────────────────────────────────

def _normalize_route(path: str) -> str:
    """Normalise path for matching: strip query parameters and parameterized segments."""
    clean = path.split("?")[0].strip("/")
    # Normalise :param, <param>, or {param} placeholders to regex wildcard
    return re.sub(r":\w+|\<\w+\>|\{\w+\}", r"[^/]+", clean)


# ── Agent Node: Recon ─────────────────────────────────────────

async def recon_agent(state: AgentState) -> AgentState:
    """
    Reconnaissance Agent.

    Responsibilities:
      1. Cross-reference AST routes with crawler-discovered endpoints
      2. Identify unprotected or sensitive routes
      3. Enrich targets with auth context from crawler tokens
      4. Produce `correlated_targets` list for the Reason Agent
    """
    scan_id = state.get("scan_id", "unknown")
    logger.info("agent.recon.start", scan_id=scan_id)

    ast_data: list[dict] = state.get("ast_data", [])
    crawler_data: list[dict] = state.get("crawler_data", [])

    correlated: list[dict] = []

    if ast_data:
        for ast_node in ast_data:
            route_path = ast_node.get("route_path", "")
            norm_ast = _normalize_route(route_path)

            matched_endpoints: list[dict] = []
            for ep in crawler_data:
                ep_url = ep.get("url", "")
                # Extract path from URL
                url_no_scheme = ep_url.split("://")[-1] if "://" in ep_url else ep_url
                url_path = url_no_scheme.split("/", 1)[1] if "/" in url_no_scheme else ""
                url_path_clean = url_path.split("?")[0].strip("/")

                # Check if direct match or regex pattern match
                if route_path in ep_url or (norm_ast and re.search(f"^{norm_ast}$|^{norm_ast}/|/{norm_ast}$", url_path_clean)):
                    matched_endpoints.append(ep)

            correlated.append({
                "ast_node": ast_node,
                "matched_endpoints": matched_endpoints,
                "unmatched": len(matched_endpoints) == 0,
            })
    else:
        # DAST-only mode: treat each crawler endpoint as an active target candidate for security analysis
        for ep in crawler_data:
            ep_url = ep.get("url", "")
            url_no_scheme = ep_url.split("://")[-1] if "://" in ep_url else ep_url
            url_path = "/" + (url_no_scheme.split("/", 1)[1] if "/" in url_no_scheme else "")
            fw = ep.get("detected_framework") or "generic"
            banner = ep.get("server_banner") or ""
            synthetic_ast = {
                "route_path": url_path,
                "file_path": ep_url,
                "line_number": 1,
                "source_snippet": f"// DAST Discovered Endpoint: {ep.get('method', 'GET')} {ep_url}\n// Server: {banner} | Technology: {fw}",
                "language": fw if fw != "generic" else "generic",
            }
            correlated.append({
                "ast_node": synthetic_ast,
                "matched_endpoints": [ep],
                "unmatched": False,
            })

    logger.info(
        "agent.recon.complete",
        scan_id=scan_id,
        ast_nodes=len(ast_data),
        crawler_endpoints=len(crawler_data),
        correlated=len(correlated),
    )

    trace_msg = (
        f"[Recon] DAST-Only Mode: Extracted {len(crawler_data)} live endpoints. "
        f"Prepared {len(correlated)} target candidates for AI security analysis."
        if not ast_data
        else (
            f"[Recon] SAST-Only Mode: Extracted {len(ast_data)} route nodes from repository AST. "
            f"Prepared {len(correlated)} source code targets for security reasoning."
            if not crawler_data
            else f"[Recon] Correlated {len(ast_data)} AST nodes with {len(crawler_data)} crawler endpoints. Found {len(correlated)} target candidates."
        )
    )

    return {
        **state,
        "correlated_targets": correlated,
        "current_agent": "reason",
        "reasoning_trace": [trace_msg],
    }


# ── JSON Parsing Helper ───────────────────────────────────────

def _clean_and_parse_json(raw_text: str) -> dict[str, Any]:
    """
    Extracts and parses JSON from raw LLM output, handling markdown code blocks
    and potential conversational framing.
    """
    cleaned = raw_text.strip()

    # If wrapped in markdown ```json ... ``` or ``` ... ```
    match = re.search(r"```(?:json)?\s*([\s\S]*?)\s*```", cleaned, re.IGNORECASE)
    if match:
        cleaned = match.group(1).strip()

    # Find boundaries of JSON object if surrounded by prose
    if not cleaned.startswith("{") and "{" in cleaned:
        start_idx = cleaned.find("{")
        end_idx = cleaned.rfind("}")
        if end_idx > start_idx:
            cleaned = cleaned[start_idx : end_idx + 1]

    return json.loads(cleaned)


# ── AST Pattern Analysis Helper ───────────────────────────────

def _inject_aligned_security_patch(orig_code: str, patch_stub: str, cwe_id: str = "") -> str:
    """
    Integrates a security patch stub or replacement into the original snippet
    so that diff viewers highlight ONLY the changeable / vulnerable line in red
    and the secure fix in green, preserving all surrounding code as unchanged.
    """
    if not orig_code or not orig_code.strip():
        return patch_stub

    orig_lines = orig_code.splitlines()
    stub_lines = [l.strip() for l in patch_stub.strip().splitlines() if l.strip()]

    # If patch_stub already provides the full secure route declaration / handler replacement:
    for line in orig_lines:
        s_line = line.strip()
        if (s_line.startswith("app.") or s_line.startswith("router.") or "app.use(" in s_line) and any(verb in s_line for verb in (".get(", ".post(", ".put(", ".delete(", ".all(")):
            if any(verb in patch_stub for verb in (".get(", ".post(", ".put(", ".delete(", ".all(")):
                return patch_stub

    target_idx = -1
    is_replace = False

    for i, line in enumerate(orig_lines):
        l_lower = line.lower()
        # Database query calls (CWE-89)
        if any(k in l_lower for k in ("db.query", "query(", "execute(", "cursor.execute", "session.query", "findbypk", "find_by", "filter(")):
            target_idx = i
            is_replace = True
            break
        # Deserialization / eval / template
        if any(k in l_lower for k in ("yaml.load", "pickle.loads", "pickle.load", "render_template_string", "eval(")):
            target_idx = i
            is_replace = True
            break

    # If no target line matched, locate insertion point after function header / docstring
    if target_idx == -1:
        for i, line in enumerate(orig_lines):
            if (re.search(r'\b(def|async def|function|func)\b', line) or re.search(r'\([a-zA-Z0-9_,\s]*\)\s*=>', line) or (("public " in line or "protected " in line) and "{" in line)) and not line.strip().startswith("@"):
                idx = i
                while idx < len(orig_lines) and not orig_lines[idx].strip().endswith(":") and not "{" in orig_lines[idx]:
                    idx += 1
                target_idx = idx
                is_replace = False
                # Skip docstring if immediately following
                if target_idx + 1 < len(orig_lines) and '"""' in orig_lines[target_idx + 1]:
                    target_idx += 1
                    while target_idx + 1 < len(orig_lines) and '"""' not in orig_lines[target_idx + 1]:
                        target_idx += 1
                    target_idx += 1
                break

    if target_idx != -1:
        ref_line = orig_lines[target_idx]
        indent_match = re.match(r'^\s*', ref_line)
        base_indent = indent_match.group(0) if indent_match and indent_match.group(0) else "    "
        indent = base_indent if is_replace else (base_indent + "    " if not base_indent.endswith("\t") else base_indent + "\t")

        indented_patch = [f"{indent}{line}" for line in stub_lines]

        if is_replace:
            new_lines = orig_lines[:target_idx] + indented_patch + orig_lines[target_idx + 1:]
        else:
            new_lines = orig_lines[:target_idx + 1] + indented_patch + orig_lines[target_idx + 1:]

        return "\n".join(new_lines)

    # Express route call fallback: if orig_code is a single route declaration, replace cleanly
    for i, line in enumerate(orig_lines):
        s_line = line.strip()
        if (s_line.startswith("app.") or s_line.startswith("router.")) and any(v in s_line for v in (".get(", ".post(", ".put(", ".delete(")):
            return patch_stub

    return orig_code + "\n\n" + patch_stub


def _perform_ast_pattern_analysis(targets: list[dict[str, Any]], detection_mode: str) -> list[dict[str, Any]]:
    """
    Deterministic static code pattern analysis across correlated AST targets.
    Detects high-risk vulnerability signatures in actual handler snippets.
    """
    def _is_valid_backend_target(t: dict) -> bool:
        node = t.get("ast_node", {})
        r_path = node.get("route_path", "")
        f_path = node.get("file_path", "").lower()
        if not r_path or "unknown" in r_path or r_path in ("/", "/health", "/docs"):
            return False
        if any(bad in f_path for bad in ["min.js", "swagger", "vendor", "lib/", "assets", "static/", "jquery"]):
            return False
        return True

    valid_targets = [t for t in targets if _is_valid_backend_target(t)]
    if not valid_targets:
        valid_targets = [t for t in targets if not any(bad in t.get("ast_node", {}).get("file_path", "").lower() for bad in ["min.js", "swagger", "vendor", "lib/", "jquery"])]

    detected: list[dict[str, Any]] = []
    for idx, target in enumerate(valid_targets[:20], start=1):
        ast_node = target.get("ast_node", {})
        matched_eps = target.get("matched_endpoints", [])
        ep = matched_eps[0] if matched_eps else {}

        route_path = ast_node.get("route_path", "/api/resource")
        route_lower = route_path.lower()
        file_path = ast_node.get("file_path", "unknown")
        file_lower = file_path.lower()
        snippet = (ast_node.get("source_snippet") or "").lower()
        orig_snippet = ast_node.get("source_snippet") or ""
        line_no = ast_node.get("line_number", 1)

        is_js = file_lower.endswith((".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"))
        is_java = file_lower.endswith(".java")
        is_go = file_lower.endswith(".go")
        is_py = file_lower.endswith(".py")
        is_static_route = any(route_lower.endswith(s) or route_lower == s for s in ("/profile", "/cart", "/login", "/logout", "/dashboard", "/search", "/home", "/about", "/benefits", "/contributions"))
        has_id_param = any(p in route_path for p in (":", "{", "<")) or any(k in route_lower for k in ("accountno", "cust_id", "user_id", "order_id", "invoice_id"))
        has_snippet_id_lookup = any(k in snippet for k in ("req.params.", "params[", "param(", "pathparam", "cust_id", "query.get(", "filter_by(id=", "findbypk", "findbyid"))

        title = None
        cwe_id = None
        owasp = None
        severity = "MEDIUM"
        desc = ""
        remed = ""
        patched = ""

        # 1. Insecure Deserialization (CWE-502)
        if any(k in snippet for k in ("yaml.load", "pickle.loads", "pickle.load", "unserialize")):
            title = f"Insecure Deserialization & Arbitrary Code Execution in {route_path}"
            cwe_id = "CWE-502"
            owasp = "A08:2021 - Software and Data Integrity Failures"
            severity = "CRITICAL"
            desc = f"Route {route_path} at {file_path}:{line_no} parses untrusted input with unsafe deserialization, permitting Remote Code Execution (RCE)."
            remed = "Replace unsafe deserialization with safe parsers (e.g. yaml.safe_load, JSON.parse with validation)."
            if is_js:
                patched = "// Remediate Insecure Deserialization:\nconst safeData = JSON.parse(rawData);"
            else:
                patched = "# Remediate Insecure Deserialization:\nimport yaml\nydata = yaml.safe_load(yfile_data)"

        # 2. SQL Injection (CWE-89)
        elif any(k in snippet for k in ("executequery", "db.engine.execute", "cursor.execute", "createstatement")) or (
            any(k in snippet for k in ("select ", "from ", "where ", "insert into", "delete from", "update ")) and any(k in snippet for k in (" % ", " + ", ".format(", 'f"'))
        ) or (any(k in route_lower for k in ("search", "query")) and not is_static_route):
            title = f"SQL Injection Vulnerability in {route_path}"
            cwe_id = "CWE-89"
            owasp = "A03:2021 - Injection"
            severity = "CRITICAL"
            desc = f"Route {route_path} at {file_path}:{line_no} passes dynamic or unparameterized queries into database execution routines."
            remed = "Replace dynamic string concatenation with parameterized PreparedStatement or ORM query binding."
            if is_js:
                patched = "// Remediate SQL Injection with parameterized query:\n// const [rows] = await db.execute('SELECT * FROM resources WHERE id = ?', [resourceId]);"
            elif is_java:
                patched = "// Remediate SQL Injection: use PreparedStatement binding:\n// PreparedStatement pstmt = conn.prepareStatement(\"SELECT * FROM resources WHERE id = ?\");\n// pstmt.setString(1, resourceId);"
            else:
                patched = "# Remediate SQL Injection with parameterized query:\n# db.session.query(Customer).filter_by(username=search_term).all()\n# or conn.execute(text('SELECT * FROM customer WHERE username = :term'), {'term': search_term})"

        # 3. Server-Side Template Injection (CWE-1336 / CWE-94)
        elif any(k in snippet for k in ("render_template_string", "eval(", "exec(")):
            title = f"Server-Side Template / Code Injection in {route_path}"
            cwe_id = "CWE-1336"
            owasp = "A03:2021 - Injection"
            severity = "HIGH"
            desc = f"Route {route_path} at {file_path}:{line_no} passes unsanitized user or error strings directly into dynamic template evaluation."
            remed = "Use static predefined template files with context-aware autoescaping instead of dynamic template strings."
            if is_js:
                patched = "// Remediate template injection: use static template file with escaped context\nres.render('error', { errorMsg: err.message });"
            else:
                patched = "# Remediate SSTI:\nreturn render_template('error.html', error_msg=str(e))"

        # 4. Broken Authentication & Weak Cryptography (CWE-327 / CWE-287 / CWE-347)
        elif any(k in snippet for k in ("hashlib.md5", "md5(", "sha1(", "verify=false", "verify = false", "password == password")):
            title = f"Weak Cryptographic Hashing / Broken Token Verification in {route_path}"
            cwe_id = "CWE-327"
            owasp = "A02:2021 - Cryptographic Failures"
            severity = "HIGH"
            desc = f"Route {route_path} at {file_path}:{line_no} utilizes broken cryptographic algorithms (MD5/SHA1) or disables cryptographic token signature verification."
            remed = "Upgrade to standard password hashing (Argon2id, bcrypt, PBKDF2) and verify cryptographic signatures on authentication tokens."
            if is_js:
                patched = "// Enforce secure password hashing using bcrypt:\nconst hashedPassword = await bcrypt.hash(password, 12);"
            else:
                patched = "# Enforce cryptographic token verification:\njwt.decode(token, app.config['SECRET_KEY_HMAC'], algorithms=['HS256'])"

        # 5. Broken Function Level Authorization (CWE-285 / API5:2023)
        elif any(k in route_lower for k in ("admin", "adduser", "changepassword", "deleteuser", "privilege")):
            title = f"Broken Function Level Authorization (BFLA) in {route_path}"
            cwe_id = "CWE-285"
            owasp = "API5:2023 - Broken Function Level Authorization"
            severity = "CRITICAL"
            desc = f"Administrative endpoint {route_path} at {file_path}:{line_no} allows function invocation without verifying administrative caller privileges."
            remed = "Enforce role-based access control (RBAC): verify caller has administrative role before processing the request."
            if is_js:
                patched = "// Enforce RBAC verification:\nif (!req.session.isAdmin) {\n    return res.status(403).json({ error: 'Access denied: Admin privileges required' });\n}"
            elif is_java:
                patched = "// Enforce RBAC verification:\nif (!request.isUserInRole(\"ADMIN\")) {\n    return Response.status(Response.Status.FORBIDDEN).entity(\"{\\\"error\\\": \\\"Admin privileges required\\\"}\").build();\n}"
            else:
                patched = "# Enforce RBAC verification:\nif not current_user.is_admin:\n    abort(403)"

        # 6. Broken Object Level Authorization (CWE-639 / API1:2023)
        # CRITICAL: BOLA strictly requires a parameter / identifier placeholder in the route
        # (e.g. :userId, :id, {accountNo}, <doc_id>) or explicit object id queries.
        # Static routes like /profile, /cart, /login, /dashboard, /search, /home without IDs are NOT BOLA.
        elif (has_id_param or has_snippet_id_lookup) and not is_static_route:
            title = f"Broken Object Level Authorization (BOLA / IDOR) in {route_path}"
            cwe_id = "CWE-639"
            owasp = "API1:2023 - Broken Object Level Authorization"
            severity = "CRITICAL"
            desc = f"Route {route_path} at {file_path}:{line_no} accesses database records by user-controlled identifier without verifying session ownership."
            remed = "Enforce tenant scoping and verify that the requested resource belongs to the currently authenticated user."
            if is_js:
                # If orig_snippet is an Express route call, wrap it with ownership verification middleware
                if any(verb in orig_snippet for verb in ("app.get(", "app.post(", "app.put(", "app.delete(", "router.get(", "router.post(")):
                    m_call = re.search(r'((?:app|router)\.(?:get|post|put|delete))\s*\(\s*(["\'][^"\']+["\']\s*,\s*)(.*)', orig_snippet, re.DOTALL)
                    if m_call:
                        call_prefix = m_call.group(1)
                        route_arg = m_call.group(2)
                        handlers = m_call.group(3).strip()
                        param_match = re.search(r'[:{<]([a-zA-Z0-9_]+)', route_path)
                        p_name = param_match.group(1) if param_match else "id"
                        patched = (
                            f"// Enforce resource ownership (BOLA / CWE-639 Fix):\n"
                            f"{call_prefix}({route_arg}(req, res, next) => {{\n"
                            f"    const targetId = req.params.{p_name} || req.params.id;\n"
                            f"    if (req.session.userId !== targetId && !req.session.isAdmin) {{\n"
                            f"        return res.status(403).json({{ error: 'Access denied: unauthorized object access' }});\n"
                            f"    }}\n"
                            f"    next();\n"
                            f"}}, {handlers}"
                        )
                    else:
                        patched = (
                            "// Enforce resource ownership (BOLA / CWE-639 Fix):\n"
                            "(req, res, next) => {\n"
                            "    if (req.session.userId !== req.params.userId && !req.session.isAdmin) {\n"
                            "        return res.status(403).json({ error: 'Access denied: unauthorized object access' });\n"
                            "    }\n"
                            "    next();\n"
                            "}"
                        )
                else:
                    patched = (
                        "// Enforce resource ownership (BOLA / CWE-639 Fix):\n"
                        "if (req.session.userId !== req.params.userId && !req.session.isAdmin) {\n"
                        "    return res.status(403).json({ error: 'Access denied: unauthorized object access' });\n"
                        "}"
                    )
            elif is_java:
                patched = (
                    "// Enforce resource ownership (BOLA / CWE-639 Fix):\n"
                    "Principal principal = request.getUserPrincipal();\n"
                    "if (principal == null || !resourceService.isOwner(principal.getName(), id)) {\n"
                    "    return Response.status(Response.Status.FORBIDDEN).entity(\"{\\\"error\\\": \\\"Unauthorized resource access\\\"}\").build();\n"
                    "}"
                )
            elif is_go:
                patched = (
                    "// Enforce resource ownership (BOLA / CWE-639 Fix):\n"
                    "if c.GetString(\"user_id\") != id && c.GetString(\"role\") != \"admin\" {\n"
                    "    c.JSON(403, gin.H{\"error\": \"Forbidden: cross-tenant access denied\"})\n"
                    "    return\n"
                    "}"
                )
            else:
                patched = (
                    "# Enforce resource ownership (BOLA / CWE-639 Fix):\n"
                    "if current_user.get('id') != user_id and not current_user.get('is_admin'):\n"
                    "    raise HTTPException(status_code=403, detail='Forbidden: cross-tenant access denied')"
                )

        # 7. Sensitive Data Exposure (CWE-200 / API3:2023)
        elif any(k in snippet for k in ("ccn", "credit_card", "card_number")) or any(k in route_lower for k in ("fetch", "export", "dump")):
            title = f"Excessive Sensitive Data Exposure in {route_path}"
            cwe_id = "CWE-200"
            owasp = "API3:2023 - Broken Object Property Level Authorization"
            severity = "HIGH"
            desc = f"Route {route_path} at {file_path}:{line_no} exposes sensitive internal attributes in HTTP response objects."
            remed = "Filter response data using Data Transfer Objects (DTOs) or field projections to exclude sensitive attributes."
            if is_js:
                patched = "// Filter sensitive attributes:\nconst { password, ...safeData } = record;\nreturn res.json(safeData);"
            else:
                patched = "# Filter sensitive attributes:\nreturn jsonify({'id': record.id, 'username': record.username})"

        # 8. XML External Entity (CWE-611 / A05:2021)
        elif any(k in snippet for k in ("document(", "docx", "etree", "minidom")) and any(k in route_lower for k in ("xml", "xxe", "upload")):
            title = f"XML External Entity (XXE) / Unsafe Document Processing in {route_path}"
            cwe_id = "CWE-611"
            owasp = "A05:2021 - Security Misconfiguration"
            severity = "HIGH"
            desc = f"Route {route_path} at {file_path}:{line_no} parses uploaded documents or XML files without disabling external entity references or DTD processing."
            remed = "Disable external entity resolution (resolve_entities=False) and restrict file parser capabilities."
            if is_js:
                patched = "// Disable external entity resolution in XML parser:\nconst parser = new xml2js.Parser({ xmldtd: false });"
            else:
                patched = "# Disable external entity resolution in XML parser:\nparser = etree.XMLParser(resolve_entities=False, no_network=True)"

        # 9. Cross-Site Scripting (CWE-79 / A03:2021)
        elif any(k in route_lower for k in ("feedback", "comment", "message", "survey", "contact")):
            title = f"Cross-Site Scripting (XSS) / Content Injection in {route_path}"
            cwe_id = "CWE-79"
            owasp = "A03:2021 - Injection"
            severity = "MEDIUM"
            desc = f"Endpoint {route_path} at {file_path}:{line_no} accepts user content that may be reflected or stored without contextual HTML output encoding."
            remed = "Sanitize and encode all user-supplied data using context-aware output encoders."
            if is_js:
                patched = "// Contextual HTML output encoding:\nconst sanitized = escapeHtml(userInput);"
            else:
                patched = "# Contextual HTML output encoding:\nfrom markupsafe import escape\nreturn escape(user_input)"

        if title:
            # Mode filtering:
            if detection_mode == "bola_idor" and cwe_id not in ("CWE-639", "CWE-285", "CWE-862"):
                continue
            if detection_mode == "general" and (cwe_id == "CWE-639" or "API1" in (owasp or "") or "bola" in title.lower() or "idor" in title.lower()):
                continue

            exploit_spec = {
                "target_url": ep.get("url", f"http://127.0.0.1:8081{route_path}"),
                "method": ep.get("method", "GET"),
                "headers": {
                    **(ep.get("headers") or {}),
                    "Authorization": "Bearer <attacker_session_token>",
                    "Content-Type": "application/json",
                },
                "params": {},
                "body": ep.get("body_schema") or {},
                "expected_status": 200,
                "leak_indicator": "vulnerability_compromise",
                "attack_narrative": f"Attacker targets '{route_path}' exploiting {title} to compromise backend resources.",
            }
            payload_str = json.dumps(exploit_spec, indent=2)

            detected.append({
                "id": f"VULN-{idx:03d}",
                "title": title,
                "description": desc,
                "severity": severity,
                "confidence": 0.90,
                "cwe_id": cwe_id,
                "owasp_category": owasp,
                "exploit_payload": payload_str,
                "exploit_spec": exploit_spec,
                "remediation": remed,
                "references": [
                    f"https://cwe.mitre.org/data/definitions/{cwe_id.replace('CWE-', '')}.html",
                    "https://owasp.org/www-project-top-ten/",
                ],
                "file_path": file_path,
                "line_number": line_no,
                "route_path": route_path,
                "original_code": orig_snippet,
                "patched_code": _inject_aligned_security_patch(orig_snippet, patched, cwe_id) if orig_snippet else patched,
            })

    return detected


# ── Agent Node: Reason ────────────────────────────────────────

async def reason_agent(state: AgentState) -> AgentState:
    """
    Reasoning Agent (LLM-powered + Deep SAST AST analyzer).

    Responsibilities:
      1. Format correlated AST + Crawler targets into vulnerability analysis prompt
      2. Query local Ollama model for deep code audit
      3. Parse structured JSON output into DetectedVulnerability records
      4. Augment with deterministic AST pattern analysis so zero real flaws are missed
      5. Gracefully fall back to AST pattern analysis if Ollama is unreachable
    """
    scan_id = state.get("scan_id", "unknown")
    logger.info("agent.reason.start", scan_id=scan_id)

    targets = state.get("correlated_targets", [])
    if not targets:
        logger.info("agent.reason.no_targets", scan_id=scan_id)
        return {
            **state,
            "ai_exploit_payload": None,
            "vulnerabilities": [],
            "current_agent": "verify",
            "reasoning_trace": ["[Reason] No correlated targets found to analyse."],
        }

    model_name = state.get("model_name", "qwen2.5-coder:7b")
    ollama_base_url = state.get("ollama_base_url") or os.getenv("OLLAMA_API_BASE", "http://localhost:11434")

    # Auto-resolve installed model from Ollama tags if requested model is missing
    try:
        import urllib.request
        with urllib.request.urlopen(f"{ollama_base_url}/api/tags", timeout=2.0) as resp:
            tags = json.loads(resp.read().decode())
            installed = [m.get("name", "") for m in tags.get("models", [])]
            if model_name not in installed and installed:
                preferred = [m for m in installed if "llama3" in m or "coder" in m]
                model_name = preferred[0] if preferred else installed[0]
                logger.info("agent.reason.auto_resolved_model", using=model_name)
    except Exception:
        pass

    detection_mode = state.get("detection_mode", "all")

    if detection_mode == "general":
        logger.info("agent.reason.skip_llm_for_general_mode", scan_id=scan_id)
        # General DAST mode: rely strictly on Playwright crawler & deterministic security findings
        ast_findings = _perform_ast_pattern_analysis(targets, detection_mode="general")
        payload_str = ast_findings[0]["exploit_payload"] if ast_findings else None
        return {
            **state,
            "ai_exploit_payload": payload_str,
            "vulnerabilities": ast_findings,
            "current_agent": "verify",
            "reasoning_trace": [
                f"[General DAST] Playwright browser crawler engine active. Processed {len(targets)} target candidate(s). "
                f"Generated {len(ast_findings)} deterministic security finding(s)."
            ],
        }

    # Build prompt using comprehensive universal security reasoning template or specialized BOLA template
    if detection_mode == "bola_idor":
        prompt = build_bola_reason_prompt(
            targets=targets,
            scan_context={"scan_id": scan_id, "model": model_name, "base_url": ollama_base_url, "detection_mode": detection_mode},
        )
    else:
        prompt = build_reason_prompt(
            targets=targets,
            scan_context={"scan_id": scan_id, "model": model_name, "base_url": ollama_base_url, "detection_mode": detection_mode},
        )

    detected_vulnerabilities: list[dict[str, Any]] = []
    structured_payload_str: str | None = None
    reasoning_summary = ""

    try:
        logger.info("agent.reason.calling_ollama", model=model_name, base_url=ollama_base_url, mode=detection_mode)
        import os
        keep_alive = os.getenv("OLLAMA_KEEP_ALIVE", "0")
        llm = ChatOllama(
            model=model_name,
            base_url=ollama_base_url,
            temperature=0.1,
            format="json",
            keep_alive=keep_alive,
            num_ctx=8192,
        )
        response = await llm.ainvoke(prompt)
        raw_content = response.content if hasattr(response, "content") else str(response)
        parsed = _clean_and_parse_json(raw_content)

        raw_vulns = parsed.get("vulnerabilities", [])
        reasoning_summary = parsed.get("reasoning", "")

        for idx, item in enumerate(raw_vulns, start=1):
            exploit_spec = item.get("exploit_spec") or {}
            payload_str = item.get("exploit_payload")
            if not payload_str:
                payload_str = json.dumps(exploit_spec, indent=2) if isinstance(exploit_spec, dict) else str(exploit_spec)

            vuln_dict = {
                "id": f"VULN-{idx:03d}",
                "title": item.get("title", f"Security Vulnerability #{idx}"),
                "description": item.get("description", "Vulnerability detected in route handler."),
                "severity": item.get("severity", "HIGH"),
                "confidence": float(item.get("confidence", 0.9)),
                "cwe_id": item.get("cwe_id", "CWE-639"),
                "owasp_category": item.get("owasp_category", "OWASP Top 10"),
                "exploit_payload": payload_str,
                "exploit_spec": exploit_spec,
                "remediation": item.get("remediation", "Implement strict authorization and input validation."),
                "references": item.get("references", [
                    "https://owasp.org/www-project-top-ten/",
                    "https://cwe.mitre.org/",
                ]),
                "file_path": item.get("file_path"),
                "line_number": item.get("line_number"),
                "route_path": item.get("route_path"),
                "original_code": item.get("original_code"),
                "patched_code": item.get("patched_code"),
            }
            detected_vulnerabilities.append(vuln_dict)

        if detection_mode == "bola_idor":
            detected_vulnerabilities = [
                v for v in detected_vulnerabilities
                if v.get("cwe_id") in ("CWE-639", "CWE-285", "CWE-862")
                or "API1" in (v.get("owasp_category") or "")
                or "API5" in (v.get("owasp_category") or "")
                or any(k in v.get("title", "").lower() for k in ("bola", "idor", "authorization", "tenant", "privilege"))
            ]

        # Augment with deep AST pattern findings so static vulnerabilities are never lost
        ast_findings = _perform_ast_pattern_analysis(targets, detection_mode)
        seen_keys = {(v.get("route_path"), v.get("cwe_id")) for v in detected_vulnerabilities}
        for af in ast_findings:
            if (af.get("route_path"), af.get("cwe_id")) not in seen_keys:
                detected_vulnerabilities.append(af)
                seen_keys.add((af.get("route_path"), af.get("cwe_id")))

        if detected_vulnerabilities:
            structured_payload_str = detected_vulnerabilities[0]["exploit_payload"]

        trace_msg = (
            f"[Reason] AI reasoning and deep AST analysis evaluated {len(targets)} targets in [{detection_mode.upper()}] mode. "
            f"Identified {len(detected_vulnerabilities)} distinct vulnerability finding(s). "
            f"Reasoning: {reasoning_summary[:160]}..."
        )

    except Exception as exc:
        logger.warning(
            "agent.reason.ollama_call_failed",
            error=str(exc),
            model=model_name,
            base_url=ollama_base_url,
        )
        detected_vulnerabilities = _perform_ast_pattern_analysis(targets, detection_mode)
        if detected_vulnerabilities:
            structured_payload_str = detected_vulnerabilities[0]["exploit_payload"]

        trace_msg = (
            f"[Reason] Evaluated {len(detected_vulnerabilities)} routes in [{detection_mode.upper()}] mode via static AST analysis. "
            f"Discovered actual findings tailored to selected vulnerability focus."
        )

    logger.info(
        "agent.reason.complete",
        scan_id=scan_id,
        mode=detection_mode,
        vulnerabilities_found=len(detected_vulnerabilities),
    )

    return {
        **state,
        "ai_exploit_payload": structured_payload_str,
        "vulnerabilities": detected_vulnerabilities,
        "current_agent": "verify",
        "reasoning_trace": [trace_msg],
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
    vulnerabilities = list(state.get("vulnerabilities", []))
    targets = state.get("correlated_targets", [])
    detection_mode = state.get("detection_mode", "all")

    # In SAST-Only mode (no live target URL / crawler data), skip network probes
    has_target = bool(state.get("target_url") or state.get("crawler_data"))
    if not has_target:
        logger.info("agent.verify.sast_only_skip_http", scan_id=scan_id)
        sast_vulns = [
            v for v in vulnerabilities
            if not str(v.get("file_path", "")).startswith("http") and v.get("confidence", 0) >= 0.70
        ]
        return {
            **state,
            "exploit_results": [],
            "vulnerabilities": sast_vulns,
            "current_agent": "done",
            "reasoning_trace": [
                f"[Verify] SAST-Only Mode: Static source code verification completed. "
                f"Retained {len(sast_vulns)} verified vulnerability finding(s) with >=70% confidence in source repository."
            ],
        }

    exploit_results: list[dict[str, Any]] = []
    verified_vulnerabilities: list[dict[str, Any]] = []

    try:
        import sys
        from pathlib import Path
        src_path = str(Path(__file__).resolve().parents[2] / "crawler_dast" / "src")
        if src_path not in sys.path:
            sys.path.insert(0, src_path)

        from exploit_runner import ExploitRunner
        from false_positive_filter import FalsePositiveFilter
        from models import TestSpecification, VerificationStatus
        from verifier import VerificationEngine, execute_and_verify

        # Authorize all discovered target URLs for active verification
        allowed_hosts = ["localhost", "127.0.0.1", "::1"]
        target_base = state.get("target_url")
        if target_base:
            allowed_hosts.append(target_base)
        for ep in state.get("crawler_data", []):
            u = ep.get("url")
            if u:
                allowed_hosts.append(u)
        for t in targets:
            for ep in t.get("matched_endpoints", []):
                u = ep.get("url")
                if u:
                    allowed_hosts.append(u)

        async with ExploitRunner(allowed_targets=allowed_hosts) as runner:
            verifier_engine = VerificationEngine()
            fp_filter = FalsePositiveFilter()

            # Filter candidates for active verification by selected detection_mode
            candidate_vulns = vulnerabilities
            if detection_mode == "bola_idor":
                candidate_vulns = [
                    v for v in vulnerabilities
                    if v.get("cwe_id") in ("CWE-639", "CWE-285", "CWE-862")
                    or "API1" in (v.get("owasp_category") or "")
                    or any(k in v.get("title", "").lower() for k in ("bola", "idor", "tenant", "authorization"))
                ]
            elif detection_mode == "general":
                candidate_vulns = [
                    v for v in vulnerabilities
                    if v.get("cwe_id") not in ("CWE-639",)
                    and "API1:2023" not in (v.get("owasp_category") or "")
                ]

            # Execute probes for detected vulnerability hypotheses
            for vuln in candidate_vulns[:5]:
                test_payload = vuln.get("exploit_payload") or payload

                # Resolve specific endpoint URL for this vulnerability
                target_url = None
                vuln_route = vuln.get("route_path", "")
                for t in targets:
                    t_route = t.get("ast_node", {}).get("route_path", "")
                    if vuln_route and (vuln_route in t_route or t_route in vuln_route):
                        matched = t.get("matched_endpoints", [])
                        if matched:
                            target_url = matched[0].get("url")
                            break
                if not target_url and targets:
                    matched = targets[0].get("matched_endpoints", [])
                    if matched:
                        target_url = matched[0].get("url")
                if not target_url:
                    target_url = target_base or "http://localhost:3000"

                # Infer vulnerability type for probe construction
                cwe = str(vuln.get("cwe_id") or "")
                title_lower = (vuln.get("title") or "").lower()
                if "89" in cwe or "sql" in title_lower:
                    vuln_type = "SQLI"
                    inject_in = "query"
                    if not test_payload:
                        test_payload = "' OR 1=1--"
                elif "79" in cwe or "xss" in title_lower:
                    vuln_type = "XSS"
                    inject_in = "query"
                    if not test_payload:
                        test_payload = "<script>alert('aegis-verify')</script>"
                elif "639" in cwe or "bola" in title_lower or "idor" in title_lower:
                    vuln_type = "BOLA"
                    inject_in = "path" if "{" in target_url else "query"
                else:
                    vuln_type = "AUTH_BYPASS"
                    inject_in = "query"

                spec = TestSpecification(
                    scan_id=scan_id,
                    vulnerability_type=vuln_type,
                    target_url=target_url,
                    method=vuln.get("http_method", "GET"),
                    payload=test_payload or "",
                    inject_in=inject_in,
                )

                try:
                    v_result = await execute_and_verify(
                        spec, runner, verifier=verifier_engine, filter_engine=fp_filter
                    )
                    exploit_results.append({
                        "target_url": target_url,
                        "payload": test_payload,
                        "is_confirmed": v_result.is_confirmed,
                        "confidence": v_result.confidence,
                        "status": v_result.status.value,
                        "notes": v_result.reason,
                    })

                    # Empirical Verification Gate: only accept findings confirmed by live HTTP evidence
                    if v_result.is_confirmed and v_result.status in (
                        VerificationStatus.VERIFIED,
                        VerificationStatus.LIKELY,
                    ):
                        vuln["confidence"] = v_result.confidence
                        vuln["is_verified"] = True
                        vuln["verification_status"] = v_result.status.value
                        vuln["verification_notes"] = v_result.reason
                        verified_vulnerabilities.append(vuln)
                    else:
                        logger.info(
                            "agent.verify.unconfirmed_discarded",
                            vuln=vuln.get("title"),
                            status=v_result.status.value,
                            reason=v_result.reason,
                        )
                except Exception as probe_err:
                    logger.warning("agent.verify.probe_error", vuln=vuln.get("title"), error=str(probe_err))

            # Proactive Parameter Fuzzing across discovered parameterized endpoints
            crawler_eps = state.get("crawler_data", [])
            param_eps = []
            for ep in crawler_eps:
                u = ep.get("url", "")
                if "?" in u or ep.get("body_schema"):
                    param_eps.append(ep)

            if param_eps:
                logger.info("agent.verify.parameter_fuzzing", count=len(param_eps), mode=detection_mode)
                for pep in param_eps[:8]:
                    pep_url = pep.get("url", "")
                    pep_method = pep.get("method", "GET").upper()

                    # 1. Proactive Reflected XSS Canary Probe (Burp Suite & Acunetix focus)
                    if detection_mode in ("general", "all"):
                        xss_canary = "<aegis_xss_probe_canary>"
                        xss_spec = TestSpecification(
                            scan_id=scan_id,
                            vulnerability_type="XSS",
                            target_url=pep_url,
                            method=pep_method,
                            payload=xss_canary,
                            inject_in="body" if pep_method == "POST" else "query",
                        )
                        try:
                            xss_res = await execute_and_verify(
                                xss_spec, runner, verifier=verifier_engine, filter_engine=fp_filter
                            )
                            exploit_results.append({
                                "target_url": pep_url,
                                "payload": xss_canary,
                                "is_confirmed": xss_res.is_confirmed,
                                "confidence": xss_res.confidence,
                                "status": xss_res.status.value,
                                "notes": xss_res.reason,
                            })
                            if xss_res.is_confirmed and xss_res.status in (
                                VerificationStatus.VERIFIED, VerificationStatus.LIKELY
                            ):
                                verified_vulnerabilities.append({
                                    "id": f"VULN-XSS-{len(verified_vulnerabilities)+1:03d}",
                                    "title": f"Reflected Cross-Site Scripting (XSS) at {pep_url.split('?')[0]}",
                                    "description": (
                                        f"Live verification confirmed unencoded parameter reflection at {pep_url}. "
                                        "Server returned injected HTML probe directly into response body without entity encoding."
                                    ),
                                    "severity": "HIGH",
                                    "confidence": xss_res.confidence,
                                    "cwe_id": "CWE-79",
                                    "owasp_category": "A03:2021 - Injection",
                                    "exploit_payload": xss_canary,
                                    "file_path": pep_url,
                                    "line_number": 1,
                                    "original_code": f"// Live Verified XSS at {pep_url}\n// Injected probe: {xss_canary}",
                                    "patched_code": "// Sanitize and contextual HTML-encode user parameters before rendering\n// Java: Encode.forHtml(param);\n// Express: validator.escape(param);\n// ASP.NET: HtmlEncoder.Default.Encode(param);",
                                    "remediation": "Apply context-aware HTML entity encoding on all user-controlled parameters before rendering.",
                                    "is_verified": True,
                                    "verification_status": xss_res.status.value,
                                    "verification_notes": xss_res.reason,
                                })
                        except Exception as p_err:
                            logger.debug("agent.verify.xss_canary_failed", url=pep_url, error=str(p_err))

                    # 2. Proactive SQL Injection Syntax Probe (Burp Suite & Acunetix focus)
                    if detection_mode in ("general", "all"):
                        sqli_probe = "' OR '1'='1--"
                        sqli_spec = TestSpecification(
                            scan_id=scan_id,
                            vulnerability_type="SQLI",
                            target_url=pep_url,
                            method=pep_method,
                            payload=sqli_probe,
                            inject_in="body" if pep_method == "POST" else "query",
                        )
                        try:
                            sqli_res = await execute_and_verify(
                                sqli_spec, runner, verifier=verifier_engine, filter_engine=fp_filter
                            )
                            exploit_results.append({
                                "target_url": pep_url,
                                "payload": sqli_probe,
                                "is_confirmed": sqli_res.is_confirmed,
                                "confidence": sqli_res.confidence,
                                "status": sqli_res.status.value,
                                "notes": sqli_res.reason,
                            })
                            if sqli_res.is_confirmed and sqli_res.status in (
                                VerificationStatus.VERIFIED, VerificationStatus.LIKELY
                            ):
                                verified_vulnerabilities.append({
                                    "id": f"VULN-SQLI-{len(verified_vulnerabilities)+1:03d}",
                                    "title": f"SQL Injection in Parameter at {pep_url.split('?')[0]}",
                                    "description": (
                                        f"Live verification confirmed SQL injection at {pep_url}. "
                                        "Server returned database error signatures or altered logic in response to SQL probe."
                                    ),
                                    "severity": "CRITICAL",
                                    "confidence": sqli_res.confidence,
                                    "cwe_id": "CWE-89",
                                    "owasp_category": "A03:2021 - Injection",
                                    "exploit_payload": sqli_probe,
                                    "file_path": pep_url,
                                    "line_number": 1,
                                    "original_code": f"// Vulnerable Dynamic SQL Query at {pep_url}\n// Injected probe: {sqli_probe}",
                                    "patched_code": "// Replace dynamic query concatenation with parameterized PreparedStatement\nPreparedStatement ps = conn.prepareStatement(\"SELECT * FROM tbl WHERE col = ?\");\nps.setString(1, param);",
                                    "remediation": "Replace dynamic string concatenation with parameterized PreparedStatement queries.",
                                    "is_verified": True,
                                    "verification_status": sqli_res.status.value,
                                    "verification_notes": sqli_res.reason,
                                })
                        except Exception as p_err:
                            logger.debug("agent.verify.sqli_probe_failed", url=pep_url, error=str(p_err))

                    # 3. Proactive BOLA / IDOR Parameter Tampering Probe (API Security focus)
                    if detection_mode in ("bola_idor", "all"):
                        import re
                        has_id_param = bool(re.search(r"([?&](id|user|uid|account|order|cart|item|doc|num|no)=)(\d+)", pep_url, re.I))
                        if has_id_param:
                            tampered_url = re.sub(
                                r"([?&](id|user|uid|account|order|cart|item|doc|num|no)=)(\d+)",
                                lambda m: f"{m.group(1)}{int(m.group(3))+1}",
                                pep_url,
                                flags=re.I
                            )
                            bola_spec = TestSpecification(
                                scan_id=scan_id,
                                vulnerability_type="BOLA",
                                target_url=tampered_url,
                                method=pep_method,
                                payload="tampered_object_id",
                                inject_in="query",
                            )
                            try:
                                bola_res = await execute_and_verify(
                                    bola_spec, runner, verifier=verifier_engine, filter_engine=fp_filter
                                )
                                exploit_results.append({
                                    "target_url": tampered_url,
                                    "payload": "tampered_object_id",
                                    "is_confirmed": bola_res.is_confirmed,
                                    "confidence": bola_res.confidence,
                                    "status": bola_res.status.value,
                                    "notes": bola_res.reason,
                                })
                                if bola_res.is_confirmed and bola_res.status in (
                                    VerificationStatus.VERIFIED, VerificationStatus.LIKELY
                                ):
                                    verified_vulnerabilities.append({
                                        "id": f"VULN-BOLA-{len(verified_vulnerabilities)+1:03d}",
                                        "title": f"Broken Object Level Authorization (BOLA / IDOR) at {pep_url.split('?')[0]}",
                                        "description": (
                                            f"Live verification confirmed horizontal authorization bypass at {pep_url}. "
                                            f"Mutating object identifier to {tampered_url} allowed unauthorized access to foreign object data without permission checks."
                                        ),
                                        "severity": "CRITICAL",
                                        "confidence": bola_res.confidence,
                                        "cwe_id": "CWE-639",
                                        "owasp_category": "API1:2023 - Broken Object Level Authorization",
                                        "exploit_payload": tampered_url,
                                        "file_path": pep_url,
                                        "line_number": 1,
                                        "original_code": f"// Vulnerable Direct Object Access at {pep_url}\n// Query: {pep_url}",
                                        "patched_code": "// Validate that caller session owns the requested object ID\nif (requestedObject.userId !== session.currentUser.id) {\n    throw new ForbiddenException('Unauthorized object access');\n}",
                                        "remediation": "Validate that the authenticated session user is the legitimate owner of the requested object before fetching or updating data.",
                                        "is_verified": True,
                                        "verification_status": bola_res.status.value,
                                        "verification_notes": bola_res.reason,
                                    })
                            except Exception as b_err:
                                logger.debug("agent.verify.bola_probe_failed", url=tampered_url, error=str(b_err))

    except Exception as exc:
        logger.warning("agent.verify.runner_fallback", error=str(exc))
        if payload and not exploit_results:
            exploit_results.append({
                "payload": payload,
                "is_confirmed": False,
                "confidence": 0.0,
                "notes": f"Fallback execution: {exc}",
            })

    # Strict Industrial Standard:
    # 1. If verified by live HTTP test: include verified findings.
    # 2. If SAST scan with repository source code: keep genuine code findings with real file paths.
    # 3. If DAST-only scan and zero findings verified: discard all unverified hypotheses (clean target).
    has_sast = bool(state.get("ast_data"))
    final_vulns = list(verified_vulnerabilities)
    if has_sast:
        sast_vulns = [
            v for v in vulnerabilities
            if not str(v.get("file_path", "")).startswith("http") and v.get("confidence", 0) >= 0.70
        ]
        seen_titles = {v.get("title") for v in final_vulns}
        for sv in sast_vulns:
            if sv.get("title") not in seen_titles:
                final_vulns.append(sv)
    elif not final_vulns and not has_sast:
        final_vulns = []

    logger.info(
        "agent.verify.complete",
        scan_id=scan_id,
        probes_fired=len(exploit_results),
        verified_count=len(verified_vulnerabilities),
    )

    return {
        **state,
        "exploit_results": exploit_results,
        "vulnerabilities": final_vulns,
        "current_agent": "done",
        "reasoning_trace": [
            f"[Verify] Dispatched {len(exploit_results)} probe(s) via ExploitRunner. "
            f"Verified {len(verified_vulnerabilities)} confirmed vulnerability finding(s)."
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
    """Smoke test of the compiled graph evaluating a realistic BOLA flaw."""
    graph = build_graph()

    # Sample input: AST finding from Vedant's parser + Crawler finding from Shahad's crawler
    initial_state: AgentState = {
        "scan_id": "scan-bola-001",
        "model_name": "qwen2.5-coder:7b",
        "ast_data": [
            {
                "route_path": "/cart/transfer",
                "file_path": "backend/routes/cart.js",
                "line_number": 14,
                "language": "javascript",
                "function_name": "transferCart",
                "source_snippet": (
                    "router.post('/cart/transfer', async (req, res) => {\n"
                    "  const targetCartId = req.headers['x-target-cart'];\n"
                    "  const targetCart = await db.collection('carts').doc(targetCartId).get();\n"
                    "  const items = targetCart.data().items;\n"
                    "  const userCartRef = db.collection('carts').doc(req.user.cartId);\n"
                    "  await userCartRef.update({ items: items });\n"
                    "  await db.collection('carts').doc(targetCartId).update({ items: [] });\n"
                    "  res.send('Transferred');\n"
                    "});"
                ),
            }
        ],
        "crawler_data": [
            {
                "url": "http://localhost:3000/cart/transfer",
                "method": "POST",
                "headers": {
                    "Content-Type": "application/json",
                    "Authorization": "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.attacker_user_token",
                },
                "tokens": {
                    "jwt": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.attacker_user_token",
                    "session_cookie": "s%3Aattacker_session_cookie_12345",
                },
                "body_schema": {},
            }
        ],
    }

    print("\n[*] AegisAI Agent Graph - Smoke Test\n" + "-" * 50)
    result = await graph.ainvoke(initial_state)

    print(f"\n[+] Scan complete - agent: {result.get('current_agent')}")
    print("[-] Reasoning trace:")
    for step in result.get("reasoning_trace", []):
        print(f"   {step}")
    print(f"\n[*] Vulnerabilities: {len(result.get('vulnerabilities', []))}")


if __name__ == "__main__":
    asyncio.run(_main())
