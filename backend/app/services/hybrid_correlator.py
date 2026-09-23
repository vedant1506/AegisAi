"""
AegisAI — Hybrid Correlator
=============================
Maps verified vulnerabilities from the LangGraph AI pipeline back to
the specific source file, line number, and handler function discovered
by the tree-sitter AST parser.

This is the critical integration step that powers the CodeDiffViewer:
without this, vulnerabilities are raw endpoint observations without
source-level context.

Algorithm:
  1. For each vulnerability, extract its associated endpoint URL path.
  2. Normalise the URL (strip host, query params, parameterize segments).
  3. Match against AST route_path entries using the same normalisation.
  4. Attach file_path, line_number, function_name, and source_snippet.
  5. Generate a simple before/after patch stub for the diff viewer.
"""

from __future__ import annotations

import re
from typing import Any
from pathlib import Path

import httpx
import structlog

from app.core.config import settings
from app.schemas.io_models import (
    ASTSchema,
    DetectedVulnerability,
    EndpointSchema,
    ProgrammingLanguage,
)

logger = structlog.get_logger(__name__)

# -- Path normalisation ----------------------------------------

# Matches :param, <param>, {param}, [param] style path segments
_PARAM_RE = re.compile(r"(:[a-zA-Z_]\w*|<[^>]+>|\{[^}]+\}|\[[^\]]+\])")


def _normalize_path(path: str) -> str:
    """
    Normalise a URL path for fuzzy matching.

    Examples:
        /api/users/42           → /api/users/[^/]+
        /api/users/:id          → /api/users/[^/]+
        /api/users/{user_id}    → /api/users/[^/]+
    """
    # Strip query string and fragment
    clean = path.split("?")[0].split("#")[0].strip("/").lower()
    # Normalise parameterised segments
    normalised = _PARAM_RE.sub("[^/]+", clean)
    return normalised


def _paths_match(pattern: str, candidate: str) -> bool:
    """
    Check if a normalised AST route pattern matches a candidate endpoint URL path.
    pattern may contain [^/]+ wildcards.
    """
    # Build a regex from the pattern
    regex = "^" + re.sub(r"\[?\^\/?]\+", "[^/]+", pattern) + "$"
    try:
        return bool(re.fullmatch(pattern.replace("[^/]+", "[^/]+"), candidate))
    except re.error:
        return pattern == candidate


def _extract_url_path(endpoint_url: str) -> str:
    """Extract just the path component from a full URL."""
    # Strip scheme + host
    path = re.sub(r"^https?://[^/]+", "", endpoint_url)
    return path.split("?")[0] if path else "/"


# -- Patch generation ------------------------------------------

def _generate_ai_patch(
    vuln: DetectedVulnerability,
    ast_node: ASTSchema | None,
    timeout: float = 60.0,
) -> tuple[str, str] | None:
    """
    Directly query the fine-tuned AegisAI security LLM (qwen2.5-coder:7b via Ollama)
    to generate a clean, real-world, repository-specific security patch.
    In DAST-only mode (where ast_node is None), generates a secure reference implementation.
    """
    snippet = (ast_node.source_snippet if ast_node and ast_node.source_snippet else vuln.original_code) or ""
    cwe_id = vuln.cwe_id or "Security Vulnerability"
    title = vuln.title or "Vulnerability"

    if snippet and len(snippet.strip().splitlines()) >= 2:
        lang = ast_node.language.value if (ast_node and ast_node.language) else "python"
        prompt = (
            f"You are AegisAI, an expert application security engineer.\n"
            f"Fix the following security vulnerability: {title} ({cwe_id}).\n\n"
            f"Vulnerable {lang} code:\n"
            f"```{lang}\n{snippet}\n```\n\n"
            f"Instructions:\n"
            f"- Rewrite the function to remediate the vulnerability properly and securely.\n"
            f"- Maintain the original function signature, logic, and coding style.\n"
            f"- Return ONLY the patched code enclosed in a single markdown code block (```{lang}...```).\n"
            f"- Do NOT include any explanations, conversational text, or commentary outside the code block."
        )
        original_to_return = snippet
    else:
        # DAST-only mode: no local source code available. Generate reference secure implementation
        route = vuln.title.split("in")[-1].strip() if "in" in vuln.title else "/api/endpoint"
        desc = vuln.description or "Unchecked endpoint parameter access"
        prompt = (
            f"You are AegisAI, an expert application security engineer.\n"
            f"A DAST vulnerability was discovered during live testing: {title} ({cwe_id}) on endpoint `{route}`.\n"
            f"Details: {desc}\n\n"
            f"Instructions:\n"
            f"- Write a secure, production-ready reference route handler remediating this vulnerability.\n"
            f"- Return ONLY the secure code enclosed in a single markdown code block (```...```).\n"
            f"- Do NOT include any explanations, conversational text, or commentary outside the code block."
        )
        original_to_return = f"// Live DAST Finding: {title} ({cwe_id})\n// Endpoint: {route}\n// No repository source code provided (DAST-Only Scan)."

    try:
        url = f"{settings.ollama_api_base.rstrip('/')}/api/generate"
        response = httpx.post(
            url,
            json={
                "model": "qwen2.5-coder:7b",
                "prompt": prompt,
                "stream": False,
                "options": {
                    "temperature": 0.1,
                    "num_predict": 512,
                },
                "keep_alive": "0",  # unload immediately after generation so VRAM stays free
            },
            timeout=timeout,
        )
        if response.status_code == 200:
            raw_text = response.json().get("response", "").strip()
            # Extract code from markdown block
            match = re.search(r"```(?:\w+)?\s*([\s\S]*?)\s*```", raw_text)
            if match:
                clean_code = match.group(1).strip()
            else:
                clean_lines = raw_text.splitlines()
                if clean_lines and clean_lines[0].strip().startswith("```"):
                    clean_lines = clean_lines[1:]
                if clean_lines and clean_lines[-1].strip().startswith("```"):
                    clean_lines = clean_lines[:-1]
                clean_code = "\n".join(clean_lines).strip()

            patched_code = clean_code
            if (
                patched_code
                and len(patched_code.splitlines()) >= 2
                and patched_code.strip() != original_to_return.strip()
            ):
                logger.info("correlator.ai_patch_success", cwe=cwe_id, length=len(patched_code))
                return original_to_return, patched_code
            else:
                logger.debug("correlator.ai_patch_rejected_identical", cwe=cwe_id)
    except Exception as exc:
        logger.warning("correlator.ai_patch_failed", error=str(exc))

    return None


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


def _generate_patch(
    vuln: DetectedVulnerability,
    ast_node: ASTSchema | None,
) -> tuple[str, str]:
    """
    Generate a realistic before/after code patch for the diff viewer,
    respecting whether the target repository is Python or JavaScript/TypeScript.
    """
    route_name = ast_node.route_path if ast_node else (
        vuln.title.split("in")[-1].strip() if "in" in vuln.title else "/api/resource/:id"
    )
    file_path = (ast_node.file_path if ast_node and ast_node.file_path else "").lower()
    is_js_ts = (
        file_path.endswith((".ts", ".js", ".tsx", ".jsx", ".mjs", ".cjs"))
        or (ast_node is not None and ast_node.language in (ProgrammingLanguage.JAVASCRIPT, ProgrammingLanguage.TYPESCRIPT))
    )

    # ── CASE 1: JAVASCRIPT / TYPESCRIPT (Express / Node.js) ────────
    if is_js_ts:
        if ast_node and ast_node.source_snippet and len(ast_node.source_snippet.strip().splitlines()) >= 1:
            original = ast_node.source_snippet
            lines = original.splitlines()
            patched_lines = []
            inserted = False
            for line in lines:
                if any(v in line for v in (".get(", ".post(", ".put(", ".delete(", "app.use(")) and not inserted:
                    m_call = re.search(r'((?:app|router)\.(?:get|post|put|delete))\s*\(\s*(["\'][^"\']+["\']\s*,\s*)(.*)', line)
                    if m_call:
                        call_prefix = m_call.group(1)
                        route_arg = m_call.group(2)
                        handlers = m_call.group(3).strip()
                        param_match = re.search(r'[:{<]([a-zA-Z0-9_]+)', route_name)
                        p_name = param_match.group(1) if param_match else "id"
                        patched_lines.append(f"// AegisAI Security Fix: Verify user ownership to prevent BOLA (CWE-639)")
                        patched_lines.append(f"{call_prefix}({route_arg}(req, res, next) => {{")
                        patched_lines.append(f"  const targetId = req.params.{p_name} || req.params.id;")
                        patched_lines.append(f"  if (req.session?.userId !== targetId && !req.session?.isAdmin) {{")
                        patched_lines.append(f"    return res.status(403).json({{ error: 'Access forbidden: cross-user access denied' }});")
                        patched_lines.append(f"  }}")
                        patched_lines.append(f"  next();")
                        patched_lines.append(f"}}, {handlers}")
                    else:
                        indent = "  "
                        patched_lines.append(line)
                        patched_lines.append(f"{indent}  // AegisAI Security Fix: Verify user ownership to prevent BOLA (CWE-639)")
                        patched_lines.append(f"{indent}  (req: any, res: any, next: any) => {{")
                        patched_lines.append(f"{indent}    if (req.user?.id != req.params.id && req.user?.role !== 'admin') {{")
                        patched_lines.append(f"{indent}      return res.status(403).json({{ error: 'Access forbidden: cross-user access denied' }});")
                        patched_lines.append(f"{indent}    }}")
                        patched_lines.append(f"{indent}    next();")
                        patched_lines.append(f"{indent}  }},")
                    inserted = True
                else:
                    patched_lines.append(line)
            if inserted:
                return original, "\n".join(patched_lines)

        # Realistic template for JS/TS Express routes
        clean_route = route_name if route_name.startswith("/") else f"/{route_name}"
        original = f"""// Vulnerable Express Route Handler ({file_path or 'routes/users.ts'})
app.route('{clean_route}')
  .get(security.isAuthorized(), async (req, res) => {{
    // Vulnerable: Returns record without verifying requesting session matches :id
    const user = await models.User.findByPk(req.params.id);
    if (!user) return res.status(404).json({{ error: 'User not found' }});
    res.json(user);
  }});"""

        patched = f"""// AegisAI Security-Hardened Route Handler (CWE-639 / BOLA Fix)
app.route('{clean_route}')
  .get(
    security.isAuthorized(),
    // AegisAI Security Fix: Verify caller ownership before accessing resource
    (req, res, next) => {{
      if (req.user?.id != req.params.id && req.user?.role !== 'admin') {{
        return res.status(403).json({{ error: 'Access forbidden: cross-user access denied' }});
      }}
      next();
    }},
    async (req, res) => {{
      const user = await models.User.findByPk(req.params.id);
      if (!user) return res.status(404).json({{ error: 'User not found' }});
      res.json(user);
    }}
  );"""
        return original, patched

    # ── CASE 3: GO (Gin, Echo, Fiber) ──────────────────────────────
    is_go = file_path.endswith(".go") or (ast_node is not None and ast_node.language == ProgrammingLanguage.GO)
    if is_go:
        if ast_node and ast_node.source_snippet and len(ast_node.source_snippet.strip().splitlines()) >= 2:
            lines = ast_node.source_snippet.splitlines()
            patched_lines = []
            inserted = False
            for line in lines:
                patched_lines.append(line)
                if ("func(" in line or "func " in line) and not inserted:
                    indent = "\t"
                    patched_lines.append(f"{indent}// AegisAI Security Fix: Verify ownership (CWE-639)")
                    patched_lines.append(f"{indent}if c.GetString(\"user_id\") != id && c.GetString(\"role\") != \"admin\" {{")
                    patched_lines.append(f"{indent}\tc.JSON(403, gin.H{{\"error\": \"Forbidden: cross-tenant access denied\"}})")
                    patched_lines.append(f"{indent}\treturn")
                    patched_lines.append(f"{indent}}}")
                    inserted = True
            if inserted:
                return ast_node.source_snippet, "\n".join(patched_lines)

        clean_route = route_name if route_name.startswith("/") else f"/{route_name}"
        orig_go = f"""// Vulnerable Go Route Handler
r.GET("{clean_route}", func(c *gin.Context) {{
    id := c.Param("id")
    record, err := db.GetResource(id)
    if err != nil {{
        c.JSON(404, gin.H{{"error": "not found"}})
        return
    }}
    c.JSON(200, record)
}})"""
        patch_go = f"""// AegisAI Security-Hardened Route Handler (CWE-639 / BOLA Fix)
r.GET("{clean_route}", func(c *gin.Context) {{
    id := c.Param("id")
    // AegisAI Security Fix: Verify caller ownership
    if c.GetString("user_id") != id && c.GetString("role") != "admin" {{
        c.JSON(403, gin.H{{"error": "Forbidden: cross-tenant access denied"}})
        return
    }}
    record, err := db.GetResource(id)
    if err != nil {{
        c.JSON(404, gin.H{{"error": "not found"}})
        return
    }}
    c.JSON(200, record)
}})"""
        return orig_go, patch_go

    # ── CASE 4: JAVA (JAX-RS / Spring Boot / Servlets) ───────────────
    is_java = file_path.endswith(".java") or (ast_node is not None and ast_node.language == ProgrammingLanguage.JAVA)
    if is_java:
        if ast_node and ast_node.source_snippet and len(ast_node.source_snippet.strip().splitlines()) >= 2:
            snippet = ast_node.source_snippet
            lines = snippet.splitlines()
            patched_lines = []
            inserted = False
            is_admin = "admin" in file_path or "admin" in route_name.lower() or "adduser" in snippet.lower()
            is_servlet = "servlet" in file_path or "httpservletresponse" in snippet.lower()
            has_account_no = "accountno" in snippet.lower() or "account_no" in snippet.lower() or "{accountno}" in route_name.lower()
            is_transfer = "transfer" in route_name.lower() or "transfer" in file_path

            cwe = (vuln.cwe_id or "").upper()
            title_lower = (vuln.title or "").lower()

            for line in lines:
                patched_lines.append(line)
                # Insert authorization / sanitization check right after opening method brace
                if not inserted and ("{" in line or "public " in line or "protected " in line) and "class " not in line and "@" not in line:
                    indent = "        " if line.startswith("\t\t") or line.startswith("        ") else "    "

                    if "CWE-89" in cwe or "sql" in title_lower:
                        patched_lines.append(f"{indent}// AegisAI Security Fix: Parameterized Query Protection (CWE-89 SQL Injection)")
                        patched_lines.append(f"{indent}// Ensure all query parameters use PreparedStatement binding instead of concatenation")
                        patched_lines.append(f"{indent}// Example: PreparedStatement pstmt = conn.prepareStatement(\"SELECT ... WHERE id = ?\");")
                        patched_lines.append(f"{indent}// pstmt.setString(1, sanitizedInput);")
                    elif "CWE-79" in cwe or "xss" in title_lower:
                        patched_lines.append(f"{indent}// AegisAI Security Fix: Context-Aware Output Encoding (CWE-79 XSS Prevention)")
                        patched_lines.append(f"{indent}// Encode user-supplied parameters before rendering: org.owasp.encoder.Encode.forHtml(input);")
                    elif "CWE-287" in cwe or "authentication" in title_lower:
                        patched_lines.append(f"{indent}// AegisAI Security Fix: Session Verification & Rate Limiting (CWE-287)")
                        if is_servlet:
                            patched_lines.append(f"{indent}if (request.getSession(false) == null) {{")
                            patched_lines.append(f"{indent}    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, \"Authentication required\");")
                            patched_lines.append(f"{indent}    return;")
                            patched_lines.append(f"{indent}}}")
                        else:
                            patched_lines.append(f"{indent}if (request.getUserPrincipal() == null) {{")
                            patched_lines.append(f"{indent}    return Response.status(Response.Status.UNAUTHORIZED).entity(\"{{\\\"error\\\": \\\"Authentication required\\\"}}\").build();")
                            patched_lines.append(f"{indent}}}")
                    elif is_admin or "CWE-285" in cwe or "bfla" in title_lower:
                        patched_lines.append(f"{indent}// AegisAI Security Fix: Verify administrative role authorization (CWE-285 / CWE-639)")
                        if is_servlet:
                            patched_lines.append(f"{indent}if (!request.isUserInRole(\"ADMIN\")) {{")
                            patched_lines.append(f"{indent}    response.sendError(HttpServletResponse.SC_FORBIDDEN, \"Access denied: Admin privileges required\");")
                            patched_lines.append(f"{indent}    return;")
                            patched_lines.append(f"{indent}}}")
                        else:
                            patched_lines.append(f"{indent}if (!request.isUserInRole(\"ADMIN\")) {{")
                            patched_lines.append(f"{indent}    return Response.status(Response.Status.FORBIDDEN)")
                            patched_lines.append(f"{indent}            .entity(\"{{\\\"error\\\": \\\"Access denied: Admin privileges required\\\"}}\")")
                            patched_lines.append(f"{indent}            .build();")
                            patched_lines.append(f"{indent}}}")
                    elif is_servlet:
                        patched_lines.append(f"{indent}// AegisAI Security Fix: Verify authenticated session and ownership (CWE-639)")
                        patched_lines.append(f"{indent}if (request.getUserPrincipal() == null) {{")
                        patched_lines.append(f"{indent}    response.sendError(HttpServletResponse.SC_UNAUTHORIZED, \"Authentication required\");")
                        patched_lines.append(f"{indent}    return;")
                        patched_lines.append(f"{indent}}}")
                    elif is_transfer or "CWE-862" in cwe:
                        patched_lines.append(f"{indent}// AegisAI Security Fix: Verify caller authorization before transaction (CWE-639 / CWE-862)")
                        patched_lines.append(f"{indent}Principal principal = request.getUserPrincipal();")
                        patched_lines.append(f"{indent}if (principal == null) {{")
                        patched_lines.append(f"{indent}    return Response.status(Response.Status.FORBIDDEN)")
                        patched_lines.append(f"{indent}            .entity(\"{{\\\"error\\\": \\\"Access denied: unauthorized transfer origin\\\"}}\")")
                        patched_lines.append(f"{indent}            .build();")
                        patched_lines.append(f"{indent}}}")
                    elif "CWE-639" in cwe or "bola" in title_lower or "idor" in title_lower:
                        patched_lines.append(f"{indent}// AegisAI Security Fix: Verify caller ownership to prevent BOLA (CWE-639)")
                        patched_lines.append(f"{indent}Principal principal = request.getUserPrincipal();")
                        patched_lines.append(f"{indent}if (principal == null) {{")
                        patched_lines.append(f"{indent}    return Response.status(Response.Status.FORBIDDEN)")
                        patched_lines.append(f"{indent}            .entity(\"{{\\\"error\\\": \\\"Access denied: unauthorized resource access\\\"}}\")")
                        patched_lines.append(f"{indent}            .build();")
                        patched_lines.append(f"{indent}}}")
                    else:
                        patched_lines.append(f"{indent}// AegisAI Security Fix: Validate session user ownership and field projection (CWE-200)")
                        patched_lines.append(f"{indent}if (request.getUserPrincipal() == null) {{")
                        patched_lines.append(f"{indent}    return Response.status(Response.Status.UNAUTHORIZED)")
                        patched_lines.append(f"{indent}            .entity(\"{{\\\"error\\\": \\\"Authentication required\\\"}}\")")
                        patched_lines.append(f"{indent}            .build();")
                        patched_lines.append(f"{indent}}}")
                    inserted = True
            if inserted:
                return ast_node.source_snippet, "\n".join(patched_lines)

        clean_route = route_name if route_name.startswith("/") else f"/{route_name}"
        orig_java = f"""@GET
@Path("{clean_route}")
public Response getResource(@PathParam("id") String id, @Context HttpServletRequest request) {{
    // Vulnerable: Returns record without verifying caller ownership
    Resource data = ResourceService.findById(id);
    return Response.ok(data).build();
}}"""
        patch_java = f"""@GET
@Path("{clean_route}")
public Response getResource(@PathParam("id") String id, @Context HttpServletRequest request) {{
    // AegisAI Security Fix: Verify caller authorization to prevent BOLA (CWE-639)
    Principal principal = request.getUserPrincipal();
    if (principal == null || !ResourceService.isOwner(principal.getName(), id)) {{
        return Response.status(Response.Status.FORBIDDEN)
                .entity("{{\\"error\\": \\"Access denied: unauthorized resource access\\"}}")
                .build();
    }}
    Resource data = ResourceService.findById(id);
    return Response.ok(data).build();
}}"""
        return orig_java, patch_java

    # ── CASE 5: PHP (Laravel / Symfony) ─────────────────────────────
    is_php = file_path.endswith(".php") or (ast_node is not None and ast_node.language == ProgrammingLanguage.PHP)
    if is_php:
        if ast_node and ast_node.source_snippet and len(ast_node.source_snippet.strip().splitlines()) >= 2:
            lines = ast_node.source_snippet.splitlines()
            patched_lines = []
            inserted = False
            for line in lines:
                patched_lines.append(line)
                if ("function" in line or "{" in line) and not inserted:
                    indent = "    "
                    patched_lines.append(f"{indent}// AegisAI Security Fix: Verify ownership (CWE-639)")
                    patched_lines.append(f"{indent}if ($request->user()->id != $id && !$request->user()->isAdmin()) {{")
                    patched_lines.append(f"{indent}    abort(403, 'Forbidden: cross-tenant access denied');")
                    patched_lines.append(f"{indent}}}")
                    inserted = True
            if inserted:
                return ast_node.source_snippet, "\n".join(patched_lines)

        clean_route = route_name if route_name.startswith("/") else f"/{route_name}"
        orig_php = f"""Route::get('{clean_route}', function (Request $request, $id) {{
    // Vulnerable: Missing authorization check on requested object id
    return Resource::findOrFail($id);
}});"""
        patch_php = f"""Route::get('{clean_route}', function (Request $request, $id) {{
    // AegisAI Security Fix: Verify caller ownership (CWE-639)
    if ($request->user()->id != $id && !$request->user()->isAdmin()) {{
        abort(403, 'Forbidden: cross-tenant access denied');
    }}
    return Resource::where('id', $id)->where('user_id', $request->user()->id)->firstOrFail();
}});"""
        return orig_php, patch_php

    # ── CASE 6: C# (ASP.NET Core) ──────────────────────────────────
    is_cs = file_path.endswith(".cs") or (ast_node is not None and ast_node.language == ProgrammingLanguage.CSHARP)
    if is_cs:
        if ast_node and ast_node.source_snippet and len(ast_node.source_snippet.strip().splitlines()) >= 2:
            lines = ast_node.source_snippet.splitlines()
            patched_lines = []
            inserted = False
            for line in lines:
                patched_lines.append(line)
                if ("{" in line or "public " in line) and not inserted:
                    indent = "    "
                    patched_lines.append(f"{indent}// AegisAI Security Fix: Verify ownership (CWE-639)")
                    patched_lines.append(f"{indent}if (User.FindFirst(ClaimTypes.NameIdentifier)?.Value != id && !User.IsInRole(\"Admin\")) {{")
                    patched_lines.append(f"{indent}    return Forbid();")
                    patched_lines.append(f"{indent}}}")
                    inserted = True
            if inserted:
                return ast_node.source_snippet, "\n".join(patched_lines)

    # ── CASE 7: DEFAULT PYTHON (FastAPI / Flask) ───────────────────
    func_name = (ast_node.function_name if ast_node and ast_node.function_name else None) or "get_resource"
    param_name = "action_id" if "action" in route_name else ("user_id" if "user" in route_name else ("doc_id" if "doc" in route_name else ("order_id" if "order" in route_name else ("project_id" if "project" in route_name else "id"))))

    snippet_source = (ast_node.source_snippet if ast_node and ast_node.source_snippet else vuln.original_code) or ""
    if snippet_source and len(snippet_source.strip().splitlines()) >= 2:
        original = snippet_source
        lines = original.splitlines()
        patched_lines = []
        inserted = False
        for line in lines:
            patched_lines.append(line)
            if ("def " in line) and not inserted and not line.strip().startswith("@"):
                leading_spaces = len(line) - len(line.lstrip())
                indent = " " * (leading_spaces + 4)
                if "639" in (vuln.cwe_id or "") or "bola" in (vuln.title or "").lower() or "idor" in (vuln.title or "").lower():
                    patched_lines.append(f"{indent}# AegisAI Security Fix: Verify caller ownership to prevent BOLA (CWE-639)")
                    patched_lines.append(f"{indent}if current_user.get('{param_name}') != {param_name} and current_user.get('role') != 'admin':")
                    patched_lines.append(f"{indent}    raise HTTPException(status_code=403, detail='Access forbidden: cross-tenant access denied')")
                elif "89" in (vuln.cwe_id or "") or "sql" in (vuln.title or "").lower():
                    patched_lines.append(f"{indent}# AegisAI Security Fix: Enforce parameterized query to prevent SQL Injection (CWE-89)")
                    patched_lines.append(f"{indent}# Replace raw string concatenation with db.query(...) or parameterized binding")
                else:
                    patched_lines.append(f"{indent}# AegisAI Security Fix: Access authorization & input validation ({vuln.cwe_id or 'Security Fix'})")
                    patched_lines.append(f"{indent}if not current_user:")
                    patched_lines.append(f"{indent}    raise HTTPException(status_code=401, detail='Authentication required')")
                inserted = True
        if inserted:
            return original, "\n".join(patched_lines)

    # Standard template for Python
    clean_route = route_name if route_name.startswith("/") else f"/{route_name}"
    original = f"""@app.get("{clean_route}")
async def {func_name}({param_name}: int, current_user: dict = Depends(get_current_user)):
    # Vulnerable: Retrieves object without validating that caller owns it
    record = db.query(Resource).filter_by(id={param_name}).first()
    if not record:
        raise HTTPException(status_code=404, detail="Item not found")
    return record"""

    patched = f"""@app.get("{clean_route}")
async def {func_name}({param_name}: int, current_user: dict = Depends(get_current_user)):
    # AegisAI Security Fix: Verify caller ownership to prevent BOLA (CWE-639)
    if current_user.get("{param_name}") != {param_name} and current_user.get("role") != "admin":
        raise HTTPException(status_code=403, detail="Access forbidden: cross-tenant access denied")

    record = db.query(Resource).filter_by(id={param_name}).first()
    if not record:
        raise HTTPException(status_code=404, detail="Item not found")
    return record"""

    return original, patched



# ── Correlator ────────────────────────────────────────────────

class HybridCorrelator:
    """
    Correlates AI-detected vulnerabilities with AST source locations.

    Enriches each DetectedVulnerability with:
      - file_path       (from the AST match)
      - line_number     (from the AST match)
      - source_snippet  (from the AST match or direct file reading)
      - original_code   (raw vulnerable snippet from real repo)
      - patched_code    (AI-generated fix)
    """

    def correlate(
        self,
        vulnerabilities: list[DetectedVulnerability],
        ast_findings: list[ASTSchema],
        endpoint_findings: list[EndpointSchema],
        repo_root: Path | str | None = None,
    ) -> list[DetectedVulnerability]:
        """
        Enrich and return the correlated vulnerability list.
        """
        if not vulnerabilities:
            return []

        # Build comprehensive AST lookups:
        ast_by_norm_route: dict[str, list[ASTSchema]] = {}
        ast_by_raw_route: dict[str, list[ASTSchema]] = {}
        ast_by_file_line: dict[tuple[str, int], ASTSchema] = {}
        ast_by_file: dict[str, list[ASTSchema]] = {}

        def _clean_file(p: str | None) -> str:
            if not p:
                return ""
            return p.replace("\\", "/").strip("/").lower()

        for node in ast_findings:
            norm = _normalize_path(node.route_path)
            ast_by_norm_route.setdefault(norm, []).append(node)
            if node.route_path:
                ast_by_raw_route.setdefault(node.route_path.strip().lower(), []).append(node)

            if node.file_path:
                cf = _clean_file(node.file_path)
                if node.line_number:
                    ast_by_file_line[(cf, node.line_number)] = node
                ast_by_file.setdefault(cf, []).append(node)

        enriched: list[DetectedVulnerability] = []

        for vuln in vulnerabilities:
            matched_ast: ASTSchema | None = None
            vf_clean = _clean_file(vuln.file_path)

            # Step 1: Match by existing source file_path & line_number if already provided
            if vf_clean:
                if vuln.line_number and (vf_clean, vuln.line_number) in ast_by_file_line:
                    matched_ast = ast_by_file_line[(vf_clean, vuln.line_number)]
                elif vf_clean in ast_by_file:
                    file_nodes = ast_by_file[vf_clean]
                    # Try matching by route_path within the same file
                    vr_clean = (vuln.route_path or "").strip().lower()
                    if vr_clean:
                        for fn in file_nodes:
                            if fn.route_path and fn.route_path.strip().lower() == vr_clean:
                                matched_ast = fn
                                break
                    if matched_ast is None:
                        for fn in file_nodes:
                            if fn.route_path and fn.route_path in (vuln.title or ""):
                                matched_ast = fn
                                break
                    if matched_ast is None and vuln.line_number:
                        matched_ast = min(file_nodes, key=lambda fn: abs((fn.line_number or 0) - vuln.line_number))
                    elif matched_ast is None:
                        matched_ast = file_nodes[0]

            # Step 2: Try to find a matching endpoint URL from crawler data
            if matched_ast is None:
                endpoint_path: str | None = self._match_endpoint_path(
                    vuln, endpoint_findings
                )
                if endpoint_path:
                    norm_ep = _normalize_path(endpoint_path)
                    candidates = ast_by_norm_route.get(norm_ep, [])
                    if candidates:
                        matched_ast = candidates[0]
                    else:
                        matched_ast = self._fuzzy_match_ast(norm_ep, {k: v[0] for k, v in ast_by_norm_route.items() if v})

            # Step 3: Match AST node by route_path
            if matched_ast is None:
                vr = (vuln.route_path or "").strip().lower()
                if vr and vr in ast_by_raw_route:
                    matched_ast = ast_by_raw_route[vr][0]
                elif vr:
                    norm_vr = _normalize_path(vr)
                    if norm_vr in ast_by_norm_route:
                        matched_ast = ast_by_norm_route[norm_vr][0]

            # Step 4: Match AST node by route appearing in title or description
            if matched_ast is None:
                for node in ast_findings:
                    if node.route_path and len(node.route_path) > 1 and (
                        node.route_path in (vuln.title or "")
                        or node.route_path in (vuln.description or "")
                    ):
                        matched_ast = node
                        break

            # Step 5: Fallback to high-value backend AST node with parameters ONLY if vuln has no file_path
            if matched_ast is None and not vuln.file_path and ast_findings:
                param_nodes = [
                    n for n in ast_findings
                    if any(p in n.route_path.lower() for p in ("{", ":", "<", "account", "user", "transfer", "bank", "profile"))
                ]
                if param_nodes:
                    matched_ast = param_nodes[0]
                else:
                    matched_ast = ast_findings[0]

            # Read exact real code from cloned repo on disk if repo_root is available
            target_file = (matched_ast.file_path if matched_ast else vuln.file_path)
            target_line = (matched_ast.line_number if matched_ast else vuln.line_number) or 1
            if repo_root and target_file:
                try:
                    disk_file = Path(repo_root) / target_file
                    if disk_file.exists():
                        content = disk_file.read_text(encoding="utf-8", errors="replace")
                        file_lines = content.splitlines()
                        line_idx = max(0, target_line - 1)
                        start = max(0, line_idx - 1)
                        while start > 0 and file_lines[start - 1].strip().startswith("@"):
                            start -= 1

                        is_py = str(target_file).lower().endswith(".py")
                        if is_py:
                            end = min(len(file_lines), line_idx + 1)
                            base_indent = None
                            for k in range(line_idx, len(file_lines)):
                                l_text = file_lines[k]
                                stripped = l_text.strip()
                                if not stripped or stripped.startswith("#"):
                                    continue
                                indent_len = len(l_text) - len(l_text.lstrip())
                                if base_indent is None:
                                    base_indent = indent_len
                                elif indent_len <= base_indent and (stripped.startswith("def ") or stripped.startswith("async def ") or stripped.startswith("@router") or stripped.startswith("@app")):
                                    end = k
                                    break
                                end = k + 1
                                if end - start > 60:
                                    break
                        else:
                            # Non-Python (JS, TS, Java, Go):
                            # First check if this statement starts a block with '{' within the first 3 lines
                            has_brace = False
                            for k in range(line_idx, min(len(file_lines), line_idx + 3)):
                                if "{" in file_lines[k]:
                                    has_brace = True
                                    break

                            if has_brace:
                                end = min(len(file_lines), line_idx + 30)
                                brace_count = 0
                                found_brace = False
                                for k in range(line_idx, min(len(file_lines), line_idx + 45)):
                                    brace_count += file_lines[k].count("{") - file_lines[k].count("}")
                                    if "{" in file_lines[k]:
                                        found_brace = True
                                    if found_brace and brace_count <= 0:
                                        end = k + 1
                                        break
                            else:
                                # Single-line statement or route registration without braces (e.g. app.get(..., handler);)
                                end = min(len(file_lines), line_idx + 1)
                                for k in range(line_idx, min(len(file_lines), line_idx + 5)):
                                    if ";" in file_lines[k] or file_lines[k].strip().endswith(");"):
                                        end = k + 1
                                        break

                        real_snippet = "\n".join(file_lines[start:end])
                        if real_snippet.strip():
                            if matched_ast:
                                matched_ast = matched_ast.model_copy(update={
                                    "source_snippet": real_snippet
                                })
                            vuln = vuln.model_copy(update={"original_code": real_snippet})
                except Exception as read_exc:
                    logger.debug("correlator.disk_read_error", error=str(read_exc))

            # Prioritize AI model-generated patch if available, else invoke Ollama fine-tuned model
            original_code = vuln.original_code or (matched_ast.source_snippet if matched_ast else "")
            patched_code = vuln.patched_code

            orig_lines = [l.strip() for l in (original_code or "").splitlines() if l.strip()]
            patch_lines = [l.strip() for l in (patched_code or "").splitlines() if l.strip()]
            shared_lines = set(orig_lines).intersection(set(patch_lines))
            is_unaligned = bool(orig_lines and len(orig_lines) >= 3 and len(shared_lines) < 2)

            needs_patch = (
                not patched_code
                or len(patched_code.strip().splitlines()) < 2
                or (original_code and patched_code.strip() == original_code.strip())
                or is_unaligned
            )

            if needs_patch:
                ai_patch = _generate_ai_patch(vuln, matched_ast)
                if ai_patch and ai_patch[0].strip() != ai_patch[1].strip():
                    original_code, patched_code = ai_patch
                else:
                    original_code, patched_code = _generate_patch(vuln, matched_ast)

            # Ensure patched_code preserves surrounding code so only changeable lines are highlighted
            if original_code and patched_code:
                orig_l = [l.strip() for l in original_code.splitlines() if l.strip()]
                patch_l = [l.strip() for l in patched_code.splitlines() if l.strip()]
                if len(orig_l) >= 3 and len(set(orig_l).intersection(set(patch_l))) < 2:
                    patched_code = _inject_aligned_security_patch(original_code, patched_code, vuln.cwe_id or "")

            remediation_text = vuln.remediation or self._default_remediation(vuln)
            final_file = matched_ast.file_path if matched_ast and (not vuln.file_path or vuln.file_path == "unknown") else vuln.file_path
            final_line = matched_ast.line_number if matched_ast and not vuln.line_number else vuln.line_number
            if final_file and final_line:
                remediation_text = (
                    f"{remediation_text}\n\n"
                    f"📁 Source: {final_file}:{final_line}"
                    + (f" ({matched_ast.function_name})" if matched_ast and matched_ast.function_name else "")
                ).strip()

            # Enrich the vulnerability model with real AST & patch fields
            enriched_vuln = vuln.model_copy(update={
                "remediation": remediation_text,
                "original_code": original_code,
                "patched_code": patched_code,
                "file_path": final_file,
                "line_number": final_line,
            })

            if matched_ast:
                logger.debug(
                    "correlator.matched",
                    vuln_title=vuln.title,
                    file=matched_ast.file_path,
                    line=matched_ast.line_number,
                )
            else:
                logger.debug("correlator.no_match", vuln_title=vuln.title)

            enriched.append(enriched_vuln)

        logger.info(
            "correlator.complete",
            input_vulns=len(vulnerabilities),
            enriched=len(enriched),
            matched=sum(1 for v in enriched if "?? Source" in (v.remediation or "")),
        )

        return enriched

    @staticmethod
    def _match_endpoint_path(
        vuln: DetectedVulnerability,
        endpoints: list[EndpointSchema],
    ) -> str | None:
        """
        Try to infer the vulnerable endpoint URL path from the vulnerability.
        Checks exploit_payload and description for URL patterns.
        """
        url_re = re.compile(r"(/api/[^\s\"']+|/[a-z][a-z0-9/_:-]{2,})", re.IGNORECASE)

        # Search title, exploit_payload, and description
        for text in [vuln.title or "", vuln.exploit_payload or "", vuln.description or ""]:
            m = url_re.search(text)
            if m:
                return m.group(1)

        # If only one endpoint exists, use it as best guess
        if len(endpoints) == 1:
            return _extract_url_path(endpoints[0].url)

        return None

    @staticmethod
    def _fuzzy_match_ast(
        normalised_ep: str,
        ast_lookup: dict[str, ASTSchema],
    ) -> ASTSchema | None:
        """
        Fuzzy path matching: find the AST route with the most matching segments.
        Handles optional /api prefixes and parameter wildcards.
        """
        ep_clean = normalised_ep.strip("/")
        if ep_clean in ast_lookup:
            return ast_lookup[ep_clean]

        ep_parts = ep_clean.split("/")
        ep_no_api = "/".join(ep_parts[1:]) if ep_parts and ep_parts[0] == "api" else None

        best_node: ASTSchema | None = None
        best_score = 0

        for norm_route, node in ast_lookup.items():
            route_clean = norm_route.strip("/")
            route_parts = route_clean.split("/")

            # Direct stripped matches
            if ep_no_api and ep_no_api == route_clean:
                return node
            if route_parts and route_parts[0] == "api" and "/".join(route_parts[1:]) == ep_clean:
                return node

            # Match segments
            score = sum(
                1
                for a, b in zip(ep_parts, route_parts)
                if a == b or a == "[^/]+" or b == "[^/]+"
            )
            if score > best_score:
                best_score = score
                best_node = node

        return best_node if best_score > 0 else None

    @staticmethod
    def _default_remediation(vuln: DetectedVulnerability) -> str:
        """Return comprehensive, multi-step engineering remediation steps based on CWE/OWASP."""
        remediations = {
            "CWE-639": (
                "### 1. Identity & Session Binding\n"
                "- Extract the caller identity strictly from verified server-side session cookies or cryptographic JWT claims (`current_user.id`).\n"
                "- Never trust or permit client-supplied user or tenant IDs in URL query parameters, path variables, or request bodies.\n\n"
                "### 2. Dual-Layer Object Ownership Verification\n"
                "- Query the database using compound filters that restrict results to the caller's tenancy: `.filter_by(id=target_id, owner_id=current_user.id)`.\n"
                "- If the record exists but belongs to another tenant/user, return HTTP 403 Forbidden (or HTTP 404 to prevent resource existence enumeration).\n\n"
                "### 3. Declarative Dependency Guards\n"
                "- Encapsulate access rules into reusable FastAPI security dependencies (e.g., `Depends(verify_resource_ownership)`).\n"
                "- Decouple endpoint business logic from access-control verification to ensure uniform enforcement across all CRUD operations.\n\n"
                "### 4. Non-Enumerable Identifiers & Defense-in-Depth\n"
                "- Replace sequential auto-increment integer IDs with cryptographically secure UUIDv4 or KSUIDs to eliminate automated scanning.\n"
                "- Log all unauthorized access attempts (HTTP 403) with user context, client IP, and resource identifiers to trigger SIEM security alerts."
            ),
            "CWE-89": (
                "### 1. Enforce Parameterised Statements\n"
                "- Use ORM methods (e.g. SQLAlchemy `.filter()`) or parameterized queries with bound parameters (`:param`).\n"
                "- Never concatenate raw user input or format strings directly into SQL queries.\n\n"
                "### 2. Strict Input Validation\n"
                "- Enforce Pydantic schema validation for all query params and payload fields before database execution.\n\n"
                "### 3. Principle of Least Privilege\n"
                "- Restrict database service accounts to only required table permissions; disallow DDL execution from web application roles."
            ),
            "CWE-79": (
                "### 1. Context-Aware Output Encoding\n"
                "- Ensure all dynamic data is HTML/URL/attribute-encoded before being reflected into DOM contexts.\n"
                "- Use modern UI frameworks (e.g. React/Next.js) that automatically escape variables by default.\n\n"
                "### 2. Implement Strict Content Security Policy (CSP)\n"
                "- Deploy headers: `Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none';`.\n"
                "- Disallow inline scripts (`'unsafe-inline'`) and dynamic code evaluation (`eval`)."
            ),
            "CWE-284": (
                "### 1. Centralised Role-Based & Attribute-Based Access Control (RBAC/ABAC)\n"
                "- Define explicit permission policies for every API route using declarative route guards.\n"
                "- Deny access by default; explicitly grant permissions based on authenticated user roles and tenant claims.\n\n"
                "### 2. Tenant Isolation at Data Layer\n"
                "- Enforce row-level security (RLS) or dedicated tenant schema isolation to prevent cross-tenant data leaks."
            ),
        }
        if vuln.cwe_id and vuln.cwe_id in remediations:
            return remediations[vuln.cwe_id]
        if vuln.owasp_category and "API1" in vuln.owasp_category:
            return remediations["CWE-639"]
        return (
            "### 1. Access Control Enforcement\n"
            "- Validate user authorization and tenancy context prior to processing requests on this endpoint.\n\n"
            "### 2. Defensive Data Handling\n"
            "- Apply strict Pydantic input validation, parameterised queries, and sanitize output responses.\n\n"
            "### 3. Continuous Audit & Testing\n"
            "- Add automated integration tests verifying that unauthorized sessions receive HTTP 403 Forbidden."
        )
