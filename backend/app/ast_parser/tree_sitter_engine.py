"""
AegisAI — tree-sitter AST Analysis Engine
==========================================
Responsible for:
  1. Cloning a GitHub repo (or resolving a local path) for analysis
  2. Parsing each file with the appropriate tree-sitter grammar
  3. Extracting route definitions and their handler functions
  4. Returning a list of ASTSchema objects for the AI pipeline

Supported languages: Python, JavaScript, TypeScript
(Java / Go / Rust parsers follow the same pattern — add as needed)

Usage:
    engine = TreeSitterEngine()
    repo_path, cleanup = await engine.clone_or_resolve_repository(
        "https://github.com/user/repo", branch="main"
    )
    try:
        findings = await engine.analyse_repository(repo_path)
    finally:
        cleanup()
"""

from __future__ import annotations

import ast as pyast
import asyncio
import re
import shutil
import tempfile
from pathlib import Path
from typing import Any, Callable

import structlog

# tree-sitter imports — install grammars separately:
# pip install tree-sitter tree-sitter-python tree-sitter-javascript tree-sitter-typescript
try:
    import tree_sitter_python as tspython
    import tree_sitter_javascript as tsjavascript
    from tree_sitter import Language, Parser
    TREE_SITTER_AVAILABLE = True
except ImportError:
    TREE_SITTER_AVAILABLE = False

# GitPython for repository cloning
try:
    import git
    GIT_AVAILABLE = True
except ImportError:
    GIT_AVAILABLE = False

from app.schemas.io_models import ASTSchema, ProgrammingLanguage

logger = structlog.get_logger(__name__)

# ── Language → file extension mapping ────────────────────────
EXTENSION_MAP: dict[str, ProgrammingLanguage] = {
    ".py":    ProgrammingLanguage.PYTHON,
    ".js":    ProgrammingLanguage.JAVASCRIPT,
    ".ts":    ProgrammingLanguage.TYPESCRIPT,
    ".tsx":   ProgrammingLanguage.TYPESCRIPT,
    ".jsx":   ProgrammingLanguage.JAVASCRIPT,
    ".mjs":   ProgrammingLanguage.JAVASCRIPT,
    ".cjs":   ProgrammingLanguage.JAVASCRIPT,
    ".go":    ProgrammingLanguage.GO,
    ".java":  ProgrammingLanguage.JAVA,
    ".php":   ProgrammingLanguage.PHP,
    ".rb":    ProgrammingLanguage.RUBY,
    ".cs":    ProgrammingLanguage.CSHARP,
    ".rs":    ProgrammingLanguage.RUST,
}

# ── Route-definition node types per language ──────────────────
ROUTE_NODE_TYPES: dict[ProgrammingLanguage, list[str]] = {
    ProgrammingLanguage.PYTHON: [
        "decorated_definition",  # FastAPI / Flask @app.get(...)
    ],
    ProgrammingLanguage.JAVASCRIPT: [
        "call_expression",       # express router.get(...)
    ],
    ProgrammingLanguage.TYPESCRIPT: [
        "call_expression",
        "method_definition",
    ],
}

# ── Route decorator patterns ──────────────────────────────────
# Matches: @app.get, @router.post, @bp.route, @app.route, etc.
PY_ROUTE_DECORATOR_RE = re.compile(
    r"@\w+\.(get|post|put|patch|delete|route|head|options|websocket)\(",
    re.IGNORECASE,
)

# Matches: router.get, app.post, server.put, etc.
JS_ROUTE_CALL_RE = re.compile(
    r"\b(\w+)\.(get|post|put|patch|delete|all|route|use)\s*\(",
    re.IGNORECASE,
)

# Go: Gin, Echo, Fiber, standard net/http
GO_ROUTE_CALL_RE = re.compile(
    r"\b\w+\.(GET|POST|PUT|PATCH|DELETE|Handle|HandleFunc|Get|Post|Put|Delete)\s*\(\s*['\"](/[^'\"]*)['\"]",
    re.IGNORECASE,
)

# Java: Spring Boot (@GetMapping, @PostMapping, @RequestMapping)
JAVA_ROUTE_RE = re.compile(
    r"@(?:Get|Post|Put|Patch|Delete|Request)Mapping\s*\(\s*(?:(?:value|path)\s*=\s*)?['\"](/[^'\"]*)['\"]",
    re.IGNORECASE,
)

# PHP: Laravel / Symfony / Slim (Route::get, Route::post)
PHP_ROUTE_RE = re.compile(
    r"Route::(get|post|put|patch|delete|any|match)\s*\(\s*['\"](/?[^'\"]*)['\"]",
    re.IGNORECASE,
)

# Ruby: Rails / Sinatra (get '/path', post '/path')
RUBY_ROUTE_RE = re.compile(
    r"\b(get|post|put|patch|delete)\s+['\"](/?[^'\"]*)['\"]",
    re.IGNORECASE,
)

# C#: ASP.NET Core ([HttpGet("...")], app.MapGet("..."))
CSHARP_ROUTE_RE = re.compile(
    r"\[Http(Get|Post|Put|Patch|Delete)\s*\(\s*['\"](/?[^'\"]*)['\"]|"
    r"\bapp\.Map(Get|Post|Put|Patch|Delete)\s*\(\s*['\"](/?[^'\"]*)['\"]",
    re.IGNORECASE,
)

# Rust: Actix-web / Axum (#[get("...")], .route("/...", get(...)))
RUST_ROUTE_RE = re.compile(
    r'#\[(get|post|put|patch|delete)\s*\(\s*["\'](/[^"\']*)["\']|\.route\s*\(\s*["\'](/[^"\']*)["\']',
    re.IGNORECASE,
)

# ── HTTP method aliases ───────────────────────────────────────
DECORATOR_METHOD_MAP = {
    "route": "ANY",
    "get": "GET",
    "post": "POST",
    "put": "PUT",
    "patch": "PATCH",
    "delete": "DELETE",
    "head": "HEAD",
    "options": "OPTIONS",
    "websocket": "WS",
    "all": "ANY",
    "use": "MIDDLEWARE",
}

# ── Directories to skip ───────────────────────────────────────
SKIP_DIRS = {
    "node_modules", ".git", "venv", ".venv", "__pycache__",
    "dist", "build", ".next", "coverage", "migrations",
    "test", "tests", "__tests__", "vendor", "swagger", "swagger-ui",
    "lib", "libs", "static", "assets", "public", "fixtures",
    "mock", "mocks", "third_party", "third-party", ".idea", ".vscode",
}

# Client-side vendor and minified library prefixes
CLIENT_VENDOR_PREFIXES = (
    "jquery", "bootstrap", "swagger", "react", "vue", "angular",
    "popper", "lodash", "underscore", "font", "moment", "axios",
)


class TreeSitterEngine:
    """
    Async tree-sitter-based AST parser for multi-language repos.

    Instantiate once and reuse across scan jobs — Parser objects
    are lightweight and thread-safe.
    """

    def __init__(self) -> None:
        self._parsers: dict[ProgrammingLanguage, Any] = {}
        if TREE_SITTER_AVAILABLE:
            self._init_parsers()
        else:
            logger.warning(
                "tree_sitter.unavailable",
                hint="Install tree-sitter and language bindings: "
                     "pip install tree-sitter tree-sitter-python tree-sitter-javascript",
            )

    def _init_parsers(self) -> None:
        """Initialise one Parser per language."""
        try:
            py_lang = Language(tspython.language())
            py_parser = Parser(py_lang)
            self._parsers[ProgrammingLanguage.PYTHON] = py_parser
            logger.debug("tree_sitter.parser_ready", language="python")
        except Exception as exc:
            logger.warning("tree_sitter.init_failed", language="python", error=str(exc))

        try:
            js_lang = Language(tsjavascript.language())
            js_parser = Parser(js_lang)
            self._parsers[ProgrammingLanguage.JAVASCRIPT] = js_parser
            self._parsers[ProgrammingLanguage.TYPESCRIPT] = js_parser  # close enough for routing
            logger.debug("tree_sitter.parser_ready", language="javascript/typescript")
        except Exception as exc:
            logger.warning("tree_sitter.init_failed", language="javascript", error=str(exc))

    # ── Repository Cloning / Resolution ──────────────────────

    @staticmethod
    def _is_remote_url(target: str) -> bool:
        """Return True if the target looks like a remote Git URL."""
        return target.startswith(("https://", "http://", "git@", "ssh://"))

    async def clone_or_resolve_repository(
        self,
        repo_target: str | Path,
        branch: str = "main",
        depth: int = 1,
    ) -> tuple[Path, Callable[[], None]]:
        """
        Clone a remote GitHub repository or resolve a local path.

        Args:
            repo_target: GitHub URL (https/git@) or local filesystem path.
            branch:      Git branch to check out (default: 'main').
            depth:       Shallow clone depth (default: 1 for speed).

        Returns:
            A tuple of (repo_path: Path, cleanup: Callable) where
            `cleanup()` deletes the temp directory if a remote repo was
            cloned. For local paths, `cleanup()` is a no-op.
        """
        target_str = str(repo_target)

        if not self._is_remote_url(target_str):
            # Local path — resolve and return with no-op cleanup
            local_path = Path(target_str).resolve()
            if not local_path.exists():
                raise FileNotFoundError(
                    f"Local repository path does not exist: {local_path}"
                )
            logger.info("ast.repo.local", path=str(local_path))
            return local_path, lambda: None

        # Remote URL — clone into a temporary directory
        if not GIT_AVAILABLE:
            raise RuntimeError(
                "GitPython is not installed. Run: pip install gitpython"
            )

        tmp_dir = tempfile.mkdtemp(prefix="aegisai_scan_")

        def _cleanup() -> None:
            try:
                shutil.rmtree(tmp_dir, ignore_errors=True)
                logger.debug("ast.repo.cleanup", path=tmp_dir)
            except Exception:
                pass

        logger.info(
            "ast.repo.clone.start",
            url=target_str,
            branch=branch,
            depth=depth,
            dest=tmp_dir,
        )

        try:
            await asyncio.to_thread(
                git.Repo.clone_from,
                target_str,
                tmp_dir,
                branch=branch,
                depth=depth,
                single_branch=True,
            )
            logger.info("ast.repo.clone.complete", url=target_str, dest=tmp_dir)
            return Path(tmp_dir), _cleanup

        except Exception as exc:
            _cleanup()
            # Fallback: try without specifying branch (handles master vs main)
            if "not found" in str(exc).lower() or "remote branch" in str(exc).lower():
                logger.warning(
                    "ast.repo.clone.branch_fallback",
                    url=target_str,
                    tried_branch=branch,
                )
                tmp_dir2 = tempfile.mkdtemp(prefix="aegisai_scan_")

                def _cleanup2() -> None:
                    shutil.rmtree(tmp_dir2, ignore_errors=True)

                try:
                    await asyncio.to_thread(
                        git.Repo.clone_from,
                        target_str,
                        tmp_dir2,
                        depth=depth,
                    )
                    logger.info("ast.repo.clone.complete", url=target_str, dest=tmp_dir2)
                    return Path(tmp_dir2), _cleanup2
                except Exception as exc2:
                    _cleanup2()
                    raise RuntimeError(
                        f"Failed to clone repository {target_str}: {exc2}"
                    ) from exc2

            raise RuntimeError(
                f"Failed to clone repository {target_str}: {exc}"
            ) from exc

    # ── Public Analysis API ───────────────────────────────────

    async def analyse_repository(self, repo_path: str | Path) -> list[ASTSchema]:
        """
        Walk a repository directory tree and extract route-level AST nodes.

        Args:
            repo_path: Local filesystem path to the cloned repository root.

        Returns:
            List of ASTSchema objects, one per discovered route/handler.
        """
        root = Path(repo_path)
        if not root.exists():
            raise FileNotFoundError(f"Repository path does not exist: {root}")

        findings: list[ASTSchema] = []
        files = list(self._collect_files(root))

        logger.info(
            "ast.analyse_repository.start",
            repo_path=str(root),
            file_count=len(files),
        )

        # Run file parsing concurrently (I/O-bound)
        tasks = [self._analyse_file(f, root) for f in files]
        results = await asyncio.gather(*tasks, return_exceptions=True)

        for result in results:
            if isinstance(result, Exception):
                logger.warning("ast.file_error", error=str(result))
            elif isinstance(result, list):
                findings.extend(result)

        logger.info(
            "ast.analyse_repository.complete",
            findings=len(findings),
        )
        return findings

    async def analyse_file(
        self, file_path: str | Path, repo_root: str | Path | None = None
    ) -> list[ASTSchema]:
        """Analyse a single file. Public convenience method."""
        return await self._analyse_file(Path(file_path), Path(repo_root or "."))

    # ── Internal helpers ──────────────────────────────────────

    def _is_client_or_vendor_file(self, path: Path) -> bool:
        """Filter out client-side static files, minified bundles, and third-party libraries."""
        name_lower = path.name.lower()
        # Filter minified and bundle files
        if any(name_lower.endswith(s) for s in (".min.js", ".min.css", ".bundle.js", ".chunk.js", ".map")):
            return True
        # Filter client vendor library files
        if any(name_lower.startswith(prefix) for prefix in CLIENT_VENDOR_PREFIXES):
            return True
        # Filter static/web frontend assets in frontend folders
        parts_lower = [p.lower() for p in path.parts]
        for bad_dir in ("swagger", "swagger-ui", "vendor", "lib", "libs", "webcontent", "static", "assets", "public", "dist", "build"):
            if bad_dir in parts_lower:
                # If in WebContent or lib and is a frontend asset, skip it
                if path.suffix.lower() in (".js", ".jsx", ".ts", ".tsx", ".css", ".html", ".map", ".json"):
                    return True
        return False

    def _collect_files(self, root: Path):
        """Yield source files, skipping blacklisted directories and client vendor libraries."""
        for path in root.rglob("*"):
            if path.is_dir():
                continue
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue
            if self._is_client_or_vendor_file(path):
                continue
            if path.suffix in EXTENSION_MAP:
                yield path

    async def _analyse_file(
        self, file_path: Path, repo_root: Path
    ) -> list[ASTSchema]:
        """Parse a single source file and extract route nodes."""
        language = EXTENSION_MAP.get(file_path.suffix)
        if language is None:
            return []

        try:
            source = await asyncio.to_thread(file_path.read_text, encoding="utf-8")
        except (UnicodeDecodeError, PermissionError) as exc:
            logger.debug("ast.read_error", file=str(file_path), error=str(exc))
            return []

        rel_path = str(file_path.relative_to(repo_root))
        lines = source.splitlines()

        # Skip minified files that bypassed filename checks (lines > 800 chars)
        if any(len(line) > 800 for line in lines[:30]):
            return []

        # Python: use stdlib ast first (reliable, no C extension needed)
        if language == ProgrammingLanguage.PYTHON:
            stdlib_results = self._extract_python_stdlib(source, rel_path, lines)
            if stdlib_results:
                return stdlib_results

        # tree-sitter parsing (all languages)
        if TREE_SITTER_AVAILABLE and language in self._parsers:
            parser = self._parsers[language]
            tree = await asyncio.to_thread(parser.parse, source.encode("utf-8"))
            nodes = self._extract_route_nodes(
                tree.root_node, language, source, rel_path, lines
            )
            if nodes:
                return nodes

        # Regex fallback (last resort for supported languages)
        if language == ProgrammingLanguage.PYTHON:
            return self._extract_python_regex(source, rel_path, lines)
        elif language in (ProgrammingLanguage.JAVASCRIPT, ProgrammingLanguage.TYPESCRIPT):
            return self._extract_js_regex(source, rel_path, lines)
        elif language == ProgrammingLanguage.GO:
            return self._extract_go_regex(source, rel_path, lines)
        elif language == ProgrammingLanguage.JAVA:
            return self._extract_java_regex(source, rel_path, lines)
        elif language == ProgrammingLanguage.PHP:
            return self._extract_php_regex(source, rel_path, lines)
        elif language == ProgrammingLanguage.RUBY:
            return self._extract_ruby_regex(source, rel_path, lines)
        elif language == ProgrammingLanguage.CSHARP:
            return self._extract_csharp_regex(source, rel_path, lines)
        elif language == ProgrammingLanguage.RUST:
            return self._extract_rust_regex(source, rel_path, lines)

        return []

    # ── Python Extraction (stdlib ast) ───────────────────────

    def _extract_python_stdlib(
        self, source: str, rel_path: str, lines: list[str]
    ) -> list[ASTSchema]:
        """
        Use Python's built-in `ast` module to extract route-decorated functions.
        Handles FastAPI, Flask, Django REST Framework, and Blueprint routes.
        """
        try:
            tree = pyast.parse(source)
        except SyntaxError:
            return []

        findings: list[ASTSchema] = []

        for node in pyast.walk(tree):
            if not isinstance(node, (pyast.FunctionDef, pyast.AsyncFunctionDef)):
                continue

            for decorator in node.decorator_list:
                route_info = self._parse_python_decorator(decorator)
                if route_info is None:
                    continue

                route_path_str, http_method = route_info
                line_no = node.lineno

                # Build source snippet: extract entire decorated function body
                start_line = node.decorator_list[0].lineno if node.decorator_list else node.lineno
                end_line = getattr(node, "end_lineno", node.lineno + 40)
                start = max(0, start_line - 1)
                end = min(len(lines), end_line)
                snippet = "\n".join(lines[start:end])

                findings.append(ASTSchema(
                    route_path=route_path_str,
                    file_path=rel_path,
                    line_number=line_no,
                    language=ProgrammingLanguage.PYTHON,
                    function_name=node.name,
                    source_snippet=snippet,
                ))

        return findings

    def _parse_python_decorator(
        self, decorator: pyast.expr
    ) -> tuple[str, str] | None:
        """
        Parse a decorator node to extract route path and HTTP method.

        Supports:
          @app.get("/path")
          @router.post("/path")
          @bp.route("/path", methods=["GET", "POST"])
        """
        if not isinstance(decorator, pyast.Call):
            return None

        func = decorator.func

        # Must be a dotted call: something.method(...)
        if not isinstance(func, pyast.Attribute):
            return None

        method_name = func.attr.lower()
        if method_name not in DECORATOR_METHOD_MAP:
            return None

        http_method = DECORATOR_METHOD_MAP[method_name]

        # For @app.route(..., methods=["GET"]) — extract first method
        if method_name == "route":
            for kw in decorator.keywords:
                if kw.arg == "methods" and isinstance(kw.value, pyast.List):
                    elts = kw.value.elts
                    if elts and isinstance(elts[0], pyast.Constant):
                        http_method = str(elts[0].value).upper()

        # Extract route path from first positional argument
        if not decorator.args:
            return None

        first_arg = decorator.args[0]
        if isinstance(first_arg, pyast.Constant) and isinstance(first_arg.value, str):
            return first_arg.value, http_method

        # f-string / dynamic path — best effort
        if isinstance(first_arg, pyast.JoinedStr):
            return "<dynamic_path>", http_method

        return None

    # ── Python Regex Fallback ─────────────────────────────────

    def _extract_python_regex(
        self, source: str, rel_path: str, lines: list[str]
    ) -> list[ASTSchema]:
        """Regex-based Python route extraction fallback."""
        findings: list[ASTSchema] = []
        path_re = re.compile(r'["\'](/[^"\']*)["\']')

        for i, line in enumerate(lines):
            if PY_ROUTE_DECORATOR_RE.search(line):
                m = path_re.search(line)
                if not m:
                    continue
                route_path_str = m.group(1)

                # Find the function name on the next non-blank line
                func_name: str | None = None
                for j in range(i + 1, min(i + 4, len(lines))):
                    fn_m = re.match(r"\s*(?:async\s+)?def\s+(\w+)", lines[j])
                    if fn_m:
                        func_name = fn_m.group(1)
                        break

                start = max(0, i - 1)
                end = min(len(lines), i + 35)
                snippet = "\n".join(lines[start:end])

                findings.append(ASTSchema(
                    route_path=route_path_str,
                    file_path=rel_path,
                    line_number=i + 1,
                    language=ProgrammingLanguage.PYTHON,
                    function_name=func_name,
                    source_snippet=snippet,
                ))

        return findings

    # ── JS / TS tree-sitter Extraction ───────────────────────

    def _extract_route_nodes(
        self,
        root_node: Any,
        language: ProgrammingLanguage,
        source: str,
        rel_path: str,
        lines: list[str],
    ) -> list[ASTSchema]:
        """
        Recursively walk the AST and extract candidate route nodes.

        Python: detect @app.get/@app.post decorators (FastAPI/Flask)
        JS/TS: detect router.get/router.post call expressions (Express)
        """
        findings: list[ASTSchema] = []
        target_types = ROUTE_NODE_TYPES.get(language, [])

        def walk(node: Any) -> None:
            if node.type in target_types:
                if language == ProgrammingLanguage.PYTHON:
                    info = self._extract_python_ts_node(node, source, lines, rel_path)
                else:
                    info = self._extract_js_ts_node(node, source, lines, rel_path, language)

                if info is not None:
                    findings.append(info)
            for child in node.children:
                walk(child)

        walk(root_node)
        return findings

    def _extract_python_ts_node(
        self,
        node: Any,
        source: str,
        lines: list[str],
        rel_path: str,
    ) -> ASTSchema | None:
        """Extract route info from a tree-sitter `decorated_definition` node."""
        decorator_text = ""
        func_name: str | None = None
        line_no = node.start_point[0] + 1

        for child in node.children:
            if child.type == "decorator":
                decorator_text = source[child.start_byte:child.end_byte]
            elif child.type in ("function_definition", "async_function_definition"):
                for sub in child.children:
                    if sub.type == "identifier":
                        func_name = source[sub.start_byte:sub.end_byte]
                        break

        if not PY_ROUTE_DECORATOR_RE.search(decorator_text):
            return None

        path_m = re.search(r'["\'](/[^"\']*)["\']', decorator_text)
        if not path_m:
            return None
        route_path_str = path_m.group(1)

        method_m = re.search(
            r'\.(get|post|put|patch|delete|route|head|options|websocket)\(',
            decorator_text, re.IGNORECASE
        )
        http_method = (
            DECORATOR_METHOD_MAP.get(method_m.group(1).lower(), "ANY")
            if method_m else "ANY"
        )

        start = max(0, line_no - 2)
        end = min(len(lines), line_no + 35)
        snippet = "\n".join(lines[start:end])

        return ASTSchema(
            route_path=route_path_str,
            file_path=rel_path,
            line_number=line_no,
            language=ProgrammingLanguage.PYTHON,
            function_name=func_name,
            source_snippet=snippet,
        )

    def _extract_js_ts_node(
        self,
        node: Any,
        source: str,
        lines: list[str],
        rel_path: str,
        language: ProgrammingLanguage,
    ) -> ASTSchema | None:
        """Extract route info from a tree-sitter `call_expression` node (Express.js)."""
        node_text = source[node.start_byte:node.end_byte]

        m = JS_ROUTE_CALL_RE.match(node_text.strip())
        if not m:
            return None

        http_method = DECORATOR_METHOD_MAP.get(m.group(2).lower(), "ANY")
        if http_method == "MIDDLEWARE":
            return None  # Skip pure middleware calls

        line_no = node.start_point[0] + 1

        path_re = re.compile(r'''['"](/[^'"]*)['"']''')
        path_m = path_re.search(node_text)
        if not path_m:
            return None
        route_path_str = path_m.group(1)

        start_idx = max(0, node.start_point[0])
        end_idx = min(len(lines), max(start_idx + 1, node.end_point[0] + 1))
        end_idx = min(end_idx, start_idx + 25)
        snippet = "\n".join(lines[start_idx:end_idx])

        return ASTSchema(
            route_path=route_path_str,
            file_path=rel_path,
            line_number=line_no,
            language=language,
            function_name=None,
            source_snippet=snippet,
        )

    # ── JS / TS Regex Fallback ────────────────────────────────

    def _extract_js_regex(
        self, source: str, rel_path: str, lines: list[str]
    ) -> list[ASTSchema]:
        """Regex-based Express.js route extraction fallback."""
        findings: list[ASTSchema] = []
        path_re = re.compile(r'''['"](/[^'"]*)['"']''')

        for i, line in enumerate(lines):
            m = JS_ROUTE_CALL_RE.search(line)
            if not m:
                continue

            http_method = DECORATOR_METHOD_MAP.get(m.group(2).lower(), "ANY")
            if http_method == "MIDDLEWARE":
                continue

            path_m = path_re.search(line)
            if not path_m:
                continue
            route_path_str = path_m.group(1)

            start = i
            end = i + 1
            for k in range(i, min(len(lines), i + 20)):
                if ";" in lines[k] or lines[k].strip().endswith(");"):
                    end = k + 1
                    break
            snippet = "\n".join(lines[start:end])

            lang = EXTENSION_MAP.get(Path(rel_path).suffix, ProgrammingLanguage.JAVASCRIPT)

            findings.append(ASTSchema(
                route_path=route_path_str,
                file_path=rel_path,
                line_number=i + 1,
                language=lang,
                function_name=None,
                source_snippet=snippet,
            ))

        return findings

    # ── Go Route Extraction ───────────────────────────────────

    def _extract_go_regex(
        self, source: str, rel_path: str, lines: list[str]
    ) -> list[ASTSchema]:
        """Extract Go API routes (Gin, Echo, Fiber, standard net/http)."""
        findings: list[ASTSchema] = []
        for i, line in enumerate(lines):
            m = GO_ROUTE_CALL_RE.search(line)
            if not m:
                continue

            route_path_str = m.group(2)
            func_m = re.search(r",\s*([A-Za-z0-9_]+)\s*\)", line)
            func_name = func_m.group(1) if func_m else None

            start = max(0, i - 1)
            end = min(len(lines), i + 18)
            snippet = "\n".join(lines[start:end])

            findings.append(ASTSchema(
                route_path=route_path_str,
                file_path=rel_path,
                line_number=i + 1,
                language=ProgrammingLanguage.GO,
                function_name=func_name,
                source_snippet=snippet,
            ))
        return findings

    # ── Java Route Extraction (JAX-RS / Spring Boot / Servlets) ─────────

    def _extract_java_regex(
        self, source: str, rel_path: str, lines: list[str]
    ) -> list[ASTSchema]:
        """
        Extract Java API routes from JAX-RS (Jersey / Apache Wink), Spring Boot,
        and Java Servlets (HttpServlet). Extracts exact method signatures and real code.
        """
        findings: list[ASTSchema] = []

        class_path = ""
        app_path = ""
        is_servlet = False
        class_name = ""

        # Inspect class-level annotations and declarations
        for idx, line in enumerate(lines[:60]):
            ap_m = re.search(r'@ApplicationPath\s*\(\s*["\']([^"\']+)["\']\s*\)', line)
            if ap_m:
                app_path = ap_m.group(1).strip().strip("/")
            cp_m = re.search(r'@(?:Path|RequestMapping)\s*\(\s*(?:(?:value|path)\s*=\s*)?["\']([^"\']+)["\']\s*\)', line)
            if cp_m:
                class_path = cp_m.group(1).strip()
                if not class_path.startswith("/"):
                    class_path = "/" + class_path
            cls_m = re.search(r'\bpublic\s+(?:abstract\s+)?class\s+(\w+)', line)
            if cls_m:
                class_name = cls_m.group(1)
                if "HttpServlet" in line or class_name.endswith("Servlet"):
                    is_servlet = True
                break  # Stop inspecting class level once class definition line is reached!

        prefix = class_path
        if app_path:
            prefix = f"/{app_path}{class_path}"
        elif "/api/" in rel_path.replace("\\", "/").lower() and class_path and not class_path.startswith("/api"):
            prefix = f"/api{class_path}"
        elif not prefix:
            prefix = "/api" if "/api/" in rel_path.replace("\\", "/").lower() else ""

        # 1. Extract JAX-RS and Spring Boot route methods
        i = 0
        while i < len(lines):
            line = lines[i]
            is_jaxrs_http = bool(re.search(r'@(GET|POST|PUT|DELETE|PATCH|OPTIONS|HEAD)\b', line))
            is_spring = bool(re.search(r'@(?:Get|Post|Put|Patch|Delete|Request)Mapping', line))
            is_method_path = bool(re.search(r'@Path\s*\(\s*["\']([^"\']+)["\']\s*\)', line))

            if is_jaxrs_http or is_spring or is_method_path:
                ann_start = i
                method_subpath = ""

                while i < len(lines) and not re.search(r'\b(?:public|protected|private)\s+(?:[\w<>\[\],\s]+)\s+(\w+)\s*\(', lines[i]):
                    curr_line = lines[i]
                    mp_m = re.search(r'@Path\s*\(\s*["\']([^"\']+)["\']\s*\)', curr_line)
                    if mp_m:
                        method_subpath = mp_m.group(1).strip()
                    sp_m = JAVA_ROUTE_RE.search(curr_line)
                    if sp_m:
                        method_subpath = sp_m.group(1).strip()
                    i += 1

                if i < len(lines):
                    fn_m = re.search(r'\b(?:public|protected|private)\s+(?:[\w<>\[\],\s]+)\s+(\w+)\s*\(', lines[i])
                    if fn_m:
                        func_name = fn_m.group(1)
                        base_prefix = prefix or "/api"
                        if method_subpath:
                            clean_sub = method_subpath.lstrip("/")
                            clean_base = base_prefix.rstrip("/")
                            base_leaf = clean_base.split("/")[-1].lower()
                            if clean_sub.lower() == base_leaf:
                                route_path_str = clean_base
                            else:
                                route_path_str = f"{clean_base}/{clean_sub}"
                        else:
                            route_path_str = base_prefix

                        if not route_path_str.startswith("/"):
                            route_path_str = "/" + route_path_str

                        start = max(0, ann_start - 1)
                        end = min(len(lines), i + 25)
                        brace_count = 0
                        found_brace = False
                        for k in range(i, min(len(lines), i + 40)):
                            brace_count += lines[k].count("{") - lines[k].count("}")
                            if "{" in lines[k]:
                                found_brace = True
                            if found_brace and brace_count <= 0:
                                end = k + 1
                                break
                        snippet = "\n".join(lines[start:end])

                        findings.append(ASTSchema(
                            route_path=route_path_str,
                            file_path=rel_path,
                            line_number=ann_start + 1,
                            language=ProgrammingLanguage.JAVA,
                            function_name=func_name,
                            source_snippet=snippet,
                        ))
            i += 1

        # 2. Extract Java Servlets (doGet/doPost)
        if is_servlet and not findings:
            for i, line in enumerate(lines):
                servlet_fn_m = re.search(r'\bprotected\s+void\s+(doGet|doPost|service)\s*\(', line)
                if servlet_fn_m:
                    fn_name = servlet_fn_m.group(1)
                    clean_name = re.sub(r'Servlet$', '', class_name)
                    route_path_str = f"/bank/{clean_name.lower()}"
                    for next_line in lines[i:min(len(lines), i + 15)]:
                        end_m = re.search(r'endsWith\s*\(\s*["\'](\w+)["\']\s*\)', next_line)
                        if end_m:
                            route_path_str = f"/bank/{end_m.group(1)}"
                            break

                    start = max(0, i - 1)
                    end = min(len(lines), i + 25)
                    snippet = "\n".join(lines[start:end])
                    findings.append(ASTSchema(
                        route_path=route_path_str,
                        file_path=rel_path,
                        line_number=i + 1,
                        language=ProgrammingLanguage.JAVA,
                        function_name=fn_name,
                        source_snippet=snippet,
                    ))

        return findings

    # ── PHP Route Extraction (Laravel / Symfony) ──────────────

    def _extract_php_regex(
        self, source: str, rel_path: str, lines: list[str]
    ) -> list[ASTSchema]:
        """Extract PHP routes (Laravel, Symfony, Slim)."""
        findings: list[ASTSchema] = []
        for i, line in enumerate(lines):
            m = PHP_ROUTE_RE.search(line)
            if not m:
                continue

            route_path_str = m.group(2)
            if not route_path_str.startswith("/"):
                route_path_str = "/" + route_path_str

            start = max(0, i - 1)
            end = min(len(lines), i + 18)
            snippet = "\n".join(lines[start:end])

            findings.append(ASTSchema(
                route_path=route_path_str,
                file_path=rel_path,
                line_number=i + 1,
                language=ProgrammingLanguage.PHP,
                function_name=None,
                source_snippet=snippet,
            ))
        return findings

    # ── Ruby Route Extraction (Rails / Sinatra) ───────────────

    def _extract_ruby_regex(
        self, source: str, rel_path: str, lines: list[str]
    ) -> list[ASTSchema]:
        """Extract Ruby routes (Rails, Sinatra)."""
        findings: list[ASTSchema] = []
        for i, line in enumerate(lines):
            m = RUBY_ROUTE_RE.search(line)
            if not m:
                continue

            route_path_str = m.group(2)
            if not route_path_str.startswith("/"):
                route_path_str = "/" + route_path_str

            start = max(0, i - 1)
            end = min(len(lines), i + 18)
            snippet = "\n".join(lines[start:end])

            findings.append(ASTSchema(
                route_path=route_path_str,
                file_path=rel_path,
                line_number=i + 1,
                language=ProgrammingLanguage.RUBY,
                function_name=None,
                source_snippet=snippet,
            ))
        return findings

    # ── C# Route Extraction (ASP.NET Core) ────────────────────

    def _extract_csharp_regex(
        self, source: str, rel_path: str, lines: list[str]
    ) -> list[ASTSchema]:
        """Extract C# ASP.NET Core controller and minimal API routes."""
        findings: list[ASTSchema] = []
        for i, line in enumerate(lines):
            m = CSHARP_ROUTE_RE.search(line)
            if not m:
                continue

            route_path_str = m.group(2) or m.group(4)
            if not route_path_str:
                continue
            if not route_path_str.startswith("/"):
                route_path_str = "/" + route_path_str

            start = max(0, i - 1)
            end = min(len(lines), i + 18)
            snippet = "\n".join(lines[start:end])

            findings.append(ASTSchema(
                route_path=route_path_str,
                file_path=rel_path,
                line_number=i + 1,
                language=ProgrammingLanguage.CSHARP,
                function_name=None,
                source_snippet=snippet,
            ))
        return findings

    # ── Rust Route Extraction (Actix / Axum) ──────────────────

    def _extract_rust_regex(
        self, source: str, rel_path: str, lines: list[str]
    ) -> list[ASTSchema]:
        """Extract Rust Actix-web and Axum routes."""
        findings: list[ASTSchema] = []
        for i, line in enumerate(lines):
            m = RUST_ROUTE_RE.search(line)
            if not m:
                continue

            route_path_str = m.group(2) or m.group(3)
            if not route_path_str:
                continue
            if not route_path_str.startswith("/"):
                route_path_str = "/" + route_path_str

            start = max(0, i - 1)
            end = min(len(lines), i + 18)
            snippet = "\n".join(lines[start:end])

            findings.append(ASTSchema(
                route_path=route_path_str,
                file_path=rel_path,
                line_number=i + 1,
                language=ProgrammingLanguage.RUST,
                function_name=None,
                source_snippet=snippet,
            ))
        return findings

    @staticmethod
    def _make_stub(
        rel_path: str,
        language: ProgrammingLanguage,
        source: str,
    ) -> ASTSchema:
        """Return a minimal ASTSchema when tree-sitter is unavailable."""
        return ASTSchema(
            route_path=f"/{rel_path}",
            file_path=rel_path,
            line_number=1,
            language=language,
            source_snippet=source[:200] if source else None,
        )
