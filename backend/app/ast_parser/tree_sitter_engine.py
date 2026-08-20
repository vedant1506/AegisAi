"""
AegisAI — tree-sitter AST Analysis Engine
==========================================
Responsible for:
  1. Cloning / reading source files from a local repo path
  2. Parsing each file with the appropriate tree-sitter grammar
  3. Extracting route definitions and their handler functions
  4. Returning a list of ASTSchema objects for the AI pipeline

Supported languages: Python, JavaScript, TypeScript
(Java / Go / Rust parsers follow the same pattern — add as needed)

Usage:
    engine = TreeSitterEngine()
    findings = await engine.analyse_repository("/tmp/cloned_repo")
"""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

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

from app.schemas.io_models import ASTSchema, ProgrammingLanguage

logger = structlog.get_logger(__name__)

# ── Language → file extension mapping ────────────────────────
EXTENSION_MAP: dict[str, ProgrammingLanguage] = {
    ".py":  ProgrammingLanguage.PYTHON,
    ".js":  ProgrammingLanguage.JAVASCRIPT,
    ".ts":  ProgrammingLanguage.TYPESCRIPT,
    ".tsx": ProgrammingLanguage.TYPESCRIPT,
    ".jsx": ProgrammingLanguage.JAVASCRIPT,
}

# ── Route-definition node types per language ──────────────────
# These tree-sitter node types are considered "route definitions"
ROUTE_NODE_TYPES: dict[ProgrammingLanguage, list[str]] = {
    ProgrammingLanguage.PYTHON: [
        "decorated_definition",  # FastAPI / Flask @app.get(...)
        "function_definition",
    ],
    ProgrammingLanguage.JAVASCRIPT: [
        "call_expression",       # express router.get(...)
        "function_declaration",
    ],
    ProgrammingLanguage.TYPESCRIPT: [
        "call_expression",
        "function_declaration",
        "method_definition",
    ],
}

# ── Directories to skip ───────────────────────────────────────
SKIP_DIRS = {
    "node_modules", ".git", "venv", ".venv", "__pycache__",
    "dist", "build", ".next", "coverage",
}


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

    # ── Public API ────────────────────────────────────────────

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

    def _collect_files(self, root: Path):
        """Yield source files, skipping blacklisted directories."""
        for path in root.rglob("*"):
            if path.is_dir():
                continue
            if any(skip in path.parts for skip in SKIP_DIRS):
                continue
            if path.suffix in EXTENSION_MAP:
                yield path

    async def _analyse_file(
        self, file_path: Path, repo_root: Path
    ) -> list[ASTSchema]:
        """
        Parse a single source file and extract route nodes.

        TODO: Implement full AST node traversal and route-pattern extraction.
              Current implementation returns a stub node per file for scaffolding.
        """
        language = EXTENSION_MAP.get(file_path.suffix)
        if language is None:
            return []

        try:
            source = await asyncio.to_thread(file_path.read_text, encoding="utf-8")
        except (UnicodeDecodeError, PermissionError) as exc:
            logger.debug("ast.read_error", file=str(file_path), error=str(exc))
            return []

        rel_path = str(file_path.relative_to(repo_root))

        if not TREE_SITTER_AVAILABLE or language not in self._parsers:
            # Graceful degradation — return a minimal schema without parsing
            return [self._make_stub(rel_path, language, source)]

        parser = self._parsers[language]

        # Parse synchronously (tree-sitter is CPU-bound, offload to thread)
        tree = await asyncio.to_thread(parser.parse, source.encode("utf-8"))

        nodes = self._extract_route_nodes(tree.root_node, language, source, rel_path)
        return nodes if nodes else [self._make_stub(rel_path, language, source)]

    def _extract_route_nodes(
        self,
        root_node: Any,
        language: ProgrammingLanguage,
        source: str,
        rel_path: str,
    ) -> list[ASTSchema]:
        """
        Recursively walk the AST and extract candidate route nodes.

        TODO: Implement language-specific pattern matching:
          - Python: detect @app.get/@app.post decorators (FastAPI/Flask)
          - JS/TS: detect router.get/router.post call expressions (Express)
          - Return one ASTSchema per discovered route handler
        """
        findings: list[ASTSchema] = []
        target_types = ROUTE_NODE_TYPES.get(language, [])

        def walk(node: Any) -> None:
            if node.type in target_types:
                line_no = node.start_point[0] + 1  # tree-sitter is 0-indexed
                snippet_lines = source.splitlines()
                start = max(0, line_no - 1)
                end = min(len(snippet_lines), line_no + 5)
                snippet = "\n".join(snippet_lines[start:end])

                # TODO: Extract actual route path from decorator / call arguments
                findings.append(ASTSchema(
                    route_path=f"/{rel_path}#L{line_no}",  # placeholder
                    file_path=rel_path,
                    line_number=line_no,
                    language=language,
                    source_snippet=snippet,
                ))

            for child in node.children:
                walk(child)

        walk(root_node)
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
