"""Phase 1: walk the target tree into a language-aware overview.

Per-language extraction follows the FM-Agent languages/registry.py interface
shape — a Protocol + dict registry — rewritten typed. Python gets precise ast
spans; other languages fall back to a table-driven heuristic (comment prefixes /
keyword config). A handler returning None means "extraction backend unavailable
for this file", which is kept distinct from "no functions found".
"""

import ast
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Protocol

EXT_TO_LANG: dict[str, str] = {
    ".py": "python",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".cxx": "cpp",
    ".hpp": "cpp",
    ".go": "go",
    ".java": "java",
    ".rs": "rust",
    ".js": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "typescript",
}

_SKIP_DIRS = frozenset({"__pycache__", "node_modules", "venv", ".venv"})


@dataclass(frozen=True)
class FunctionSpan:
    """One extracted function: name plus 1-based inclusive line span."""

    name: str
    start: int
    end: int


@dataclass(frozen=True)
class FileOverview:
    path: str  # target-relative, posix separators
    language: str
    line_count: int
    # None means the extraction backend was unavailable for this file — not the
    # same as an empty tuple (parsed, but no functions found).
    functions: tuple[FunctionSpan, ...] | None


@dataclass(frozen=True)
class Overview:
    root: Path
    files: tuple[FileOverview, ...]


class LanguageHandler(Protocol):
    """Extraction backend for one language."""

    def function_spans(self, text: str) -> list[FunctionSpan] | None:
        """Function spans for one file, or None when the backend cannot parse it."""
        ...


class PythonHandler:
    """Precise spans via the ast module; None on syntax errors."""

    def function_spans(self, text: str) -> list[FunctionSpan] | None:
        try:
            tree = ast.parse(text)
        except SyntaxError:
            return None
        spans = [
            FunctionSpan(node.name, node.lineno, node.end_lineno or node.lineno)
            for node in ast.walk(tree)
            if isinstance(node, ast.FunctionDef | ast.AsyncFunctionDef)
        ]
        return sorted(spans, key=lambda span: span.start)


@dataclass(frozen=True)
class HeuristicSpec:
    """Table entry driving the regex-based fallback extractor for one language."""

    comment_prefixes: tuple[str, ...]
    signature: re.Pattern[str]  # capture group 1: the function name


class HeuristicHandler:
    """Generic extractor: a signature regex plus brace-balance span detection."""

    def __init__(self, spec: HeuristicSpec) -> None:
        self._spec = spec

    def function_spans(self, text: str) -> list[FunctionSpan]:
        lines = text.splitlines()
        spans: list[FunctionSpan] = []
        for index, line in enumerate(lines):
            match = self._spec.signature.search(line)
            if match is not None:
                spans.append(FunctionSpan(match.group(1), index + 1, self._find_end(lines, index)))
        return spans

    @staticmethod
    def _find_end(lines: list[str], start: int) -> int:
        depth = 0
        opened = False
        for lineno in range(start, len(lines)):
            depth += lines[lineno].count("{") - lines[lineno].count("}")
            if "{" in lines[lineno]:
                opened = True
            if opened and depth <= 0:
                return lineno + 1
        return len(lines)


_C_FAMILY = HeuristicSpec(
    comment_prefixes=("//", "/*"),
    signature=re.compile(r"^\s*(?:[\w:<>,\*&\[\]]+\s+)+(\w+)\s*\([^;{}]*\)\s*\{?"),
)
_GO = HeuristicSpec(
    comment_prefixes=("//", "/*"),
    signature=re.compile(r"^func\s+(?:\(\s*\w+\s+[\w\*]+\s*\)\s+)?(\w+)\s*\("),
)
_RUST = HeuristicSpec(
    comment_prefixes=("//", "/*"),
    signature=re.compile(r"^\s*(?:pub\s+)?fn\s+(\w+)"),
)

_HEURISTIC_SPECS: dict[str, HeuristicSpec] = {
    "c": _C_FAMILY,
    "cpp": _C_FAMILY,
    "java": _C_FAMILY,
    "javascript": _C_FAMILY,
    "typescript": _C_FAMILY,
    "go": _GO,
    "rust": _RUST,
}

# The per-language handler registry: add an entry here to support a language.
HANDLERS: dict[str, LanguageHandler] = {
    "python": PythonHandler(),
    **{lang: HeuristicHandler(spec) for lang, spec in _HEURISTIC_SPECS.items()},
}


def build_overview(root: Path) -> Overview:
    """Walk ``root`` and summarise every recognised source file."""
    files: list[FileOverview] = []
    for path in sorted(root.rglob("*")):
        if not path.is_file():
            continue
        rel = path.relative_to(root)
        if any(part.startswith(".") or part in _SKIP_DIRS for part in rel.parts[:-1]):
            continue
        language = EXT_TO_LANG.get(path.suffix.lower())
        if language is None:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        handler = HANDLERS.get(language)
        spans = handler.function_spans(text) if handler is not None else None
        files.append(
            FileOverview(
                path=rel.as_posix(),
                language=language,
                line_count=text.count("\n") + 1,
                functions=None if spans is None else tuple(spans),
            )
        )
    return Overview(root=root, files=tuple(files))
