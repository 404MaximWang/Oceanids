"""Phase 1.5: the agent-written project overview (overview.md).

Unlike the mechanical function index (function_index.py), this is an LLM-written
summary of the whole target — purpose, architecture, entry points, risky areas —
injected into the context of every later agent (explorer, probe generator, probe
auditor).

The document lives at ``<target>/.oceanids/overview.md`` (artifacts anchor at the
ORIGINAL target, so it survives across runs). Resume semantics: an existing
non-empty file is reused as-is. A missing or empty file is generated; when
generation produces nothing, it is retried exactly once; still missing after
that — OverviewError, abort.
"""

from pathlib import Path

from oceanids.io_utils import atomic_write_text
from oceanids.llm.base import LLMClient
from oceanids.pipeline.function_index import FunctionIndex

OVERVIEW_FILENAME = "overview.md"


class OverviewError(RuntimeError):
    """overview.md could not be produced (the single retry is already burned)."""


def _prompt(index: FunctionIndex) -> str:
    listing = "\n".join(
        f"- {file.path} ({file.language}, {file.line_count} lines): "
        + (
            "functions unknown"
            if file.functions is None
            else ", ".join(span.name for span in file.functions) or "no functions"
        )
        for file in index.files
    )
    return (
        "Write a concise project overview in Markdown for the source tree below. "
        "Cover: the project's purpose, module/architecture layout, public entry "
        "points, and the areas where bugs are most likely. This document is "
        "injected as context into later analysis agents. "
        "Reply with ONLY the Markdown document, no prose around it.\n\n"
        f"Files:\n{listing}"
    )


def load_or_generate(index: FunctionIndex, llm: LLMClient, path: Path) -> str:
    """Return overview.md's content, generating it first when the file is missing.

    Generation gets one retry; a still-missing/empty document after that raises
    OverviewError — the caller aborts the run.
    """
    if path.exists() and (text := path.read_text(encoding="utf-8")).strip():
        return text  # an existing non-empty document is reused as-is
    prompt = _prompt(index)
    for _attempt in range(2):  # first try + exactly one retry
        try:
            text = llm.complete(prompt)
        except Exception:  # noqa: BLE001 — a backend failure is a failed attempt
            continue
        if text.strip():
            atomic_write_text(path, text)
            return text
    raise OverviewError(f"overview generation produced no {path} after one retry")
