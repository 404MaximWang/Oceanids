"""Final phase: every confirmed_bugs row (all probe-verified) rendered to markdown.

Entries are grouped and sorted by CWE id, with the canonical CWE name taken
from the originating candidate (candidate_issues.cwe_id is the single source
of typing — there is no separate classification stage).
"""

from pathlib import Path

from oceanids.cwe import format_cwe
from oceanids.db import ConfirmedStore
from oceanids.io_utils import atomic_write_text
from oceanids.models import CandidateIssue, ConfirmedBug


def render_markdown(rows: list[tuple[ConfirmedBug, CandidateIssue]]) -> str:
    """Render confirmed bugs (joined with their candidates), grouped by CWE id."""
    ordered = sorted(rows, key=lambda pair: (pair[1].cwe_id, pair[1].function))
    lines = ["# Oceanids bug report", ""]
    if not ordered:
        lines.append("No confirmed bugs.")
    current_cwe: int | None = None
    for bug, candidate in ordered:
        if candidate.cwe_id != current_cwe:
            current_cwe = candidate.cwe_id
            lines += [f"## {format_cwe(current_cwe)}", ""]
        lines += [
            f"### #{bug.id} {candidate.function} — {candidate.bug_category}",
            "",
            f"- file: `{candidate.file}`",
            f"- evidence key: `{bug.evidence_key}`",
            f"- probe: `{bug.probe_path}`",
            "",
            candidate.description,
            "",
            f"Trigger: {candidate.trigger}",
            "",
        ]
    return "\n".join(lines) + "\n"


def write_report(confirmed: ConfirmedStore, path: Path) -> Path:
    """Write the full confirmed_bugs table to ``path`` (atomic)."""
    content = render_markdown(confirmed.confirmed_with_candidates())
    return atomic_write_text(path, content)
