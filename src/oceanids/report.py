"""Final phase: every confirmed_bugs row (all probe-verified) rendered to markdown.

Entries are grouped and sorted by CWE id, with the canonical CWE name taken
from the originating candidate (candidate_issues.cwe_id is the single source
of typing — there is no separate classification stage).

An appendix surfaces the unresolved candidates: ``inconclusive`` (no evidence
either way within the attempt budget — typically a broken environment waiting
to be fixed) and ``rejected`` (with the persisted reject_reason, so generator
refusals and clean-run false positives stay auditable). Nothing in the
appendix is claimed as a bug; it exists so misses and refusals stay visible
instead of silently disappearing from the run's only human-facing artifact.
"""

from pathlib import Path

from oceanids.cwe import format_cwe
from oceanids.db import CandidateStore, ConfirmedStore
from oceanids.io_utils import atomic_write_text
from oceanids.models import CandidateIssue, CandidateStatus, ConfirmedBug


def render_markdown(
    rows: list[tuple[ConfirmedBug, CandidateIssue]],
    appendix: list[CandidateIssue] | None = None,
) -> str:
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
    unresolved = _appendix_lines(appendix or [])
    if unresolved:
        lines += unresolved
    return "\n".join(lines) + "\n"


def _appendix_lines(candidates: list[CandidateIssue]) -> list[str]:
    """Appendix for inconclusive/rejected candidates; empty when none exist."""
    inconclusive = [c for c in candidates if c.status is CandidateStatus.INCONCLUSIVE]
    rejected = [c for c in candidates if c.status is CandidateStatus.REJECTED]
    if not inconclusive and not rejected:
        return []
    lines = [
        "## Appendix: unresolved candidates",
        "",
        "None of these are claimed as bugs; they are listed for manual triage.",
        "",
    ]
    if inconclusive:
        lines += ["### Inconclusive (no conclusive evidence within the attempt budget)", ""]
        for c in sorted(inconclusive, key=lambda c: (c.file, c.function)):
            reason = f" — {c.reject_reason}" if c.reject_reason else ""
            lines.append(
                f"- `{c.function}` (`{c.file}`, {format_cwe(c.cwe_id)}), "
                f"{c.verify_attempts} attempt(s){reason}"
            )
        lines.append("")
    if rejected:
        lines += ["### Rejected (with reason)", ""]
        for c in sorted(rejected, key=lambda c: (c.file, c.function)):
            reason = f" — {c.reject_reason}" if c.reject_reason else ""
            lines.append(
                f"- `{c.function}` (`{c.file}`, {format_cwe(c.cwe_id)}){reason}"
            )
        lines.append("")
    return lines


def write_report(
    confirmed: ConfirmedStore, candidates: CandidateStore, path: Path
) -> Path:
    """Write confirmed bugs plus the unresolved-candidates appendix (atomic)."""
    content = render_markdown(
        confirmed.confirmed_with_candidates(), candidates.all()
    )
    return atomic_write_text(path, content)
