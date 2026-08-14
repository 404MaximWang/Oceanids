"""Phase 3.4: the probe auditor — an LLM gate between probe_gen and checker.

Static review only (nothing is executed here). The auditor checks two things:
(a) whether the probe's expected output is faithful to the spec/docstring of
the target function, and (b) whether the probe's inputs can actually reach the
targeted path inside the target function. A rejected probe goes back to
probe_gen with the feedback for a bounded rewrite; when the rewrite budget is
exhausted the candidate is marked rejected (the feedback is kept as the reason).
"""

from pathlib import Path

from oceanids.cwe import format_cwe
from oceanids.llm.base import Json, LLMClient, call_structured
from oceanids.models import CandidateIssue, Probe

_AUDIT_SCHEMA = '{"verdict": "ok"|"invalid", "feedback": str}'

_AUDIT_EXAMPLES = """\
Examples of valid responses (reply with ONLY the JSON object, no markdown or prose):

{"verdict": "ok", "feedback": ""}

{"verdict": "invalid", "feedback": "The probe hard-codes the buggy output as \
the expected result, so it cannot distinguish a fix from the bug."}

{"verdict": "invalid", "feedback": "The trigger input never reaches the \
vulnerable path because the function returns early on empty input."}

Important: feedback is a JSON string. If it contains quotes or backslashes \
they must be escaped, e.g.: \\" and \\\\\\."""


class AuditVerdict:
    """The auditor's decision on one probe."""

    def __init__(self, *, ok: bool, feedback: str) -> None:
        self.ok = ok
        self.feedback = feedback

    def __repr__(self) -> str:
        return f"AuditVerdict(ok={self.ok!r}, feedback={self.feedback!r})"


def _validate_audit(data: Json) -> AuditVerdict:
    """Strict contract check; raises ValueError on any violation."""
    if not isinstance(data, dict) or set(data) != {"verdict", "feedback"}:
        raise ValueError("audit must be a JSON object with exactly keys verdict, feedback")
    verdict, feedback = data["verdict"], data["feedback"]
    if verdict not in ("ok", "invalid"):
        raise ValueError(f"verdict must be 'ok' or 'invalid', got {verdict!r}")
    if not isinstance(feedback, str):
        raise ValueError("feedback must be a string")
    if verdict == "invalid" and not feedback.strip():
        raise ValueError("an invalid verdict must explain itself in feedback")
    return AuditVerdict(ok=verdict == "ok", feedback=feedback)


def audit_probe(
    candidate: CandidateIssue,
    probe: Probe,
    target_root: Path,
    llm: LLMClient,
    *,
    max_retries: int = 3,
    overview: str = "",
) -> AuditVerdict | None:
    """Statically audit one probe against its candidate and the target source.

    Returns None when the auditor LLM never produces a valid contract answer —
    the caller then leaves the candidate pending for a later run. ``overview``
    is the agent-written project overview injected into the prompt.
    """
    try:
        source = (target_root / candidate.file).read_text(encoding="utf-8", errors="replace")
    except OSError:
        # No target source, no audit — checks (a) and (b) would be meaningless.
        # Treat as "auditor unavailable": the candidate stays pending.
        return None
    prompt = (
        f"AUDIT probe for candidate in file {candidate.file}, function {candidate.function}.\n"
        f"Project overview (overview.md):\n{overview}\n\n"
        f"Bug type: {format_cwe(candidate.cwe_id)}.\n"
        f"Bug category: {candidate.bug_category}.\n"
        f"Description: {candidate.description}\n"
        f"Trigger: {candidate.trigger}\n"
        "Review the probe STATICALLY (do not execute it). Check two things:\n"
        "(a) the probe's expected output is faithful to the target function's "
        "spec/docstring — a probe that hard-codes buggy behaviour as 'expected' is invalid;\n"
        "(b) the probe's inputs can actually reach the targeted path inside the target "
        "function — a probe that can never trigger the described bug is invalid.\n"
        f"Reply with JSON: {_AUDIT_SCHEMA}\n\n"
        f"{_AUDIT_EXAMPLES}\n\n"
        f"Probe script:\n```\n{probe.script}\n```\n\n"
        f"Target source ({candidate.file}):\n```\n{source}\n```"
    )
    return call_structured(
        llm, prompt, _validate_audit, _AUDIT_SCHEMA, max_retries=max_retries
    )
