"""Phase 3: probe generation. Generate-only — probes are never executed here.

The probe is a machine-readable JSON contract (interpreter command template +
self-contained script). It is validated strictly: anything that does not match
the contract after retries is a generation failure and the candidate stays
pending for a later run. When the probe auditor rejects a probe, its feedback
is fed back here as ``rewrite_feedback`` for a bounded rewrite.

The generator may also REFUSE a candidate outright (FM-Agent's validator has
the same escape hatch via its error class): a structured
``{"refuse": true, "reason": ...}`` answer ends the candidate as rejected with
the reason persisted — for candidates that cannot be probed through the public
entry point at all. A refusal is an auditable opinion, never silent.
"""

from pathlib import Path

from oceanids.cwe import format_cwe
from oceanids.io_utils import atomic_write_text
from oceanids.llm.base import Json, LLMClient, call_structured
from oceanids.models import CandidateIssue, Probe, ProbeRefusal
from oceanids.sandbox.base import PROBE_REACHED_MARKER, PROBE_SETUP_MARKER

_PROBE_SCHEMA = (
    '{"interpreter": ["<command>", ...], "script": "<self-contained source>"}'
    ' OR {"refuse": true, "reason": "<why this candidate cannot be probed>"}'
)


def _validate_probe(data: Json) -> tuple[tuple[str, ...], str] | str:
    """Strict contract check; raises ValueError on any violation.

    Returns ``(interpreter, script)`` for a probe, or the reason string for a
    refusal (the caller wraps it in a ProbeRefusal with the candidate id).
    """
    if not isinstance(data, dict):
        raise ValueError("probe must be a JSON object")
    if set(data) == {"refuse", "reason"}:
        if data["refuse"] is not True:
            raise ValueError("refuse must be true when the refusal form is used")
        reason = data["reason"]
        if not isinstance(reason, str) or not reason.strip():
            raise ValueError("a refusal must explain itself in reason")
        return reason
    if set(data) != {"interpreter", "script"}:
        raise ValueError(
            "probe must be a JSON object with exactly keys interpreter, script, "
            "or the refusal form {refuse, reason}"
        )
    interpreter = data["interpreter"]
    script = data["script"]
    if (
        not isinstance(interpreter, list)
        or not interpreter
        or not all(isinstance(part, str) and part for part in interpreter)
    ):
        raise ValueError("probe interpreter must be a non-empty array of strings")
    if not isinstance(script, str) or not script.strip():
        raise ValueError("probe script must be a non-empty string")
    for marker in (PROBE_SETUP_MARKER, PROBE_REACHED_MARKER):
        if marker not in script:
            raise ValueError(f"probe script must print the {marker} marker")
    return (tuple(str(part) for part in interpreter), script)


def generate_probe(
    candidate: CandidateIssue,
    llm: LLMClient,
    probes_dir: Path,
    *,
    max_retries: int,
    rewrite_feedback: str = "",
    overview: str = "",
) -> Probe | ProbeRefusal | None:
    """Generate one probe for one candidate; None when the LLM never complies.

    Returns a ProbeRefusal when the generator legitimately refuses (the
    candidate cannot be probed through the public entry point); the caller
    persists the refusal reason as the candidate's reject_reason.
    ``rewrite_feedback`` carries the probe auditor's rejection reason on a
    rewrite attempt, so the generator can fix the flagged problem. ``overview``
    is the agent-written project overview injected into the prompt.
    """
    if candidate.id is None:
        raise ValueError("probe generation only accepts persisted candidates")
    prompt = (
        f"PROBE for candidate in file {candidate.file}, function {candidate.function}.\n"
        f"Project overview (overview.md):\n{overview}\n\n"
        f"Bug type: {format_cwe(candidate.cwe_id)}.\n"
        f"Bug category: {candidate.bug_category}.\n"
        f"Description: {candidate.description}\n"
        f"Trigger: {candidate.trigger}\n"
        "Write a self-contained probe script that deterministically triggers the bug "
        "through the public entry point only, exiting non-zero (or crashing) when the "
        "bug fires. The probe MUST print two marker lines to stdout or its result is "
        "discarded regardless of exit code:\n"
        f"1. {PROBE_SETUP_MARKER} — only AFTER the target module and all its "
        "dependencies loaded successfully and sanity checks passed (this proves the "
        "environment is intact; a crash on import must NOT print it);\n"
        f"2. {PROBE_REACHED_MARKER} — only when the trigger input actually enters "
        "the targeted function/path (e.g. by wrapping the target function, or by "
        "observing behaviour unique to that path).\n"
        "For hang-style bugs, print both markers before handing the trigger to a "
        "watched child/worker so a timeout still carries them.\n"
        "If the candidate CANNOT be probed at all — the trigger cannot reach the "
        "target through the public entry point, it needs an external resource "
        "(network/hardware), or the description is self-contradictory — refuse "
        "instead of writing a vacuous probe: reply with the refusal form and a "
        "concrete reason. Refusing is only for the genuinely unprobeable.\n"
        f"Reply with JSON: {_PROBE_SCHEMA}"
    )
    if rewrite_feedback:
        prompt += (
            "\n\nYour previous probe was REJECTED by the auditor with this feedback; "
            f"fix the flagged problem in the rewrite:\n{rewrite_feedback}"
        )
    result = call_structured(
        llm, prompt, _validate_probe, _PROBE_SCHEMA, max_retries=max_retries
    )
    if result is None:
        return None  # generation failed; candidate stays pending for the next run
    if isinstance(result, str):
        return ProbeRefusal(candidate_id=candidate.id, reason=result)
    interpreter, script = result
    path = probes_dir / f"probe_{candidate.id}"
    atomic_write_text(path, script)
    return Probe(candidate_id=candidate.id, interpreter=interpreter, script=script, path=path)
