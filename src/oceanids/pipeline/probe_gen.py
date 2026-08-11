"""Phase 3: probe generation. Generate-only — probes are never executed here.

The probe is a machine-readable JSON contract (interpreter command template +
self-contained script). It is validated strictly: anything that does not match
the contract after retries is a generation failure and the candidate stays
pending for a later run. When the probe auditor rejects a probe, its feedback
is fed back here as ``rewrite_feedback`` for a bounded rewrite.
"""

from pathlib import Path

from oceanids.cwe import format_cwe
from oceanids.io_utils import atomic_write_text
from oceanids.llm.base import Json, LLMClient, call_structured
from oceanids.models import CandidateIssue, Probe

_PROBE_SCHEMA = '{"interpreter": ["<command>", ...], "script": "<self-contained source>"}'


def _validate_probe(data: Json) -> tuple[tuple[str, ...], str]:
    """Strict contract check; raises ValueError on any violation."""
    if not isinstance(data, dict) or set(data) != {"interpreter", "script"}:
        raise ValueError("probe must be a JSON object with exactly keys interpreter, script")
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
    return (tuple(str(part) for part in interpreter), script)


def generate_probe(
    candidate: CandidateIssue,
    llm: LLMClient,
    probes_dir: Path,
    *,
    max_retries: int,
    rewrite_feedback: str = "",
    overview: str = "",
) -> Probe | None:
    """Generate one probe for one candidate; None when the LLM never complies.

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
        f"bug fires. Reply with JSON: {_PROBE_SCHEMA}"
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
    interpreter, script = result
    path = probes_dir / f"probe_{candidate.id}"
    atomic_write_text(path, script)
    return Probe(candidate_id=candidate.id, interpreter=interpreter, script=script, path=path)
