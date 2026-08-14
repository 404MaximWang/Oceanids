"""Core data model shared by every pipeline phase.

The schema stays language-agnostic on purpose: a candidate is identified by
(file, function, cwe_id), and a probe is a self-contained script whose
interpreter is just a command template.
"""

import enum
from dataclasses import dataclass
from pathlib import Path


class CandidateStatus(enum.StrEnum):
    """Lifecycle of one row in candidate_issues.

    ``duplicate`` means the probe DID prove the bug, but its evidence was
    already represented in confirmed_bugs by another candidate — distinct
    from ``confirmed`` (first proof) so duplicate-attribution density stays
    measurable, and from ``pending`` so resumes never re-probe it.
    ``inconclusive`` is the terminal state for candidates whose verification
    never produced evidence either way within the attempt budget (broken
    environment, bare timeouts) — it asserts nothing about the candidate and
    is never retried automatically; reset it to ``pending`` manually once the
    environment is fixed.
    """

    PENDING = "pending"
    REJECTED = "rejected"
    CONFIRMED = "confirmed"
    DUPLICATE = "duplicate"
    INCONCLUSIVE = "inconclusive"


class VerdictKind(enum.StrEnum):
    """Outcome of one checker verification run."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"
    # The probe never proved its environment was intact (no setup marker) —
    # says nothing about the candidate; it stays pending.
    SETUP_FAILURE = "setup_failure"
    # Environment intact but the probe never proved the trigger reached the
    # targeted path — the probe goes back for a bounded rewrite.
    UNREACHABLE = "unreachable"


@dataclass(frozen=True)
class CandidateIssue:
    """One raw finding reported by an explorer agent (table candidate_issues).

    Dedup key is (file, function, cwe_id); bug_category stays a free-text label
    from the exploration stage and plays no role in dedup. ``reject_reason``
    records why a rejected candidate was rejected (auditor budget exhausted,
    generator refusal, or a clean checker run). ``verify_attempts`` counts
    checker runs that produced no evidence either way (setup failure, bare
    timeout).
    """

    file: str
    function: str
    cwe_id: int
    bug_category: str
    description: str
    trigger: str
    status: CandidateStatus = CandidateStatus.PENDING
    id: int | None = None
    reject_reason: str | None = None
    verify_attempts: int = 0


@dataclass(frozen=True)
class Probe:
    """A self-contained verification script plus its interpreter command template."""

    candidate_id: int
    interpreter: tuple[str, ...]
    script: str
    path: Path | None = None


@dataclass(frozen=True)
class ProbeRefusal:
    """The generator's structured refusal to probe a candidate.

    A refusal is an OPINION with a reason (e.g. the trigger cannot reach the
    target through the public entry point), not proof — it is persisted as the
    candidate's reject_reason so refusals stay auditable after the fact.
    """

    candidate_id: int
    reason: str


@dataclass(frozen=True)
class Evidence:
    """Machine-readable oracle data collected from the checker's own sandbox run."""

    exit_code: int
    timed_out: bool
    stdout: str
    stderr: str
    sanitizer_hits: tuple[str, ...]
    top_frames: tuple[str, ...]
    oracle_fired: bool
    evidence_key: str
    # Probe contract markers: the probe proved its dependencies loaded intact
    # (setup_ok) and that the trigger input reached the targeted path
    # (reached). Both are required before an oracle firing confirms anything.
    setup_ok: bool = False
    reached: bool = False


@dataclass(frozen=True)
class Verdict:
    """The checker's decision for one candidate; only self-run evidence is trusted."""

    candidate_id: int
    kind: VerdictKind
    reason: str
    evidence: Evidence | None = None
    confirmed_id: int | None = None


@dataclass(frozen=True)
class ConfirmedBug:
    """A probe-verified bug (table confirmed_bugs).

    The CWE typing lives solely on the originating candidate (explorer output,
    constrained subset); the join in ConfirmedStore supplies it for reporting.
    """

    candidate_id: int
    probe_path: str
    evidence_key: str
    id: int | None = None
