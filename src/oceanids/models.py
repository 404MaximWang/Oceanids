"""Core data model shared by every pipeline phase.

The schema stays language-agnostic on purpose: a candidate is identified by
(file, function, bug_category), and a probe is a self-contained script whose
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
    """

    PENDING = "pending"
    REJECTED = "rejected"
    CONFIRMED = "confirmed"
    DUPLICATE = "duplicate"


class VerdictKind(enum.StrEnum):
    """Outcome of one checker verification run."""

    TRUE_POSITIVE = "true_positive"
    FALSE_POSITIVE = "false_positive"


@dataclass(frozen=True)
class CandidateIssue:
    """One raw finding reported by an explorer agent (table candidate_issues).

    Dedup key is (function, cwe_id); bug_category stays a free-text label from
    the exploration stage and plays no role in dedup.
    """

    file: str
    function: str
    cwe_id: int
    bug_category: str
    description: str
    trigger: str
    status: CandidateStatus = CandidateStatus.PENDING
    id: int | None = None


@dataclass(frozen=True)
class Probe:
    """A self-contained verification script plus its interpreter command template."""

    candidate_id: int
    interpreter: tuple[str, ...]
    script: str
    path: Path | None = None


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
