"""Checker: true/false-positive routing, evidence dedup, dependency hash lock."""

import sys
from pathlib import Path

import pytest

from oceanids.db import CandidateStore, ConfirmedStore, Database
from oceanids.models import CandidateIssue, CandidateStatus, Probe
from oceanids.pipeline.checker import Checker
from oceanids.sandbox.base import DependencyDriftError, hash_tree
from oceanids.sandbox.local import LocalSandbox


def _setup(tmp_path: Path) -> tuple[CandidateStore, ConfirmedStore, Path]:
    target = tmp_path / "target"
    target.mkdir()
    (target / "victim.py").write_text(
        "def crash() -> None:\n    raise ValueError('boom')\n", encoding="utf-8"
    )
    db = Database(tmp_path / "x.db")
    return CandidateStore(db), ConfirmedStore(db), target


def _candidate(candidates: CandidateStore, function: str = "crash") -> CandidateIssue:
    row_id = candidates.insert(
        CandidateIssue(
            file="victim.py",
            function=function,
            cwe_id=703,
            bug_category="uncaught-exception",
            description="crash raises",
            trigger="crash()",
        )
    )
    assert row_id is not None
    stored = candidates.get(row_id)
    assert stored is not None
    return stored


def _probe(tmp_path: Path, candidate_id: int, crashing: bool) -> Probe:
    script = "import victim\nvictim.crash()\n" if crashing else "print('all good')\n"
    path = tmp_path / "probes" / f"probe_{candidate_id}"
    path.parent.mkdir(exist_ok=True)
    path.write_text(script, encoding="utf-8")
    return Probe(
        candidate_id=candidate_id, interpreter=(sys.executable,), script=script, path=path
    )


def _checker(
    candidates: CandidateStore, confirmed: ConfirmedStore, target: Path
) -> Checker:
    return Checker(
        target,
        hash_tree(target),
        lambda: LocalSandbox(target),
        candidates,
        confirmed,
        timeout_s=30,
    )


def test_true_positive_confirms_candidate(tmp_path: Path) -> None:
    candidates, confirmed, target = _setup(tmp_path)
    candidate = _candidate(candidates)
    probe = _probe(tmp_path, candidate.id or 0, crashing=True)
    verdict = _checker(candidates, confirmed, target).verify(candidate, probe)

    assert verdict.kind.value == "true_positive"
    assert verdict.confirmed_id is not None
    assert verdict.evidence is not None
    assert verdict.evidence.oracle_fired
    assert verdict.evidence.sanitizer_hits  # traceback marker seen
    assert verdict.evidence.top_frames  # violation frames extracted
    stored = candidates.get(candidate.id or 0)
    assert stored is not None and stored.status is CandidateStatus.CONFIRMED
    assert confirmed.count() == 1


def test_false_positive_rejects_candidate(tmp_path: Path) -> None:
    candidates, confirmed, target = _setup(tmp_path)
    candidate = _candidate(candidates)
    probe = _probe(tmp_path, candidate.id or 0, crashing=False)
    verdict = _checker(candidates, confirmed, target).verify(candidate, probe)

    assert verdict.kind.value == "false_positive"
    assert verdict.confirmed_id is None
    stored = candidates.get(candidate.id or 0)
    assert stored is not None and stored.status is CandidateStatus.REJECTED
    assert confirmed.count() == 0


def test_evidence_dedup_across_candidates(tmp_path: Path) -> None:
    candidates, confirmed, target = _setup(tmp_path)
    first = _candidate(candidates, function="crash")
    second = _candidate(candidates, function="crash-alias")
    checker = _checker(candidates, confirmed, target)
    # Both candidates point at the same crash; the same probe proves both.
    probe1 = _probe(tmp_path, first.id or 0, crashing=True)
    verdict1 = checker.verify(first, probe1)
    probe2 = _probe(tmp_path, second.id or 0, crashing=True)
    verdict2 = checker.verify(second, probe2)

    assert verdict1.confirmed_id is not None
    # Same violation evidence → INSERT OR IGNORE on evidence_key, no new row.
    assert verdict2.confirmed_id is None
    assert confirmed.count() == 1
    # First proof → confirmed; dedup hit → duplicate (proven but already
    # represented), never pending again so resumes never re-probe it.
    stored1 = candidates.get(first.id or 0)
    assert stored1 is not None and stored1.status is CandidateStatus.CONFIRMED
    stored2 = candidates.get(second.id or 0)
    assert stored2 is not None and stored2.status is CandidateStatus.DUPLICATE
    assert "#1" in verdict2.reason  # dup verdict names the representing bug


def test_dependency_drift_refuses_execution(tmp_path: Path) -> None:
    candidates, confirmed, target = _setup(tmp_path)
    candidate = _candidate(candidates)
    probe = _probe(tmp_path, candidate.id or 0, crashing=True)
    checker = _checker(candidates, confirmed, target)
    (target / "victim.py").write_text("# drifted\n", encoding="utf-8")
    with pytest.raises(DependencyDriftError):
        checker.verify(candidate, probe)
