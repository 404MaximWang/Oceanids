"""Dedup semantics of candidate_issues and confirmed_bugs."""

from pathlib import Path

from oceanids.db import CandidateStore, ConfirmedStore, Database
from oceanids.models import CandidateIssue, CandidateStatus, ConfirmedBug


def _stores(tmp_path: Path) -> tuple[CandidateStore, ConfirmedStore]:
    db = Database(tmp_path / "test.db")
    return CandidateStore(db), ConfirmedStore(db)


def _issue(
    function: str = "f", category: str = "cat", cwe_id: int = 369, file: str = "a.py"
) -> CandidateIssue:
    return CandidateIssue(
        file=file,
        function=function,
        cwe_id=cwe_id,
        bug_category=category,
        description="d",
        trigger="t",
    )


def test_candidate_insert_dedups_on_function_and_cwe(tmp_path: Path) -> None:
    candidates, _ = _stores(tmp_path)
    first = candidates.insert(_issue())
    assert first is not None
    # Same (file, function, cwe_id) key: INSERT OR IGNORE swallows it — even
    # when the free-text bug_category label differs.
    assert candidates.insert(_issue(category="other-label")) is None
    # Same function, different cwe_id: a distinct candidate.
    assert candidates.insert(_issue(cwe_id=476)) is not None
    # Different function, same cwe_id: also distinct.
    assert candidates.insert(_issue(function="g")) is not None
    assert candidates.count() == 3


def test_candidate_insert_dedup_key_includes_file(tmp_path: Path) -> None:
    """Same-named functions in different files are distinct candidates."""
    candidates, _ = _stores(tmp_path)
    assert candidates.insert(_issue(file="a.py")) is not None
    assert candidates.insert(_issue(file="b.py")) is not None
    assert candidates.count() == 2


def test_candidate_status_flow(tmp_path: Path) -> None:
    candidates, _ = _stores(tmp_path)
    issue_id = candidates.insert(_issue())
    assert issue_id is not None
    pending = candidates.select_pending()
    assert [issue.id for issue in pending] == [issue_id]
    candidates.update_status(issue_id, CandidateStatus.REJECTED)
    assert candidates.select_pending() == []
    stored = candidates.get(issue_id)
    assert stored is not None
    assert stored.status is CandidateStatus.REJECTED


def test_confirmed_insert_dedups_on_evidence_key(tmp_path: Path) -> None:
    candidates, confirmed = _stores(tmp_path)
    issue_id = candidates.insert(_issue())
    assert issue_id is not None
    bug = ConfirmedBug(candidate_id=issue_id, probe_path="probe_1", evidence_key="key-1")
    first = confirmed.insert(bug)
    assert first is not None
    assert confirmed.insert(bug) is None  # evidence_key UNIQUE
    other = confirmed.insert(
        ConfirmedBug(candidate_id=issue_id, probe_path="probe_2", evidence_key="key-2")
    )
    assert other is not None
    assert confirmed.count() == 2


def test_confirmed_with_candidates_join(tmp_path: Path) -> None:
    candidates, confirmed = _stores(tmp_path)
    issue_id = candidates.insert(_issue(function="victim"))
    assert issue_id is not None
    bug_id = confirmed.insert(
        ConfirmedBug(candidate_id=issue_id, probe_path="p", evidence_key="k")
    )
    rows = confirmed.confirmed_with_candidates()
    assert len(rows) == 1
    bug, candidate = rows[0]
    assert bug.id == bug_id
    assert candidate.function == "victim"
    assert candidate.id == issue_id
