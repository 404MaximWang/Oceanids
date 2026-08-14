"""Explorer pool: one file, one agent, once — success burns the chance, failure doesn't."""

from pathlib import Path

from oceanids.db import CandidateStore, Database, ExploredFilesStore
from oceanids.llm.mock import MockLLM
from oceanids.pipeline.dispatch import dispatch
from oceanids.pipeline.explorer import explore
from oceanids.pipeline.function_index import build_function_index


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    (target / "alpha.py").write_text(
        "def f(x: int) -> int:\n    return x + 1\n", encoding="utf-8"
    )
    (target / "beta.py").write_text(
        "def g(x: int) -> int:\n    return x - 1\n", encoding="utf-8"
    )
    # Test files are excluded from dispatch.
    (target / "test_alpha.py").write_text(
        "def test_f() -> None:\n    assert True\n", encoding="utf-8"
    )
    return target


def _stores(tmp_path: Path) -> tuple[CandidateStore, ExploredFilesStore]:
    db = Database(tmp_path / "x.db")
    return CandidateStore(db), ExploredFilesStore(db)


_ISSUE = (
    '[{"function": "f", "cwe_id": 369, "bug_category": "off-by-one",'
    ' "description": "adds instead of subtracting", "trigger": "f(1)"}]'
)


def _llm() -> MockLLM:
    return MockLLM(routes=[("EXPLORE file alpha.py", _ISSUE)], default="[]")


def test_dispatch_excludes_test_files(tmp_path: Path) -> None:
    target = _target(tmp_path)
    tasks = dispatch(build_function_index(target))
    assert [task.path for task in tasks] == ["alpha.py", "beta.py"]


def test_explorer_inserts_and_marks_explored(tmp_path: Path) -> None:
    target = _target(tmp_path)
    tasks = dispatch(build_function_index(target))
    store, explored = _stores(tmp_path)

    stats = explore(target, tasks, _llm(), store, explored, pool_size=2, max_retries=0)
    assert stats.files == 2
    assert stats.files_skipped == 0
    assert stats.candidates_new == 1
    assert stats.llm_failures == 0
    # Success (even an empty issues array) burns the file's single chance.
    assert explored.is_explored("alpha.py")
    assert explored.is_explored("beta.py")
    issue = store.all()[0]
    assert issue.file == "alpha.py"
    assert issue.function == "f"
    assert issue.cwe_id == 369
    assert issue.bug_category == "off-by-one"


def test_explorer_skips_already_explored_files(tmp_path: Path) -> None:
    target = _target(tmp_path)
    tasks = dispatch(build_function_index(target))
    store, explored = _stores(tmp_path)
    llm = _llm()
    explore(target, tasks, llm, store, explored, pool_size=2, max_retries=0)
    calls_first = len(llm.calls)

    stats = explore(target, tasks, llm, store, explored, pool_size=2, max_retries=0)
    assert stats.files == 0
    assert stats.files_skipped == 2
    assert len(llm.calls) == calls_first  # no agent call for explored files
    assert store.count() == 1  # table did not grow


def test_explorer_rerun_with_lost_state_dedups(tmp_path: Path) -> None:
    target = _target(tmp_path)
    tasks = dispatch(build_function_index(target))
    store, explored = _stores(tmp_path)
    explore(target, tasks, _llm(), store, explored, pool_size=2, max_retries=0)

    # A fresh state store (state lost) re-explores; 法一 dedup keeps the table stable.
    fresh_state = ExploredFilesStore(Database(tmp_path / "y.db"))
    stats = explore(target, tasks, _llm(), store, fresh_state, pool_size=2, max_retries=0)
    assert stats.candidates_new == 0
    assert stats.candidates_dup == 1
    assert store.count() == 1


def test_explorer_failure_does_not_burn_the_chance(tmp_path: Path) -> None:
    target = _target(tmp_path)
    tasks = dispatch(build_function_index(target))
    store, explored = _stores(tmp_path)
    llm = MockLLM(routes=[], default="not json at all")
    stats = explore(target, tasks, llm, store, explored, pool_size=2, max_retries=1)
    assert stats.llm_failures == 2
    assert store.count() == 0
    # Failed rounds are NOT marked: the files stay re-explorable next run.
    assert not explored.is_explored("alpha.py")
    assert not explored.is_explored("beta.py")

    stats2 = explore(target, tasks, _llm(), store, explored, pool_size=2, max_retries=0)
    assert stats2.files == 2  # re-explored, not skipped
    assert stats2.candidates_new == 1


def test_explorer_rejects_malformed_issues(tmp_path: Path) -> None:
    target = _target(tmp_path)
    tasks = dispatch(build_function_index(target))
    store, explored = _stores(tmp_path)
    llm = MockLLM(routes=[], default='[{"function": "f", "bug_category": "x"}]')
    stats = explore(target, tasks, llm, store, explored, pool_size=2, max_retries=0)
    assert stats.candidates_new == 0
    assert stats.llm_failures == 2


def test_explorer_rejects_cwe_id_outside_subset(tmp_path: Path) -> None:
    target = _target(tmp_path)
    tasks = dispatch(build_function_index(target))
    store, explored = _stores(tmp_path)
    issue = (
        '[{"function": "f", "cwe_id": 9999, "bug_category": "x",'
        ' "description": "d", "trigger": "t"}]'
    )
    llm = MockLLM(routes=[], default=issue)
    stats = explore(target, tasks, llm, store, explored, pool_size=2, max_retries=1)
    assert stats.candidates_new == 0
    assert stats.llm_failures == 2
    assert store.count() == 0


def test_explorer_rejects_blank_text_fields(tmp_path: Path) -> None:
    target = _target(tmp_path)
    tasks = dispatch(build_function_index(target))
    store, explored = _stores(tmp_path)
    issue = (
        '[{"function": "   ", "cwe_id": 369, "bug_category": "x",'
        ' "description": "d", "trigger": "t"}]'
    )
    llm = MockLLM(routes=[], default=issue)
    stats = explore(target, tasks, llm, store, explored, pool_size=2, max_retries=1)
    assert stats.candidates_new == 0
    assert store.count() == 0
