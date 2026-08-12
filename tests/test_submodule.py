"""--submodule: exploration scoped to one target-relative directory.

The function index and the agent-written overview always cover the whole
project; only the dispatched exploration tasks are filtered. Scoped runs
share the target's .oceanids db, so scoped passes compose with later
unscoped ones (already-explored files are skipped by path).
"""

import json
import shutil
from pathlib import Path

import pytest

from oceanids.cli import main
from oceanids.config import PathsCfg, RunCfg, Settings
from oceanids.db import Database, ExploredFilesStore
from oceanids.llm.mock import MockLLM
from oceanids.orchestrator import run_pipeline
from oceanids.pipeline.dispatch import dispatch
from oceanids.pipeline.function_index import FileIndex, FunctionIndex

FIXTURE = Path(__file__).parent / "fixtures" / "vuln_app"


def _index() -> FunctionIndex:
    files = tuple(
        FileIndex(path=p, language="python", line_count=10, functions=None)
        for p in ("a/x.py", "a/sub/y.py", "b/z.py", "a/test_x.py")
    )
    return FunctionIndex(root=Path("/tmp/whatever"), files=files)


def test_dispatch_scope_filters_by_directory() -> None:
    assert [t.path for t in dispatch(_index())] == ["a/x.py", "a/sub/y.py", "b/z.py"]
    assert [t.path for t in dispatch(_index(), "a")] == ["a/x.py", "a/sub/y.py"]
    assert [t.path for t in dispatch(_index(), "a/sub")] == ["a/sub/y.py"]
    assert dispatch(_index(), "c") == []
    # A trailing slash is tolerated; a prefix that is not a directory is not.
    assert [t.path for t in dispatch(_index(), "a/")] == ["a/x.py", "a/sub/y.py"]
    assert dispatch(_index(), "a/su") == []


def _settings(tmp_path: Path, submodule: str | None) -> Settings:
    return Settings(
        run=RunCfg(pool_size=2, sandbox="local", llm="mock", timeout_s=30,
                   submodule=submodule),
        paths=PathsCfg(
            db=str(tmp_path / "oceanids.db"),
            probes_dir=str(tmp_path / "probes"),
            report=str(tmp_path / "report.md"),
        ),
    )


def _llm() -> MockLLM:
    return MockLLM(
        routes=[
            (
                "EXPLORE file calculator.py",
                json.dumps(
                    [
                        {
                            "function": "average",
                            "cwe_id": 369,
                            "bug_category": "division-by-zero",
                            "description": "average([]) crashes on empty input",
                            "trigger": "average([])",
                        }
                    ]
                ),
            )
        ],
        default="[]",
    )


def test_scoped_run_explores_only_the_submodule(tmp_path: Path) -> None:
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    sub = target / "sub"
    sub.mkdir()
    (target / "textutil.py").rename(sub / "textutil.py")

    scoped = run_pipeline(target, _settings(tmp_path, "sub"), _llm())
    assert scoped.tasks == 1  # only sub/textutil.py; calculator.py out of scope
    assert scoped.candidates_new == 0  # the calculator.py candidate is outside
    explored = ExploredFilesStore(Database(tmp_path / "oceanids.db"))
    assert explored.is_explored("sub/textutil.py")
    assert not explored.is_explored("calculator.py")

    # A later unscoped run composes: the scoped file is skipped, the rest runs.
    full = run_pipeline(target, _settings(tmp_path, None), _llm())
    assert full.tasks == 1  # calculator.py only; sub/textutil.py already explored
    assert full.files_skipped == 1
    assert full.candidates_new == 1


def test_submodule_validation(tmp_path: Path) -> None:
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    with pytest.raises(SystemExit, match="escapes the target tree"):
        main(["run", str(target), "--submodule", "../elsewhere"])
    with pytest.raises(SystemExit, match="not a directory"):
        main(["run", str(target), "--submodule", "no-such-dir"])
