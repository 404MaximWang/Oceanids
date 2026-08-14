"""dispatch: test-file exclusion and --submodule scoping."""

from pathlib import Path

from oceanids.pipeline.dispatch import dispatch
from oceanids.pipeline.function_index import FileIndex, FunctionIndex


def _index(*paths: str) -> FunctionIndex:
    return FunctionIndex(
        root=Path("."),
        files=tuple(
            FileIndex(path=p, language="python", line_count=1, functions=()) for p in paths
        ),
    )


def test_scope_filters_to_prefix() -> None:
    tasks = dispatch(_index("pkg/a.py", "pkg/sub/b.py", "other/c.py"), "pkg")
    assert [task.path for task in tasks] == ["pkg/a.py", "pkg/sub/b.py"]


def test_scope_dot_means_no_scope() -> None:
    tasks = dispatch(_index("a.py", "pkg/b.py"), ".")
    assert [task.path for task in tasks] == ["a.py", "pkg/b.py"]


def test_test_files_are_excluded() -> None:
    tasks = dispatch(_index("a.py", "tests/test_a.py", "b_test.py"))
    assert [task.path for task in tasks] == ["a.py"]
