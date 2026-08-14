"""overview.md: reuse existing / generate on missing / one retry / then abort."""

from pathlib import Path

import pytest

from oceanids.llm.mock import MockLLM
from oceanids.pipeline.function_index import FileIndex, FunctionIndex
from oceanids.pipeline.overview import OverviewError, load_or_generate


def _index() -> FunctionIndex:
    return FunctionIndex(
        root=Path("."),
        files=(FileIndex(path="app.py", language="python", line_count=10, functions=()),),
    )


def test_existing_overview_is_reused(tmp_path: Path) -> None:
    path = tmp_path / "overview.md"
    path.write_text("# existing overview\n", encoding="utf-8")
    llm = MockLLM(routes=[], default="generated")

    text = load_or_generate(_index(), llm, path)

    assert text == "# existing overview\n"
    assert llm.calls == []  # no regeneration when the file is already there


def test_empty_overview_file_is_regenerated(tmp_path: Path) -> None:
    """A zero-byte leftover must not be injected into every later prompt."""
    path = tmp_path / "overview.md"
    path.write_text("", encoding="utf-8")
    llm = MockLLM(routes=[], default="# regenerated\n")

    text = load_or_generate(_index(), llm, path)

    assert text == "# regenerated\n"
    assert len(llm.calls) == 1


def test_missing_overview_is_generated_and_written(tmp_path: Path) -> None:
    path = tmp_path / "overview.md"
    llm = MockLLM(routes=[], default="# generated overview\n")

    text = load_or_generate(_index(), llm, path)

    assert text == "# generated overview\n"
    assert path.read_text(encoding="utf-8") == text
    assert len(llm.calls) == 1


def test_empty_generation_is_retried_exactly_once(tmp_path: Path) -> None:
    path = tmp_path / "overview.md"
    llm = MockLLM(routes=[], default="")
    responses = iter(["", "# retry worked\n"])
    llm.complete = lambda prompt: (llm.calls.append(prompt), next(responses))[1]

    text = load_or_generate(_index(), llm, path)

    assert text == "# retry worked\n"
    assert len(llm.calls) == 2  # first try + the single retry


def test_still_missing_after_retry_aborts(tmp_path: Path) -> None:
    path = tmp_path / "overview.md"
    llm = MockLLM(routes=[], default="")

    with pytest.raises(OverviewError):
        load_or_generate(_index(), llm, path)

    assert len(llm.calls) == 2  # burned both attempts, then gave up
    assert not path.exists()
