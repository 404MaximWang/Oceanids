"""resolve_artifact_path: relative values anchor at .oceanids and cannot escape it."""

from pathlib import Path

import pytest

from oceanids.orchestrator import resolve_artifact_path


def test_relative_anchors_under_artifacts(tmp_path: Path) -> None:
    resolved = resolve_artifact_path(tmp_path, "report.md")
    assert resolved == (tmp_path / ".oceanids" / "report.md").resolve()


def test_dotdot_escape_is_rejected(tmp_path: Path) -> None:
    with pytest.raises(ValueError, match="escapes"):
        resolve_artifact_path(tmp_path, "../../outside.db")


def test_absolute_is_used_as_is(tmp_path: Path) -> None:
    assert resolve_artifact_path(tmp_path, "/tmp/abs.db") == Path("/tmp/abs.db")
