"""Frozen target snapshot: git worktree snapshot, copytree fallback, cleanup."""

import shutil
import subprocess
from pathlib import Path

import pytest

from oceanids.freeze import frozen_target

needs_git = pytest.mark.skipif(shutil.which("git") is None, reason="git binary not available")


def _git(repo: Path, *args: str) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args], check=True, capture_output=True, text=True
    ).stdout.strip()


def _git_repo(tmp_path: Path) -> Path:
    """A scratch repo under tmp_path (never the Oceanids repo itself)."""
    repo = tmp_path / "repo"
    repo.mkdir()
    _git(repo, "init", "-q")
    _git(repo, "config", "user.email", "test@example.com")
    _git(repo, "config", "user.name", "test")
    (repo / "app.py").write_text("def f() -> int:\n    return 1\n", encoding="utf-8")
    _git(repo, "add", "app.py")
    _git(repo, "commit", "-q", "-m", "initial")
    return repo


@needs_git
def test_git_snapshot_captures_edits_and_untracked(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    # Uncommitted edit + untracked file + the artifacts dir with run output.
    (repo / "app.py").write_text("def f() -> int:\n    return 2\n", encoding="utf-8")
    (repo / "new.py").write_text("def g() -> None:\n    pass\n", encoding="utf-8")
    (repo / ".oceanids").mkdir()
    (repo / ".oceanids" / "oceanids.db").write_text("db", encoding="utf-8")
    status_before = _git(repo, "status", "--porcelain")

    with frozen_target(repo) as snapshot:
        assert (snapshot / "app.py").read_text(encoding="utf-8") == (
            "def f() -> int:\n    return 2\n"
        )
        assert (snapshot / "new.py").is_file()  # untracked files are captured
        assert not (snapshot / ".oceanids").exists()  # artifacts stay out of the snapshot

    # The original repo's index and working tree were never touched.
    assert _git(repo, "status", "--porcelain") == status_before
    assert (repo / "app.py").read_text(encoding="utf-8") == "def f() -> int:\n    return 2\n"
    # The temporary worktree registration is gone from the original repo.
    assert _git(repo, "worktree", "list", "--porcelain").count("worktree ") == 1


@needs_git
def test_git_snapshot_removed_on_clean_exit(tmp_path: Path) -> None:
    repo = _git_repo(tmp_path)
    with frozen_target(repo) as snapshot:
        assert snapshot.is_dir()
        base = snapshot.parent
    assert not base.exists()


def test_non_git_copytree_fallback(tmp_path: Path) -> None:
    target = tmp_path / "plain"
    target.mkdir()
    (target / "app.py").write_text("def f() -> None:\n    pass\n", encoding="utf-8")
    (target / ".git").mkdir()  # stray VCS internals; not a real repo
    (target / ".git" / "HEAD").write_text("x", encoding="utf-8")
    (target / ".oceanids").mkdir()
    (target / ".oceanids" / "report.md").write_text("r", encoding="utf-8")

    with frozen_target(target) as snapshot:
        assert (snapshot / "app.py").is_file()
        assert not (snapshot / ".git").exists()  # a plain copy needs no VCS internals
        assert not (snapshot / ".oceanids").exists()  # artifacts stay out
        base = snapshot.parent
    assert not base.exists()  # cleaned on exit


def test_snapshot_kept_on_exception(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    target = tmp_path / "plain"
    target.mkdir()
    (target / "app.py").write_text("x = 1\n", encoding="utf-8")
    with pytest.raises(RuntimeError, match="boom"), frozen_target(target) as snapshot:
        raise RuntimeError("boom")
    assert snapshot.is_dir()  # kept for debugging, path reported on stderr
    assert "frozen snapshot kept for debugging" in capsys.readouterr().err
    shutil.rmtree(snapshot.parent)  # manual cleanup of the kept snapshot
