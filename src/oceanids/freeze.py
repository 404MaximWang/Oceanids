"""Frozen target snapshot: drift becomes impossible by construction.

Typed rewrite of FM-Agent src/git.py's ``frozen_worktree`` (same technique): a
private git index (GIT_INDEX_FILE) snapshots HEAD + uncommitted edits +
untracked files into a throwaway commit, materialised via
``git worktree add --detach`` into a temp dir; non-git targets degrade to a
plain ``shutil.copytree``. The original repo's real index and working tree are
never touched, and the whole pipeline runs on the frozen copy — no downstream
hash lock is needed because the copy cannot drift.

Cleanup: the snapshot is removed on clean exit; on exception it is kept and
its path printed to stderr for debugging.
"""

import contextlib
import os
import shutil
import subprocess
import sys
import tempfile
from collections.abc import Iterator, Sequence
from pathlib import Path

# The pipeline's own artifacts dir (<target>/.oceanids/), always kept out of
# the snapshot. orchestrator.resolve_artifact_path anchors artifacts at the
# ORIGINAL target under this name, so the frozen copy must not duplicate them.
ARTIFACTS_DIRNAME = ".oceanids"

_SNAPSHOT_MESSAGE = "oceanids snapshot"


def _git(repo: Path, *args: str, env: dict[str, str] | None = None) -> str:
    return subprocess.run(
        ["git", "-C", str(repo), *args],
        check=True,
        capture_output=True,
        text=True,
        env=env,
    ).stdout.strip()


def _is_git_repo(path: Path) -> bool:
    """True when ``path`` is inside a git repository with at least one commit."""
    try:
        _git(path, "rev-parse", "--verify", "HEAD")
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False
    return True


@contextlib.contextmanager
def frozen_target(
    target: Path, *, exclude: Sequence[str] = (ARTIFACTS_DIRNAME,)
) -> Iterator[Path]:
    """Yield a frozen snapshot of ``target``'s current working-tree state.

    The snapshot captures committed state PLUS uncommitted edits and untracked
    files (via the private index, so gitignored paths are skipped the same way
    ``git add -A`` skips them). ``exclude`` directory names are kept out of the
    snapshot; the copytree fallback additionally ignores ``.git`` — a plain
    copy has no use for VCS internals.
    """
    target = target.resolve()
    # Include the repo name in the temp prefix so concurrent runs across
    # different targets are distinguishable (e.g. oceanids_wt_myrepo_a3k9d2/).
    repo_name = target.name or "repo"
    base = Path(tempfile.mkdtemp(prefix=f"oceanids_wt_{repo_name}_"))
    snapshot = base / "snapshot"
    is_git = _is_git_repo(target)
    try:
        if is_git:
            # Private index: the repo's own index file is never read or written.
            env = dict(os.environ, GIT_INDEX_FILE=str(base / "index"))
            _git(target, "read-tree", "HEAD", env=env)
            # Stage tracked edits + untracked files (gitignored paths skipped).
            _git(target, "add", "-A", env=env)
            if exclude:
                # Covers repos that do NOT gitignore the artifacts dir.
                _git(target, "rm", "-r", "--cached", "--quiet", "--ignore-unmatch",
                     "--", *exclude, env=env)
            tree = _git(target, "write-tree", env=env)
            commit = _git(target, "commit-tree", tree, "-p", "HEAD",
                          "-m", _SNAPSHOT_MESSAGE, env=env)
            _git(target, "worktree", "add", "--detach", str(snapshot), commit)
        else:
            shutil.copytree(
                target,
                snapshot,
                ignore=shutil.ignore_patterns(".git", *exclude),
                symlinks=True,
            )
        yield snapshot
    except BaseException:
        print(
            f"oceanids: frozen snapshot kept for debugging: {snapshot}",
            file=sys.stderr,
        )
        raise
    if is_git:
        # Unregister first so `git worktree list` in the original repo stays clean.
        subprocess.run(
            ["git", "-C", str(target), "worktree", "remove", "--force", str(snapshot)],
            check=False,
            capture_output=True,
        )
    shutil.rmtree(base, ignore_errors=True)
