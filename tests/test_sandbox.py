"""Sandbox backends: local execution, oracle helpers, bwrap/qemu guards."""

import shutil
import sys
from pathlib import Path

import pytest

from oceanids.sandbox.base import (
    SandboxUnavailableError,
    extract_top_frames,
    make_evidence_key,
)
from oceanids.sandbox.bwrap import BwrapSandbox
from oceanids.sandbox.local import LocalSandbox
from oceanids.sandbox.qemu import QemuSandbox


def _write_target(root: Path) -> None:
    (root / "mod.py").write_text(
        "def boom() -> None:\n    raise RuntimeError('x')\n", encoding="utf-8"
    )


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    target.mkdir()
    _write_target(target)
    return target


def test_local_sandbox_exit_zero(tmp_path: Path) -> None:
    target = _target(tmp_path)
    script = tmp_path / "ok.py"
    script.write_text("import mod\nprint('fine')\n", encoding="utf-8")
    result = LocalSandbox(target).run([sys.executable, str(script)], timeout_s=30)
    assert result.exit_code == 0
    assert result.stdout.strip() == "fine"
    assert not result.timed_out


def test_local_sandbox_captures_crash(tmp_path: Path) -> None:
    target = _target(tmp_path)
    script = tmp_path / "crash.py"
    script.write_text("import mod\nmod.boom()\n", encoding="utf-8")
    result = LocalSandbox(target).run([sys.executable, str(script)], timeout_s=30)
    assert result.exit_code != 0
    assert "Traceback (most recent call last)" in result.stderr
    assert "RuntimeError: x" in result.stderr


def test_local_sandbox_timeout(tmp_path: Path) -> None:
    target = _target(tmp_path)
    script = tmp_path / "slow.py"
    script.write_text("import time\ntime.sleep(30)\n", encoding="utf-8")
    result = LocalSandbox(target).run([sys.executable, str(script)], timeout_s=1)
    assert result.timed_out
    assert result.exit_code == -1


def test_local_sandbox_fresh_copy_per_run(tmp_path: Path) -> None:
    target = _target(tmp_path)
    script = tmp_path / "dirty.py"
    script.write_text(
        "from pathlib import Path\n"
        "marker = Path('leftover.txt')\n"
        "print('seen' if marker.exists() else 'clean')\n"
        "marker.write_text('x')\n",
        encoding="utf-8",
    )
    sandbox = LocalSandbox(target)
    first = sandbox.run([sys.executable, str(script)], timeout_s=30)
    second = sandbox.run([sys.executable, str(script)], timeout_s=30)
    assert first.stdout.strip() == "clean"
    assert second.stdout.strip() == "clean"  # no state leaks between runs


def test_extract_top_frames_normalises_workdir() -> None:
    stderr = (
        "Traceback (most recent call last):\n"
        '  File "/tmp/xyz/probe_1", line 2, in <module>\n'
        "    boom()\n"
        '  File "/tmp/xyz/target/mod.py", line 2, in boom\n'
        "RuntimeError: x\n"
    )
    frames = extract_top_frames(stderr, workdir="/tmp/xyz")
    assert frames == ("$WORK/probe_1", "$WORK/target/mod.py")
    # Same crash in a different workdir must produce the same evidence key.
    moved = stderr.replace("/tmp/xyz", "/tmp/other")
    moved_frames = extract_top_frames(moved, workdir="/tmp/other")
    assert make_evidence_key(frames, stderr, workdir="/tmp/xyz") == make_evidence_key(
        moved_frames, moved, workdir="/tmp/other"
    )


def test_bwrap_missing_binary_errors(tmp_path: Path) -> None:
    if shutil.which("bwrap") is not None:
        pytest.skip("bwrap installed; missing-binary path not testable")
    with pytest.raises(SandboxUnavailableError):
        BwrapSandbox(tmp_path)


def test_bwrap_command_construction(tmp_path: Path) -> None:
    if shutil.which("bwrap") is None:
        pytest.skip("bwrap not installed")
    sandbox = BwrapSandbox(tmp_path)
    command = sandbox.build_command(["/bin/true"])
    assert command[0].endswith("bwrap")
    assert "--ro-bind" in command
    assert command[-1] == "/bin/true"


def test_qemu_missing_binary_errors(tmp_path: Path) -> None:
    if shutil.which("qemu-system-x86_64") is not None:
        pytest.skip("qemu installed; missing-binary path not testable")
    with pytest.raises(SandboxUnavailableError):
        QemuSandbox(tmp_path).build_command(["/bin/true"])
