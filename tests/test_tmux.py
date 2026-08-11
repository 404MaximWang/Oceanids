"""--tmux launcher: hard error without tmux, command construction, real launch."""

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from oceanids import tmux as tmux_mod
from oceanids.tmux import _session_name, launch_in_tmux


def test_missing_tmux_errors_out(
    monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    assert launch_in_tmux(["run", "/tmp/whatever", "--tmux"]) == 2
    assert "tmux is not installed" in capsys.readouterr().err


def test_command_construction(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(shutil, "which", lambda _name: "/fake/tmux")
    monkeypatch.setattr(tmux_mod, "LOG_PATH", tmp_path / ".oceanids" / "oceanids.log")
    calls: list[list[str]] = []

    def _fake_run(argv: list[str], **kw: object) -> subprocess.CompletedProcess[str]:
        calls.append(argv)
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(subprocess, "run", _fake_run)

    rc = launch_in_tmux(["run", "/tmp/my proj", "--tmux", "--db", "x.db", "--sandbox", "local"])

    assert rc == 0
    (argv,) = calls
    assert argv[:4] == ["tmux", "new-session", "-d", "-s"]
    shell = argv[5]
    assert f"{sys.executable} -m oceanids run" in shell
    assert "--tmux" not in shell  # flag stripped from the replayed command
    assert "--db x.db" in shell and "--sandbox local" in shell
    assert shell.endswith(f"> {tmp_path}/.oceanids/oceanids.log 2>&1")
    assert (tmp_path / ".oceanids").is_dir()
    out = capsys.readouterr().out
    assert "tmux attach -t" in out


def test_session_name_sanitized() -> None:
    name = _session_name("/tmp/we:ird.proj")
    assert name.startswith("oceanids-we-ird-proj-")
    assert "." not in name.removeprefix("oceanids-") and ":" not in name


@pytest.mark.skipif(shutil.which("tmux") is None, reason="tmux not installed")
def test_real_tmux_launch(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """End-to-end against real tmux: the detached session writes the log."""
    monkeypatch.setattr(tmux_mod, "LOG_PATH", tmp_path / ".oceanids" / "oceanids.log")
    monkeypatch.chdir(tmp_path)
    # Replaying a guaranteed-to-fail run still exercises the full plumbing:
    # tmux session starts, child runs, output lands in the log.
    rc = launch_in_tmux(["run", str(tmp_path / "empty-target"), "--llm", "mock"])
    assert rc == 0
    for _ in range(50):
        if tmux_mod.LOG_PATH.exists() and tmux_mod.LOG_PATH.stat().st_size > 0:
            break
        import time

        time.sleep(0.1)
    assert tmux_mod.LOG_PATH.exists()
