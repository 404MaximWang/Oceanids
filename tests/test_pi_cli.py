"""PiCLILLM: argv construction, stdin prompt, error tails; real pi gated by shutil.which."""

import shutil
import stat
from pathlib import Path

import pytest

from oceanids.llm.base import LLMBackendError
from oceanids.llm.pi_cli import PiCLILLM


def _script(tmp_path: Path, body: str) -> str:
    path = tmp_path / "fake_pi"
    path.write_text(body, encoding="utf-8")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)
    return str(path)


def test_build_command_uses_template_and_stdin() -> None:
    llm = PiCLILLM(["pi", "-p"], timeout_s=5)
    command = llm.build_command("hello prompt")
    assert command.argv == ("pi", "-p")
    assert command.stdin == "hello prompt"
    assert command.display() == "pi -p <stdin>"


def test_complete_pipes_prompt_and_returns_stdout(tmp_path: Path) -> None:
    fake = _script(tmp_path, "#!/bin/bash\ncat\n")
    llm = PiCLILLM([fake], timeout_s=10)
    assert llm.complete("ping") == "ping"


def test_complete_runs_in_pinned_cwd(tmp_path: Path) -> None:
    workdir = tmp_path / "target"
    workdir.mkdir()
    fake = _script(tmp_path, "#!/bin/bash\npwd\n")
    llm = PiCLILLM([fake], timeout_s=10, cwd=workdir)
    assert Path(llm.complete("x")).resolve() == workdir.resolve()


def test_nonzero_exit_raises_with_output_tail(tmp_path: Path) -> None:
    fake = _script(tmp_path, "#!/bin/bash\nhead -c 9000 /dev/zero | tr '\\0' E\nexit 3\n")
    llm = PiCLILLM([fake], timeout_s=10)
    with pytest.raises(LLMBackendError) as excinfo:
        llm.complete("x")
    message = str(excinfo.value)
    assert "code 3" in message
    assert "E" * 100 in message  # tail content preserved
    assert len(message) < 6000  # but truncated to the 4000-char tail, not the full 9000


def test_timeout_raises(tmp_path: Path) -> None:
    fake = _script(tmp_path, "#!/bin/bash\nsleep 30\n")
    llm = PiCLILLM([fake], timeout_s=1)
    with pytest.raises(LLMBackendError, match="timed out"):
        llm.complete("x")


def test_missing_binary_errors() -> None:
    llm = PiCLILLM(["definitely-not-a-real-pi-binary-xyz"], timeout_s=1)
    with pytest.raises(LLMBackendError, match="not found in PATH"):
        llm.complete("x")


def test_real_pi_integration() -> None:
    if shutil.which("pi") is None:
        pytest.skip("pi not installed")
    answer = PiCLILLM(["pi", "-p"], timeout_s=60).complete("Reply with exactly: ok")
    assert "ok" in answer.lower()
