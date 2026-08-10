"""pi backend: badlogic pi-mono terminal coding agent, driven as a CLI subprocess.

The boilerplate follows FM-Agent's cli_backend.py (rewritten typed): a frozen
dataclass describing argv + stdin, subprocess execution with a timeout, and
failures raised with the last few thousand characters of output attached.

NOTE: the default command template ``["pi", "-p"]`` has NOT been verified
against a real pi installation — it lives in the config ([llm.pi].command)
precisely so the verified flags can be dropped in without a code change.
"""

import shlex
import shutil
import subprocess
from collections.abc import Sequence
from dataclasses import dataclass

from oceanids.llm.base import LLMBackendError

#: How many trailing output characters are attached to a failure error.
ERROR_TAIL_CHARS = 4000


@dataclass(frozen=True)
class PiCommand:
    """One pi invocation: the argv plus the prompt fed to stdin."""

    argv: tuple[str, ...]
    stdin: str

    def display(self) -> str:
        return shlex.join(self.argv) + " <stdin>"


class PiCLILLM:
    """LLMClient that pipes each prompt to the pi CLI's stdin and returns stdout."""

    def __init__(self, command: Sequence[str] = ("pi", "-p"), *, timeout_s: int = 600) -> None:
        if not command:
            raise LLMBackendError("backend 'pi' requires a non-empty command template")
        self._command = tuple(command)
        self._timeout_s = timeout_s

    def build_command(self, prompt: str) -> PiCommand:
        """The command for one prompt: template argv unchanged, prompt via stdin."""
        return PiCommand(argv=self._command, stdin=prompt)

    def complete(self, prompt: str) -> str:
        command = self.build_command(prompt)
        binary = command.argv[0]
        if shutil.which(binary) is None:
            raise LLMBackendError(
                f"backend 'pi' selected but the {binary!r} binary was not found in PATH; "
                "install pi or fix llm.pi.command"
            )
        try:
            proc = subprocess.run(
                list(command.argv),
                input=command.stdin,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=self._timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            raise LLMBackendError(
                f"backend 'pi' timed out after {self._timeout_s}s running "
                f"{command.display()}"
            ) from exc
        if proc.returncode != 0:
            tail = (proc.stdout or "")[-ERROR_TAIL_CHARS:]
            raise LLMBackendError(
                f"backend 'pi' exited with code {proc.returncode} running "
                f"{command.display()}: {tail}"
            )
        return proc.stdout.strip()
