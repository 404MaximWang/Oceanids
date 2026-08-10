"""bubblewrap sandbox backend: command construction plus execution.

Selected for regular untrusted workloads. Raises SandboxUnavailableError with a
clear message when the bwrap binary is not installed.
"""

import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from oceanids.sandbox.base import ExecutionResult, SandboxUnavailableError

SANDBOX_TARGET = "/target"


class BwrapSandbox:
    """Executes probes under bubblewrap: read-only target, private tmp, no network."""

    def __init__(self, target_root: Path) -> None:
        binary = shutil.which("bwrap")
        if binary is None:
            raise SandboxUnavailableError(
                "sandbox backend 'bwrap' selected but the bwrap binary was not found in "
                "PATH; install bubblewrap or use --sandbox local"
            )
        self._binary = binary
        self._target_root = target_root.resolve()

    def build_command(self, command: Sequence[str]) -> list[str]:
        """Read-only bind of the target, private tmpfs, unshared namespaces."""
        return [
            self._binary,
            "--die-with-parent",
            "--unshare-all",
            "--ro-bind",
            str(self._target_root),
            SANDBOX_TARGET,
            "--tmpfs",
            "/tmp",
            "--chdir",
            SANDBOX_TARGET,
            "--",
            *command,
        ]

    def run(self, command: Sequence[str], *, timeout_s: int) -> ExecutionResult:
        try:
            proc = subprocess.run(
                self.build_command(command),
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return ExecutionResult(
                exit_code=-1, stdout="", stderr="", workdir=SANDBOX_TARGET, timed_out=True
            )
        return ExecutionResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            workdir=SANDBOX_TARGET,
        )
