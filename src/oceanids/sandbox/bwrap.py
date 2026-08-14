"""bubblewrap sandbox backend: command construction plus execution.

Selected for regular untrusted workloads. Raises SandboxUnavailableError with a
clear message when the bwrap binary is not installed.

bwrap starts from an empty root: only explicitly bound paths exist inside.
Besides the read-only target bind, we therefore bind the host system dirs an
interpreter needs (/usr, /lib, /lib64, /bin, /sbin — whichever exist) and every
existing absolute path on the command line at its original location (the probe
script itself, an absolute interpreter binary), so commands composed on the
host work unchanged inside.
"""

import shutil
import subprocess
from collections.abc import Sequence
from pathlib import Path

from oceanids.sandbox.base import ExecutionResult, SandboxUnavailableError, to_text

SANDBOX_TARGET = "/target"

#: Host dirs an interpreter/runtime typically needs; bound read-only when present.
_SYSTEM_BINDS = ("/usr", "/lib", "/lib64", "/bin", "/sbin")


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
        """Read-only binds (system dirs, target, absolute path args), private tmpfs."""
        argv = [self._binary, "--die-with-parent", "--unshare-all"]
        for directory in _SYSTEM_BINDS:
            if Path(directory).is_dir():
                argv += ["--ro-bind", directory, directory]
        argv += ["--ro-bind", str(self._target_root), SANDBOX_TARGET]
        # Command args that name existing host files (probe script, absolute
        # interpreter path) must exist inside at the same location.
        for arg in command:
            path = Path(arg)
            if path.is_absolute() and path.exists():
                argv += ["--ro-bind", str(path), str(path)]
        argv += [
            "--tmpfs",
            "/tmp",
            "--setenv",
            "OCEANIDS_TARGET",
            SANDBOX_TARGET,
            # The probe lives outside /target: its sys.path[0] is its own dir,
            # so target imports need this knob (same role as in LocalSandbox).
            "--setenv",
            "PYTHONPATH",
            SANDBOX_TARGET,
            "--chdir",
            SANDBOX_TARGET,
            "--",
            *command,
        ]
        return argv

    def run(self, command: Sequence[str], *, timeout_s: int) -> ExecutionResult:
        try:
            proc = subprocess.run(
                self.build_command(command),
                capture_output=True,
                text=True,
                timeout=timeout_s,
                check=False,
            )
        except subprocess.TimeoutExpired as exc:
            # Keep partial output: a hang-style probe prints its markers BEFORE
            # hanging, and the checker reads them from the captured text.
            return ExecutionResult(
                exit_code=-1,
                stdout=to_text(exc.stdout),
                stderr=to_text(exc.stderr),
                workdir=SANDBOX_TARGET,
                timed_out=True,
            )
        return ExecutionResult(
            exit_code=proc.returncode,
            stdout=proc.stdout,
            stderr=proc.stderr,
            workdir=SANDBOX_TARGET,
        )
