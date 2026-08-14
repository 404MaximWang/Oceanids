"""Local sandbox: subprocess in a fresh temporary copy of the target tree.

Development fallback that runs anywhere (including macOS). Cleanliness comes
from rebuilding the work directory from scratch on every run; isolation is
weak by design — untrusted workloads belong on bwrap/qemu.
"""

import os
import shutil
import subprocess
import tempfile
from collections.abc import Sequence
from pathlib import Path

from oceanids.sandbox.base import ExecutionResult, to_text

TARGET_DIR_NAME = "target"


class LocalSandbox:
    """Runs one command per call inside a brand-new temp work directory."""

    def __init__(self, target_root: Path) -> None:
        self._target_root = target_root

    def run(self, command: Sequence[str], *, timeout_s: int) -> ExecutionResult:
        with tempfile.TemporaryDirectory(prefix="oceanids-") as tmp:
            workdir = Path(tmp)
            shutil.copytree(self._target_root, workdir / TARGET_DIR_NAME)
            env = dict(os.environ)
            # Language-agnostic escape hatch plus the common import path knob.
            env["OCEANIDS_TARGET"] = str(workdir / TARGET_DIR_NAME)
            env["PYTHONPATH"] = (
                str(workdir / TARGET_DIR_NAME) + os.pathsep + env.get("PYTHONPATH", "")
            )
            try:
                proc = subprocess.run(
                    list(command),
                    cwd=workdir,
                    env=env,
                    capture_output=True,
                    text=True,
                    timeout=timeout_s,
                    check=False,
                )
            except subprocess.TimeoutExpired as exc:
                return ExecutionResult(
                    exit_code=-1,
                    stdout=to_text(exc.stdout),
                    stderr=to_text(exc.stderr),
                    workdir=str(workdir),
                    timed_out=True,
                )
            return ExecutionResult(
                exit_code=proc.returncode,
                stdout=proc.stdout,
                stderr=proc.stderr,
                workdir=str(workdir),
            )
