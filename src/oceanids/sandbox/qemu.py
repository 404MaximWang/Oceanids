"""QEMU backend (EXPERIMENTAL): full-VM command construction for high-risk probes.

v1 only builds the command line; actually booting a guest is left to a
follow-up, so run() always raises SandboxUnavailableError. Requires a guest
kernel and disk image, neither of which is wired into the config yet.
"""

import shutil
from collections.abc import Sequence
from pathlib import Path

from oceanids.sandbox.base import ExecutionResult, SandboxUnavailableError


class QemuSandbox:
    """EXPERIMENTAL — do not select for production runs."""

    def __init__(
        self,
        target_root: Path,
        *,
        kernel: Path | None = None,
        image: Path | None = None,
    ) -> None:
        self._target_root = target_root
        self._kernel = kernel
        self._image = image

    def _binary(self) -> str:
        binary = shutil.which("qemu-system-x86_64")
        if binary is None:
            raise SandboxUnavailableError(
                "sandbox backend 'qemu' is experimental and requires qemu-system-x86_64 "
                "in PATH (not found); use --sandbox local"
            )
        return binary

    def build_command(self, command: Sequence[str]) -> list[str]:
        """Construct the qemu-system-x86_64 invocation for one probe run."""
        binary = self._binary()
        if self._kernel is None or self._image is None:
            raise SandboxUnavailableError(
                "sandbox backend 'qemu' is experimental: configure a guest kernel and "
                "disk image before running probes under it"
            )
        return [
            binary,
            "-kernel",
            str(self._kernel),
            "-drive",
            f"file={self._image},format=qcow2,if=virtio",
            "-nographic",
            "-m",
            "1024",
            "-virtfs",
            f"local,path={self._target_root},mount_tag=target,security_model=none,readonly=on",
            # The guest-side probe command is conveyed via the kernel append line in v1.
            "-append",
            "console=ttyS0 oceanids.probe=" + " ".join(command),
        ]

    def run(self, command: Sequence[str], *, timeout_s: int) -> ExecutionResult:
        raise SandboxUnavailableError(
            "sandbox backend 'qemu' is experimental: guest execution is not wired up in "
            f"v1 (would run: {self.build_command(command)!r}, timeout {timeout_s}s)"
        )
