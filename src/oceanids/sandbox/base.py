"""Sandbox protocol and oracle primitives.

Separation of powers (docs/arch.puml): a sandbox only executes; it never
decides. Oracle derivation (exit code / sanitizer markers / top stack frames)
is pure data collection — the verdict belongs to the checker alone. The
pipeline runs on a frozen snapshot of the target (oceanids.freeze), so no
dependency hash lock is needed — drift is impossible by construction.
"""

import hashlib
import re
from collections.abc import Sequence
from dataclasses import dataclass
from typing import Protocol

# Substrings treated as sanitizer/analyser firings when seen on stdout/stderr.
SANITIZER_MARKERS: tuple[str, ...] = (
    "AddressSanitizer",
    "UndefinedBehaviorSanitizer",
    "ThreadSanitizer",
    "MemorySanitizer",
    "LeakSanitizer",
    "runtime error:",
    "Traceback (most recent call last)",
)

_FRAME_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r'File "(?P<loc>[^"]+)", line \d+'),  # Python traceback
    re.compile(r"(?P<loc>[\w./-]+:\d+)(?::\d+)?"),  # generic file:line[:col]
)

_TOP_FRAME_COUNT = 3


class SandboxUnavailableError(RuntimeError):
    """Raised when a configured sandbox backend cannot run on this host."""


@dataclass(frozen=True)
class ExecutionResult:
    """Raw outcome of one sandboxed execution; no judgement attached."""

    exit_code: int
    stdout: str
    stderr: str
    workdir: str
    timed_out: bool = False


class Sandbox(Protocol):
    """Execution-only backend. Implementations must not interpret results."""

    def run(self, command: Sequence[str], *, timeout_s: int) -> ExecutionResult:
        """Execute ``command`` in a fresh, clean environment."""
        ...


def detect_sanitizer_hits(text: str) -> tuple[str, ...]:
    """Sanitizer markers found in the combined output."""
    return tuple(marker for marker in SANITIZER_MARKERS if marker in text)


def extract_top_frames(text: str, *, workdir: str = "") -> tuple[str, ...]:
    """First ``_TOP_FRAME_COUNT`` source locations mentioned in ``text``.

    Sandbox workdir prefixes are normalised to ``$WORK`` so identical bugs
    produce identical evidence keys across runs (evidence dedup depends on it).
    """
    frames: list[str] = []
    for line in text.splitlines():
        for pattern in _FRAME_PATTERNS:
            match = pattern.search(line)
            if match is not None:
                loc = match.group("loc")
                if workdir:
                    loc = loc.replace(workdir, "$WORK")
                frames.append(loc)
                break
        if len(frames) >= _TOP_FRAME_COUNT:
            break
    return tuple(frames)


def make_evidence_key(frames: Sequence[str], stderr: str, *, workdir: str = "") -> str:
    """Stable dedup key: violation point / top-3 stack frames, hashed."""
    basis = "|".join(frames) if frames else stderr.replace(workdir, "$WORK")[:500]
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()
