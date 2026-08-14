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

# Structured markers a probe must print to stdout. Both are hard prerequisites
# for a confirmation: the checker never trusts a bare non-zero exit, because a
# probe that crashes on import (broken dependency) exits non-zero too.
PROBE_SETUP_MARKER = "OCEANIDS_PROBE_SETUP_OK"
PROBE_REACHED_MARKER = "OCEANIDS_PROBE_REACHED"

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


def detect_probe_markers(text: str) -> tuple[bool, bool]:
    """Probe contract markers found in the output: (setup_ok, reached).

    ``setup_ok`` proves the probe loaded the target and its dependencies
    intact; ``reached`` proves the trigger input entered the targeted path.
    """
    return (PROBE_SETUP_MARKER in text, PROBE_REACHED_MARKER in text)


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


def make_evidence_key(
    frames: Sequence[str], stderr: str, *, workdir: str = "", fallback: str = ""
) -> str:
    """Stable dedup key: violation point / top-3 stack frames, hashed.

    When neither frames nor stderr carry any signal (a silent crash: bare
    non-zero exit, empty output), the per-candidate ``fallback`` identity keeps
    the key unique — a constant empty-input hash would make evidence dedup
    swallow DISTINCT bugs as duplicates of the first silent crash.
    """
    if frames:
        basis = "|".join(frames)
    else:
        # str.replace with an empty pattern inserts everywhere — only
        # normalise when there is a real workdir prefix to strip.
        normalized = stderr.replace(workdir, "$WORK") if workdir else stderr
        stripped = normalized.strip()
        basis = stripped[:500] if stripped else f"silent:{fallback}"
    return hashlib.sha256(basis.encode("utf-8")).hexdigest()


def to_text(data: str | bytes | None) -> str:
    """Decode captured subprocess output (None/bytes/str) to text."""
    if data is None:
        return ""
    if isinstance(data, bytes):
        return data.decode("utf-8", "replace")
    return data
