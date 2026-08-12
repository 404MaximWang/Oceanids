"""Launch ``oceanids run`` detached inside tmux (the ``--tmux`` flag).

The pipeline keeps its default interactive foreground behavior; --tmux opts
into a detached tmux session that replays the same command (via
``python -m oceanids``, flag stripped) with stdout/stderr redirected to
<target>/.oceanids/oceanids.log — the same artifacts dir every other path
anchors at (orchestrator.resolve_artifact_path), so the log location never
depends on the launch CWD or the tmux session's working directory. Missing
tmux is a hard error, not a fallback.
"""

import os
import shlex
import shutil
import subprocess
import sys
from pathlib import Path

from oceanids.freeze import ARTIFACTS_DIRNAME

LOG_FILENAME = "oceanids.log"


def log_path(target: str) -> Path:
    """The run log, anchored at <target>/.oceanids/ like every other artifact."""
    return Path(target).resolve() / ARTIFACTS_DIRNAME / LOG_FILENAME


def _session_name(target: str) -> str:
    """tmux session names reject '.' and ':'; keep it identifiable and unique."""
    base = Path(target).resolve().name or "run"
    safe = "".join(ch if ch.isalnum() or ch in "-_" else "-" for ch in base)
    return f"oceanids-{safe}-{os.getpid()}"


def launch_in_tmux(argv: list[str]) -> int:
    """Re-run ``argv`` (an ``oceanids run`` invocation) detached in tmux.

    Returns the process exit code: 2 when tmux is unavailable, 0 once the
    session was started (the pipeline's own outcome lands in the log file).
    """
    if shutil.which("tmux") is None:
        print(
            "oceanids: --tmux requested but tmux is not installed (not on PATH)",
            file=sys.stderr,
        )
        return 2
    child = [arg for arg in argv if arg != "--tmux"]
    target = child[child.index("run") + 1] if "run" in child else ""
    log = log_path(target)
    log.parent.mkdir(parents=True, exist_ok=True)
    inner = shlex.join([sys.executable, "-m", "oceanids", *child])
    session = _session_name(target)
    shell = f"{inner} > {shlex.quote(str(log))} 2>&1"
    subprocess.run(["tmux", "new-session", "-d", "-s", session, shell], check=True)
    print(f"[Oceanids] Detached tmux session: {session}")
    print(f"[Oceanids] Log: {log}  (tail -f to follow)")
    print(f"[Oceanids] Attach: tmux attach -t {session}")
    return 0
