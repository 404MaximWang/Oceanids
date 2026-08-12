"""Verification stage pool: concurrency, serial-equivalence, failure isolation."""

import json
import shutil
import sys
import time
from pathlib import Path

from oceanids.config import PathsCfg, RunCfg, Settings
from oceanids.db import CandidateStore, ConfirmedStore, Database
from oceanids.llm.base import LLMClient, StageClients
from oceanids.llm.mock import MockLLM
from oceanids.models import CandidateIssue, CandidateStatus
from oceanids.orchestrator import VerifyStats, run_verify_stage
from oceanids.sandbox.base import PROBE_REACHED_MARKER, PROBE_SETUP_MARKER

FIXTURE = Path(__file__).parent / "fixtures" / "vuln_app"

_PROBE_JSON = json.dumps(
    {
        "interpreter": [sys.executable],
        "script": (
            "import calculator\n"
            f"print('{PROBE_SETUP_MARKER}')\n"
            f"print('{PROBE_REACHED_MARKER}')\n"
            "calculator.average([])\n"
        ),
    }
)
_AUDIT_OK = '{"verdict": "ok", "feedback": ""}'


def _mock() -> MockLLM:
    return MockLLM(
        routes=[("AUDIT probe", _AUDIT_OK), ("PROBE for candidate", _PROBE_JSON)],
        default="[]",
    )


class _SleepyLLM:
    """Wraps a client and stalls every call — makes concurrency measurable."""

    def __init__(self, inner: LLMClient, delay: float) -> None:
        self._inner = inner
        self._delay = delay

    def complete(self, prompt: str) -> str:
        time.sleep(self._delay)
        return self._inner.complete(prompt)


class _BoomLLM:
    """Raises on prompts containing the marker; complies otherwise."""

    def __init__(self, inner: LLMClient, marker: str) -> None:
        self._inner = inner
        self._marker = marker

    def complete(self, prompt: str) -> str:
        if self._marker in prompt:
            raise RuntimeError("boom")
        return self._inner.complete(prompt)


def _setup(tmp_path: Path, n: int) -> tuple[Path, Settings, CandidateStore, ConfirmedStore]:
    """A frozen stand-in (fixture copy) plus a DB with n pending candidates."""
    frozen = tmp_path / "frozen"
    shutil.copytree(FIXTURE, frozen)
    db = Database(tmp_path / "oceanids.db")
    candidates = CandidateStore(db)
    for i in range(n):
        candidates.insert(
            CandidateIssue(
                file="calculator.py",
                function=f"func_{i}",  # distinct (function, cwe_id) keys
                cwe_id=369,
                bug_category="division-by-zero",
                description=f"candidate {i}",
                trigger="average([])",
            )
        )
    settings = Settings(
        run=RunCfg(sandbox="local", llm="mock", timeout_s=30),
        paths=PathsCfg(probes_dir=str(tmp_path / "probes")),
    )
    return frozen, settings, candidates, ConfirmedStore(db)

def _run(
    frozen: Path,
    settings: Settings,
    candidates: CandidateStore,
    confirmed: ConfirmedStore,
    llm: LLMClient,
    pool_size: int,
) -> VerifyStats:
    settings.run.verify_pool_size = pool_size
    return run_verify_stage(
        candidates.select_pending(),
        frozen=frozen,
        settings=settings,
        clients=StageClients.uniform(llm),
        candidates=candidates,
        confirmed=confirmed,
        probes_dir=Path(settings.paths.probes_dir),
        overview="",
    )


def test_verify_pool_matches_serial_results(tmp_path: Path) -> None:
    """Same candidates, pool 1 vs pool 4: identical tallies and table contents."""
    serial = _run(*_setup(tmp_path / "serial", 4), _mock(), 1)
    parallel = _run(*_setup(tmp_path / "parallel", 4), _mock(), 4)

    # All four probes prove the same crash: first one confirms, the rest dedup.
    assert serial.probes == 4
    assert serial.confirmed_new == 1
    assert serial.failures == 0
    assert (parallel.probes, parallel.confirmed_new, parallel.failures) == (
        serial.probes,
        serial.confirmed_new,
        serial.failures,
    )
    assert ConfirmedStore(Database(tmp_path / "parallel" / "oceanids.db")).count() == 1


def test_verify_pool_is_actually_concurrent(tmp_path: Path) -> None:
    """A 0.2s-stalled LLM: pool of 4 must be far faster than serial for 4 candidates."""
    frozen, settings, candidates, confirmed = _setup(tmp_path / "serial", 4)
    start = time.monotonic()
    _run(frozen, settings, candidates, confirmed, _SleepyLLM(_mock(), 0.2), 1)
    serial_s = time.monotonic() - start

    frozen, settings, candidates, confirmed = _setup(tmp_path / "parallel", 4)
    start = time.monotonic()
    _run(frozen, settings, candidates, confirmed, _SleepyLLM(_mock(), 0.2), 4)
    parallel_s = time.monotonic() - start

    assert parallel_s < serial_s * 0.7, f"pool not faster: {parallel_s=:.2f} {serial_s=:.2f}"


def test_verify_pool_isolates_candidate_failures(tmp_path: Path) -> None:
    """One candidate raising mid-chain never sinks the pool; it stays pending."""
    frozen, settings, candidates, confirmed = _setup(tmp_path, 4)
    # Arm candidate func_1: its description carries the marker, so its probe
    # generation raises RuntimeError (call_structured only catches ValueError).
    doomed = next(c for c in candidates.select_pending() if c.function == "func_1")
    store_conn = candidates._db.conn  # test-only tweak via the store's connection
    store_conn.execute(
        "UPDATE candidate_issues SET description = 'BOOM' WHERE id = ?", (doomed.id,)
    )
    store_conn.commit()

    stats = _run(frozen, settings, candidates, confirmed, _BoomLLM(_mock(), "BOOM"), 4)

    assert stats.failures == 1
    assert stats.probes == 3  # the other three went through
    stored = candidates.get(doomed.id or 0)
    assert stored is not None and stored.status is CandidateStatus.PENDING
