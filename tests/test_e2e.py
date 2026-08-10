"""End-to-end: orchestrator over tests/fixtures/vuln_app with MockLLM + local sandbox.

No network, no containers. Covers the full loop (single exploration pass →
probe → audit gate → check → report), the "once" semantics (explored files are
skipped on resume; failed files are re-explored), and the idempotency
guarantee: running twice must not grow confirmed_bugs.
"""

import json
import sys
from pathlib import Path

from oceanids.config import PathsCfg, RunCfg, Settings
from oceanids.db import CandidateStore, ConfirmedStore, Database, ExploredFilesStore
from oceanids.llm.base import StageClients
from oceanids.llm.mock import MockLLM
from oceanids.models import CandidateStatus
from oceanids.orchestrator import run_pipeline

FIXTURE = Path(__file__).parent / "fixtures" / "vuln_app"

_AUDIT_OK = '{"verdict": "ok", "feedback": ""}'


def _settings(tmp_path: Path) -> Settings:
    return Settings(
        run=RunCfg(pool_size=2, sandbox="local", llm="mock", timeout_s=30),
        paths=PathsCfg(
            db=str(tmp_path / "oceanids.db"),
            probes_dir=str(tmp_path / "probes"),
            report=str(tmp_path / "report.md"),
        ),
    )


def _issue_json() -> str:
    return json.dumps(
        [
            {
                "function": "average",
                "cwe_id": 369,
                "bug_category": "division-by-zero",
                "description": "average([]) divides by len(numbers) which is zero",
                "trigger": "average([])",
            }
        ]
    )


def _probe_json() -> str:
    return json.dumps(
        {
            "interpreter": [sys.executable],
            "script": "import calculator\ncalculator.average([])\n",
        }
    )


def _llm() -> MockLLM:
    return MockLLM(
        routes=[
            ("AUDIT probe", _AUDIT_OK),
            ("PROBE for candidate", _probe_json()),
            ("EXPLORE file calculator.py", _issue_json()),
        ],
        default="[]",  # textutil.py: nothing found
    )


def test_e2e_full_pipeline(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    summary = run_pipeline(FIXTURE, settings, _llm())

    assert summary.tasks == 2  # calculator.py + textutil.py
    assert summary.files_skipped == 0
    assert summary.candidates_new == 1
    assert summary.probes == 1
    assert summary.audit_rejected == 0
    assert summary.confirmed_new == 1
    assert summary.rejected == 0

    db = Database(Path(settings.paths.db))
    candidates = CandidateStore(db)
    confirmed = ConfirmedStore(db)
    assert confirmed.count() == 1
    bug = confirmed.all()[0]
    candidate = candidates.get(bug.candidate_id)
    assert candidate is not None
    assert candidate.status is CandidateStatus.CONFIRMED
    assert candidate.function == "average"
    assert candidate.cwe_id == 369  # single source of CWE typing

    report = summary.report_path.read_text(encoding="utf-8")
    assert "average" in report
    assert "division-by-zero" in report
    assert "CWE-369: Divide By Zero" in report  # canonical CWE form
    assert "severity" not in report
    assert "priority" not in report


def test_e2e_idempotent_across_runs(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    run_pipeline(FIXTURE, settings, _llm())
    count_first = ConfirmedStore(Database(Path(settings.paths.db))).count()

    summary2 = run_pipeline(FIXTURE, settings, _llm())
    count_second = ConfirmedStore(Database(Path(settings.paths.db))).count()

    assert count_first == 1
    assert count_second == count_first  # no growth on re-run
    assert summary2.confirmed_new == 0


def test_e2e_explored_files_are_skipped_on_rerun(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    llm = _llm()
    run_pipeline(FIXTURE, settings, llm)
    calls_first = len(llm.calls)

    db = Database(Path(settings.paths.db))
    explored = ExploredFilesStore(db)
    assert explored.is_explored("calculator.py")
    assert explored.is_explored("textutil.py")

    summary2 = run_pipeline(FIXTURE, settings, llm)
    # Both files burned their chance in run 1: nothing is dispatched again.
    assert summary2.tasks == 0
    assert summary2.files_skipped == 2
    assert not any("EXPLORE" in call for call in llm.calls[calls_first:])


def test_e2e_failed_exploration_is_retried_next_run(tmp_path: Path) -> None:
    settings = _settings(tmp_path)
    broken = MockLLM(routes=[], default="not json")  # every explore call fails
    summary1 = run_pipeline(FIXTURE, settings, broken)

    assert summary1.candidates_new == 0
    db = Database(Path(settings.paths.db))
    explored = ExploredFilesStore(db)
    # Failure does not burn the chance: nothing is marked explored.
    assert not explored.is_explored("calculator.py")
    assert not explored.is_explored("textutil.py")

    summary2 = run_pipeline(FIXTURE, settings, _llm())
    # The failed files are explored again — and now yield the candidate.
    assert summary2.tasks == 2
    assert summary2.files_skipped == 0
    assert summary2.candidates_new == 1
    assert summary2.confirmed_new == 1


def test_e2e_stage_clients_route_each_stage(tmp_path: Path) -> None:
    """StageClients wiring: every stage talks only to its own backend."""
    settings = _settings(tmp_path)
    full = _llm()
    # Split the single scripted mock into three per-stage mocks.
    explorer_llm = MockLLM(
        routes=[("EXPLORE file calculator.py", full._routes[2][1])], default="[]"
    )
    probe_llm = MockLLM(routes=[("PROBE for candidate", full._routes[1][1])], default="[]")
    auditor_llm = MockLLM(routes=[("AUDIT probe", full._routes[0][1])], default="[]")
    clients = StageClients(explorer=explorer_llm, probe=probe_llm, auditor=auditor_llm)
    summary = run_pipeline(FIXTURE, settings, clients)

    assert summary.confirmed_new == 1
    assert any("EXPLORE" in call for call in explorer_llm.calls)
    assert any("PROBE" in call for call in probe_llm.calls)
    assert any("AUDIT" in call for call in auditor_llm.calls)
    # No cross-talk: each backend saw only its own stage's prompts.
    assert not any("PROBE" in call or "AUDIT" in call for call in explorer_llm.calls)
    assert not any("EXPLORE" in call or "AUDIT" in call for call in probe_llm.calls)
    assert not any("EXPLORE" in call or "PROBE for" in call for call in auditor_llm.calls)
