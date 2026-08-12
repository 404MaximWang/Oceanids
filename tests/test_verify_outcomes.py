"""Verify-stage outcomes: generator refusal, evidence-less attempts, inconclusive.

Covers the FM-Agent-style lifecycle additions: the generator's structured
refusal (rejected with the reason persisted, auditor never consulted), the
attempt budget on evidence-less runs (setup failure / bare timeout), and the
terminal inconclusive state once the budget is exhausted.
"""

import json
import shutil
import sys
from pathlib import Path

from oceanids.config import PathsCfg, RunCfg, Settings
from oceanids.db import CandidateStore, ConfirmedStore, Database
from oceanids.llm.base import StageClients
from oceanids.llm.mock import MockLLM
from oceanids.models import CandidateStatus
from oceanids.orchestrator import run_pipeline
from oceanids.sandbox.base import PROBE_REACHED_MARKER, PROBE_SETUP_MARKER

FIXTURE = Path(__file__).parent / "fixtures" / "vuln_app"

_AUDIT_OK = '{"verdict": "ok", "feedback": ""}'

_EXPLORER = MockLLM(
    routes=[
        (
            "EXPLORE file calculator.py",
            json.dumps(
                [
                    {
                        "function": "average",
                        "cwe_id": 369,
                        "bug_category": "division-by-zero",
                        "description": "average([]) crashes on empty input",
                        "trigger": "average([])",
                    }
                ]
            ),
        )
    ],
    default="[]",
)


def _target(tmp_path: Path) -> Path:
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    return target


def _settings(tmp_path: Path, *, verify_attempts: int = 3) -> Settings:
    return Settings(
        run=RunCfg(
            pool_size=2,
            sandbox="local",
            llm="mock",
            timeout_s=30,
            verify_attempts=verify_attempts,
        ),
        paths=PathsCfg(
            db=str(tmp_path / "oceanids.db"),
            probes_dir=str(tmp_path / "probes"),
            report=str(tmp_path / "report.md"),
        ),
    )


def _clients(probe_response: str) -> tuple[StageClients, MockLLM]:
    probe = MockLLM(routes=[("PROBE for candidate", probe_response)], default="[]")
    auditor = MockLLM(routes=[("AUDIT probe", _AUDIT_OK)], default="[]")
    return StageClients(explorer=_EXPLORER, probe=probe, auditor=auditor), auditor


def test_generator_refusal_rejects_with_reason(tmp_path: Path) -> None:
    clients, auditor = _clients(
        json.dumps({"refuse": True, "reason": "no public entry point reaches average()"})
    )
    settings = _settings(tmp_path)
    summary = run_pipeline(_target(tmp_path), settings, clients)

    assert summary.generator_refused == 1
    assert summary.confirmed_new == 0
    assert auditor.calls == []  # refusal short-circuits before the audit gate
    candidate = CandidateStore(Database(Path(settings.paths.db))).all()[0]
    assert candidate.status is CandidateStatus.REJECTED
    assert candidate.reject_reason == "no public entry point reaches average()"
    assert ConfirmedStore(Database(Path(settings.paths.db))).count() == 0


_CRASH_ON_IMPORT_PROBE = json.dumps(
    {
        "interpreter": [sys.executable],
        # Passes static validation (marker literals present) but dies on
        # import — the markers never reach stdout, so nothing is provable.
        "script": (
            "import totally_missing_dep_xyz\n"
            f"print('{PROBE_SETUP_MARKER}')\n"
            f"print('{PROBE_REACHED_MARKER}')\n"
        ),
    }
)


def test_evidence_less_attempts_end_inconclusive(tmp_path: Path) -> None:
    clients, _ = _clients(_CRASH_ON_IMPORT_PROBE)
    settings = _settings(tmp_path, verify_attempts=2)
    target = _target(tmp_path)

    first = run_pipeline(target, settings, clients)
    assert first.setup_failures == 1
    assert first.inconclusive == 0
    candidate = CandidateStore(Database(Path(settings.paths.db))).all()[0]
    assert candidate.status is CandidateStatus.PENDING  # budget remains
    assert candidate.verify_attempts == 1

    second = run_pipeline(target, settings, clients)
    assert second.inconclusive == 1
    candidate = CandidateStore(Database(Path(settings.paths.db))).all()[0]
    assert candidate.status is CandidateStatus.INCONCLUSIVE
    assert candidate.verify_attempts == 2
    assert candidate.reject_reason is not None and "no evidence" in candidate.reject_reason
    assert ConfirmedStore(Database(Path(settings.paths.db))).count() == 0

    # Terminal: a third run must not retry an inconclusive candidate.
    third = run_pipeline(target, settings, clients)
    assert third.probes == 0
    assert third.setup_failures == 0
    assert third.inconclusive == 0
    candidate = CandidateStore(Database(Path(settings.paths.db))).all()[0]
    assert candidate.verify_attempts == 2  # untouched
