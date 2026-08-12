"""Probe auditor gate: ok / invalid-then-rewrite-ok / rewrite-budget-exhausted paths."""

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


def _target(tmp_path: Path) -> Path:
    """A private copy of the fixture — freezing it never touches this repo's git."""
    target = tmp_path / "target"
    shutil.copytree(FIXTURE, target)
    return target


def _settings(tmp_path: Path, *, probe_audit: bool = True, probe_retries: int = 2) -> Settings:
    return Settings(
        run=RunCfg(
            pool_size=2,
            sandbox="local",
            llm="mock",
            timeout_s=30,
            probe_audit=probe_audit,
            probe_retries=probe_retries,
        ),
        paths=PathsCfg(
            db=str(tmp_path / "oceanids.db"),
            probes_dir=str(tmp_path / "probes"),
            report=str(tmp_path / "report.md"),
        ),
    )


def _explorer_and_probe() -> tuple[MockLLM, MockLLM]:
    explorer = MockLLM(
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
    probe = MockLLM(
        routes=[
            (
                "PROBE for candidate",
                json.dumps(
                    {
                        "interpreter": [sys.executable],
                        "script": (
                            "import calculator\n"
                            f"print('{PROBE_SETUP_MARKER}')\n"
                            f"print('{PROBE_REACHED_MARKER}')\n"
                            "calculator.average([])\n"
                        ),
                    }
                ),
            )
        ],
        default="[]",
    )
    return explorer, probe


class _ScriptedAuditor:
    """Plays back a scripted list of verdicts, recording every prompt."""

    def __init__(self, verdicts: list[str]) -> None:
        self._verdicts = list(verdicts)
        self.calls: list[str] = []

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        if not self._verdicts:
            return '{"verdict": "ok", "feedback": ""}'
        return self._verdicts.pop(0)


def test_audit_ok_path_confirms(tmp_path: Path) -> None:
    explorer, probe = _explorer_and_probe()
    auditor = _ScriptedAuditor(['{"verdict": "ok", "feedback": ""}'])
    clients = StageClients(explorer=explorer, probe=probe, auditor=auditor)
    summary = run_pipeline(_target(tmp_path), _settings(tmp_path), clients)

    assert summary.confirmed_new == 1
    assert summary.audit_rejected == 0
    assert len(auditor.calls) == 1  # one probe, one audit, no rewrite


def test_audit_invalid_then_rewrite_ok(tmp_path: Path) -> None:
    explorer, probe = _explorer_and_probe()
    auditor = _ScriptedAuditor(
        [
            '{"verdict": "invalid", "feedback": "input never reaches the division"}',
            '{"verdict": "ok", "feedback": ""}',
        ]
    )
    clients = StageClients(explorer=explorer, probe=probe, auditor=auditor)
    summary = run_pipeline(_target(tmp_path), _settings(tmp_path), clients)

    assert summary.confirmed_new == 1
    assert summary.audit_rejected == 0
    assert len(auditor.calls) == 2
    # The rewrite carried the auditor's feedback back to probe_gen.
    assert any(
        "REJECTED by the auditor" in call and "input never reaches the division" in call
        for call in probe.calls
    )


def test_audit_rewrite_budget_exhausted_rejects_candidate(tmp_path: Path) -> None:
    explorer, probe = _explorer_and_probe()
    auditor = _ScriptedAuditor(
        ['{"verdict": "invalid", "feedback": "hard-coded expectation"}'] * 3
    )
    clients = StageClients(explorer=explorer, probe=probe, auditor=auditor)
    settings = _settings(tmp_path, probe_retries=2)
    summary = run_pipeline(_target(tmp_path), settings, clients)

    assert summary.confirmed_new == 0
    assert summary.audit_rejected == 1
    # Initial probe + 2 rewrites = 3 audits.
    assert len(auditor.calls) == 3
    db = Database(Path(settings.paths.db))
    candidate = CandidateStore(db).all()[0]
    assert candidate.status is CandidateStatus.REJECTED
    assert ConfirmedStore(db).count() == 0


def test_audit_disabled_skips_auditor(tmp_path: Path) -> None:
    explorer, probe = _explorer_and_probe()
    auditor = _ScriptedAuditor([])  # would answer ok anyway; must not be called
    clients = StageClients(explorer=explorer, probe=probe, auditor=auditor)
    summary = run_pipeline(_target(tmp_path), _settings(tmp_path, probe_audit=False), clients)

    assert summary.confirmed_new == 1
    assert auditor.calls == []


def test_audit_garbage_contract_leaves_candidate_pending(tmp_path: Path) -> None:
    explorer, probe = _explorer_and_probe()
    auditor = MockLLM(routes=[], default="not json")  # never a valid audit contract
    clients = StageClients(explorer=explorer, probe=probe, auditor=auditor)
    settings = _settings(tmp_path)
    summary = run_pipeline(_target(tmp_path), settings, clients)

    assert summary.confirmed_new == 0
    assert summary.audit_rejected == 0  # not rejected — just not actionable this run
    candidate = CandidateStore(Database(Path(settings.paths.db))).all()[0]
    assert candidate.status is CandidateStatus.PENDING
