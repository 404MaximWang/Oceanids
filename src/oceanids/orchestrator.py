"""Glue: discoverer → explorer pool → probe auditor → probe verifier → report.

Flow (docs/arch.puml): overview/dispatch → ONE exploration pass ("one file, one
agent, once" — only a successful round burns the file's chance; already
explored files are skipped on resume) → per pending candidate: probe generation
→ probe auditor gate (invalid probes go back for a bounded rewrite; budget
exhausted → candidate rejected, feedback kept) → checker verification →
markdown report.
"""

import sys
from dataclasses import dataclass
from pathlib import Path

from oceanids.config import Settings
from oceanids.db import CandidateStore, ConfirmedStore, Database, ExploredFilesStore
from oceanids.llm.base import LLMClient, StageClients
from oceanids.models import CandidateIssue, CandidateStatus, Probe, VerdictKind
from oceanids.pipeline import dispatch, explorer, probe_audit, probe_gen
from oceanids.pipeline.checker import Checker
from oceanids.pipeline.overview import build_overview
from oceanids.report import write_report
from oceanids.sandbox.base import Sandbox, hash_tree
from oceanids.sandbox.bwrap import BwrapSandbox
from oceanids.sandbox.local import LocalSandbox
from oceanids.sandbox.qemu import QemuSandbox


@dataclass(frozen=True)
class RunSummary:
    tasks: int
    files_skipped: int
    candidates_new: int
    candidates_dup: int
    probes: int
    audit_rejected: int
    confirmed_new: int
    rejected: int
    report_path: Path


def make_sandbox(backend: str, target_root: Path) -> Sandbox:
    """Build one sandbox instance for ``backend``; raises on unknown/unavailable."""
    if backend == "local":
        return LocalSandbox(target_root)
    if backend == "bwrap":
        return BwrapSandbox(target_root)
    if backend == "qemu":
        return QemuSandbox(target_root)
    raise ValueError(f"unknown sandbox backend: {backend!r}")


def _audit_gate(
    candidate: CandidateIssue,
    probe: Probe,
    target: Path,
    settings: Settings,
    clients: StageClients,
    candidates: CandidateStore,
    probes_dir: Path,
) -> tuple[str, Probe | None]:
    """The auditor loop; returns (outcome, probe).

    outcome is "ok" (probe passed, possibly after rewrites), "rejected"
    (rewrite budget exhausted — candidate marked rejected, auditor feedback
    kept as the reason), or "pending" (auditor/generator unavailable — candidate
    stays pending for a later run).
    """
    if candidate.id is None:
        raise ValueError("audit gate only accepts persisted candidates")
    rewrites_left = settings.run.probe_retries
    current: Probe | None = probe
    while current is not None:
        verdict = probe_audit.audit_probe(
            candidate, current, target, clients.auditor, max_retries=1
        )
        if verdict is None:
            return ("pending", None)
        if verdict.ok:
            return ("ok", current)
        if rewrites_left == 0:
            candidates.update_status(candidate.id, CandidateStatus.REJECTED)
            print(
                f"oceanids: candidate #{candidate.id} ({candidate.function}) rejected by "
                f"probe auditor after {settings.run.probe_retries} rewrites: "
                f"{verdict.feedback}",
                file=sys.stderr,
            )
            return ("rejected", None)
        rewrites_left -= 1
        print(
            f"oceanids: auditor sent probe for {candidate.function} back for rewrite "
            f"({rewrites_left} left): {verdict.feedback}",
            file=sys.stderr,
        )
        current = probe_gen.generate_probe(
            candidate, clients.probe, probes_dir,
            max_retries=settings.run.probe_retries,
            rewrite_feedback=verdict.feedback,
        )
    return ("pending", None)


def run_pipeline(target: Path, settings: Settings, llm: LLMClient | StageClients) -> RunSummary:
    """Run the whole harness against ``target`` and write the markdown report.

    ``llm`` is either one client used for every stage (single-backend wiring) or
    a StageClients fixed mapping routing explorer / probe_gen / auditor to their
    configured backends.
    """
    clients = llm if isinstance(llm, StageClients) else StageClients.uniform(llm)
    target = target.resolve()
    # Hard constraint: snapshot the dependency hash lock before any execution.
    dep_manifest = hash_tree(target)
    db = Database(Path(settings.paths.db))
    candidates = CandidateStore(db)
    confirmed = ConfirmedStore(db)
    explored = ExploredFilesStore(db)

    # One exploration pass: explore() itself skips already-explored files and
    # only marks files whose agent round succeeded.
    stats = explorer.explore(
        target, dispatch.dispatch(build_overview(target)), clients.explorer, candidates,
        explored, pool_size=settings.run.pool_size, max_retries=1,
    )

    probes_dir = Path(settings.paths.probes_dir)

    def sandbox_factory() -> Sandbox:
        return make_sandbox(settings.run.sandbox, target)

    checker = Checker(
        target, dep_manifest, sandbox_factory, candidates, confirmed,
        timeout_s=settings.run.timeout_s,
    )
    probes = audit_rejected = confirmed_new = rejected = 0
    for candidate in candidates.select_pending():
        probe = probe_gen.generate_probe(
            candidate, clients.probe, probes_dir, max_retries=settings.run.probe_retries
        )
        if probe is None:
            continue  # generation failed; candidate stays pending for the next run
        if settings.run.probe_audit:
            outcome, probe = _audit_gate(
                candidate, probe, target, settings, clients, candidates, probes_dir
            )
            if outcome == "rejected":
                audit_rejected += 1
                continue
            if probe is None:
                continue  # auditor/generator unavailable; stays pending
        probes += 1
        verdict = checker.verify(candidate, probe)
        if verdict.confirmed_id is not None:
            confirmed_new += 1
        elif verdict.kind is VerdictKind.FALSE_POSITIVE:
            rejected += 1

    report_path = write_report(confirmed, Path(settings.paths.report))
    return RunSummary(
        tasks=stats.files,
        files_skipped=stats.files_skipped,
        candidates_new=stats.candidates_new,
        candidates_dup=stats.candidates_dup,
        probes=probes,
        audit_rejected=audit_rejected,
        confirmed_new=confirmed_new,
        rejected=rejected,
        report_path=report_path,
    )
