"""Glue: discoverer → explorer pool → probe auditor → probe verifier → report.

Flow (docs/arch.puml): freeze the target (private-index git worktree snapshot,
copytree fallback for non-git dirs — drift is impossible by construction) →
overview/dispatch on the frozen copy → ONE exploration pass ("one file, one
agent, once" — only a successful round burns the file's chance; already
explored files are skipped on resume) → per pending candidate: probe generation
→ probe auditor gate (invalid probes go back for a bounded rewrite; budget
exhausted → candidate rejected, feedback kept) → checker verification →
markdown report.

Artifacts follow the target (FM-Agent's ``<proj_dir>/fm_agent/`` pattern):
relative ``paths.*`` values resolve under the ORIGINAL ``<target>/.oceanids/``
(not the frozen copy), so resume works from any CWD; absolute values are used
as-is.
"""

import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

from oceanids.config import Settings
from oceanids.db import CandidateStore, ConfirmedStore, Database, ExploredFilesStore
from oceanids.freeze import ARTIFACTS_DIRNAME, frozen_target
from oceanids.llm.base import LLMClient, StageClients
from oceanids.models import CandidateIssue, CandidateStatus, Probe, VerdictKind
from oceanids.pipeline import dispatch, explorer, probe_audit, probe_gen
from oceanids.pipeline.checker import Checker
from oceanids.pipeline.overview import build_overview
from oceanids.report import write_report
from oceanids.sandbox.base import Sandbox
from oceanids.sandbox.bwrap import BwrapSandbox
from oceanids.sandbox.local import LocalSandbox
from oceanids.sandbox.qemu import QemuSandbox


def resolve_artifact_path(target: Path, configured: str) -> Path:
    """Resolve one ``paths.*`` value: absolute stays, relative goes under the artifacts dir."""
    path = Path(configured)
    if path.is_absolute():
        return path
    return target / ARTIFACTS_DIRNAME / path


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
    verify_failures: int
    report_path: Path


@dataclass(frozen=True)
class VerifyStats:
    """Tallies of the concurrent verification stage."""

    probes: int
    audit_rejected: int
    confirmed_new: int
    rejected: int
    failures: int


def make_sandbox(backend: str, target_root: Path) -> Sandbox:
    """Build one sandbox instance for ``backend``; raises on unknown/unavailable."""
    if backend == "local":
        return LocalSandbox(target_root)
    if backend == "bwrap":
        return BwrapSandbox(target_root)
    if backend == "qemu":
        return QemuSandbox(target_root)
    raise ValueError(f"unknown sandbox backend: {backend!r}")


def _verify_chain(
    candidate: CandidateIssue,
    *,
    frozen: Path,
    settings: Settings,
    clients: StageClients,
    candidates: CandidateStore,
    checker: Checker,
    probes_dir: Path,
) -> str:
    """One candidate's full chain: generate → audit gate → sandbox verify.

    Returns a tally category: "pending" (kept for a later run), "audit_rejected",
    "confirmed", "rejected", or "duplicate" (proven but already represented).
    """
    probe = probe_gen.generate_probe(
        candidate, clients.probe, probes_dir, max_retries=settings.run.probe_retries
    )
    if probe is None:
        return "pending"  # generation failed; candidate stays pending for the next run
    if settings.run.probe_audit:
        outcome, probe = _audit_gate(
            candidate, probe, frozen, settings, clients, candidates, probes_dir
        )
        if outcome == "rejected":
            return "audit_rejected"
        if probe is None:
            return "pending"  # auditor/generator unavailable; stays pending
    verdict = checker.verify(candidate, probe)
    if verdict.confirmed_id is not None:
        return "confirmed"
    if verdict.kind is VerdictKind.FALSE_POSITIVE:
        return "rejected"
    return "duplicate"


def run_verify_stage(
    pending: list[CandidateIssue],
    *,
    frozen: Path,
    settings: Settings,
    clients: StageClients,
    candidates: CandidateStore,
    confirmed: ConfirmedStore,
    probes_dir: Path,
) -> VerifyStats:
    """Verify candidates concurrently (generate → audit → sandbox per candidate).

    Store connections are per-thread (Database hands them out via thread-local),
    the checker is stateless and builds a fresh sandbox per verification, and
    probe files are named by candidate id — so the chain is pool-safe. One
    candidate raising never sinks the pool: it is counted as a failure, left
    pending, and the rest proceed.
    """
    checker = Checker(
        frozen,
        lambda: make_sandbox(settings.run.sandbox, frozen),
        candidates,
        confirmed,
        timeout_s=settings.run.timeout_s,
    )
    tallies = {"confirmed": 0, "rejected": 0, "duplicate": 0, "audit_rejected": 0, "pending": 0}
    failures = 0
    done = 0
    total = len(pending)
    if total:
        print(
            f"[Oceanids] Verify stage: {total} pending candidate(s), "
            f"pool={settings.run.verify_pool_size}"
        )
    with ThreadPoolExecutor(max_workers=settings.run.verify_pool_size) as pool:
        futures = {
            pool.submit(
                _verify_chain,
                candidate,
                frozen=frozen,
                settings=settings,
                clients=clients,
                candidates=candidates,
                checker=checker,
                probes_dir=probes_dir,
            ): candidate
            for candidate in pending
        }
        for future in as_completed(futures):
            candidate = futures[future]
            done += 1
            try:
                outcome = future.result()
                tallies[outcome] += 1
                print(
                    f"[Oceanids] [{done}/{total}] candidate #{candidate.id} "
                    f"({candidate.function}) -> {outcome}"
                )
            except Exception as exc:  # noqa: BLE001 — pool isolation is the point
                failures += 1
                print(
                    f"[Oceanids] [{done}/{total}] candidate #{candidate.id} "
                    f"({candidate.function}) verification failed: {exc}",
                    file=sys.stderr,
                )
    return VerifyStats(
        probes=tallies["confirmed"] + tallies["rejected"] + tallies["duplicate"],
        audit_rejected=tallies["audit_rejected"],
        confirmed_new=tallies["confirmed"],
        rejected=tallies["rejected"],
        failures=failures,
    )


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
    # Artifacts anchor at the ORIGINAL target (the stable resume anchor); the
    # pipeline itself runs entirely on the frozen snapshot below.
    db_path = resolve_artifact_path(target, settings.paths.db)
    db_path.parent.mkdir(parents=True, exist_ok=True)
    db = Database(db_path)
    candidates = CandidateStore(db)
    confirmed = ConfirmedStore(db)
    explored = ExploredFilesStore(db)
    probes_dir = resolve_artifact_path(target, settings.paths.probes_dir)

    # Hard constraint: freeze the target before any analysis or execution.
    # Everything downstream reads/runs the frozen copy, so drift is impossible
    # by construction (no hash lock needed).
    with frozen_target(target) as frozen:
        print(f"[Oceanids] Frozen snapshot: {frozen}")
        # One exploration pass: explore() itself skips already-explored files and
        # only marks files whose agent round succeeded.
        stats = explorer.explore(
            frozen, dispatch.dispatch(build_overview(frozen)), clients.explorer, candidates,
            explored, pool_size=settings.run.pool_size, max_retries=1,
        )
        print(
            f"[Oceanids] Explore done: {stats.files} file(s) explored, "
            f"{stats.files_skipped} skipped (already explored), "
            f"+{stats.candidates_new} candidates ({stats.candidates_dup} dup, "
            f"{stats.llm_failures} failed)"
        )

        verify = run_verify_stage(
            candidates.select_pending(),
            frozen=frozen,
            settings=settings,
            clients=clients,
            candidates=candidates,
            confirmed=confirmed,
            probes_dir=probes_dir,
        )

    report_path = write_report(confirmed, resolve_artifact_path(target, settings.paths.report))
    print(f"[Oceanids] Report written: {report_path}")
    return RunSummary(
        tasks=stats.files,
        files_skipped=stats.files_skipped,
        candidates_new=stats.candidates_new,
        candidates_dup=stats.candidates_dup,
        probes=verify.probes,
        audit_rejected=verify.audit_rejected,
        confirmed_new=verify.confirmed_new,
        rejected=verify.rejected,
        verify_failures=verify.failures,
        report_path=report_path,
    )
