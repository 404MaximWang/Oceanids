"""Glue: discoverer → explorer pool → probe auditor → probe verifier → report.

Flow (docs/arch.puml): freeze the target (private-index git worktree snapshot,
copytree fallback for non-git dirs — drift is impossible by construction) →
function index / dispatch on the frozen copy → agent-written overview.md (one
retry, then abort — injected into every later agent's context) → ONE
exploration pass ("one file, one agent, once" — only a successful round burns
the file's chance; already explored files are skipped on resume) → per pending
candidate: probe generation
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
from oceanids.models import (
    CandidateIssue,
    CandidateStatus,
    Probe,
    ProbeRefusal,
    VerdictKind,
)
from oceanids.pipeline import dispatch, explorer, overview, probe_audit, probe_gen
from oceanids.pipeline.checker import Checker
from oceanids.pipeline.function_index import build_function_index
from oceanids.report import write_report
from oceanids.sandbox.base import PROBE_REACHED_MARKER, Sandbox
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
    generator_refused: int
    confirmed_new: int
    rejected: int
    setup_failures: int
    inconclusive: int
    verify_failures: int
    report_path: Path


@dataclass(frozen=True)
class VerifyStats:
    """Tallies of the concurrent verification stage."""

    probes: int
    audit_rejected: int
    generator_refused: int
    confirmed_new: int
    rejected: int
    setup_failures: int
    inconclusive: int
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
    overview: str,
) -> str:
    """One candidate's full chain: generate → audit gate → sandbox verify.

    Returns a tally category: "pending" (kept for a later run), "audit_rejected",
    "confirmed", "rejected", "duplicate" (proven but already represented),
    "generator_refused" (the generator refused with a reason — candidate
    rejected, reason persisted), "setup_failure" (probe never proved its
    environment intact — attempt counted, candidate stays pending), or
    "inconclusive" (attempt budget exhausted without evidence either way).
    """
    probe = probe_gen.generate_probe(
        candidate, clients.probe, probes_dir,
        max_retries=settings.run.probe_retries, overview=overview,
    )
    if probe is None:
        return "pending"  # generation failed; candidate stays pending for the next run
    if isinstance(probe, ProbeRefusal):
        # The generator's structured refusal: an auditable opinion, persisted
        # as the reject reason — never a silent skip.
        candidates.update_status(candidate.id, CandidateStatus.REJECTED, probe.reason)
        print(
            f"oceanids: candidate #{candidate.id} ({candidate.function}) rejected: "
            f"generator refused — {probe.reason}",
            file=sys.stderr,
        )
        return "generator_refused"
    if settings.run.probe_audit:
        outcome, probe = _audit_gate(
            candidate, probe, frozen, settings, clients, candidates, probes_dir, overview
        )
        if outcome == "rejected":
            return "audit_rejected"
        if probe is None:
            return "pending"  # auditor/generator unavailable; stays pending
    verdict = checker.verify(candidate, probe)
    # The probe ran but never proved the trigger reached the targeted path:
    # bounded rewrite loop (same budget as probe generation), then rejected.
    rewrites_left = settings.run.probe_retries
    while verdict.kind is VerdictKind.UNREACHABLE:
        if rewrites_left == 0:
            candidates.update_status(
                candidate.id,
                CandidateStatus.REJECTED,
                f"probe could not reach the target path after "
                f"{settings.run.probe_retries} rewrites",
            )
            print(
                f"oceanids: candidate #{candidate.id} ({candidate.function}) rejected: "
                f"probe could not reach the target path after "
                f"{settings.run.probe_retries} rewrites",
                file=sys.stderr,
            )
            return "rejected"
        rewrites_left -= 1
        print(
            f"oceanids: probe for {candidate.function} did not reach the target "
            f"path; rewriting ({rewrites_left} left)",
            file=sys.stderr,
        )
        probe = probe_gen.generate_probe(
            candidate, clients.probe, probes_dir,
            max_retries=settings.run.probe_retries,
            rewrite_feedback=(
                "Your previous probe ran but never printed the "
                f"{PROBE_REACHED_MARKER} marker — the trigger input did not "
                "provably enter the targeted function/path. Instrument or wrap "
                "the target so that reaching the path prints the marker."
            ),
            overview=overview,
        )
        if probe is None:
            return "pending"  # rewrite generation failed; stays pending
        if isinstance(probe, ProbeRefusal):
            candidates.update_status(candidate.id, CandidateStatus.REJECTED, probe.reason)
            print(
                f"oceanids: candidate #{candidate.id} ({candidate.function}) rejected: "
                f"generator refused — {probe.reason}",
                file=sys.stderr,
            )
            return "generator_refused"
        verdict = checker.verify(candidate, probe)
    if verdict.kind is VerdictKind.SETUP_FAILURE:
        # Environment not provably intact (incl. bare timeouts without
        # markers): count the evidence-less attempt (FM-Agent's error class);
        # the budget decides pending-vs-inconclusive.
        attempts = candidates.increment_attempts(candidate.id)
        if attempts >= settings.run.verify_attempts:
            candidates.update_status(
                candidate.id,
                CandidateStatus.INCONCLUSIVE,
                f"no evidence after {attempts} verification attempt(s); "
                "last run did not prove its environment intact",
            )
            print(
                f"oceanids: candidate #{candidate.id} ({candidate.function}) "
                f"inconclusive after {attempts} attempt(s)",
                file=sys.stderr,
            )
            return "inconclusive"
        return "setup_failure"  # budget remains; stays pending for the next run
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
    overview: str = "",
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
    tallies = {
        "confirmed": 0,
        "rejected": 0,
        "duplicate": 0,
        "audit_rejected": 0,
        "generator_refused": 0,
        "pending": 0,
        "setup_failure": 0,
        "inconclusive": 0,
    }
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
                overview=overview,
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
        generator_refused=tallies["generator_refused"],
        confirmed_new=tallies["confirmed"],
        rejected=tallies["rejected"],
        setup_failures=tallies["setup_failure"],
        inconclusive=tallies["inconclusive"],
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
    overview: str,
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
            candidate, current, target, clients.auditor, max_retries=1, overview=overview
        )
        if verdict is None:
            return ("pending", None)
        if verdict.ok:
            return ("ok", current)
        if rewrites_left == 0:
            candidates.update_status(
                candidate.id, CandidateStatus.REJECTED, verdict.feedback
            )
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
            overview=overview,
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
        index = build_function_index(frozen)
        # The agent-written project overview: reused when it already exists,
        # generated otherwise (one retry, then OverviewError aborts the run).
        overview_path = resolve_artifact_path(target, overview.OVERVIEW_FILENAME)
        overview_text = overview.load_or_generate(index, clients.explorer, overview_path)
        print(f"[Oceanids] Project overview: {overview_path}")
        # One exploration pass: explore() itself skips already-explored files and
        # only marks files whose agent round succeeded.
        stats = explorer.explore(
            frozen, dispatch.dispatch(index), clients.explorer, candidates,
            explored, pool_size=settings.run.pool_size, max_retries=1,
            overview=overview_text,
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
            overview=overview_text,
        )

    report_path = write_report(
        confirmed, candidates, resolve_artifact_path(target, settings.paths.report)
    )
    print(f"[Oceanids] Report written: {report_path}")
    return RunSummary(
        tasks=stats.files,
        files_skipped=stats.files_skipped,
        candidates_new=stats.candidates_new,
        candidates_dup=stats.candidates_dup,
        probes=verify.probes,
        audit_rejected=verify.audit_rejected,
        generator_refused=verify.generator_refused,
        confirmed_new=verify.confirmed_new,
        rejected=verify.rejected,
        setup_failures=verify.setup_failures,
        inconclusive=verify.inconclusive,
        verify_failures=verify.failures,
        report_path=report_path,
    )
