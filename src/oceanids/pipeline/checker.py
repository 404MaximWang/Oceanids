"""Phase 3.5 + 4: the independent checker.

For every probe the checker builds a brand-new clean sandbox instance, re-runs
the probe itself and trusts only its own evidence. A confirmation requires ALL
of: the probe printed its setup marker (dependencies loaded intact), its
reached marker (the trigger input entered the targeted path), and the oracle
fired (non-zero exit / timeout / sanitizer hit). True positives land in
confirmed_bugs (evidence-key dedup, arch.puml 法二) and flip the candidate to
confirmed; a clean run with both markers flips it to rejected. Runs without
the setup or reached markers prove nothing: the candidate is left untouched
(SETUP_FAILURE) or sent back for a probe rewrite (UNREACHABLE). The target
cannot drift mid-run: the pipeline handed the checker a frozen snapshot
(oceanids.freeze).
"""

from collections.abc import Callable
from pathlib import Path

from oceanids.db import CandidateStore, ConfirmedStore
from oceanids.models import (
    CandidateIssue,
    CandidateStatus,
    ConfirmedBug,
    Evidence,
    Probe,
    Verdict,
    VerdictKind,
)
from oceanids.sandbox.base import (
    ExecutionResult,
    Sandbox,
    detect_probe_markers,
    detect_sanitizer_hits,
    extract_top_frames,
    make_evidence_key,
)


class Checker:
    """Verifies probes in fresh sandbox instances; the only trusted judge."""

    def __init__(
        self,
        target_root: Path,
        sandbox_factory: Callable[[], Sandbox],
        candidates: CandidateStore,
        confirmed: ConfirmedStore,
        *,
        timeout_s: int,
    ) -> None:
        self._target_root = target_root
        self._sandbox_factory = sandbox_factory
        self._candidates = candidates
        self._confirmed = confirmed
        self._timeout_s = timeout_s

    def verify(self, candidate: CandidateIssue, probe: Probe) -> Verdict:
        """Re-run one probe in a clean sandbox and route the candidate by the outcome."""
        if candidate.id is None:
            raise ValueError("checker only accepts persisted candidates")
        if probe.path is None:
            raise ValueError("probe must be written to disk before verification")
        # Fresh, clean sandbox instance per verification — never reuse state.
        sandbox = self._sandbox_factory()
        result = sandbox.run(
            [*probe.interpreter, str(probe.path.resolve())], timeout_s=self._timeout_s
        )
        evidence = self._collect_evidence(result, probe.path)
        if not evidence.setup_ok:
            # The probe never proved its environment was intact (missing setup
            # marker) — a crash-on-import exits non-zero too, so nothing here
            # is evidence about the candidate. Leave it pending.
            return Verdict(
                candidate_id=candidate.id,
                kind=VerdictKind.SETUP_FAILURE,
                reason="probe did not print its setup marker; dependencies may be broken",
                evidence=evidence,
            )
        if not evidence.reached:
            # Environment intact, but the trigger never provably entered the
            # targeted path — the probe goes back for a bounded rewrite.
            return Verdict(
                candidate_id=candidate.id,
                kind=VerdictKind.UNREACHABLE,
                reason="probe did not print its reached marker; trigger may not hit the target path",
                evidence=evidence,
            )
        if evidence.oracle_fired:
            bug = ConfirmedBug(
                candidate_id=candidate.id,
                probe_path=str(probe.path),
                evidence_key=evidence.evidence_key,
            )
            # Atomic: the bug row and the candidate's confirmed flip land together.
            new_id, representing_id = self._confirmed.insert_and_confirm(bug)
            reason = "oracle fired in the checker's own clean re-run"
            if new_id is None:
                reason += f"; evidence already represented by confirmed bug #{representing_id}"
            return Verdict(
                candidate_id=candidate.id,
                kind=VerdictKind.TRUE_POSITIVE,
                reason=reason,
                evidence=evidence,
                confirmed_id=new_id,
            )
        self._candidates.update_status(
            candidate.id,
            CandidateStatus.REJECTED,
            "probe ran clean in the checker's own re-run",
        )
        return Verdict(
            candidate_id=candidate.id,
            kind=VerdictKind.FALSE_POSITIVE,
            reason="probe ran clean in the checker's own re-run",
            evidence=evidence,
        )

    @staticmethod
    def _collect_evidence(result: ExecutionResult, probe_path: Path) -> Evidence:
        """Oracle: exit code, timeout, and sanitizer markers — all from the own run.

        The probe file path is normalised to ``$PROBE`` (like the sandbox workdir
        to ``$WORK``) so two different probes triggering the same violation point
        produce the same evidence key — that is what evidence dedup keys on.
        """
        normalized = result.stderr.replace(str(probe_path.resolve()), "$PROBE")
        output = result.stdout + "\n" + normalized
        hits = detect_sanitizer_hits(output)
        setup_ok, reached = detect_probe_markers(output)
        frames = extract_top_frames(normalized, workdir=result.workdir)
        oracle_fired = result.exit_code != 0 or result.timed_out or bool(hits)
        return Evidence(
            exit_code=result.exit_code,
            timed_out=result.timed_out,
            stdout=result.stdout,
            stderr=result.stderr,
            sanitizer_hits=hits,
            top_frames=frames,
            oracle_fired=oracle_fired,
            evidence_key=make_evidence_key(frames, normalized, workdir=result.workdir),
            setup_ok=setup_ok,
            reached=reached,
        )
