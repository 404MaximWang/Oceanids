"""Command line entry point: oceanids run <target>."""

import argparse
import sys
from pathlib import Path

from oceanids.config import Settings, load_settings
from oceanids.llm.api import APILLM
from oceanids.llm.base import LLMClient, StageClients
from oceanids.llm.mock import MockLLM
from oceanids.llm.pi_cli import PiCLILLM
from oceanids.orchestrator import run_pipeline
from oceanids.tmux import launch_in_tmux

_LLM_CHOICES = ["mock", "api", "pi"]


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="oceanids")
    sub = parser.add_subparsers(dest="command", required=True)
    run = sub.add_parser("run", help="run the full pipeline against a target tree")
    run.add_argument("target", type=Path, help="path to the target source tree")
    run.add_argument("--db", type=Path, default=None, help="SQLite database path")
    run.add_argument("--sandbox", choices=["local", "bwrap", "qemu"], default=None)
    run.add_argument("--llm", choices=_LLM_CHOICES, default=None,
                     help="unified backend override for all three stages")
    run.add_argument("--explorer-llm", choices=_LLM_CHOICES, default=None,
                     help="backend for the explorer pool only")
    run.add_argument("--probe-llm", choices=_LLM_CHOICES, default=None,
                     help="backend for probe generation only")
    run.add_argument("--auditor-llm", choices=_LLM_CHOICES, default=None,
                     help="backend for the probe auditor only")
    run.add_argument("--pool-size", type=int, default=None, help="explorer pool size")
    run.add_argument("--verify-pool-size", type=int, default=None,
                     help="verification pool size (probe gen → audit → sandbox)")
    run.add_argument("--tmux", action="store_true",
                     help="run detached in tmux, logging to ./.oceanids/oceanids.log")
    return parser


def build_client(backend: str, settings: Settings) -> LLMClient:
    """Instantiate one backend by name; unknown names fail with a readable exit."""
    if backend == "mock":
        # Offline placeholder backend: scripted routes come from tests; a real
        # scripted-replay source plugs in here later.
        return MockLLM(routes=[], default="[]")
    if backend == "api":
        return APILLM(settings.llm.api)
    if backend == "pi":
        return PiCLILLM(settings.llm.pi.command, timeout_s=settings.llm.pi.timeout_s)
    raise SystemExit(
        f"oceanids: unknown llm backend {backend!r} (expected one of {_LLM_CHOICES})"
    )


def build_stage_clients(
    settings: Settings,
    *,
    unified: str | None = None,
    explorer: str | None = None,
    probe: str | None = None,
    auditor: str | None = None,
) -> StageClients:
    """Resolve the fixed per-stage backend mapping and build the clients.

    Precedence per stage: stage CLI flag > unified CLI flag > stage config field
    > run.llm config default. No fallback escalation, no heuristic routing.
    """
    explorer_name = explorer or unified or settings.run.explorer_llm or settings.run.llm
    probe_name = probe or unified or settings.run.probe_llm or settings.run.llm
    auditor_name = auditor or unified or settings.run.auditor_llm or settings.run.llm
    return StageClients(
        explorer=build_client(explorer_name, settings),
        probe=build_client(probe_name, settings),
        auditor=build_client(auditor_name, settings),
    )


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run":
        if args.tmux:
            return launch_in_tmux(list(argv) if argv is not None else sys.argv[1:])
        settings = load_settings()
        # CLI flags override the layered config.
        if args.db is not None:
            settings.paths.db = str(args.db)
        if args.sandbox is not None:
            settings.run.sandbox = args.sandbox
        if args.pool_size is not None:
            settings.run.pool_size = args.pool_size
        if args.verify_pool_size is not None:
            settings.run.verify_pool_size = args.verify_pool_size
        clients = build_stage_clients(
            settings,
            unified=args.llm,
            explorer=args.explorer_llm,
            probe=args.probe_llm,
            auditor=args.auditor_llm,
        )
        summary = run_pipeline(args.target, settings, clients)
        print(
            f"tasks={summary.tasks} skipped={summary.files_skipped} "
            f"candidates(+{summary.candidates_new}/dup {summary.candidates_dup}) "
            f"probes={summary.probes} audit_rejected={summary.audit_rejected} "
            f"confirmed(+{summary.confirmed_new}) rejected={summary.rejected} "
            f"verify_failures={summary.verify_failures} report={summary.report_path}"
        )
        return 0
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
