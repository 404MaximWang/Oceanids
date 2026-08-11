"""Phase 2.5: the explorer agent pool — one file, one agent, once.

A ThreadPoolExecutor fans the dispatch tasks out to the LLM; each finding goes
into candidate_issues via INSERT OR IGNORE (write-time key dedup, arch.puml 法一).

"Once" semantics: a file burns its single exploration chance ONLY when the
agent's answer passes the validator. A failed round (retries exhausted, still
no legal output) is NOT marked — the file is explored again on the next run.
Files already marked explored are skipped before dispatch (resume).
"""

from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, replace
from pathlib import Path

from oceanids.cwe import is_valid, prompt_listing
from oceanids.db import CandidateStore, ExploredFilesStore
from oceanids.llm.base import Json, LLMClient, call_structured
from oceanids.models import CandidateIssue
from oceanids.pipeline.dispatch import Task

_ISSUES_SCHEMA = (
    '[{"function": str, "cwe_id": int (from the CWE subset), "bug_category": str, '
    '"description": str, "trigger": str}]'
)
_ISSUE_KEYS = {"function", "cwe_id", "bug_category", "description", "trigger"}


@dataclass(frozen=True)
class ExplorationStats:
    files: int
    files_skipped: int
    candidates_new: int
    candidates_dup: int
    llm_failures: int


def _validate_issues(data: Json) -> list[CandidateIssue]:
    """The explorer report: a plain JSON array of issue objects."""
    if not isinstance(data, list):
        raise ValueError("expected a JSON array of issues")
    issues: list[CandidateIssue] = []
    for item in data:
        if not isinstance(item, dict) or set(item) != _ISSUE_KEYS:
            raise ValueError(f"issue object must have exactly keys {sorted(_ISSUE_KEYS)}")
        cwe_id = item["cwe_id"]
        if not isinstance(cwe_id, int) or isinstance(cwe_id, bool) or not is_valid(cwe_id):
            raise ValueError(f"cwe_id must be an integer from the CWE subset, got {cwe_id!r}")
        if not all(
            isinstance(item[key], str) and item[key]
            for key in ("function", "bug_category", "description", "trigger")
        ):
            raise ValueError("issue text fields must be non-empty strings")
        issues.append(
            CandidateIssue(
                file="",  # filled by the caller
                function=str(item["function"]),
                cwe_id=cwe_id,
                bug_category=str(item["bug_category"]),
                description=str(item["description"]),
                trigger=str(item["trigger"]),
            )
        )
    return issues


def _explore_one(
    root: Path,
    task: Task,
    llm: LLMClient,
    store: CandidateStore,
    max_retries: int,
) -> tuple[int, int, bool]:
    """Analyze one file; returns (new, dup, llm_failed)."""
    source = (root / task.path).read_text(encoding="utf-8", errors="replace")
    functions = (
        "none extracted"
        if task.functions is None
        else ", ".join(f"{span.name} (lines {span.start}-{span.end})" for span in task.functions)
    )
    prompt = (
        f"EXPLORE file {task.path} (language: {task.language}).\n"
        f"Functions: {functions}.\n"
        "Report likely bugs as a JSON array of objects with keys function, cwe_id, "
        "bug_category, description, trigger. Report [] when nothing looks wrong.\n"
        "cwe_id must come from this CWE subset (id + name + description):\n"
        f"{prompt_listing()}\n\n"
        f"```\n{source}\n```"
    )
    issues = call_structured(
        llm, prompt, _validate_issues, _ISSUES_SCHEMA, max_retries=max_retries
    )
    if issues is None:
        return (0, 0, True)
    new = dup = 0
    for issue in issues:
        row_id = store.insert(replace(issue, file=task.path))
        if row_id is None:
            dup += 1
        else:
            new += 1
    return (new, dup, False)


def explore(
    root: Path,
    tasks: list[Task],
    llm: LLMClient,
    store: CandidateStore,
    explored: ExploredFilesStore,
    *,
    pool_size: int,
    max_retries: int = 1,
) -> ExplorationStats:
    """Run the explorer pool once over the not-yet-explored tasks.

    Already-explored files are skipped (resume); a file is marked explored only
    when its agent round succeeded — failures stay re-explorable next run.
    """
    pending = [task for task in tasks if not explored.is_explored(task.path)]
    skipped = len(tasks) - len(pending)
    new = dup = failures = 0
    done = 0
    total = len(pending)
    with ThreadPoolExecutor(max_workers=pool_size, thread_name_prefix="explorer") as pool:
        futures = {
            pool.submit(_explore_one, root, task, llm, store, max_retries): task
            for task in pending
        }
        for future in as_completed(futures):
            task = futures[future]
            added, repeated, failed = future.result()
            new += added
            dup += repeated
            failures += int(failed)
            done += 1
            if failed:
                print(
                    f"[Oceanids] [{done}/{total}] {task.path}: "
                    "exploration failed, kept for next run"
                )
            else:
                # Success burned the file's single chance — even when the answer
                # was an empty issues array.
                explored.mark_explored(task.path)
                print(
                    f"[Oceanids] [{done}/{total}] {task.path}: "
                    f"+{added} candidates ({repeated} dup)"
                )
    return ExplorationStats(
        files=len(pending),
        files_skipped=skipped,
        candidates_new=new,
        candidates_dup=dup,
        llm_failures=failures,
    )
