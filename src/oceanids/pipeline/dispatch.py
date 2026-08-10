"""Phase 2: split the overview into per-file exploration tasks.

Test files are excluded using the cross-language heuristics ported (and typed)
from FM-Agent's file_utils.py: known test directory names plus test-file naming
patterns.
"""

import re
from dataclasses import dataclass

from oceanids.pipeline.overview import FunctionSpan, Overview

TEST_DIR_NAMES: frozenset[str] = frozenset(
    {
        "test",
        "tests",
        "__tests__",
        "testing",
        "test_helpers",
        "testdata",
        "testutils",
        "fixtures",
        "mocks",
    }
)

TEST_FILE_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(pattern)
    for pattern in (
        r"^test_.*\.py$",  # Python: test_foo.py
        r"^.*_test\.py$",  # Python: foo_test.py
        r"^conftest\.py$",  # pytest fixtures
        r"^.*_test\.go$",  # Go: foo_test.go
        r"^.*_test\.(?:cpp|cc|cxx|c|h|hpp)$",  # C/C++: foo_test.cpp
        r"^test_.*\.(?:cpp|cc|cxx|c|h|hpp)$",  # C/C++: test_foo.cpp
        r"^.*Test(?:s|Case)?\.java$",  # Java: FooTest.java
        r"^.*\.(?:test|spec)\.(?:js|jsx|ts|tsx)$",  # JS/TS: foo.test.js
        r"^.*_test\.rs$",  # Rust: foo_test.rs
    )
)


def is_test_file(rel_path: str) -> bool:
    """True when the target-relative path looks like a test file."""
    parts = rel_path.replace("\\", "/").split("/")
    if any(part.lower() in TEST_DIR_NAMES for part in parts[:-1]):
        return True
    basename = parts[-1]
    return any(pattern.match(basename) for pattern in TEST_FILE_PATTERNS)


@dataclass(frozen=True)
class Task:
    """One unit of exploration work: a single non-test source file."""

    path: str
    language: str
    functions: tuple[FunctionSpan, ...] | None


def dispatch(overview: Overview) -> list[Task]:
    """Turn the overview into exploration tasks, excluding test files."""
    return [
        Task(path=file.path, language=file.language, functions=file.functions)
        for file in overview.files
        if not is_test_file(file.path)
    ]
