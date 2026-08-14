"""SQLite persistence layer.

Schema mirrors docs/arch.puml: candidate_issues dedupes at write time via
UNIQUE(file, function, cwe_id) + INSERT OR IGNORE; confirmed_bugs dedupes by
evidence_key. Connections are created per thread (the explorer pool writes from
a ThreadPoolExecutor) and the database runs in WAL mode.

Schema note: the candidate dedup key includes ``file`` — same-named functions
in different files (main, close, parse) are distinct candidates. CWE typing
lives only on candidate_issues. There is deliberately NO migration logic — the
database is a disposable run artifact; delete old oceanids.db files.
"""

import sqlite3
import threading
from pathlib import Path

from oceanids.models import CandidateIssue, CandidateStatus, ConfirmedBug

SCHEMA = """
CREATE TABLE IF NOT EXISTS candidate_issues (
    id INTEGER PRIMARY KEY,
    file TEXT NOT NULL,
    function TEXT NOT NULL,
    cwe_id INTEGER NOT NULL,
    bug_category TEXT NOT NULL,
    description TEXT NOT NULL,
    trigger TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'pending'
        CHECK (status IN ('pending', 'rejected', 'confirmed', 'duplicate', 'inconclusive')),
    reject_reason TEXT,
    verify_attempts INTEGER NOT NULL DEFAULT 0,
    UNIQUE (file, function, cwe_id)
);
CREATE TABLE IF NOT EXISTS confirmed_bugs (
    id INTEGER PRIMARY KEY,
    candidate_id INTEGER NOT NULL REFERENCES candidate_issues (id),
    probe_path TEXT NOT NULL,
    evidence_key TEXT NOT NULL UNIQUE
);
CREATE TABLE IF NOT EXISTS explored_files (
    file TEXT PRIMARY KEY
);
"""


class _ThreadState(threading.local):
    conn: sqlite3.Connection | None = None


class Database:
    """Owns the SQLite file and hands out one WAL connection per thread."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self._state = _ThreadState()
        conn = self._new_connection()
        try:
            conn.executescript(SCHEMA)
            conn.commit()
        finally:
            conn.close()

    def _new_connection(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path, timeout=30.0)
        conn.row_factory = sqlite3.Row
        conn.execute("PRAGMA journal_mode=WAL")
        conn.execute("PRAGMA foreign_keys=ON")
        return conn

    @property
    def conn(self) -> sqlite3.Connection:
        """The calling thread's connection, created lazily."""
        if self._state.conn is None:
            self._state.conn = self._new_connection()
        return self._state.conn

    def close(self) -> None:
        """Close the calling thread's connection, if any."""
        if self._state.conn is not None:
            self._state.conn.close()
            self._state.conn = None


def _row_to_candidate(row: sqlite3.Row) -> CandidateIssue:
    return CandidateIssue(
        id=int(row["id"]),
        file=str(row["file"]),
        function=str(row["function"]),
        cwe_id=int(row["cwe_id"]),
        bug_category=str(row["bug_category"]),
        description=str(row["description"]),
        trigger=str(row["trigger"]),
        status=CandidateStatus(str(row["status"])),
        reject_reason=None if row["reject_reason"] is None else str(row["reject_reason"]),
        verify_attempts=int(row["verify_attempts"]),
    )


def _row_to_bug(row: sqlite3.Row) -> ConfirmedBug:
    return ConfirmedBug(
        id=int(row["id"]),
        candidate_id=int(row["candidate_id"]),
        probe_path=str(row["probe_path"]),
        evidence_key=str(row["evidence_key"]),
    )


class CandidateStore:
    """Read/write access to candidate_issues."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def insert(self, issue: CandidateIssue) -> int | None:
        """INSERT OR IGNORE on UNIQUE(file, function, cwe_id); None on a duplicate."""
        cur = self._db.conn.execute(
            """
            INSERT OR IGNORE INTO candidate_issues
                (file, function, cwe_id, bug_category, description, trigger, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
            """,
            (
                issue.file,
                issue.function,
                issue.cwe_id,
                issue.bug_category,
                issue.description,
                issue.trigger,
                issue.status.value,
            ),
        )
        self._db.conn.commit()
        if cur.rowcount == 0:
            return None
        return cur.lastrowid

    def get(self, issue_id: int) -> CandidateIssue | None:
        row = self._db.conn.execute(
            "SELECT * FROM candidate_issues WHERE id = ?", (issue_id,)
        ).fetchone()
        return None if row is None else _row_to_candidate(row)

    def select_pending(self) -> list[CandidateIssue]:
        rows = self._db.conn.execute(
            "SELECT * FROM candidate_issues WHERE status = ? ORDER BY id",
            (CandidateStatus.PENDING.value,),
        ).fetchall()
        return [_row_to_candidate(row) for row in rows]

    def update_status(
        self, issue_id: int, status: CandidateStatus, reason: str | None = None
    ) -> None:
        """Set the candidate's status; ``reason`` is persisted as reject_reason."""
        if reason is None:
            self._db.conn.execute(
                "UPDATE candidate_issues SET status = ? WHERE id = ?",
                (status.value, issue_id),
            )
        else:
            self._db.conn.execute(
                "UPDATE candidate_issues SET status = ?, reject_reason = ? WHERE id = ?",
                (status.value, reason, issue_id),
            )
        self._db.conn.commit()

    def increment_attempts(self, issue_id: int) -> int:
        """Count one evidence-less verification run; returns the new total."""
        self._db.conn.execute(
            "UPDATE candidate_issues SET verify_attempts = verify_attempts + 1 WHERE id = ?",
            (issue_id,),
        )
        self._db.conn.commit()
        row = self._db.conn.execute(
            "SELECT verify_attempts AS n FROM candidate_issues WHERE id = ?", (issue_id,)
        ).fetchone()
        return int(row["n"])

    def count(self) -> int:
        row = self._db.conn.execute("SELECT COUNT(*) AS n FROM candidate_issues").fetchone()
        return int(row["n"])

    def all(self) -> list[CandidateIssue]:
        rows = self._db.conn.execute("SELECT * FROM candidate_issues ORDER BY id").fetchall()
        return [_row_to_candidate(row) for row in rows]


class ConfirmedStore:
    """Read/write access to confirmed_bugs."""

    def __init__(self, db: Database) -> None:
        self._db = db

    def insert(self, bug: ConfirmedBug) -> int | None:
        """INSERT OR IGNORE on UNIQUE(evidence_key); None when the evidence was already known."""
        cur = self._db.conn.execute(
            """
            INSERT OR IGNORE INTO confirmed_bugs
                (candidate_id, probe_path, evidence_key)
            VALUES (?, ?, ?)
            """,
            (bug.candidate_id, bug.probe_path, bug.evidence_key),
        )
        self._db.conn.commit()
        if cur.rowcount == 0:
            return None
        return cur.lastrowid

    def insert_and_confirm(self, bug: ConfirmedBug) -> tuple[int | None, int]:
        """Atomically insert the bug AND resolve its candidate's lifecycle.

        Both writes land in one BEGIN IMMEDIATE transaction, so a crash can
        never leave a confirmed row pointing at a still-pending candidate.
        New evidence flips the candidate to ``confirmed``; a dedup hit flips
        it to ``duplicate`` — the bug IS proven, merely already represented.

        Returns (new_id, representing_id): new_id is None on a dedup hit;
        representing_id is the confirmed_bugs row standing for this evidence.
        """
        conn = self._db.conn
        conn.execute("BEGIN IMMEDIATE")
        try:
            cur = conn.execute(
                """
                INSERT OR IGNORE INTO confirmed_bugs
                    (candidate_id, probe_path, evidence_key)
                VALUES (?, ?, ?)
                """,
                (bug.candidate_id, bug.probe_path, bug.evidence_key),
            )
            new_id = cur.lastrowid if cur.rowcount else None
            if new_id is None:
                row = conn.execute(
                    "SELECT id FROM confirmed_bugs WHERE evidence_key = ?",
                    (bug.evidence_key,),
                ).fetchone()
                representing_id = int(row["id"])
                new_status = CandidateStatus.DUPLICATE
            else:
                representing_id = new_id
                new_status = CandidateStatus.CONFIRMED
            conn.execute(
                "UPDATE candidate_issues SET status = ? WHERE id = ?",
                (new_status.value, bug.candidate_id),
            )
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        return (new_id, representing_id)

    def get(self, bug_id: int) -> ConfirmedBug | None:
        row = self._db.conn.execute(
            "SELECT * FROM confirmed_bugs WHERE id = ?", (bug_id,)
        ).fetchone()
        return None if row is None else _row_to_bug(row)

    def count(self) -> int:
        row = self._db.conn.execute("SELECT COUNT(*) AS n FROM confirmed_bugs").fetchone()
        return int(row["n"])

    def all(self) -> list[ConfirmedBug]:
        rows = self._db.conn.execute("SELECT * FROM confirmed_bugs ORDER BY id").fetchall()
        return [_row_to_bug(row) for row in rows]

    def confirmed_with_candidates(self) -> list[tuple[ConfirmedBug, CandidateIssue]]:
        """Every confirmed bug joined with its originating candidate, for reporting."""
        rows = self._db.conn.execute(
            """
            SELECT b.*, c.id AS c_id, c.file, c.function, c.cwe_id AS c_cwe_id,
                   c.bug_category, c.description, c.trigger, c.status,
                   c.reject_reason, c.verify_attempts
            FROM confirmed_bugs b JOIN candidate_issues c ON c.id = b.candidate_id
            ORDER BY b.id
            """
        ).fetchall()
        pairs: list[tuple[ConfirmedBug, CandidateIssue]] = []
        for row in rows:
            candidate = CandidateIssue(
                id=int(row["c_id"]),
                file=str(row["file"]),
                function=str(row["function"]),
                cwe_id=int(row["c_cwe_id"]),
                bug_category=str(row["bug_category"]),
                description=str(row["description"]),
                trigger=str(row["trigger"]),
                status=CandidateStatus(str(row["status"])),
                reject_reason=None if row["reject_reason"] is None else str(row["reject_reason"]),
                verify_attempts=int(row["verify_attempts"]),
            )
            pairs.append((_row_to_bug(row), candidate))
        return pairs


class ExploredFilesStore:
    """The set of files already SUCCESSFULLY explored ("one file, one agent, once").

    Only a round whose LLM output passed the validator burns the file's single
    chance: failed rounds are NOT recorded here, so a re-run (resume) explores
    the file again. Persisted in SQLite to make the resume semantic durable.
    """

    def __init__(self, db: Database) -> None:
        self._db = db

    def mark_explored(self, file: str) -> None:
        """Record that ``file`` used up its one exploration chance."""
        self._db.conn.execute(
            "INSERT OR IGNORE INTO explored_files (file) VALUES (?)", (file,)
        )
        self._db.conn.commit()

    def is_explored(self, file: str) -> bool:
        """True when ``file`` was already explored successfully (skip on resume)."""
        row = self._db.conn.execute(
            "SELECT 1 AS x FROM explored_files WHERE file = ?", (file,)
        ).fetchone()
        return row is not None
