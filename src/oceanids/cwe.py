"""Curated CWE subset: the closed vocabulary for bug typing in Oceanids.

Subset provenance and curation principles
------------------------------------------
Base layer: the complete MITRE "CWE Top 25 Most Dangerous Software Weaknesses",
**2024** list (https://cwe.mitre.org/top25/archive/2024/2024_cwe_top25.html).

Extension layer: 14 common, language-agnostic Base/Class weaknesses the Top 25
skews away from (the list is web- and memory-safety heavy). They were chosen so
that typical logic and resource-management bugs found by LLM code review have a
home: CWE-369, CWE-835, CWE-674, CWE-401, CWE-617, CWE-703, CWE-252, CWE-400,
CWE-404, CWE-415, CWE-191, CWE-457, CWE-667, CWE-772.

Total: 39 entries. Every cwe_id an explorer emits must be in this table;
validators reject anything else mechanically (see ``is_valid``).
"""

from dataclasses import dataclass


@dataclass(frozen=True)
class CWEEntry:
    """One CWE weakness: numeric id, canonical name, one-line description."""

    id: int
    name: str
    description: str


CWE_TABLE: tuple[CWEEntry, ...] = (
    # --- CWE Top 25 (2024), in ranked order ---------------------------------
    CWEEntry(787, "Out-of-bounds Write",
             "Data is written past the end or before the start of the intended buffer."),
    CWEEntry(79, "Improper Neutralization of Input During Web Page Generation ('Cross-site "
             "Scripting')", "Untrusted input is rendered as web page content without escaping."),
    CWEEntry(89, "Improper Neutralization of Special Elements used in an SQL Command ('SQL "
             "Injection')", "User input reaches an SQL command without proper neutralization."),
    CWEEntry(416, "Use After Free", "Memory is referenced after it has been freed."),
    CWEEntry(78, "Improper Neutralization of Special Elements used in an OS Command ('OS "
             "Command Injection')", "User input reaches an OS shell command unsanitized."),
    CWEEntry(20, "Improper Input Validation", "Input is not validated before it affects "
             "control flow or data flow."),
    CWEEntry(125, "Out-of-bounds Read", "Data is read past the end or before the start of "
             "the intended buffer."),
    CWEEntry(22, "Improper Limitation of a Pathname to a Restricted Directory ('Path "
             "Traversal')", "External input escapes the intended directory via path elements."),
    CWEEntry(352, "Cross-Site Request Forgery (CSRF)", "State-changing requests are not "
             "verified to originate from the legitimate user."),
    CWEEntry(434, "Unrestricted Upload of File with Dangerous Type", "Uploaded files of "
             "dangerous types are accepted without restriction."),
    CWEEntry(862, "Missing Authorization", "No authorization check is performed for a "
             "sensitive action."),
    CWEEntry(476, "NULL Pointer Dereference", "A pointer/reference expected to be valid is "
             "dereferenced while NULL."),
    CWEEntry(287, "Improper Authentication", "The identity of an actor is not verified "
             "correctly."),
    CWEEntry(190, "Integer Overflow or Wraparound", "An arithmetic operation wraps around "
             "the integer's maximum or minimum."),
    CWEEntry(502, "Deserialization of Untrusted Data", "Untrusted serialized data is "
             "deserialized without validation."),
    CWEEntry(77, "Improper Neutralization of Special Elements used in a Command ('Command "
             "Injection')", "Input is incorporated into a command without neutralization."),
    CWEEntry(119, "Improper Restriction of Operations within the Bounds of a Memory Buffer",
             "Operations read or write outside a memory buffer's bounds."),
    CWEEntry(798, "Use of Hard-coded Credentials", "Credentials are embedded directly in "
             "the source code or data."),
    CWEEntry(918, "Server-Side Request Forgery (SSRF)", "The server fetches attacker-"
             "controlled URLs without validation."),
    CWEEntry(306, "Missing Authentication for Critical Function", "A critical function is "
             "reachable without any authentication."),
    CWEEntry(362, "Concurrent Execution using Shared Resource with Improper Synchronization "
             "('Race Condition')", "Shared state is accessed concurrently without proper "
             "synchronization."),
    CWEEntry(269, "Improper Privilege Management", "Privileges are assigned, dropped, or "
             "checked incorrectly."),
    CWEEntry(94, "Improper Control of Generation of Code ('Code Injection')", "Attacker-"
             "controlled input is compiled or interpreted as code."),
    CWEEntry(863, "Incorrect Authorization", "An authorization check exists but grants or "
             "denies access incorrectly."),
    CWEEntry(276, "Incorrect Default Permissions", "Default permissions on a resource are "
             "too permissive."),
    # --- Language-agnostic Base/Class additions ------------------------------
    CWEEntry(369, "Divide By Zero", "A division or modulo is computed with a zero divisor."),
    CWEEntry(835, "Loop with Unreachable Exit Condition ('Infinite Loop')", "A loop's exit "
             "condition can never be satisfied."),
    CWEEntry(674, "Uncontrolled Recursion", "Recursion depth is unbounded and can exhaust "
             "the stack."),
    CWEEntry(401, "Missing Release of Memory after Effective Lifetime", "Allocated memory "
             "is never released after its last use."),
    CWEEntry(617, "Reachable Assertion", "An assertion can be triggered by attacker-"
             "controlled or unexpected input."),
    CWEEntry(703, "Improper Check or Handling of Exceptional Conditions", "Exceptional "
             "conditions (errors, edge cases) are not checked or handled properly."),
    CWEEntry(252, "Unchecked Return Value", "A function's return value signalling failure "
             "is ignored."),
    CWEEntry(400, "Uncontrolled Resource Consumption", "Resource usage grows without bound "
             "under adversarial input."),
    CWEEntry(404, "Improper Resource Shutdown or Release", "A resource is not shut down or "
             "released correctly."),
    CWEEntry(415, "Double Free", "The same memory is freed more than once."),
    CWEEntry(191, "Integer Underflow (Wrap or Wraparound)", "A subtraction wraps below the "
             "integer's minimum."),
    CWEEntry(457, "Use of Uninitialized Variable", "A variable is read before it is "
             "assigned a value."),
    CWEEntry(667, "Improper Locking", "Locks are acquired or released in the wrong order "
             "or not at all."),
    CWEEntry(772, "Missing Release of Resource after Effective Lifetime", "A non-memory "
             "resource (handle, connection) is never released."),
)

CWE_IDS: frozenset[int] = frozenset(entry.id for entry in CWE_TABLE)

_BY_ID: dict[int, CWEEntry] = {entry.id: entry for entry in CWE_TABLE}


def is_valid(cwe_id: int) -> bool:
    """True when ``cwe_id`` belongs to the curated subset."""
    return cwe_id in _BY_ID


def lookup(cwe_id: int) -> CWEEntry | None:
    """The table entry for ``cwe_id``, or None when outside the subset."""
    return _BY_ID.get(cwe_id)


def format_cwe(cwe_id: int) -> str:
    """Canonical display form, e.g. ``CWE-369: Divide By Zero``."""
    entry = _BY_ID.get(cwe_id)
    return f"CWE-{cwe_id}: {entry.name}" if entry is not None else f"CWE-{cwe_id}"


def prompt_listing() -> str:
    """The whole subset as prompt-ready lines: id + name + one-line description."""
    return "\n".join(
        f"CWE-{entry.id} {entry.name} — {entry.description}" for entry in CWE_TABLE
    )
