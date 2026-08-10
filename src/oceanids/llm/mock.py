"""Scripted, deterministic LLM backend used for tests and offline runs."""

from collections.abc import Sequence


class MockLLM:
    """Answers prompts from an ordered script table.

    Each route is (marker, response); the first marker appearing as a substring
    of the prompt wins. Every prompt is recorded in ``calls`` for assertions.
    """

    def __init__(self, routes: Sequence[tuple[str, str]], default: str | None = None) -> None:
        self._routes = list(routes)
        self._default = default
        self.calls: list[str] = []

    def complete(self, prompt: str) -> str:
        self.calls.append(prompt)
        for marker, response in self._routes:
            if marker in prompt:
                return response
        if self._default is not None:
            return self._default
        raise KeyError(f"MockLLM: no route matched prompt: {prompt[:120]!r}")
