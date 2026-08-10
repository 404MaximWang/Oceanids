"""LLM client protocol plus the shared structured-output machinery.

Two ideas are taken from FM-Agent's llm_client.py and rewritten typed:
- tolerant single-JSON extraction via json.JSONDecoder.raw_decode scanning
  (markdown fences / prose around exactly one JSON value are accepted), and
- the parse -> validate -> feedback retry protocol for structured outputs.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any, Protocol, TypeVar

T = TypeVar("T")

Json = dict[str, Any] | list[Any]
Validator = Callable[[Json], T]


class LLMBackendError(RuntimeError):
    """A backend could not produce a completion (missing binary, retries exhausted...)."""


class LLMClient(Protocol):
    """Minimal text-completion interface every backend must satisfy."""

    def complete(self, prompt: str) -> str:
        """Return the model's text for one prompt."""
        ...


@dataclass(frozen=True)
class StageClients:
    """Fixed per-stage backend mapping: explorer / probe_gen / probe auditor.

    Routing is configuration-driven only — no fallback escalation, no heuristics.
    """

    explorer: LLMClient
    probe: LLMClient
    auditor: LLMClient

    @classmethod
    def uniform(cls, client: LLMClient) -> StageClients:
        """One client for every stage (the classic single-backend wiring)."""
        return cls(explorer=client, probe=client, auditor=client)


def extract_json(text: str) -> Json:
    """Extract the single JSON object/array in an LLM response.

    A bare JSON document is preferred; otherwise the whole text is scanned with
    raw_decode and exactly one embedded JSON object/array is tolerated. Zero or
    multiple values are rejected because picking one would be ambiguous.
    """
    stripped = text.strip()
    try:
        data: Any = json.loads(stripped)
    except json.JSONDecodeError as direct_exc:
        decoder = json.JSONDecoder()
        values: list[Json] = []
        index = 0
        while index < len(stripped):
            starts = [
                pos
                for pos in (stripped.find("{", index), stripped.find("[", index))
                if pos != -1
            ]
            if not starts:
                break
            start = min(starts)
            try:
                value, end = decoder.raw_decode(stripped, start)
            except json.JSONDecodeError:
                index = start + 1
                continue
            if isinstance(value, dict | list):
                values.append(value)
            index = end
        if len(values) == 1:
            return values[0]
        if len(values) > 1:
            raise ValueError("LLM response contains multiple JSON values") from None
        raise ValueError(f"LLM response is not valid JSON: {direct_exc}") from direct_exc
    if isinstance(data, dict | list):
        return data
    raise ValueError("LLM response must contain a JSON object or array")


def call_structured[T](
    client: LLMClient,
    prompt: str,
    validator: Validator[T],
    schema_description: str,
    *,
    max_retries: int = 2,
) -> T | None:
    """Call the LLM until it returns JSON accepted by ``validator``.

    On a parse/validation failure the error is fed back to the model and the
    request retried; returns None after ``1 + max_retries`` failed attempts.
    """
    feedback = ""
    for _attempt in range(1 + max_retries):
        response = client.complete(prompt + feedback)
        try:
            return validator(extract_json(response))
        except ValueError as exc:
            feedback = (
                f"\n\nYour previous response was invalid: {exc}. "
                f"Return only valid JSON matching this schema: {schema_description}. "
                "Do not include Markdown, tags, or prose."
            )
    return None
