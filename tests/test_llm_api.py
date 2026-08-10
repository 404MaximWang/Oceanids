"""APILLM: retry budgets, backoff, and message shape — no network (fake client injected)."""

from types import SimpleNamespace
from typing import Any

import httpx
import pytest
from openai import APIConnectionError, APIStatusError, APITimeoutError, RateLimitError

from oceanids.config import APICfg
from oceanids.llm.api import APILLM
from oceanids.llm.base import LLMBackendError

_REQUEST = httpx.Request("POST", "https://example.test/v1/chat/completions")


def _cfg(**overrides: Any) -> APICfg:
    base: dict[str, Any] = {
        "model": "test-model",
        "api_key": "k",
        "max_retries": 2,
        "max_rate_limit_retries": 3,
    }
    return APICfg(**(base | overrides))


def _status_error(status: int) -> APIStatusError:
    return APIStatusError("boom", response=httpx.Response(status, request=_REQUEST), body=None)


def _rate_limit_error() -> RateLimitError:
    return RateLimitError("slow down", response=httpx.Response(429, request=_REQUEST), body=None)


class _FakeCompletions:
    """Plays back a scripted list of texts (returned) or exceptions (raised)."""

    def __init__(self, script: list[Any]) -> None:
        self._script = list(script)
        self.calls: list[dict[str, Any]] = []

    def create(self, *, model: str, messages: list[Any]) -> Any:
        self.calls.append({"model": model, "messages": messages})
        outcome = self._script.pop(0)
        if isinstance(outcome, Exception):
            raise outcome
        message = SimpleNamespace(content=outcome)
        return SimpleNamespace(choices=[SimpleNamespace(message=message)])


def _make(script: list[Any]) -> tuple[APILLM, _FakeCompletions, list[float]]:
    completions = _FakeCompletions(script)
    client = SimpleNamespace(chat=SimpleNamespace(completions=completions))
    sleeps: list[float] = []
    llm = APILLM(_cfg(), client=client, sleeper=sleeps.append, jitter=lambda: 0.0)
    return llm, completions, sleeps


def test_success_message_shape() -> None:
    llm, completions, sleeps = _make(["hello"])
    assert llm.complete("the prompt") == "hello"
    assert sleeps == []
    call = completions.calls[0]
    assert call["model"] == "test-model"
    assert call["messages"] == [{"role": "user", "content": "the prompt"}]


def test_rate_limit_retries_with_backoff() -> None:
    llm, completions, sleeps = _make([_rate_limit_error(), _rate_limit_error(), "ok"])
    assert llm.complete("p") == "ok"
    assert len(completions.calls) == 3
    # Exponential backoff, deterministic with jitter() == 0: 5s then 10s.
    assert sleeps == [5.0, 10.0]


def test_rate_limit_budget_exhausted() -> None:
    llm, _, _ = _make([_rate_limit_error()] * 4)
    with pytest.raises(LLMBackendError, match="rate limited"):
        llm.complete("p")


def test_transient_5xx_uses_separate_budget() -> None:
    llm, completions, sleeps = _make([_status_error(500), "ok"])
    assert llm.complete("p") == "ok"
    assert len(completions.calls) == 2
    assert sleeps == [5.0]


def test_transient_budget_exhausted() -> None:
    llm, _, _ = _make([_status_error(503)] * 3)
    with pytest.raises(LLMBackendError, match="transient"):
        llm.complete("p")


def test_rate_limit_and_transient_budgets_are_independent() -> None:
    # Two 429s plus two 500s interleaved: neither budget (3 / 2) is exhausted.
    script = [
        _rate_limit_error(), _status_error(500), _rate_limit_error(), _status_error(502), "ok",
    ]
    llm, completions, _ = _make(script)
    assert llm.complete("p") == "ok"
    assert len(completions.calls) == 5


def test_http_400_fails_immediately() -> None:
    llm, completions, sleeps = _make([_status_error(400), "ok"])
    with pytest.raises(LLMBackendError, match="HTTP 400"):
        llm.complete("p")
    assert len(completions.calls) == 1  # no retry
    assert sleeps == []


def test_connection_and_timeout_errors_are_transient() -> None:
    script = [APIConnectionError(request=_REQUEST), APITimeoutError(request=_REQUEST), "ok"]
    llm, completions, _ = _make(script)
    assert llm.complete("p") == "ok"
    assert len(completions.calls) == 3


def test_missing_api_key_or_model_fail_fast() -> None:
    with pytest.raises(LLMBackendError, match="API key"):
        APILLM(_cfg(api_key=""))
    with pytest.raises(LLMBackendError, match="model"):
        APILLM(_cfg(model=""))
