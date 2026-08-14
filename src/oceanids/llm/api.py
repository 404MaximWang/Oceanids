"""API backend: OpenAI-compatible chat completions endpoint.

Retry strategy follows the shape of FM-Agent's llm_client.py (rewritten typed):
rate limits (429) and transient failures (5xx / connection / timeout) keep
SEPARATE budgets, each with exponential backoff plus jitter; a 400 fails
immediately. The SDK's own retry layer is disabled (max_retries=0) so this is
the only place retries happen.
"""

import random
import time
from collections.abc import Callable
from typing import Any

from openai import APIConnectionError, APIStatusError, APITimeoutError, OpenAI, RateLimitError
from openai.types.chat import ChatCompletionMessageParam, ChatCompletionUserMessageParam

from oceanids.config import APICfg
from oceanids.llm.base import LLMBackendError

#: Environment variable carrying the API key (overlaid into APICfg.api_key).
API_KEY_ENV_VAR = "OCEANIDS_LLM_API_KEY"


class APILLM:
    """LLMClient backed by an OpenAI-compatible chat completions endpoint."""

    def __init__(
        self,
        cfg: APICfg,
        *,
        client: Any | None = None,
        sleeper: Callable[[float], None] = time.sleep,
        jitter: Callable[[], float] = random.random,
    ) -> None:
        if not cfg.api_key:
            raise LLMBackendError(
                f"backend 'api' requires an API key in the {API_KEY_ENV_VAR} environment variable"
            )
        if not cfg.model:
            raise LLMBackendError("backend 'api' requires llm.api.model to be set")
        self._cfg = cfg
        # client/sleeper/jitter are injectable so tests never touch the network.
        self._client: Any = client if client is not None else OpenAI(
            api_key=cfg.api_key,
            base_url=cfg.base_url,
            timeout=cfg.timeout_s,
            max_retries=0,  # retries are owned by complete() below
        )
        self._sleeper = sleeper
        self._jitter = jitter

    def _create(self, prompt: str) -> str:
        messages: list[ChatCompletionMessageParam] = [
            ChatCompletionUserMessageParam(role="user", content=prompt)
        ]
        response = self._client.chat.completions.create(model=self._cfg.model, messages=messages)
        if not response.choices:
            # Content filtering and some proxies answer with zero choices.
            raise LLMBackendError("backend 'api' returned no choices")
        content: str | None = response.choices[0].message.content
        if content is None:
            raise LLMBackendError("backend 'api' returned an empty completion")
        return content

    def _backoff(self, attempt: int, *, cap: float, jitter_max: float) -> float:
        return min(2.0 ** (attempt - 1) * 5.0, cap) + self._jitter() * jitter_max

    def complete(self, prompt: str) -> str:
        rate_limit_attempts = 0
        transient_attempts = 0
        while True:
            try:
                return self._create(prompt)
            except RateLimitError as exc:
                rate_limit_attempts += 1
                if rate_limit_attempts > self._cfg.max_rate_limit_retries:
                    raise LLMBackendError(
                        f"backend 'api' rate limited after {rate_limit_attempts} attempts: {exc}"
                    ) from exc
                self._sleeper(self._backoff(rate_limit_attempts, cap=300.0, jitter_max=10.0))
            except APIStatusError as exc:
                if exc.status_code == 429:
                    rate_limit_attempts += 1
                    if rate_limit_attempts > self._cfg.max_rate_limit_retries:
                        raise LLMBackendError(
                            f"backend 'api' rate limited after {rate_limit_attempts} "
                            f"attempts: {exc}"
                        ) from exc
                    self._sleeper(self._backoff(rate_limit_attempts, cap=300.0, jitter_max=10.0))
                elif 400 <= exc.status_code < 500:
                    # Client error other than 429: retrying cannot help.
                    raise LLMBackendError(
                        f"backend 'api' rejected the request (HTTP {exc.status_code}): {exc}"
                    ) from exc
                else:
                    transient_attempts += 1
                    if transient_attempts > self._cfg.max_retries:
                        raise LLMBackendError(
                            f"backend 'api' failed after {transient_attempts} transient "
                            f"errors (last: HTTP {exc.status_code}): {exc}"
                        ) from exc
                    self._sleeper(self._backoff(transient_attempts, cap=60.0, jitter_max=3.0))
            except (APIConnectionError, APITimeoutError) as exc:
                transient_attempts += 1
                if transient_attempts > self._cfg.max_retries:
                    raise LLMBackendError(
                        f"backend 'api' failed after {transient_attempts} transient "
                        f"connection/timeout errors: {exc}"
                    ) from exc
                self._sleeper(self._backoff(transient_attempts, cap=60.0, jitter_max=3.0))
