"""Layered configuration: built-in defaults < oceanids.toml < mapped process env < init.

The pattern follows FM-Agent's config.py (pydantic + pydantic-settings), rewritten
typed and without its back-compat constant layer: per-section BaseModel with
extra="forbid", Field numeric constraints, and a fail-fast readable SystemExit on
load errors.
"""

import os
import tomllib
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError
from pydantic.fields import FieldInfo
from pydantic_settings import BaseSettings, PydanticBaseSettingsSource, SettingsConfigDict

DEFAULT_CONFIG_NAME = "oceanids.toml"
CONFIG_ENV_VAR = "OCEANIDS_CONFIG"

# Environment variable -> dotted path of (section, ..., field). The single place
# mapping an env var to a setting; doubles as documentation of every override.
_ENV_MAP: dict[str, tuple[str, ...]] = {
    "OCEANIDS_DB": ("paths", "db"),
    "OCEANIDS_PROBES_DIR": ("paths", "probes_dir"),
    "OCEANIDS_REPORT": ("paths", "report"),
    "OCEANIDS_POOL_SIZE": ("run", "pool_size"),
    "OCEANIDS_VERIFY_POOL_SIZE": ("run", "verify_pool_size"),
    "OCEANIDS_SANDBOX": ("run", "sandbox"),
    "OCEANIDS_LLM": ("run", "llm"),
    "OCEANIDS_EXPLORER_LLM": ("run", "explorer_llm"),
    "OCEANIDS_PROBE_LLM": ("run", "probe_llm"),
    "OCEANIDS_AUDITOR_LLM": ("run", "auditor_llm"),
    "OCEANIDS_TIMEOUT_S": ("run", "timeout_s"),
    "OCEANIDS_LLM_API_KEY": ("llm", "api", "api_key"),
    "OCEANIDS_LLM_BASE_URL": ("llm", "api", "base_url"),
    "OCEANIDS_LLM_MODEL": ("llm", "api", "model"),
}


# LLM backend names, routable per pipeline stage (fixed mapping, no fallback).
BackendName = Literal["mock", "api", "pi"]


class _Section(BaseModel):
    """Base for config sections: unknown keys are errors, not silent defaults."""

    model_config = ConfigDict(extra="forbid")


class APICfg(_Section):
    """[llm.api]: OpenAI-compatible chat completions endpoint."""

    base_url: str = "https://openrouter.ai/api/v1"
    model: str = ""
    # Secret — env-only by convention (OCEANIDS_LLM_API_KEY), never commit to toml.
    api_key: str = ""
    timeout_s: int = Field(default=120, gt=0)
    # Retry budgets are separate: rate limits (429) and transient errors (5xx /
    # connection) each get their own counter.
    max_retries: int = Field(default=5, ge=0)
    max_rate_limit_retries: int = Field(default=10, ge=0)


class PiCfg(_Section):
    """[llm.pi]: badlogic pi-mono terminal coding agent, driven as a CLI subprocess.

    NOTE: the default command template has NOT been verified against a real pi
    binary; it is configurable precisely so the verified flags can be dropped in.
    """

    command: list[str] = ["pi", "-p"]  # argv template; the prompt goes to stdin
    timeout_s: int = Field(default=600, gt=0)


class LLMCfg(_Section):
    api: APICfg = APICfg()
    pi: PiCfg = PiCfg()


class RunCfg(_Section):
    pool_size: int = Field(default=4, gt=0)
    verify_pool_size: int = Field(default=4, gt=0)
    sandbox: Literal["local", "bwrap", "qemu"] = "local"
    # Unified default backend for every stage; the per-stage fields below win
    # when set. Per-stage fields default to None (fall back to llm). The unified
    # default is pi; mock stays for tests/development.
    llm: BackendName = "pi"
    explorer_llm: BackendName | None = None
    probe_llm: BackendName | None = None
    auditor_llm: BackendName | None = None
    timeout_s: int = Field(default=30, gt=0)
    probe_retries: int = Field(default=2, ge=0)
    # Budget of evidence-less verification runs (setup failure / bare timeout)
    # before a candidate goes terminal-inconclusive (FM-Agent's error class).
    verify_attempts: int = Field(default=3, ge=1)
    # Probe auditor gate (between probe_gen and checker): on by default.
    probe_audit: bool = True
    # --submodule: scope exploration to one target-relative directory; the
    # function index and overview still cover the whole project. None = all.
    submodule: str | None = None


class PathsCfg(_Section):
    # Relative values resolve under <target>/.oceanids/ (artifacts follow the
    # target); absolute values are used as-is. Resolution lives in
    # orchestrator.resolve_artifact_path and applies to toml/env/CLI alike.
    db: str = "oceanids.db"
    probes_dir: str = "probes"
    report: str = "report.md"


def _resolve_config_path() -> Path:
    explicit = os.environ.get(CONFIG_ENV_VAR)
    if explicit:
        path = Path(explicit)
        if not path.is_file():
            # A typo'd OCEANIDS_CONFIG should fail fast, not fall back to defaults.
            raise SystemExit(f"oceanids: {CONFIG_ENV_VAR} points at a missing file: {path}")
        return path
    # A missing default oceanids.toml is tolerated: built-in defaults apply.
    return Path(DEFAULT_CONFIG_NAME)


class _LayeredSource(PydanticBaseSettingsSource):
    """oceanids.toml as the base layer, mapped process env overlaid on top."""

    def __init__(self, settings_cls: type[BaseSettings], path: Path) -> None:
        super().__init__(settings_cls)
        data: dict[str, Any] = {}
        if path.is_file():
            data = tomllib.loads(path.read_text(encoding="utf-8"))
        for env_name, field_path in _ENV_MAP.items():
            value = os.environ.get(env_name)
            if value is not None:
                node = data
                for part in field_path[:-1]:
                    child = node.setdefault(part, {})
                    if not isinstance(child, dict):
                        raise SystemExit(
                            f"oceanids: env var {env_name} conflicts with a non-section "
                            f"config key {part!r}"
                        )
                    node = child
                node[field_path[-1]] = value
        self._data = data

    def get_field_value(self, field: FieldInfo, field_name: str) -> tuple[Any, str, bool]:
        # Abstract on the base class but unused: __call__ returns the whole merged
        # mapping, so pydantic never falls back to per-field extraction.
        raise NotImplementedError

    def __call__(self) -> dict[str, Any]:
        return self._data


class Settings(BaseSettings):
    # forbid: a mistyped section or key in oceanids.toml is an error, not a silent
    # fallback to the default — the whole point of a typed config.
    model_config = SettingsConfigDict(extra="forbid")

    run: RunCfg = RunCfg()
    paths: PathsCfg = PathsCfg()
    llm: LLMCfg = LLMCfg()

    @classmethod
    def settings_customise_sources(
        cls,
        settings_cls: type[BaseSettings],
        init_settings: PydanticBaseSettingsSource,
        env_settings: PydanticBaseSettingsSource,
        dotenv_settings: PydanticBaseSettingsSource,
        file_secret_settings: PydanticBaseSettingsSource,
    ) -> tuple[PydanticBaseSettingsSource, ...]:
        # init (programmatic) wins; everything else is folded into _LayeredSource,
        # which already applies env > toml > field defaults.
        return (init_settings, _LayeredSource(settings_cls, _resolve_config_path()))


def load_settings() -> Settings:
    """Validate and return settings; any bad value fails fast with a readable exit."""
    try:
        return Settings()
    except (ValidationError, tomllib.TOMLDecodeError) as exc:
        raise SystemExit(f"oceanids: invalid configuration\n{exc}") from None
