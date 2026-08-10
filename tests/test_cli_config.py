"""Stage routing: config fields, CLI flag overrides, unknown backend errors."""

import pytest

from oceanids.cli import build_client, build_stage_clients
from oceanids.config import APICfg, LLMCfg, RunCfg, Settings
from oceanids.llm.api import APILLM
from oceanids.llm.mock import MockLLM
from oceanids.llm.pi_cli import PiCLILLM


def test_defaults_are_pi_everywhere() -> None:
    # run.llm defaults to "pi"; per-stage fields fall back to it.
    clients = build_stage_clients(Settings(run=RunCfg()))
    assert isinstance(clients.explorer, PiCLILLM)
    assert isinstance(clients.probe, PiCLILLM)
    assert isinstance(clients.auditor, PiCLILLM)


def test_stage_config_field_routes_one_stage() -> None:
    clients = build_stage_clients(Settings(run=RunCfg(explorer_llm="mock")))
    assert isinstance(clients.explorer, MockLLM)
    assert isinstance(clients.probe, PiCLILLM)
    assert isinstance(clients.auditor, PiCLILLM)


def test_auditor_config_field_routes_auditor() -> None:
    clients = build_stage_clients(Settings(run=RunCfg(auditor_llm="mock")))
    assert isinstance(clients.explorer, PiCLILLM)
    assert isinstance(clients.probe, PiCLILLM)
    assert isinstance(clients.auditor, MockLLM)


def test_unified_flag_covers_all_stages() -> None:
    clients = build_stage_clients(Settings(run=RunCfg()), unified="mock")
    assert isinstance(clients.explorer, MockLLM)
    assert isinstance(clients.probe, MockLLM)
    assert isinstance(clients.auditor, MockLLM)


def test_stage_flag_beats_unified_flag() -> None:
    clients = build_stage_clients(Settings(run=RunCfg()), unified="pi", probe="mock")
    assert isinstance(clients.explorer, PiCLILLM)
    assert isinstance(clients.probe, MockLLM)
    assert isinstance(clients.auditor, PiCLILLM)


def test_auditor_flag_beats_unified_flag() -> None:
    clients = build_stage_clients(Settings(run=RunCfg()), unified="pi", auditor="mock")
    assert isinstance(clients.explorer, PiCLILLM)
    assert isinstance(clients.probe, PiCLILLM)
    assert isinstance(clients.auditor, MockLLM)


def test_unified_flag_beats_stage_config() -> None:
    settings = Settings(run=RunCfg(explorer_llm="pi"))
    clients = build_stage_clients(settings, unified="mock")
    assert isinstance(clients.explorer, MockLLM)


def test_api_backend_builds_from_config() -> None:
    settings = Settings(
        run=RunCfg(probe_llm="api"),
        llm=LLMCfg(api=APICfg(model="test-model", api_key="k")),
    )
    clients = build_stage_clients(settings)
    assert isinstance(clients.probe, APILLM)
    assert isinstance(clients.explorer, PiCLILLM)


def test_unknown_backend_name_fails_clearly() -> None:
    with pytest.raises(SystemExit, match="unknown llm backend"):
        build_client("nope", Settings(run=RunCfg()))


def test_env_overlay_maps_stage_fields_and_api_key(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("OCEANIDS_EXPLORER_LLM", "pi")
    monkeypatch.setenv("OCEANIDS_AUDITOR_LLM", "api")
    monkeypatch.setenv("OCEANIDS_LLM_API_KEY", "secret-from-env")
    settings = Settings()
    assert settings.run.explorer_llm == "pi"
    assert settings.run.auditor_llm == "api"
    assert settings.llm.api.api_key == "secret-from-env"
    assert settings.run.probe_llm is None  # untouched stays None -> run.llm default
