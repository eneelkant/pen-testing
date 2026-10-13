"""Static checks for Shannon controlled E2E infrastructure (no Docker required)."""

from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[2]


def test_compose_override_dual_homes_temporal_only():
    path = ROOT / "scripts" / "shannon-compose-external-net.yml"
    cfg = yaml.safe_load(path.read_text(encoding="utf-8"))
    nets = cfg["networks"]
    assert nets["default"]["name"] == "shannon-net"
    assert nets["default"]["external"] is True
    assert nets["shannon-host"]["name"] == "pen-shannon-host"
    assert nets["shannon-host"]["external"] is True
    # Temporal dual-homed; no worker service redefined here.
    assert set(cfg["services"]["temporal"]["networks"]) == {"default", "shannon-host"}
    assert list(cfg["services"].keys()) == ["temporal"]


def test_shannon_models_fixture_points_at_local_mock():
    path = ROOT / "tests" / "fixtures" / "shannon_models.json"
    data = __import__("json").loads(path.read_text(encoding="utf-8"))
    provider = data["providers"]["shannon-mock"]
    assert "shannon-llm-mock" in provider["baseUrl"]
    assert provider["api"] == "openai-completions"
    assert any(m["id"] == "gpt-test" for m in provider["models"])


def test_temporal_host_ready_script_exists_and_is_executable():
    path = ROOT / "scripts" / "shannon_temporal_host_ready.sh"
    assert path.is_file()
    assert path.stat().st_mode & 0o111


def test_docker_wrap_injects_compose_override_when_managed():
    wrap = (ROOT / "scripts" / "shannon-docker-wrap").read_text(encoding="utf-8")
    assert "shannon-compose-external-net.yml" in wrap
    assert 'pen.managed' in wrap or 'pen.managed' in wrap.replace('"', "")
    assert '== "compose"' in wrap or 'compose' in wrap
