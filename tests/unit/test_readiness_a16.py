"""Regression tests for 0.2.0a16 transport, strict readiness, and deployment encryption."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import yaml
from cryptography.fernet import Fernet

from core.cli import main
from core.ops.crypto import encryption_status, protect_text

ROOT = Path(__file__).resolve().parents[2]


def _key() -> str:
    return Fernet.generate_key().decode("ascii")


def _scopes(tmp_path: Path) -> Path:
    path = tmp_path / "registry.yaml"
    path.write_text("authorizations: []\n", encoding="utf-8")
    return path


def _strict_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("PEN_DOCTOR_STRICT", "1")
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_SCOPES_FILE", str(_scopes(tmp_path)))
    monkeypatch.delenv("PEN_ALLOW_SHANNON_FULL_PIPELINE", raising=False)
    monkeypatch.delenv("PEN_MAX_INFLIGHT_SCANS", raising=False)
    monkeypatch.delenv("PEN_SKIP_SCOPE_RATE_LIMIT_RPS", raising=False)


def test_mcp_refuses_remote_transports():
    from mcp_server.server import mcp

    with pytest.raises(PermissionError, match="stdio only"):
        mcp.run("sse")
    with pytest.raises(PermissionError, match="stdio only"):
        mcp.run("streamable-http", host="0.0.0.0", port=8080)
    with pytest.raises(PermissionError, match="listener"):
        mcp.run("stdio", host="127.0.0.1")


def test_invalid_fernet_key_is_rejected(monkeypatch):
    monkeypatch.setenv("PEN_DATA_KEY", "not-a-fernet-key")
    status = encryption_status()
    assert status["state"] == "invalid-key"
    assert status["enabled"] is False
    with pytest.raises(PermissionError, match="valid Fernet"):
        protect_text("hello")


def test_doctor_strict_fails_when_encryption_is_off(tmp_path: Path, monkeypatch, capsys):
    _strict_env(monkeypatch, tmp_path)
    monkeypatch.delenv("PEN_DATA_KEY", raising=False)
    monkeypatch.delenv("PEN_REQUIRE_DATA_ENCRYPTION", raising=False)
    code = main(["doctor"])
    assert code == 1
    assert "encryption is off" in capsys.readouterr().out


def test_doctor_strict_fails_on_invalid_key(tmp_path: Path, monkeypatch, capsys):
    _strict_env(monkeypatch, tmp_path)
    monkeypatch.setenv("PEN_DATA_KEY", "not-a-fernet-key")
    code = main(["doctor"])
    assert code == 1
    assert "encryption key is invalid" in capsys.readouterr().out


def test_doctor_strict_fails_when_full_pipeline_enabled(tmp_path: Path, monkeypatch, capsys):
    _strict_env(monkeypatch, tmp_path)
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    monkeypatch.setenv("PEN_ALLOW_SHANNON_FULL_PIPELINE", "1")
    code = main(["doctor"])
    assert code == 1
    data = json.loads(capsys.readouterr().out)
    assert data["strict_errors"] == ["Shannon full pipeline is enabled"]


def test_doctor_strict_passes_for_supported_controls(tmp_path: Path, monkeypatch, capsys):
    _strict_env(monkeypatch, tmp_path)
    key = _key()
    monkeypatch.setenv("PEN_REQUIRE_DATA_ENCRYPTION", "1")
    monkeypatch.setenv("PEN_DATA_KEY", key)
    code = main(["doctor"])
    text = capsys.readouterr().out
    assert code == 0
    data = json.loads(text)
    assert data["strict_errors"] == []
    assert data["encryption"]["state"] == "enabled"
    assert data["encryption"]["enabled"] is True
    assert key not in text
    assert data["gates"]["shannon_full_pipeline"] is False


def test_compose_supported_deployment_requires_encryption():
    rendered = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    document = yaml.safe_load(rendered)
    env = document["services"]["orchestrator"]["environment"]
    assert env["PEN_REQUIRE_DATA_ENCRYPTION"] == "true"
    assert env["PEN_DOCTOR_STRICT"] == "true"
    assert env["PEN_ALLOW_SHANNON_FULL_PIPELINE"] == "false"
    assert env["PEN_DATA_KEY"] == "${PEN_DATA_KEY:-}"
    assert env["PEN_DATA_KEY"].startswith("${")
    assert "BEGIN OPENSSH" not in rendered


def test_runtime_script_fails_closed_without_encryption_key():
    text = (ROOT / "scripts/docker_runtime_verify.sh").read_text(encoding="utf-8")
    assert "ORCHESTRATOR_STRICT_MISSING_KEY_BLOCKED" in text
    assert "env -u PEN_DATA_KEY" in text
    assert "ORCHESTRATOR_STRICT_DOCTOR_OK" in text
