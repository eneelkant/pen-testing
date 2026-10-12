import json
from pathlib import Path

from core.cli import main
from core.config import load_config
from core.diagnostics import collect_diagnostics
from core.reporting import generate_daily_report
from providers import list_provider_status


def test_load_config_defaults(tmp_path, monkeypatch):
    monkeypatch.delenv("PEN_REQUIRE_SCOPE", raising=False)
    cfg = load_config()
    assert cfg.require_scope_for_active is True
    assert "shannon" in cfg.shannon_package


def test_diagnostics_reports_missing_docker():
    cfg = load_config()
    data = collect_diagnostics(cfg)
    assert "platform" in data
    assert "tools" in data
    assert "recommendations" in data
    # In this CI/agent environment docker is typically missing.
    if not data["tools"]["docker"]:
        assert any("Docker" in r for r in data["recommendations"])


def test_providers_status_no_secrets(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-should-not-appear")
    status = list_provider_status()
    blob = json.dumps(status)
    assert "sk-test" not in blob
    assert status["openai"]["env_present"]["OPENAI_API_KEY"] is True


def test_cli_scope_check_unauthorized(capsys):
    code = main(["scope-check", "--target", "https://example.com", "--category", "active"])
    assert code == 1
    out = capsys.readouterr().out
    assert '"allowed": false' in out.lower().replace(" ", "") or '"allowed": false' in out


def test_cli_daily_report(tmp_path):
    out = tmp_path / "daily.md"
    code = main(["daily-report", "--output", str(out)])
    assert code == 0
    assert out.exists()
    assert out.with_suffix(".json").exists()


def test_generate_daily_report_redacts(tmp_path):
    path = generate_daily_report(
        output_path=tmp_path / "d.md",
        tool_runs=[{"tool": "shannon", "version": "3.4.0", "status": "skipped"}],
        next_actions=["Register authorized staging target"],
    )
    assert "Local report only" in path.read_text()


def test_cli_health_json(capsys):
    code = main(["health", "--tool", "headers"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["headers"]["healthy"] is True
