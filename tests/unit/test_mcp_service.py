import asyncio
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "installers"))
from client_config import backup_file, merge_mcp_servers, write_json  # noqa: E402
from mcp_server import service
from mcp_server.server import mcp


def _list_tool_names() -> set[str]:
    result = mcp.list_tools()
    tools = asyncio.run(result) if asyncio.iscoroutine(result) else result
    return {t.name for t in tools}


def test_mcp_tool_discovery():
    names = _list_tool_names()
    assert "platform_status" in names
    assert "run_security_assessment" in names
    assert "validate_target_scope" in names


def test_validate_scope_rejects_public():
    result = service.validate_target_scope("https://example.com", "active")
    assert result["allowed"] is False


def test_assessment_requires_confirm_for_live():
    result = service.run_security_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        dry_run=False,
        confirm_authorized=False,
    )
    assert result["ok"] is False
    assert "confirm_authorized" in result["error"]


def test_dry_run_assessment_and_export(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    result = service.run_security_assessment(
        tool="shannon",
        target="https://staging.example.invalid",
        repo_path=str(Path(__file__).resolve().parents[2]),
        dry_run=True,
    )
    assert result.get("assessment_id")
    status = service.get_assessment_status(result["assessment_id"])
    assert status["ok"] is True
    exported = service.export_report(result["assessment_id"], outdir=str(tmp_path / "out"))
    assert exported["ok"] is True
    assert Path(exported["markdown"]).exists()


def test_missing_assessment():
    assert service.get_assessment_status("does-not-exist")["ok"] is False


def test_config_backup_preserves_unrelated(tmp_path):
    path = tmp_path / "mcp.json"
    path.write_text(json.dumps({"mcpServers": {"other": {"command": "true"}}}), encoding="utf-8")
    backup = backup_file(path)
    assert backup and backup.exists()
    merged = merge_mcp_servers(json.loads(path.read_text()), "pen-testing", {"command": "python"})
    write_json(path, merged, do_backup=False)
    data = json.loads(path.read_text())
    assert "other" in data["mcpServers"]
    assert "pen-testing" in data["mcpServers"]


def test_check_dependencies_structure():
    deps = service.check_dependencies()
    assert "missing" in deps
    assert "present" in deps


def test_list_integrations_includes_shannon_briar():
    items = service.list_integrations()["integrations"]
    assert "shannon" in items
    assert "briar" in items
