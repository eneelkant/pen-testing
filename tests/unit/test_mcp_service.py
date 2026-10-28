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
    # Authorized fixture URL so dry-run is not scope-blocked.
    result = service.run_security_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        dry_run=True,
    )
    assert result.get("assessment_id")
    status = service.get_assessment_status(result["assessment_id"])
    assert status["ok"] is True
    exported = service.export_report(
        result["assessment_id"], outdir=str(tmp_path / "reports" / "export-out")
    )
    assert exported["ok"] is True, exported
    assert Path(exported["markdown"]).exists()


def test_missing_assessment():
    assert service.get_assessment_status("00000000-0000-4000-8000-000000000000")["ok"] is False


def test_assessment_id_rejects_path_traversal():
    result = service.get_assessment_status("../../etc/passwd")
    assert result["ok"] is False
    assert "UUID" in result["error"]


def test_export_outdir_confined(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    created = service.run_security_assessment(
        tool="shannon",
        target="https://staging.example.invalid",
        repo_path=str(Path(__file__).resolve().parents[2]),
        dry_run=True,
    )
    aid = created["assessment_id"]
    bad = service.export_report(aid, outdir=str(tmp_path.parent / "pen-testing-escape"))
    assert bad["ok"] is False
    assert "inside reports_dir" in bad["error"]


def test_invalid_url_rejected():
    result = service.validate_target_scope("not-a-url", "active")
    assert result["allowed"] is False
    assert "http" in result["reason"].lower()


def test_mcp_local_scan_path_excludes_cwd(tmp_path, monkeypatch):
    work = tmp_path / "work"
    reports = tmp_path / "reports"
    work.mkdir()
    reports.mkdir()
    monkeypatch.setenv("PEN_WORK_DIR", str(work))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(reports))
    monkeypatch.chdir(tmp_path)
    outside = tmp_path / "outside-src"
    outside.mkdir()
    # Path is under cwd but not under work/reports — MCP must refuse.
    result = service._confine_local_scan_path(
        service.resolve_platform_config(),
        str(outside),
        None,
    )
    assert isinstance(result, dict)
    assert result.get("ok") is False
    assert "outside allowed roots" in result.get("error", "")
    inside = work / "src"
    inside.mkdir()
    confined = service._confine_local_scan_path(
        service.resolve_platform_config(),
        str(inside),
        None,
    )
    assert isinstance(confined, str)
    assert Path(confined) == inside.resolve()


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


def test_mcp_local_scan_path_refuses_traversal_and_symlink_escape(tmp_path, monkeypatch):
    work = tmp_path / "work"
    reports = tmp_path / "reports"
    outside = tmp_path / "outside"
    for directory in (work, reports, outside):
        directory.mkdir()
    monkeypatch.setenv("PEN_WORK_DIR", str(work))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(reports))
    monkeypatch.chdir(tmp_path)
    cfg = service.resolve_platform_config()

    traversal = service._confine_local_scan_path(cfg, str(work / ".." / "outside"), None)
    assert isinstance(traversal, dict) and traversal.get("ok") is False

    link = work / "link"
    link.symlink_to(outside, target_is_directory=True)
    escaped = service._confine_local_scan_path(cfg, str(link), None)
    assert isinstance(escaped, dict) and escaped.get("ok") is False

    # repo_path takes precedence over target and is confined the same way.
    via_repo = service._confine_local_scan_path(cfg, str(work), str(outside))
    assert isinstance(via_repo, dict) and via_repo.get("ok") is False
