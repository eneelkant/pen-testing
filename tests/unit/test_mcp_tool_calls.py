"""End-to-end MCP tool call coverage via the SDK call_tool API."""

from __future__ import annotations

import asyncio
import inspect
import json
from pathlib import Path

import pytest

from mcp_server.server import mcp


async def _call(name: str, args: dict):
    result = mcp.call_tool(name, args)
    if inspect.iscoroutine(result):
        result = await result
    return result


def _payload(result) -> dict:
    # FastMCP's call_tool returns a tuple: (content_list, structured_content_dict)
    if isinstance(result, tuple):
        if len(result) >= 2 and result[1]:
            return dict(result[1])
        for item in result[0] or []:
            text = getattr(item, "text", None)
            if text:
                return json.loads(text)
        return {}
    # Legacy: object with .structured_content / .content attrs
    if getattr(result, "structured_content", None):
        return dict(result.structured_content)
    for item in result.content or []:
        text = getattr(item, "text", None)
        if text:
            return json.loads(text)
    return {}


def test_all_tools_registered():
    result = mcp.list_tools()
    tools = asyncio.run(result) if inspect.iscoroutine(result) else result
    names = {t.name for t in tools}
    assert names == {
        "platform_status",
        "check_dependencies",
        "validate_target_scope",
        "list_integrations",
        "run_local_diagnostics",
        "plan_assessment",
        "authorize_assessment",
        "run_security_assessment",
        "get_assessment_status",
        "list_findings",
        "export_report",
    }


def test_platform_status_tool():
    result = asyncio.run(_call("platform_status", {}))
    data = _payload(result)
    assert data["ok"] is True
    assert "diagnostics" in data


def test_check_dependencies_tool():
    result = asyncio.run(_call("check_dependencies", {}))
    data = _payload(result)
    assert "missing" in data
    assert "present" in data


def test_validate_scope_missing_required_errors():
    with pytest.raises(Exception):
        asyncio.run(_call("validate_target_scope", {}))


def test_validate_scope_out_of_scope():
    result = asyncio.run(_call("validate_target_scope", {"target": "https://example.com"}))
    data = _payload(result)
    assert data["allowed"] is False


def test_validate_scope_authorized_fixture():
    result = asyncio.run(
        _call("validate_target_scope", {"target": "http://127.0.0.1:18080/", "category": "passive"})
    )
    data = _payload(result)
    assert data["allowed"] is True


def test_list_integrations_tool():
    result = asyncio.run(_call("list_integrations", {}))
    data = _payload(result)
    assert "shannon" in data["integrations"]
    assert "briar" in data["integrations"]


def test_run_local_diagnostics_tool():
    result = asyncio.run(_call("run_local_diagnostics", {}))
    data = _payload(result)
    assert data["ok"] is True
    assert data["destructive"] is False


def test_assessment_dry_run_authorized(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    result = asyncio.run(
        _call(
            "run_security_assessment",
            {
                "tool": "headers",
                "target": "http://127.0.0.1:18080/",
                "category": "passive",
                "dry_run": True,
            },
        )
    )
    data = _payload(result)
    assert data.get("assessment_id")
    assert data.get("status") in {"skipped", "succeeded", "blocked", "failed"}
    # dry-run should not require confirm; authorized fixture should not hard-fail schema
    status = asyncio.run(_call("get_assessment_status", {"assessment_id": data["assessment_id"]}))
    assert _payload(status)["ok"] is True


def test_assessment_requires_confirm():
    result = asyncio.run(
        _call(
            "run_security_assessment",
            {
                "tool": "headers",
                "target": "http://127.0.0.1:18080/",
                "dry_run": False,
                "confirm_authorized": False,
            },
        )
    )
    data = _payload(result)
    assert data["ok"] is False
    assert "confirm_authorized" in data["error"]


def test_invalid_tool_literal_rejected():
    with pytest.raises(Exception):
        asyncio.run(_call("run_security_assessment", {"tool": "nuclei", "target": "https://x"}))


def test_export_and_findings_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    created = asyncio.run(
        _call(
            "run_security_assessment",
            {
                "tool": "shannon",
                "target": "https://staging.example.invalid",
                "repo_path": str(Path(__file__).resolve().parents[2]),
                "dry_run": True,
            },
        )
    )
    aid = _payload(created)["assessment_id"]
    findings = _payload(asyncio.run(_call("list_findings", {"assessment_id": aid})))
    assert findings["ok"] is True
    exported = _payload(
        asyncio.run(
            _call(
                "export_report",
                {"assessment_id": aid, "outdir": str(tmp_path / "reports" / "out")},
            )
        )
    )
    assert exported["ok"] is True
    assert Path(exported["markdown"]).exists()
