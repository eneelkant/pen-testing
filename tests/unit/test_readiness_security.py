"""Readiness-focused security and failure-handling tests."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from unittest.mock import MagicMock

from core.config import PlatformConfig
from core.execution import CommandResult, CommandRunner
from core.scope import (
    AuthorizationRecord,
    ScopeEngine,
    same_origin,
    validate_redirect_stays_in_scope,
)
from integrations.base import AdapterRequest
from integrations.briar import BriarAdapter
from integrations.scanners.headers import HeadersAdapter
from integrations.shannon import ShannonAdapter


def test_authorized_target_accepted():
    engine = ScopeEngine.from_file("scopes/registry.yaml")
    decision = engine.evaluate("http://127.0.0.1:18080/", test_category="passive")
    assert decision.allowed is True


def test_missing_authorization_rejected():
    engine = ScopeEngine([])
    decision = engine.evaluate("https://no-record.example", test_category="active")
    assert decision.allowed is False


def test_production_active_blocked_by_default():
    engine = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="prod",
                program_url="https://example.invalid",
                target_id="prod",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=["https://prod.example.invalid"],
                allowed_test_categories=["active"],
                environment="production",
            )
        ]
    )
    decision = engine.evaluate(
        "https://prod.example.invalid",
        test_category="active",
        require_non_production=True,
    )
    assert decision.allowed is False
    assert "production" in decision.reason.lower()


def test_redirect_cross_origin_rejected():
    ok, reason = validate_redirect_stays_in_scope(
        "https://staging.example.invalid/app",
        "https://evil.example/phish",
    )
    assert ok is False
    assert "leaves authorized origin" in reason


def test_redirect_same_origin_allowed():
    ok, dest = validate_redirect_stays_in_scope(
        "https://staging.example.invalid/app",
        "/login",
    )
    assert ok is True
    assert same_origin("https://staging.example.invalid/app", dest)


def test_headers_blocks_cross_origin_redirect(tmp_path: Path):
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(302)
            self.send_header("Location", "https://evil.example/out")
            self.end_headers()

        def log_message(self, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), H)
    port = server.server_address[1]
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/"
    cfg = PlatformConfig(reports_dir=tmp_path)
    scope = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="t",
                program_url="https://example.invalid",
                target_id="t",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=[url],
                allowed_test_categories=["passive", "active"],
                environment="local",
            )
        ]
    )
    result = HeadersAdapter(cfg, scope).run(AdapterRequest(target=url, test_category="passive"))
    server.server_close()
    assert result.status == "blocked"
    assert "redirect" in (result.error or "").lower()


def test_shannon_missing_docker_blocks_live_run(tmp_path: Path):
    cfg = PlatformConfig(reports_dir=tmp_path)
    runner = MagicMock()
    runner.which.side_effect = lambda b: "/usr/bin/npx" if b in {"npx", "node"} else None
    runner.run.return_value = CommandResult(["npx"], 0, "3.4.0", "")
    url = "https://staging.example.invalid"
    scope = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="t",
                program_url="https://example.invalid",
                target_id="t",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=[url],
                allowed_test_categories=["active"],
                environment="staging",
            )
        ]
    )
    adapter = ShannonAdapter(cfg, scope, runner=runner)
    result = adapter.run(
        AdapterRequest(target=url, repo_path=str(Path(__file__).resolve().parents[2]))
    )
    assert result.status == "blocked"
    assert "docker" in (result.error or "").lower()


def test_briar_missing_package_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_BRIAR_EXEC", "host")
    cfg = PlatformConfig(reports_dir=tmp_path)
    runner = MagicMock()
    runner.which.return_value = None
    runner.run.return_value = CommandResult(["python"], 1, "", "ModuleNotFoundError")
    adapter = BriarAdapter(cfg, ScopeEngine([]), runner=runner, python_bin="python3")
    health = adapter.healthcheck()
    assert health["installed"] is False
    assert health["healthy"] is False


def test_briar_compose_without_docker_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_BRIAR_EXEC", "compose")
    cfg = PlatformConfig(reports_dir=tmp_path)
    runner = MagicMock()
    runner.which.return_value = None
    adapter = BriarAdapter(cfg, ScopeEngine([]), runner=runner)
    health = adapter.healthcheck()
    assert health["healthy"] is False
    assert any("docker" in e.lower() for e in health.get("errors", []))


def test_command_timeout_marks_result(tmp_path: Path):
    runner = CommandRunner()
    result = runner.run(["sleep", "5"], timeout=1, log_path=tmp_path / "t.log")
    assert result.timed_out is True
    assert result.returncode == 124
    assert (tmp_path / "t.log").exists()


def test_expired_record_with_explicit_now():
    engine = ScopeEngine.from_file("scopes/registry.yaml")
    decision = engine.evaluate(
        "https://expired.example.invalid",
        test_category="active",
        now=datetime(2026, 10, 12, tzinfo=timezone.utc),
    )
    assert decision.allowed is False
