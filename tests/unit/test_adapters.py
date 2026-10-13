from pathlib import Path
from unittest.mock import MagicMock

from core.config import PlatformConfig
from core.execution import CommandResult
from core.scope import AuthorizationRecord, ScopeEngine
from integrations.base import AdapterRequest
from integrations.briar import BriarAdapter
from integrations.scanners import HeadersAdapter
from integrations.shannon import ShannonAdapter


def _scope_allowing(url: str) -> ScopeEngine:
    return ScopeEngine(
        [
            AuthorizationRecord(
                program_name="t",
                program_url="https://example.invalid",
                target_id="t",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=[url],
                allowed_test_categories=["active", "passive", "dast"],
                environment="local",
            )
        ]
    )


def test_shannon_blocks_without_scope():
    cfg = PlatformConfig()
    adapter = ShannonAdapter(cfg, ScopeEngine([]))
    result = adapter.run(
        AdapterRequest(target="https://example.com", repo_path=".", test_category="active")
    )
    assert result.status == "blocked"


def test_shannon_dry_run_plan(tmp_path: Path):
    cfg = PlatformConfig(reports_dir=tmp_path)
    url = "https://staging.example.invalid"
    adapter = ShannonAdapter(cfg, _scope_allowing(url))
    result = adapter.run(
        AdapterRequest(
            target=url,
            repo_path=str(Path(__file__).resolve().parents[2]),
            dry_run=True,
        )
    )
    assert result.status == "skipped"
    assert "npx" in result.artifacts["planned_command"]
    assert "--url" in result.artifacts["planned_command"] or "-u" in result.artifacts["planned_command"]


def test_shannon_requires_repo(tmp_path: Path):
    cfg = PlatformConfig(reports_dir=tmp_path)
    url = "https://staging.example.invalid"
    adapter = ShannonAdapter(cfg, _scope_allowing(url))
    result = adapter.run(AdapterRequest(target=url))
    assert result.status == "failed"
    assert "repo" in (result.error or "").lower()


def test_briar_capability_detection_uses_runner(monkeypatch):
    monkeypatch.setenv("PEN_BRIAR_EXEC", "host")
    cfg = PlatformConfig()
    runner = MagicMock()
    runner.which.return_value = "/usr/bin/briar"

    def fake_run(cmd, **kwargs):
        joined = " ".join(cmd)
        if "briar-pentest" in joined or "importlib.metadata" in joined:
            return CommandResult(list(cmd), 0, "0.4.62", "")
        if "--help" in cmd and "scan" not in cmd:
            return CommandResult(list(cmd), 0, "Commands:\n  setup\n  scan\n  demo\n", "")
        if "scan" in cmd and "--help" in cmd:
            return CommandResult(list(cmd), 0, "--quick\n--deep\n--url\n", "")
        return CommandResult(list(cmd), 1, "", "fail")

    runner.run.side_effect = fake_run
    adapter = BriarAdapter(cfg, ScopeEngine([]), runner=runner)
    health = adapter.healthcheck()
    assert health["installed"] is True
    assert health["commands"]["scan_quick"] is True
    assert health["commands"]["scan_deep"] is True


def test_briar_blocks_unauthorized():
    cfg = PlatformConfig()
    adapter = BriarAdapter(cfg, ScopeEngine([]))
    result = adapter.run(AdapterRequest(target="https://example.com", mode="quick"))
    assert result.status == "blocked"


def test_headers_missing_on_fixture(tmp_path: Path):
    # Spin a tiny local server in-thread
    import threading
    from http.server import BaseHTTPRequestHandler, HTTPServer

    class H(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            self.send_response(200)
            self.send_header("Content-Type", "text/plain")
            self.end_headers()
            self.wfile.write(b"ok")

        def log_message(self, *args):
            return

    server = HTTPServer(("127.0.0.1", 0), H)
    port = server.server_address[1]
    thread = threading.Thread(target=server.handle_request, daemon=True)
    thread.start()
    url = f"http://127.0.0.1:{port}/"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = HeadersAdapter(cfg, _scope_allowing(url))
    result = adapter.run(AdapterRequest(target=url, test_category="passive"))
    server.server_close()
    assert result.status == "succeeded"
    assert any("content-security-policy" in f.title for f in result.findings)


def test_shannon_healthcheck_missing_docker():
    cfg = PlatformConfig()
    runner = MagicMock()
    runner.which.side_effect = lambda b: "/usr/bin/npx" if b in {"npx", "node"} else None
    runner.run.return_value = CommandResult(["npx"], 0, '{"version":"3.4.0"}', "")
    adapter = ShannonAdapter(cfg, runner=runner)
    health = adapter.healthcheck()
    assert health["cli_reachable"] is True
    assert health["healthy"] is False
    assert any("Docker" in e for e in health["errors"])
