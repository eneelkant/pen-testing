"""Regression tests for post-merge security hardening."""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import patch

import pytest

from core.config import PlatformConfig
from core.findings import normalize_generic_finding
from core.findings.redaction import redact_text
from core.net import is_loopback_hostname, redact_url_userinfo, require_http_url, validate_resolved_target
from core.paths import confine_path
from core.scope import AuthorizationRecord, ScopeEngine
from integrations.base import AdapterRequest
from integrations.scanners.gitleaks import GitleaksAdapter
from integrations.scanners.headers import HeadersAdapter
from integrations.scanners.trivy import TrivyAdapter


def test_require_http_url_rejects_file_scheme():
    with pytest.raises(ValueError, match="http"):
        require_http_url("file:///etc/passwd")


def test_loopback_hostname_not_substring():
    assert is_loopback_hostname("127.0.0.1")
    assert is_loopback_hostname("localhost")
    assert not is_loopback_hostname("evil.example")
    # Substring tricks must not count as loopback hosts
    assert not is_loopback_hostname(None)


def test_redact_url_userinfo():
    assert (
        redact_url_userinfo("https://user:s3cret@host.example/a")
        == "https://host.example/a"
    )
    assert "s3cret" not in redact_text("https://user:s3cret@host.example/a")


def test_schemeless_path_asset_does_not_authorize_whole_host():
    engine = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="p",
                program_url="https://example.invalid",
                target_id="t",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=["staging.example.com/app"],
                allowed_test_categories=["active"],
                environment="staging",
            )
        ]
    )
    assert engine.evaluate("https://staging.example.com/app", test_category="active").allowed is True
    assert engine.evaluate("https://staging.example.com/app/x", test_category="active").allowed is True
    assert engine.evaluate("https://staging.example.com/other", test_category="active").allowed is False


def test_headers_fail_closed_without_scope_engine(tmp_path: Path):
    cfg = PlatformConfig(reports_dir=tmp_path, require_scope_for_active=True)
    adapter = HeadersAdapter(cfg, scope_engine=None)
    result = adapter.run(
        AdapterRequest(target="http://127.0.0.1:9/", test_category="passive", dry_run=False)
    )
    assert result.status == "blocked"
    assert "scope" in (result.error or "").lower()


def test_headers_rejects_file_scheme(tmp_path: Path):
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
                allowed_assets=["file:///etc/passwd"],
                allowed_test_categories=["passive", "active"],
                environment="local",
            )
        ]
    )
    result = HeadersAdapter(cfg, scope).run(
        AdapterRequest(target="file:///etc/passwd", test_category="passive")
    )
    assert result.status == "blocked"
    assert "http" in (result.error or "").lower()


def test_headers_skip_scope_substring_does_not_bypass(tmp_path: Path):
    cfg = PlatformConfig(reports_dir=tmp_path, require_scope_for_active=True)
    adapter = HeadersAdapter(cfg, scope_engine=None)
    # Old bug: '127.0.0.1' substring in query skipped scope entirely.
    result = adapter.run(
        AdapterRequest(
            target="http://example.com/?x=127.0.0.1",
            test_category="passive",
            skip_scope_check=True,
            dry_run=True,
        )
    )
    assert result.status == "blocked"


def test_validate_resolved_blocks_named_host_to_private(monkeypatch):
    import socket

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    with pytest.raises(PermissionError, match="non-public"):
        validate_resolved_target("http://evil.example/")


def test_validate_resolved_allows_loopback_literal():
    validate_resolved_target("http://127.0.0.1:9/", allow_non_public_literal=True)


def test_confine_path_blocks_escape(tmp_path: Path):
    root = tmp_path / "work"
    root.mkdir()
    with pytest.raises(PermissionError):
        confine_path("/etc/passwd", [root])
    inside = root / "proj"
    inside.mkdir()
    assert confine_path(inside, [root]) == inside.resolve()


def test_gitleaks_blocks_path_outside_roots(tmp_path: Path):
    cfg = PlatformConfig(work_dir=tmp_path / "work", reports_dir=tmp_path / "reports")
    (tmp_path / "work").mkdir()
    (tmp_path / "reports").mkdir()
    adapter = GitleaksAdapter(cfg)
    result = adapter.run(AdapterRequest(target="/etc", dry_run=True))
    assert result.status == "blocked"


def test_trivy_docker_cmd_uses_network_none(tmp_path: Path):
    cfg = PlatformConfig(work_dir=tmp_path, reports_dir=tmp_path / "reports")
    (tmp_path / "reports").mkdir()
    target = tmp_path / "src"
    target.mkdir()
    adapter = TrivyAdapter(cfg)
    adapter.healthcheck = lambda: {"binary": None, "docker": "/usr/bin/docker", "healthy": True}  # type: ignore
    captured: dict = {}

    def fake_run(cmd, **kwargs):
        captured["cmd"] = cmd

        class R:
            ok = True
            timed_out = False
            returncode = 0
            stderr = ""
            stdout = ""

        return R()

    adapter.runner.run = fake_run  # type: ignore
    result = adapter.run(AdapterRequest(target=str(target), dry_run=False))
    assert result.status == "succeeded"
    assert "--network" in captured["cmd"]
    assert "none" in captured["cmd"]


def test_finding_redacts_userinfo_in_free_text():
    finding = normalize_generic_finding(
        title="Leak https://user:pass@evil.example/x",
        category="test",
        source_tool="unit",
        asset="https://user:pass@evil.example/x",
        impact="see https://user:pass@evil.example/x",
        observed_behavior="token https://user:pass@evil.example/x",
    )
    data = finding.to_dict()
    blob = str(data)
    assert "user:pass" not in blob
    assert "pass@" not in blob


def test_cli_skip_scope_requires_env(tmp_path: Path, monkeypatch):
    from core.cli import main

    monkeypatch.delenv("PEN_ALLOW_SKIP_SCOPE", raising=False)
    monkeypatch.setenv("PEN_SCOPES_FILE", str(tmp_path / "missing.yaml"))
    code = main(
        [
            "run",
            "--tool",
            "headers",
            "--target",
            "http://127.0.0.1:9/",
            "--dry-run",
            "--skip-scope-check",
        ]
    )
    assert code == 2


def test_cli_skip_scope_with_env_gate(tmp_path: Path, monkeypatch):
    from core.cli import main

    monkeypatch.setenv("PEN_ALLOW_SKIP_SCOPE", "1")
    # Use dry-run so no network; skip scope with env gate.
    code = main(
        [
            "run",
            "--tool",
            "shannon",
            "--target",
            "https://127.0.0.1:9",
            "--repo",
            str(Path(__file__).resolve().parents[2]),
            "--dry-run",
            "--skip-scope-check",
            "--output",
            str(tmp_path / "out.json"),
        ]
    )
    assert code == 0
