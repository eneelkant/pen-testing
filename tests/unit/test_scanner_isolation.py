"""Regression tests for scanner egress policy and scope-override dual gates."""

from __future__ import annotations

import socket
from pathlib import Path
from unittest.mock import MagicMock

import pytest

from core.config import PlatformConfig
from core.isolation import (
    assert_live_destination_allowed,
    evaluate_destination,
    load_isolation_policy,
    validate_redirect_destination,
)
from core.isolation.policy import IsolationPolicy
from core.scope import AuthorizationRecord, ScopeEngine
from integrations.base import AdapterRequest
from integrations.briar import BriarAdapter
from integrations.shannon import ShannonAdapter


def _scope(url: str) -> ScopeEngine:
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


def test_policy_defaults_require_egress(monkeypatch):
    monkeypatch.delenv("PEN_REQUIRE_EGRESS_POLICY", raising=False)
    monkeypatch.delenv("PEN_ALLOW_SCOPE_DISABLE", raising=False)
    policy = load_isolation_policy()
    assert policy.require_egress_policy is True
    assert policy.allow_scope_disable is False


def test_unauthorized_hostname_denied():
    decision = evaluate_destination(
        "https://evil.example/",
        policy=IsolationPolicy(),
        scope_engine=ScopeEngine([]),
    )
    assert decision.allowed is False
    assert "scope" in decision.reason.lower() or "denied" in decision.reason.lower()


def test_private_ipv4_literal_respects_policy():
    denied = evaluate_destination(
        "http://10.0.0.5/",
        policy=IsolationPolicy(allow_non_public_literals=False),
        scope_engine=None,
    )
    assert denied.allowed is False
    allowed = evaluate_destination(
        "http://10.0.0.5/",
        policy=IsolationPolicy(allow_non_public_literals=True),
        scope_engine=None,
    )
    assert allowed.allowed is True


def test_ipv6_loopback_literal_allowed_when_configured():
    decision = evaluate_destination(
        "http://[::1]:8080/",
        policy=IsolationPolicy(allow_non_public_literals=True),
    )
    assert decision.allowed is True


def test_dns_rebinding_named_host_to_private(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    decision = evaluate_destination(
        "http://rebind.example/",
        policy=IsolationPolicy(block_non_public_resolved=True),
        scope_engine=None,
    )
    assert decision.allowed is False
    assert "non-public" in decision.reason.lower()


def test_dns_change_between_answers_blocks_private(monkeypatch):
    # Mixed answers: any non-public IP in the set must fail closed.
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("203.0.113.10", port)),
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    decision = evaluate_destination("http://mixed.example/", scope_engine=None)
    assert decision.allowed is False


def test_redirect_to_unauthorized_origin_blocked():
    ok, reason = validate_redirect_destination(
        "https://staging.example.invalid/app",
        "https://evil.example/phish",
    )
    assert ok is False
    assert "origin" in reason.lower() or "leaves" in reason.lower()


def test_redirect_same_origin_with_private_resolve_blocked(monkeypatch):
    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.1.2.3", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = validate_redirect_destination(
        "https://staging.example.invalid/app",
        "/login",
    )
    assert ok is False
    assert "non-public" in reason.lower()


def test_missing_scope_fail_closed_on_adapter(tmp_path: Path):
    cfg = PlatformConfig(reports_dir=tmp_path, require_scope_for_active=True)
    adapter = ShannonAdapter(cfg, scope_engine=None)
    result = adapter.run(
        AdapterRequest(
            target="https://staging.example.invalid",
            repo_path=str(tmp_path),
            dry_run=False,
        )
    )
    assert result.status == "blocked"
    assert "scope" in (result.error or "").lower()


def test_require_scope_false_needs_dual_gate(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_SCOPE_DISABLE", "0")
    # Ensure policy loader sees the dual-gate as disabled.
    monkeypatch.delenv("PEN_ALLOW_SCOPE_DISABLE", raising=False)
    monkeypatch.setenv("PEN_ALLOW_SCOPE_DISABLE", "false")
    cfg = PlatformConfig(reports_dir=tmp_path, require_scope_for_active=False)
    adapter = BriarAdapter(cfg, scope_engine=None)
    result = adapter.run(
        AdapterRequest(target="https://staging.example.invalid", mode="quick", dry_run=True)
    )
    # dry_run still runs preflight (egress skipped) — dual-gate must fire
    assert result.status == "blocked"
    assert "PEN_ALLOW_SCOPE_DISABLE" in (result.error or "")


def test_require_scope_false_with_dual_gate(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_SCOPE_DISABLE", "1")
    cfg = PlatformConfig(reports_dir=tmp_path, require_scope_for_active=False)
    adapter = ShannonAdapter(cfg, scope_engine=None)
    result = adapter.run(
        AdapterRequest(
            target="https://staging.example.invalid",
            repo_path=str(Path(__file__).resolve().parents[2]),
            dry_run=True,
        )
    )
    assert result.status == "skipped"


def test_live_shannon_blocks_dns_rebinding_before_launch(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_SHANNON_LIVE", "1")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = ShannonAdapter(cfg, _scope(url))
    # Force health to look ready so we would reach launch without egress gate.
    adapter.healthcheck = lambda: {  # type: ignore
        "cli_reachable": True,
        "docker_available": True,
        "errors": [],
        "healthy": True,
    }
    adapter.runner = MagicMock()
    result = adapter.run(
        AdapterRequest(
            target=url,
            repo_path=str(Path(__file__).resolve().parents[2]),
            dry_run=False,
        )
    )
    assert result.status == "blocked"
    assert "non-public" in (result.error or "").lower()
    adapter.runner.run.assert_not_called()


def test_live_shannon_requires_explicit_allow_even_when_dns_ok(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("PEN_ALLOW_SHANNON_LIVE", raising=False)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = ShannonAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: {  # type: ignore
        "cli_reachable": True,
        "docker_available": True,
        "errors": [],
        "healthy": True,
    }
    adapter.runner = MagicMock()
    result = adapter.run(
        AdapterRequest(
            target=url,
            repo_path=str(Path(__file__).resolve().parents[2]),
            dry_run=False,
        )
    )
    assert result.status == "blocked"
    assert "PEN_ALLOW_SHANNON_LIVE" in (result.error or "")
    adapter.runner.run.assert_not_called()


def test_live_shannon_launches_only_with_allow_and_public_dns(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_SHANNON_LIVE", "1")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = ShannonAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: {  # type: ignore
        "cli_reachable": True,
        "docker_available": True,
        "errors": [],
        "healthy": True,
    }
    runner = MagicMock()

    class R:
        ok = True
        timed_out = False
        returncode = 0
        stdout = ""
        stderr = ""

    runner.run.return_value = R()
    adapter.runner = runner
    result = adapter.run(
        AdapterRequest(
            target=url,
            repo_path=str(Path(__file__).resolve().parents[2]),
            dry_run=False,
        )
    )
    assert result.status == "succeeded"
    runner.run.assert_called_once()


def test_assert_live_destination_skipped_on_dry_run():
    decision = assert_live_destination_allowed(
        "https://evil.example/",
        scope_engine=ScopeEngine([]),
        dry_run=True,
    )
    assert decision.allowed is True


def test_egress_allow_hosts_restricts(monkeypatch):
    monkeypatch.setenv("PEN_EGRESS_ALLOW_HOSTS", "allowed.example")
    policy = load_isolation_policy()
    assert evaluate_destination(
        "https://other.example/",
        policy=policy,
        scope_engine=None,
    ).allowed is False
    # Allowlisted host still subject to DNS non-public policy
    def fake_getaddrinfo(host, port, *args, **kwargs):
        # 8.8.8.8 is a globally routed address for policy unit tests only.
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    assert evaluate_destination(
        "https://allowed.example/",
        policy=policy,
        scope_engine=None,
    ).allowed is True


def test_mcp_cannot_set_skip_scope_for_shannon(tmp_path: Path, monkeypatch):
    from mcp_server import service
    from mcp_server.config import resolve_platform_config

    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_SCOPES_FILE", str(tmp_path / "missing-scopes.yaml"))
    (tmp_path / "work").mkdir()
    (tmp_path / "reports").mkdir()
    # Even with confirm_authorized, missing registry must fail closed for live shannon.
    result = service.run_security_assessment(
        tool="shannon",
        target="https://staging.example.invalid",
        dry_run=False,
        confirm_authorized=True,
        repo_path=str(Path(__file__).resolve().parents[2]),
    )
    assert result.get("ok") is False
    assert "authorization" in (result.get("error") or "").lower() or result.get("status") == "blocked"
