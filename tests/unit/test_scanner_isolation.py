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
    resolve_project_network_name,
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
    monkeypatch.delenv("PEN_ALLOW_EGRESS_DISABLE", raising=False)
    monkeypatch.delenv("PEN_ALLOW_SCOPE_DISABLE", raising=False)
    monkeypatch.delenv("PEN_ALLOW_SHANNON_LIVE", raising=False)
    monkeypatch.delenv("PEN_ALLOW_SHANNON_UNCONTAINED_NET", raising=False)
    monkeypatch.delenv("PEN_ALLOW_BRIAR_LIVE", raising=False)
    monkeypatch.delenv("PEN_ALLOW_BRIAR_HOST_NET", raising=False)
    monkeypatch.delenv("PEN_BRIAR_EXEC", raising=False)
    policy = load_isolation_policy()
    assert policy.require_egress_policy is True
    assert policy.allow_egress_disable is False
    assert policy.allow_scope_disable is False
    assert policy.allow_shannon_live is False
    assert policy.allow_shannon_uncontained_net is False
    assert policy.allow_briar_live is False
    assert policy.briar_exec_mode == "compose"
    assert policy.allow_briar_host_net is False


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
    # Unit tests do not run Docker prepare; exercise uncontained dual-gate path.
    monkeypatch.setenv("PEN_ALLOW_SHANNON_UNCONTAINED_NET", "1")

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
    assert (result.metadata or {}).get("network_mode") == "uncontained"
    runner.run.assert_called_once()


def test_live_shannon_controlled_prepare_failure_blocks(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_SHANNON_LIVE", "1")
    monkeypatch.delenv("PEN_ALLOW_SHANNON_UNCONTAINED_NET", raising=False)

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
    adapter._prepare_controlled_network = lambda: {"ok": False, "error": "docker missing"}  # type: ignore
    adapter.runner = MagicMock()
    result = adapter.run(
        AdapterRequest(
            target=url,
            repo_path=str(Path(__file__).resolve().parents[2]),
            dry_run=False,
        )
    )
    assert result.status == "blocked"
    assert "controlled network" in (result.error or "").lower() or "PEN_ALLOW_SHANNON_UNCONTAINED_NET" in (
        result.error or ""
    )
    assert (result.metadata or {}).get("isolation") == "shannon_controlled_net"
    adapter.runner.run.assert_not_called()


def test_live_shannon_controlled_prepare_success_uses_wrap_path(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_SHANNON_LIVE", "1")
    monkeypatch.delenv("PEN_ALLOW_SHANNON_UNCONTAINED_NET", raising=False)

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
    wrap = tmp_path / "wrap"
    wrap.mkdir()
    adapter._prepare_controlled_network = lambda: {  # type: ignore
        "ok": True,
        "wrap_dir": str(wrap),
        "real_docker": "/usr/bin/docker",
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
    assert (result.metadata or {}).get("network_mode") == "controlled"
    kwargs = runner.run.call_args.kwargs
    assert "PATH" in (kwargs.get("env") or {})
    assert str(wrap) in kwargs["env"]["PATH"]


def test_prepare_controlled_network_stages_named_docker_shim(tmp_path: Path, monkeypatch):
    """Regression: wrap must be on PATH as `docker`, not only shannon-docker-wrap."""
    root = Path(__file__).resolve().parents[2]
    wrap_script = root / "scripts" / "shannon-docker-wrap"
    assert wrap_script.is_file()
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = ShannonAdapter(cfg, scope_engine=None)
    runner = MagicMock()

    class R:
        ok = True
        timed_out = False
        returncode = 0
        stdout = "SHANNON_CONTROLLED_NET_READY\n"
        stderr = ""

    runner.run.return_value = R()
    adapter.runner = runner
    monkeypatch.setattr(
        "integrations.shannon.adapter.ShannonAdapter._resolve_real_docker_binary",
        staticmethod(lambda: "/usr/bin/docker"),
    )
    result = adapter._prepare_controlled_network()
    assert result["ok"] is True
    wrap_dir = Path(result["wrap_dir"])
    assert wrap_dir.name == ".shannon-docker-bin"
    docker_shim = wrap_dir / "docker"
    assert docker_shim.is_symlink()
    assert docker_shim.resolve() == wrap_script.resolve()
    assert result["real_docker"] == "/usr/bin/docker"


def test_resolve_real_docker_skips_wrap_shim(tmp_path: Path, monkeypatch):
    wrap_bin = tmp_path / ".shannon-docker-bin"
    wrap_bin.mkdir()
    shim = wrap_bin / "docker"
    shim.symlink_to(Path(__file__).resolve().parents[2] / "scripts" / "shannon-docker-wrap")
    real = tmp_path / "real-docker"
    real.write_text("#!/bin/sh\n")
    real.chmod(0o755)
    monkeypatch.setenv("PATH", f"{wrap_bin}:{tmp_path}")
    monkeypatch.setattr("integrations.shannon.adapter.shutil.which", lambda _: str(shim))
    resolved = ShannonAdapter._resolve_real_docker_binary()
    assert "shannon-docker-wrap" not in resolved
    assert resolved in {str(real), "/usr/bin/docker", "/usr/local/bin/docker"}


def test_shannon_validate_model_flag_in_start_command(tmp_path: Path):
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = ShannonAdapter(cfg, scope_engine=None)
    models = tmp_path / "models.json"
    models.write_text("{}", encoding="utf-8")
    cmd = adapter._build_start_command(
        AdapterRequest(
            target="http://10.0.0.5:8080/",
            repo_path=str(tmp_path),
            extra={"validate_model": True, "models_config": str(models)},
        ),
        tmp_path,
    )
    assert "--validate-model" in cmd
    assert "--models-config" in cmd
    assert str(models.resolve()) in cmd
    assert "start" in cmd


def _healthy_briar() -> dict:
    return {
        "installed": True,
        "healthy": True,
        "errors": [],
        "commands": {"scan": True},
    }


def test_live_briar_blocks_dns_rebinding_before_launch(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_BRIAR_LIVE", "1")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    adapter.runner = MagicMock()
    result = adapter.run(
        AdapterRequest(target=url, mode="quick", dry_run=False)
    )
    assert result.status == "blocked"
    assert "non-public" in (result.error or "").lower()
    adapter.runner.run.assert_not_called()


def test_live_briar_requires_explicit_allow_even_when_dns_ok(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("PEN_ALLOW_BRIAR_LIVE", raising=False)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    adapter.runner = MagicMock()
    result = adapter.run(
        AdapterRequest(target=url, mode="quick", dry_run=False)
    )
    assert result.status == "blocked"
    assert "PEN_ALLOW_BRIAR_LIVE" in (result.error or "")
    assert (result.metadata or {}).get("isolation") == "briar_live_gate"
    adapter.runner.run.assert_not_called()


def test_live_briar_compose_launches_with_allow_and_public_dns(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_BRIAR_LIVE", "1")
    monkeypatch.setenv("PEN_BRIAR_EXEC", "compose")
    monkeypatch.setenv("PEN_COMPOSE_DIR", str(Path(__file__).resolve().parents[2]))

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    monkeypatch.setattr(
        "integrations.briar.adapter.assert_network_internal",
        lambda name: None,
    )
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: {  # type: ignore
        "healthy": True,
        "exec_mode": "compose",
        "errors": [],
        "commands": {"scan": True},
    }
    runner = MagicMock()

    class R:
        def __init__(self, stdout: str = ""):
            self.ok = True
            self.timed_out = False
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    def run_side_effect(cmd, **kwargs):
        if len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "compose" and "config" in cmd:
            return R(stdout='{"name":"pen-testing","networks":{"pen-scanner-live":{"internal":true}}}')
        if len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "network" and "ls" in cmd:
            return R(stdout="pen-testing_pen-scanner-live\n")
        return R()

    runner.run.side_effect = run_side_effect
    runner.which.return_value = "/usr/bin/docker"
    adapter.runner = runner
    result = adapter.run(
        AdapterRequest(target=url, mode="quick", dry_run=False)
    )
    assert result.status == "succeeded"
    assert runner.run.call_count >= 4  # create + config + network ls + scan
    cmd = runner.run.call_args_list[-1][0][0]
    assert cmd[:2] == ["docker", "compose"]
    assert "briar-live" in cmd
    assert (result.metadata or {}).get("network") == "pen-scanner-live"


def test_live_briar_host_requires_host_net_ack(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_BRIAR_LIVE", "1")
    monkeypatch.setenv("PEN_BRIAR_EXEC", "host")
    monkeypatch.delenv("PEN_ALLOW_BRIAR_HOST_NET", raising=False)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    adapter.runner = MagicMock()
    result = adapter.run(AdapterRequest(target=url, mode="quick", dry_run=False))
    assert result.status == "blocked"
    assert "PEN_ALLOW_BRIAR_HOST_NET" in (result.error or "")
    assert (result.metadata or {}).get("isolation") == "briar_host_net_gate"
    adapter.runner.run.assert_not_called()


def test_live_briar_host_launches_with_dual_host_acks(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_BRIAR_LIVE", "1")
    monkeypatch.setenv("PEN_BRIAR_EXEC", "host")
    monkeypatch.setenv("PEN_ALLOW_BRIAR_HOST_NET", "1")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    runner = MagicMock()

    class R:
        ok = True
        timed_out = False
        returncode = 0
        stdout = ""
        stderr = ""

    runner.run.return_value = R()
    runner.which.return_value = "/usr/bin/briar"
    adapter.runner = runner
    result = adapter.run(AdapterRequest(target=url, mode="quick", dry_run=False))
    assert result.status == "succeeded"
    cmd = runner.run.call_args[0][0]
    assert cmd[0] in {"/usr/bin/briar", "briar"} or cmd[0].endswith("python")
    assert "docker" not in cmd[:2]


def test_briar_demo_skips_live_gate(tmp_path: Path, monkeypatch):
    monkeypatch.delenv("PEN_ALLOW_BRIAR_LIVE", raising=False)
    monkeypatch.setenv("PEN_BRIAR_EXEC", "host")
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, scope_engine=None)
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    runner = MagicMock()

    class R:
        ok = True
        timed_out = False
        returncode = 0
        stdout = ""
        stderr = ""

    runner.run.return_value = R()
    runner.which.return_value = "/usr/bin/briar"
    adapter.runner = runner
    result = adapter.run(
        AdapterRequest(target="", mode="demo", dry_run=False, extra={"demo": True})
    )
    assert result.status == "succeeded"
    runner.run.assert_called_once()


def test_briar_compose_dry_run_plans_docker_compose(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_BRIAR_EXEC", "compose")
    monkeypatch.setenv("PEN_COMPOSE_DIR", str(Path(__file__).resolve().parents[2]))
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    result = adapter.run(AdapterRequest(target=url, mode="quick", dry_run=True))
    assert result.status == "skipped"
    planned = result.artifacts["planned_command"]
    assert "docker compose" in planned
    assert "briar-live" in planned
    assert "/work/out" in planned


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


def test_skip_scope_does_not_bypass_egress_dns_gate_shannon(tmp_path: Path, monkeypatch):
    """Regression: PEN_ALLOW_SKIP_SCOPE must not disable launch-time DNS policy."""
    monkeypatch.setenv("PEN_ALLOW_SHANNON_LIVE", "1")
    monkeypatch.setenv("PEN_ALLOW_SKIP_SCOPE", "1")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = ShannonAdapter(cfg, scope_engine=None)
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
            skip_scope_check=True,
        )
    )
    assert result.status == "blocked"
    assert "non-public" in (result.error or "").lower()
    adapter.runner.run.assert_not_called()


def test_skip_scope_does_not_bypass_egress_dns_gate_briar(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_BRIAR_LIVE", "1")
    monkeypatch.setenv("PEN_ALLOW_SKIP_SCOPE", "1")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, scope_engine=None)
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    adapter.runner = MagicMock()
    result = adapter.run(
        AdapterRequest(target=url, mode="quick", dry_run=False, skip_scope_check=True)
    )
    assert result.status == "blocked"
    assert "non-public" in (result.error or "").lower()
    adapter.runner.run.assert_not_called()


def test_egress_disable_requires_dual_gate(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_SHANNON_LIVE", "1")
    monkeypatch.setenv("PEN_REQUIRE_EGRESS_POLICY", "false")
    monkeypatch.delenv("PEN_ALLOW_EGRESS_DISABLE", raising=False)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

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
    assert "PEN_ALLOW_EGRESS_DISABLE" in (result.error or "")
    adapter.runner.run.assert_not_called()


def test_egress_disable_with_dual_gate_allows_when_live_ack(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_SHANNON_LIVE", "1")
    monkeypatch.setenv("PEN_ALLOW_SHANNON_UNCONTAINED_NET", "1")
    monkeypatch.setenv("PEN_REQUIRE_EGRESS_POLICY", "false")
    monkeypatch.setenv("PEN_ALLOW_EGRESS_DISABLE", "1")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

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


def test_shannon_live_gate_does_not_enable_briar(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_SHANNON_LIVE", "1")
    monkeypatch.delenv("PEN_ALLOW_BRIAR_LIVE", raising=False)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    adapter.runner = MagicMock()
    result = adapter.run(AdapterRequest(target=url, mode="quick", dry_run=False))
    assert result.status == "blocked"
    assert "PEN_ALLOW_BRIAR_LIVE" in (result.error or "")
    adapter.runner.run.assert_not_called()


def test_mcp_demo_does_not_waive_confirm_for_shannon(tmp_path: Path, monkeypatch):
    from mcp_server import service

    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    (tmp_path / "work").mkdir()
    (tmp_path / "reports").mkdir()
    result = service.run_security_assessment(
        tool="shannon",
        target="https://staging.example.invalid",
        dry_run=False,
        confirm_authorized=False,
        demo=True,
        repo_path=str(Path(__file__).resolve().parents[2]),
    )
    assert result.get("ok") is False
    assert "confirm_authorized" in (result.get("error") or "")


def test_compose_networks_must_be_internal():
    from core.isolation import compose_networks_must_be_internal

    compose_networks_must_be_internal(
        {
            "networks": {
                "pen-scanner-isolated": {"internal": True},
                "pen-scanner-live": {"name": "pen-scanner-live", "internal": True},
            }
        },
        ("pen-scanner-isolated", "pen-scanner-live"),
    )
    with pytest.raises(PermissionError, match="internal"):
        compose_networks_must_be_internal(
            {"networks": {"pen-scanner-live": {"driver": "bridge"}}},
            ("pen-scanner-live",),
        )
    with pytest.raises(PermissionError, match="missing"):
        compose_networks_must_be_internal({"networks": {}}, ("pen-scanner-live",))


def test_resolve_project_network_name_prefers_project_prefix():
    assert (
        resolve_project_network_name(
            project_name="pen-testing",
            network_key="pen-scanner-live",
            listed_names=["other_pen-scanner-live", "pen-testing_pen-scanner-live"],
        )
        == "pen-testing_pen-scanner-live"
    )
    with pytest.raises(PermissionError, match="Ambiguous"):
        resolve_project_network_name(
            project_name="missing",
            network_key="pen-scanner-live",
            listed_names=["a_pen-scanner-live", "b_pen-scanner-live"],
        )


def test_assert_network_internal_fail_closed(monkeypatch):
    from core.isolation import NetworkIsolationStatus, assert_network_internal
    from core.isolation import network_assert as na

    monkeypatch.setattr(
        na,
        "inspect_network",
        lambda name: NetworkIsolationStatus(name, True, False, {}, "network is not internal"),
    )
    with pytest.raises(PermissionError, match="not internal"):
        assert_network_internal("pen-scanner-live")


def test_live_briar_blocks_when_network_not_internal(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_BRIAR_LIVE", "1")
    monkeypatch.setenv("PEN_BRIAR_EXEC", "compose")
    monkeypatch.setenv("PEN_COMPOSE_DIR", str(Path(__file__).resolve().parents[2]))

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    def _not_internal(name: str) -> None:
        raise PermissionError(
            f"Required isolation network {name!r} is not internal/ready: network is not internal"
        )

    monkeypatch.setattr(
        "integrations.briar.adapter.assert_network_internal",
        _not_internal,
    )
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    runner = MagicMock()

    class R:
        def __init__(self, stdout: str = "pen-testing_pen-scanner-live\n"):
            self.ok = True
            self.timed_out = False
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    def run_side_effect(cmd, **kwargs):
        if len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "compose" and "config" in cmd:
            return R(stdout='{"name":"pen-testing"}')
        return R()

    runner.run.side_effect = run_side_effect
    adapter.runner = runner
    result = adapter.run(AdapterRequest(target=url, mode="quick", dry_run=False))
    assert result.status == "blocked"
    assert "internal" in (result.error or "").lower()
    assert (result.metadata or {}).get("isolation") == "briar_network_internal"
    # Must not reach the scan launch (create/config/ls only).
    for call in runner.run.call_args_list:
        cmd = call[0][0]
        assert not (len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "compose" and "run" in cmd)


def test_live_briar_blocks_when_isolation_network_missing(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_BRIAR_LIVE", "1")
    monkeypatch.setenv("PEN_BRIAR_EXEC", "compose")
    monkeypatch.setenv("PEN_COMPOSE_DIR", str(Path(__file__).resolve().parents[2]))

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    runner = MagicMock()

    class R:
        def __init__(self, stdout: str = "bridge\nnone\n"):
            self.ok = True
            self.timed_out = False
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    def run_side_effect(cmd, **kwargs):
        if len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "compose" and "config" in cmd:
            return R(stdout='{"name":"pen-testing"}')
        return R()

    runner.run.side_effect = run_side_effect
    adapter.runner = runner
    result = adapter.run(AdapterRequest(target=url, mode="quick", dry_run=False))
    assert result.status == "blocked"
    assert "not found" in (result.error or "").lower() or "internal" in (result.error or "").lower()
    assert (result.metadata or {}).get("isolation") == "briar_network_internal"


def test_live_briar_blocks_ambiguous_unrelated_networks(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_ALLOW_BRIAR_LIVE", "1")
    monkeypatch.setenv("PEN_BRIAR_EXEC", "compose")
    monkeypatch.setenv("PEN_COMPOSE_DIR", str(Path(__file__).resolve().parents[2]))

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    url = "https://staging.example.invalid"
    cfg = PlatformConfig(reports_dir=tmp_path)
    adapter = BriarAdapter(cfg, _scope(url))
    adapter.healthcheck = lambda: _healthy_briar()  # type: ignore
    runner = MagicMock()

    class R:
        def __init__(self, stdout: str = ""):
            self.ok = True
            self.timed_out = False
            self.returncode = 0
            self.stdout = stdout
            self.stderr = ""

    def run_side_effect(cmd, **kwargs):
        if len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "compose" and "config" in cmd:
            return R(stdout='{"name":"pen-testing"}')
        if len(cmd) >= 2 and cmd[0] == "docker" and cmd[1] == "network" and "ls" in cmd:
            # Label filter empty → fallback list has only decoys (no project prefix).
            if any(str(a).startswith("label=") for a in cmd):
                return R(stdout="")
            return R(stdout="decoy_a_pen-scanner-live\ndecoy_b_pen-scanner-live\n")
        return R()

    runner.run.side_effect = run_side_effect
    adapter.runner = runner
    result = adapter.run(AdapterRequest(target=url, mode="quick", dry_run=False))
    assert result.status == "blocked"
    assert "ambiguous" in (result.error or "").lower()
    assert (result.metadata or {}).get("isolation") == "briar_network_internal"
