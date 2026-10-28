import sys

from mcp_server import service


def test_docker_missing_does_not_fallback_to_python(monkeypatch):
    """T1 & T3: Missing Docker stays None instead of inheriting a Python path."""
    def mock_which(cmd):
        return None if cmd == "docker" else f"/usr/bin/{cmd}"

    monkeypatch.setattr("shutil.which", mock_which)

    deps = service.check_dependencies()

    assert deps["present"]["docker"] is None
    assert deps["present"]["docker"] != sys.executable
    assert "docker is missing from PATH" in deps["missing_engines"]
    assert deps["core_ok"] is True
    assert deps["active_engines_ready"] is False


def test_git_optional_absent(monkeypatch):
    """T6: Optional git absence does not break core runtime readiness."""
    def mock_which(cmd):
        return None if cmd == "git" else f"/usr/bin/{cmd}"

    monkeypatch.setattr("shutil.which", mock_which)

    deps = service.check_dependencies()

    assert deps["present"]["git"] is None
    assert any("git" in item for item in deps["optional_absent"])
    assert deps["core_ok"] is True


def test_cross_tool_consistency(monkeypatch):
    """Dependency and platform status retain consistent, scoped readiness values."""
    monkeypatch.setattr(
        "shutil.which",
        lambda cmd: None if cmd == "docker" else f"/usr/bin/{cmd}",
    )

    deps = service.check_dependencies()
    status = service.platform_status()
    diag = status["diagnostics"]

    assert deps["present"]["docker"] is None
    # Legacy diagnostics keep the collector's tools shape, with dependency paths
    # provided separately so daemon/Compose health fields are not lost.
    assert diag["tools"]["docker"] is None
    assert "docker_daemon_ok" in diag["tools"]
    assert "compose_ok" in diag["tools"]
    assert diag["dependency_tools"]["docker"] is None
    assert diag["core_ok"] is True
    assert diag["active_engines_ready"] is False
    assert diag["dependency_failures_scope"] == "engine_prerequisites_only"
    assert diag["core_dependency_failures"] == deps["missing_core"]
    assert diag["all_dependency_failures"] == deps["missing"]
    assert diag["missing_engines"] == deps["missing_engines"]
    assert "shannon" in diag["unhealthy_integrations"]
    assert "briar" in diag["unhealthy_integrations"]


def test_all_deps_present_and_healthy(monkeypatch):
    """All executable prerequisites present yields ready engine statuses."""
    monkeypatch.setattr("shutil.which", lambda cmd: f"/usr/bin/{cmd}")

    deps = service.check_dependencies()

    assert deps["present"]["docker"] == "/usr/bin/docker"
    assert len(deps["missing_engines"]) == 0
    assert deps["core_ok"] is True
    assert deps["active_engines_ready"] is True
    assert deps["ok"] is True



def test_node_and_npx_are_detected_independently(monkeypatch):
    for missing_tool in ("node", "npx"):
        monkeypatch.setattr(
            "shutil.which",
            lambda cmd, missing_tool=missing_tool: (
                None if cmd == missing_tool else f"/usr/bin/{cmd}"
            ),
        )

        deps = service.check_dependencies()

        assert deps["present"][missing_tool] is None
        assert f"{missing_tool} is missing from PATH" in deps["missing_engines"]
        assert deps["core_ok"] is True
        assert deps["active_engines_ready"] is False


def test_missing_core_import_marks_core_not_ready(monkeypatch):
    import builtins

    real_import = builtins.__import__

    def import_without_mcp(name, *args, **kwargs):
        if name == "mcp":
            raise ImportError("simulated missing mcp")
        return real_import(name, *args, **kwargs)

    monkeypatch.setattr(builtins, "__import__", import_without_mcp)
    monkeypatch.setattr("shutil.which", lambda cmd: f"/usr/bin/{cmd}")

    deps = service.check_dependencies()

    assert deps["core_ok"] is False
    assert deps["ok"] is False
    assert deps["present"]["mcp"] is False
    assert any("mcp" in item for item in deps["missing_core"])
    assert deps["active_engines_ready"] is True


def test_legacy_dependency_response_keys_remain_available(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: f"/usr/bin/{cmd}")

    deps = service.check_dependencies()

    for key in ("ok", "present", "missing", "shannon", "briar", "recommendations"):
        assert key in deps
    assert isinstance(deps["shannon"], dict)
    assert isinstance(deps["briar"], dict)
    assert "healthy" in deps["shannon"]
    assert "healthy" in deps["briar"]


def test_engine_prerequisite_readiness_does_not_claim_daemon_health(monkeypatch):
    monkeypatch.setattr("shutil.which", lambda cmd: f"/usr/bin/{cmd}")
    monkeypatch.setattr(
        service,
        "collect_diagnostics",
        lambda cfg: {
            "tools": {
                "python": sys.executable,
                "docker": "/usr/bin/docker",
                "docker_daemon_ok": False,
                "compose": None,
                "compose_ok": False,
                "gh": None,
            }
        },
    )

    status = service.platform_status()
    diag = status["diagnostics"]

    assert diag["active_engines_ready"] is True
    assert diag["engines"]["shannon"] is True
    assert diag["engines"]["briar"] is True
    assert diag["dependency_tools"]["docker"] == "/usr/bin/docker"
    assert diag["tools"]["docker_daemon_ok"] is False
    assert diag["tools"]["compose_ok"] is False
