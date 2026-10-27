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
    """T9: Dependency and platform status expose consistent readiness values."""
    monkeypatch.setattr(
        "shutil.which",
        lambda cmd: None if cmd == "docker" else f"/usr/bin/{cmd}",
    )

    deps = service.check_dependencies()
    status = service.platform_status()

    assert deps["present"]["docker"] is None
    assert status["diagnostics"]["tools"]["docker"] is None
    assert status["diagnostics"]["core_ok"] is True
    assert status["diagnostics"]["active_engines_ready"] is False
    assert "shannon" in status["diagnostics"]["unhealthy_integrations"]
    assert "briar" in status["diagnostics"]["unhealthy_integrations"]


def test_all_deps_present_and_healthy(monkeypatch):
    """All executable prerequisites present yields ready engine statuses."""
    monkeypatch.setattr("shutil.which", lambda cmd: f"/usr/bin/{cmd}")

    deps = service.check_dependencies()

    assert deps["present"]["docker"] == "/usr/bin/docker"
    assert len(deps["missing_engines"]) == 0
    assert deps["core_ok"] is True
    assert deps["active_engines_ready"] is True
    assert deps["ok"] is True
