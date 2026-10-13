import shutil

import pytest

from core.config import load_config
from core.diagnostics import collect_diagnostics


@pytest.mark.docker
def test_docker_prerequisite_detection():
    data = collect_diagnostics(load_config())
    if shutil.which("docker") is None:
        pytest.skip("Docker not installed in this environment")
    assert data["tools"]["docker"]


@pytest.mark.integration
def test_briar_package_optional(monkeypatch):
    from integrations.briar import BriarAdapter

    monkeypatch.setenv("PEN_BRIAR_EXEC", "host")
    health = BriarAdapter(load_config()).healthcheck()
    # Pass whether installed or not — assert structure
    assert "installed" in health
    assert "commands" in health
