from __future__ import annotations

import subprocess
from pathlib import Path

import pytest

from scripts.detect_image_sensitive_changes import classify_paths, changed_paths, is_image_sensitive_path
from scripts.image_gate_status import evaluate_gate


@pytest.mark.parametrize(
    "path",
    [
        "Dockerfile", ".dockerignore", "docker-compose.yml", "docker-compose.override.yaml",
        "docker/candidates/shannon/Dockerfile", "docker/candidates/requirements.json",
        "core/supply_chain/images.py", "core/supply_chain/image_baseline.json",
        "requirements/dev.txt", "requirements.txt", "requirements-prod.in",
        "pyproject.toml", "uv.lock", "poetry.lock", "package-lock.json",
        "pnpm-lock.yaml", "go.mod", "go.sum", "Cargo.lock",
        "integrations/scanners/trivy.py", "integrations/shannon/adapter.py",
        "integrations/briar/adapter.py", "scripts/docker_runtime_verify.sh",
        "scripts/verify_image_candidate.py", "scripts/verify_self_built_candidates.sh",
        "scripts/detect_image_sensitive_changes.py", "scripts/image_gate_status.py",
        ".github/workflows/image-gates.yml", ".github/workflows/release.yml",
        ".github/workflows/self-built-image-candidates.yml",
        ".github/actions/setup-scanner/action.yml",
        "tests/unit/test_image_gate_workflow_helpers.py",
    ],
)
def test_image_sensitive_paths_trigger_gate(path: str) -> None:
    assert is_image_sensitive_path(path)


@pytest.mark.parametrize(
    "path",
    [
        "README.md", "docs/ARCHITECTURE.md",
        "reports/upstream/issue-drafts-final-review.md",
        "reports/production-readiness/baseline.md",
        "tests/unit/test_scope_engine.py", "core/scope/engine.py",
        "mcp_server/server.py", "CHANGELOG.md",
    ],
)
def test_non_image_paths_do_not_trigger_gate(path: str) -> None:
    assert not is_image_sensitive_path(path)


def test_normalizes_windows_separators_and_dot_prefix() -> None:
    sensitive, matched = classify_paths([r".\docker\Dockerfile"])
    assert sensitive is True
    assert matched == ["docker/Dockerfile"]


def test_deduplicates_sensitive_paths_preserving_order() -> None:
    sensitive, matched = classify_paths(["Dockerfile", "README.md", "Dockerfile", "docker/a"])
    assert sensitive is True
    assert matched == ["Dockerfile", "docker/a"]


def test_empty_change_set_is_not_applicable() -> None:
    assert classify_paths([]) == (False, [])


def test_first_push_without_base_fails_closed_to_full_gate() -> None:
    paths = changed_paths("0" * 40, "a" * 40)
    sensitive, matched = classify_paths(paths)
    assert sensitive is True
    assert matched == ["<unknown-base:full-image-gate-required>"]


def test_changed_paths_uses_no_renames_so_old_sensitive_path_is_not_lost(tmp_path: Path, monkeypatch) -> None:
    subprocess.run(["git", "init", str(tmp_path)], check=True, capture_output=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.email", "test@example.invalid"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "config", "user.name", "Test"], check=True)
    dockerfile = tmp_path / "Dockerfile"
    dockerfile.write_text("FROM scratch\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "Dockerfile"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "base"], check=True, capture_output=True)
    base = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()
    dockerfile.rename(tmp_path / "README.md")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(["git", "-C", str(tmp_path), "commit", "-m", "rename"], check=True, capture_output=True)
    head = subprocess.check_output(["git", "-C", str(tmp_path), "rev-parse", "HEAD"], text=True).strip()
    monkeypatch.chdir(tmp_path)
    paths = changed_paths(base, head)
    assert "Dockerfile" in paths
    assert "README.md" in paths
    assert classify_paths(paths)[0] is True


@pytest.mark.parametrize(
    ("detect", "needed", "scan", "expected_code", "contains"),
    [
        ("success", "false", "skipped", 0, "NOT_APPLICABLE"),
        ("success", "true", "success", 0, "PASS"),
        ("success", "true", "failure", 1, "FAIL"),
        ("success", "true", "cancelled", 1, "FAIL"),
        ("success", "true", "skipped", 1, "FAIL"),
        ("success", "true", "", 1, "FAIL"),
        ("failure", "false", "skipped", 1, "FAIL"),
        ("cancelled", "false", "skipped", 1, "FAIL"),
        ("success", "maybe", "skipped", 1, "FAIL"),
        ("success", "false", "failure", 1, "FAIL"),
        ("success", "false", "cancelled", 1, "FAIL"),
        ("success", "false", "success", 0, "PASS"),
        ("success", "false", "timed_out", 1, "FAIL"),
        ("success", "false", "neutral", 1, "FAIL"),
    ],
)
def test_aggregator_decision_matrix(detect, needed, scan, expected_code, contains) -> None:
    code, message = evaluate_gate(detect, needed, scan)
    assert code == expected_code
    assert contains in message


def test_not_applicable_is_not_release_evidence() -> None:
    code, message = evaluate_gate("success", "false", "skipped")
    assert code == 0
    assert "NOT a security scan pass" in message
    assert "absolute release image gate remains separate" in message


def test_detector_fails_closed_when_git_diff_cannot_be_resolved() -> None:
    with pytest.raises(subprocess.CalledProcessError):
        changed_paths("not-a-real-base", "not-a-real-head")
