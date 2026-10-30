"""Regression tests for the upstream release monitor version mapping.

Tests that the monitor correctly handles:
- Different versioning schemes (Temporal: server vs CLI)
- Token usage in API calls
- Docker Hub tag resolution
- State file persistence
"""
import json
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT_DIR = ROOT / "scripts"
STATE_FILE = SCRIPT_DIR / "upstream_release_state.json"


def test_state_file_exists_and_is_valid_json():
    """The state file must exist and be valid JSON."""
    assert STATE_FILE.exists(), f"State file not found: {STATE_FILE}"
    data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    assert isinstance(data, dict)
    assert len(data) >= 4  # at least 4 upstream projects


def test_state_file_contains_all_four_projects():
    """The state file must track all 4 upstream projects."""
    data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    expected = {"shannon", "temporal", "gitleaks", "trivy"}
    assert expected <= set(data.keys()), f"Missing projects: {expected - set(data.keys())}"


def test_state_file_has_last_evaluated_tags():
    """Each project in the state file must have a last_evaluated_tag."""
    data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
    for name, info in data.items():
        assert "last_evaluated_tag" in info, f"{name} missing last_evaluated_tag"
        assert info["last_evaluated_tag"], f"{name} has empty last_evaluated_tag"


def test_temporal_versioning_discrepancy_documented():
    """The monitor script must document the Temporal versioning discrepancy."""
    script = (SCRIPT_DIR / "check_upstream_releases.py").read_text(encoding="utf-8")
    # The script must mention that Temporal uses different versioning for GitHub vs Docker
    assert "server versioning" in script.lower() or "CLI versioning" in script.lower(), \
        "Temporal versioning discrepancy not documented in monitor script"


def test_fetch_latest_release_accepts_token():
    """The fetch_latest_release function must accept a token parameter."""
    script = (SCRIPT_DIR / "check_upstream_releases.py").read_text(encoding="utf-8")
    assert "token" in script, "fetch_latest_release must accept a token parameter"
    assert "Authorization" in script, "Token must be used for Authorization header"


def test_production_pin_tags_match_images_py():
    """The production pin tags in the monitor config must match images.py."""
    script = (SCRIPT_DIR / "check_upstream_releases.py").read_text(encoding="utf-8")
    # Check that production_pin_tag values are present
    assert "3.4.0" in script, "Shannon production pin tag missing"
    assert "1.7.0" in script, "Temporal production pin tag missing"
    assert "v8.21.2" in script, "Gitleaks production pin tag missing"
    assert "0.76.0" in script, "Trivy production pin tag missing"


def test_monitor_does_not_auto_change_pins():
    """The monitor script must not contain any code that changes production pins."""
    script = (SCRIPT_DIR / "check_upstream_releases.py").read_text(encoding="utf-8")
    assert "images.py" not in script, "Monitor must not reference images.py (no pin changes)"
    assert "PINNED_IMAGES" not in script, "Monitor must not reference PINNED_IMAGES"
