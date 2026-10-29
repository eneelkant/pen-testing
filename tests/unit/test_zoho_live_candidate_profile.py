"""The proposed Zoho live profile must stay disabled and refuse live execution."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.assessment.profile import load_assessment_profile, validate_profile_request
from mcp_server import service

PROFILE = Path("configs/assessment_profiles/zoho_live_candidate.yaml")


def test_live_candidate_profile_is_disabled_by_default():
    profile = load_assessment_profile(PROFILE)
    assert profile.profile_id == "zoho_live_candidate"
    assert profile.live_execution_enabled is False
    assert "shannon" not in profile.allowed_tools
    assert "briar" not in profile.allowed_tools
    assert "headers" in profile.allowed_tools


def test_live_candidate_blocks_live_execution_even_for_synthetic_host():
    profile = load_assessment_profile(PROFILE)
    with pytest.raises(PermissionError, match="live_execution_enabled"):
        validate_profile_request(
            profile,
            tool="headers",
            category="passive",
            target="https://app.example.test/",
            dry_run=False,
        )


def test_mcp_authorize_with_live_candidate_is_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    result = service.authorize_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        profile_id="zoho_live_candidate",
        confirm_authorized=True,
    )
    assert result["ok"] is False
    assert "live_execution_enabled" in (result.get("error") or "")


def test_profile_notes_contain_placeholders_not_real_hosts():
    text = PROFILE.read_text(encoding="utf-8")
    assert "REPLACE_WITH_EXACT_AUTHORIZED_HOST_AND_BASE_URL" in text
    assert "live_execution_enabled: false" in text
    # Guard against accidentally committing a common Zoho host as an executable target.
    for host in ("accounts.zoho.com", "www.zoho.com", "mail.zoho.com"):
        assert f"https://{host}" not in text
