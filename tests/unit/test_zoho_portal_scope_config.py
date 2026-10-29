"""Config-only authorization for the Zoho VRP portal (no live network traffic)."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.assessment.profile import load_assessment_profile, validate_profile_request
from core.scope import ScopeEngine
from mcp_server import service
from mcp_server.server import mcp
import asyncio
import inspect

REGISTRY = Path("scopes/registry.yaml")
PROFILE = Path("configs/assessment_profiles/zoho_bugbounty_portal_headers.yaml")
SYNTHETIC = Path("configs/assessment_profiles/zoho_non_destructive.yaml")


def test_mcp_bound_approval_tools_exist_in_this_checkout():
    result = mcp.list_tools()
    tools = asyncio.run(result) if inspect.iscoroutine(result) else result
    names = {t.name for t in tools}
    assert "plan_assessment" in names
    assert "authorize_assessment" in names
    assert "run_security_assessment" in names
    assert "validate_target_scope" in names


def test_exact_portal_url_accepted_for_passive_only():
    engine = ScopeEngine.from_file(REGISTRY)
    decision = engine.evaluate(
        "https://bugbounty.zohocorp.com/",
        test_category="passive",
        for_live_execution=True,
    )
    assert decision.allowed is True
    assert decision.live_execution_allowed is True
    assert decision.matched_record is not None
    assert decision.matched_record.target_id == "zoho-bugbounty-portal"


def test_portal_path_on_exact_host_accepted_for_passive():
    engine = ScopeEngine.from_file(REGISTRY)
    assert engine.evaluate(
        "https://bugbounty.zohocorp.com/bb/info",
        test_category="passive",
    ).allowed is True


def test_other_zoho_hosts_and_subdomains_denied():
    engine = ScopeEngine.from_file(REGISTRY)
    for target in (
        "https://www.zoho.com/",
        "https://accounts.zoho.com/",
        "https://mail.zoho.com/",
        "https://evil.bugbounty.zohocorp.com/",
        "https://bugbounty.zohocorp.com.attacker.invalid/",
    ):
        assert engine.evaluate(target, test_category="passive").allowed is False, target


def test_http_and_non_443_denied():
    engine = ScopeEngine.from_file(REGISTRY)
    assert engine.evaluate("http://bugbounty.zohocorp.com/", test_category="passive").allowed is False
    assert engine.evaluate("https://bugbounty.zohocorp.com:8443/", test_category="passive").allowed is False


def test_active_category_denied_on_portal_entry():
    engine = ScopeEngine.from_file(REGISTRY)
    decision = engine.evaluate(
        "https://bugbounty.zohocorp.com/",
        test_category="active",
        for_live_execution=True,
    )
    assert decision.allowed is False


def test_portal_headers_profile_limits_tools_and_keeps_synthetic_unchanged():
    portal = load_assessment_profile(PROFILE)
    synthetic = load_assessment_profile(SYNTHETIC)
    assert portal.live_execution_enabled is True
    assert portal.require_synthetic_targets is False
    assert portal.allowed_tools == ("headers",)
    assert portal.allowed_categories == ("passive",)
    assert portal.max_timeout_seconds == 60
    assert synthetic.live_execution_enabled is False
    assert synthetic.require_synthetic_targets is True
    with pytest.raises(PermissionError):
        validate_profile_request(
            portal,
            tool="shannon",
            category="passive",
            target="https://bugbounty.zohocorp.com/",
            dry_run=True,
        )


def test_mcp_validate_scope_matches_registry_without_network():
    result = service.validate_target_scope(
        "https://bugbounty.zohocorp.com/",
        category="passive",
    )
    assert result["allowed"] is True
    denied = service.validate_target_scope("https://www.zoho.com/", category="passive")
    assert denied["allowed"] is False


def test_plan_assessment_does_not_launch_scanner():
    plan = service.plan_assessment(
        tool="headers",
        target="https://bugbounty.zohocorp.com/",
        category="passive",
        profile_id="zoho_bugbounty_portal_headers",
        timeout_seconds=60,
    )
    assert plan["ok"] is True
    assert plan["launches_scanner"] is False
