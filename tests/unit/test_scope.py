from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.scope import ScopeEngine, load_authorization_registry


FIXTURE = Path(__file__).resolve().parents[2] / "scopes" / "registry.yaml"


def test_load_registry():
    records = load_authorization_registry(FIXTURE)
    assert len(records) >= 2
    assert records[0].program_name


def test_unauthorized_public_url_rejected():
    engine = ScopeEngine.from_file(FIXTURE)
    decision = engine.evaluate("https://example.com", test_category="active")
    assert decision.allowed is False
    assert "explicit authorization" in decision.reason.lower() or "no explicit" in decision.reason.lower()


def test_local_fixture_allowed_for_passive():
    engine = ScopeEngine.from_file(FIXTURE)
    decision = engine.evaluate("http://127.0.0.1:18080/", test_category="passive")
    assert decision.allowed is True


def test_expired_authorization_rejected():
    engine = ScopeEngine.from_file(FIXTURE)
    decision = engine.evaluate(
        "https://expired.example.invalid",
        test_category="active",
        now=datetime(2026, 3, 24, tzinfo=timezone.utc),
    )
    assert decision.allowed is False
    assert "expired" in decision.reason.lower()


def test_category_restriction():
    engine = ScopeEngine.from_file(FIXTURE)
    # Remove active from a copy via require on fixture with only passive — use custom record
    from core.scope import AuthorizationRecord

    engine = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="p",
                program_url="https://example.invalid",
                target_id="t",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=["https://only-passive.example.invalid"],
                allowed_test_categories=["passive"],
                environment="staging",
            )
        ]
    )
    decision = engine.evaluate("https://only-passive.example.invalid", test_category="active")
    assert decision.allowed is False
    assert "not allowed" in decision.reason.lower()


def test_no_subdomain_expansion():
    from core.scope import AuthorizationRecord

    engine = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="p",
                program_url="https://example.invalid",
                target_id="t",
                asset_type="host",
                scope_source="test",
                policy_reference="t",
                allowed_assets=["example.invalid"],
                allowed_test_categories=["active"],
                environment="staging",
            )
        ]
    )
    assert engine.evaluate("https://example.invalid", test_category="active").allowed is True
    assert engine.evaluate("https://evil.example.invalid", test_category="active").allowed is False


def test_require_raises():
    engine = ScopeEngine.from_file(FIXTURE)
    with pytest.raises(PermissionError):
        engine.require("https://not-authorized.example", test_category="active")


def test_private_ip_not_auto_authorized():
    engine = ScopeEngine.from_file(FIXTURE)
    decision = engine.evaluate("http://10.0.0.1/", test_category="active")
    assert decision.allowed is False


def test_exclusion_blocks_exact_asset():
    from core.scope import AuthorizationRecord

    engine = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="p",
                program_url="https://example.invalid",
                target_id="t",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=["https://staging.example.invalid"],
                excluded_assets=["https://staging.example.invalid/logout"],
                allowed_test_categories=["active"],
                environment="staging",
            )
        ]
    )
    assert engine.evaluate("https://staging.example.invalid", test_category="active").allowed is True
    assert engine.evaluate("https://staging.example.invalid/logout", test_category="active").allowed is False
