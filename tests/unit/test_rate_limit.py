"""Process-local authorization rate limits and live-scan concurrency."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest

from core.config import PlatformConfig
from core.scope import AuthorizationRecord, ScopeEngine
from core.scope.models import ScopeDecision
from core.scope.rate_limit import (
    acquire_scan_slot,
    enforce_rate_limit,
    release_scan_slot,
    reset_rate_limiter,
)
from integrations.base import AdapterRequest
from integrations.scanners import HeadersAdapter


def _decision(rps: float | None, target_id: str = "local-fixture") -> ScopeDecision:
    record = AuthorizationRecord(
        program_name="local",
        program_url="https://example.invalid",
        target_id=target_id,
        asset_type="url",
        scope_source="test",
        policy_reference="policy",
        allowed_assets=["http://127.0.0.1:18080/"],
        rate_limit_rps=rps,
        environment="local",
    )
    return ScopeDecision(allowed=True, reason="test", matched_record=record, policy_reference="policy")


@pytest.fixture(autouse=True)
def _clean_limiter():
    reset_rate_limiter()
    yield
    reset_rate_limiter()


def test_rate_limit_rejects_a_second_request_inside_the_interval():
    now = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    decision = _decision(1)
    enforce_rate_limit(decision, now=now)
    with pytest.raises(PermissionError, match="Rate limit exceeded"):
        enforce_rate_limit(decision, now=now)
    enforce_rate_limit(decision, now=now + timedelta(seconds=1))


def test_missing_rate_limit_does_not_block():
    enforce_rate_limit(_decision(None))
    enforce_rate_limit(_decision(None))


def test_non_positive_rate_limit_fails_closed():
    with pytest.raises(PermissionError, match="positive"):
        enforce_rate_limit(_decision(0))


def test_dry_run_preflight_does_not_consume_the_authorization_budget():
    url = "http://127.0.0.1:18080/"
    scope = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="local",
                program_url="https://example.invalid",
                target_id="local-fixture",
                asset_type="url",
                scope_source="test",
                policy_reference="policy",
                allowed_assets=[url],
                allowed_test_categories=["active", "passive"],
                rate_limit_rps=1,
                environment="local",
            )
        ]
    )
    adapter = HeadersAdapter(PlatformConfig(), scope)
    now = datetime(2026, 10, 17, 12, 0, tzinfo=timezone.utc)
    adapter.preflight(AdapterRequest(target=url, test_category="passive", dry_run=True))
    adapter.preflight(AdapterRequest(target=url, test_category="passive", dry_run=True))
    enforce_rate_limit(scope.require(url, test_category="passive"), now=now)
    with pytest.raises(PermissionError, match="Rate limit exceeded"):
        enforce_rate_limit(scope.require(url, test_category="passive"), now=now)


def test_live_preflight_enforces_the_authorization_rate_limit(monkeypatch):
    url = "http://127.0.0.1:18080/"
    scope = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="local",
                program_url="https://example.invalid",
                target_id="local-fixture",
                asset_type="url",
                scope_source="test",
                policy_reference="policy",
                allowed_assets=[url],
                allowed_test_categories=["active", "passive"],
                rate_limit_rps=1,
                environment="local",
            )
        ]
    )
    adapter = HeadersAdapter(PlatformConfig(), scope)
    stamps = iter(
        [
            datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc),
            datetime(2026, 10, 17, 12, 0, 0, tzinfo=timezone.utc),
        ]
    )

    class _FrozenDateTime(datetime):
        @classmethod
        def now(cls, tz=None):
            return next(stamps)

    monkeypatch.setattr("core.scope.rate_limit.datetime", _FrozenDateTime)
    adapter.preflight(AdapterRequest(target=url, test_category="passive", dry_run=False))
    with pytest.raises(PermissionError, match="Rate limit exceeded"):
        adapter.preflight(AdapterRequest(target=url, test_category="passive", dry_run=False))


def test_inflight_cap_is_process_local(monkeypatch):
    monkeypatch.setenv("PEN_MAX_INFLIGHT_SCANS", "1")
    acquire_scan_slot()
    with pytest.raises(PermissionError, match="In-flight scan limit"):
        acquire_scan_slot()
    release_scan_slot()
    acquire_scan_slot()
    release_scan_slot()


def test_invalid_inflight_cap_fails_closed(monkeypatch):
    monkeypatch.setenv("PEN_MAX_INFLIGHT_SCANS", "0")
    with pytest.raises(PermissionError, match="1 to 64"):
        acquire_scan_slot()
