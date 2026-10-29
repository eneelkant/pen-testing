"""Adversarial regression tests for bound, single-use live-assessment approvals."""

from datetime import datetime, timedelta, timezone

import pytest

from core.scope.approval import ApprovalStore, normalize_approval_target


NOW = datetime(2026, 10, 29, 7, 0, tzinfo=timezone.utc)


def issue_approval(store: ApprovalStore, **overrides):
    values = {
        "target": "https://example.com",
        "tool": "zap",
        "category": "active",
        "mode": "safe-active",
        "profile_id": "baseline",
        "plan_fingerprint": "fingerprint-123",
        "now": NOW,
    }
    values.update(overrides)
    return store.issue(**values)


def consume_approval(store: ApprovalStore, approval_id: str, **overrides):
    values = {
        "target": "https://example.com/",
        "tool": "ZAP",
        "category": "ACTIVE",
        "mode": "safe-active",
        "profile_id": "BASELINE",
        "plan_fingerprint": "fingerprint-123",
        "now": NOW + timedelta(seconds=1),
    }
    values.update(overrides)
    return store.consume(approval_id, **values)


def test_approval_normalizes_url_before_binding_and_consumption():
    store = ApprovalStore()
    grant = issue_approval(store, target=" HTTPS://EXAMPLE.COM/ ")

    assert grant.target == "https://example.com:443/"
    consumed = consume_approval(store, grant.approval_id)

    assert consumed.approval_id == grant.approval_id
    assert consumed.consumed is True


@pytest.mark.parametrize(
    ("field", "override"),
    [
        ("target", {"target": "https://other.example/"}),
        ("tool", {"tool": "nuclei"}),
        ("category", {"category": "passive"}),
        ("mode", {"mode": "full-authorized"}),
        ("profile_id", {"profile_id": "different-profile"}),
        ("plan_fingerprint", {"plan_fingerprint": "different-fingerprint"}),
    ],
)
def test_approval_rejects_request_that_does_not_match_bound_plan(field, override):
    store = ApprovalStore()
    grant = issue_approval(store)

    with pytest.raises(PermissionError, match="does not match"):
        consume_approval(store, grant.approval_id, **override)

    # A failed mismatched attempt must not burn a legitimate approval.
    consumed = consume_approval(store, grant.approval_id)
    assert consumed.consumed is True


def test_approval_is_single_use_and_replay_is_rejected():
    store = ApprovalStore()
    grant = issue_approval(store)

    consume_approval(store, grant.approval_id)

    with pytest.raises(PermissionError, match="already been consumed"):
        consume_approval(store, grant.approval_id)


def test_unknown_or_blank_approval_id_is_rejected():
    store = ApprovalStore()

    with pytest.raises(PermissionError, match="requires a bound approval_id"):
        consume_approval(store, "")

    with pytest.raises(PermissionError, match="not found"):
        consume_approval(store, "not-a-real-approval-id")


def test_expired_approval_is_rejected():
    store = ApprovalStore()
    grant = issue_approval(store, ttl_seconds=30)

    with pytest.raises(PermissionError, match="expired"):
        consume_approval(
            store,
            grant.approval_id,
            now=NOW + timedelta(seconds=31),
        )


def test_policy_version_mismatch_is_rejected():
    store = ApprovalStore()
    grant = issue_approval(store)
    grant.policy_version = "old-or-unknown-policy"

    with pytest.raises(PermissionError, match="policy version mismatch"):
        consume_approval(store, grant.approval_id)


@pytest.mark.parametrize("ttl_seconds", [29, 86_401, 0, -1])
def test_invalid_approval_lifetime_is_rejected(ttl_seconds):
    store = ApprovalStore()

    with pytest.raises(ValueError, match="between 30 and 86400"):
        issue_approval(store, ttl_seconds=ttl_seconds)


def test_approval_target_rejects_url_userinfo():
    with pytest.raises(ValueError, match="userinfo"):
        normalize_approval_target("https://user:secret@example.com/")


def test_approval_target_rejects_control_characters():
    with pytest.raises(ValueError, match="control characters"):
        normalize_approval_target("https://example.com/\nheader: injected")
