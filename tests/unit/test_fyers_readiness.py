"""FYERS bounty readiness regressions — local fixtures only, no FYERS network I/O."""

from __future__ import annotations

import asyncio
import inspect
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import yaml

from core.assessment.profile import (
    TRANSACTION_CAPABILITIES,
    load_assessment_profile,
    profile_allows_capability,
    profile_blocks_live_execution,
)
from core.findings import (
    EvidenceContext,
    EvidenceValidationStatus,
    normalize_generic_finding,
    redact_secrets,
    redact_text,
    validate_finding_evidence,
)
from core.findings.redaction import allowlist_finding_fields
from core.scope import (
    AuthorizationRecord,
    ScopeEngine,
    execution_plan_hash,
    get_approval_store,
    policy_fingerprint,
    registry_content_digest,
    reset_approval_store,
    validate_absolute_http_url,
    validate_redirect_stays_in_scope,
)
from core.synthetic import SyntheticAuthService, SyntheticFinancialAPI
from mcp_server import service
from mcp_server.server import mcp

ROOT = Path(__file__).resolve().parents[2]
PROFILE = ROOT / "configs" / "assessment_profiles" / "fyers_non_destructive.yaml"


@pytest.fixture(autouse=True)
def _reset_approvals():
    reset_approval_store()
    yield
    reset_approval_store()


def test_fyers_profile_disables_live_and_blocks_transactions():
    profile = load_assessment_profile(PROFILE)
    assert profile.profile_id == "fyers_non_destructive"
    assert profile.live_execution_enabled is False
    assert profile.require_bound_approval is True
    blocked, _ = profile_blocks_live_execution(profile)
    assert blocked is True
    for cap in TRANSACTION_CAPABILITIES:
        ok, _ = profile_allows_capability(profile, cap)
        assert ok is False
    ok, _ = profile_allows_capability(profile, "otp_bruteforce")
    assert ok is False
    assert "fyers-api.example.test" in profile.allowed_synthetic_hosts
    # No real FYERS production hostnames in the profile file.
    text = PROFILE.read_text(encoding="utf-8")
    assert "api.fyers.in" not in text
    assert "fyers.in" not in text or "fyers.in/bug-bounty-program" in text


def test_default_deny_and_lookalike_hosts():
    engine = ScopeEngine.from_file(ROOT / "scopes" / "registry.yaml")
    assert engine.evaluate("https://fyers.in", test_category="passive").allowed is False
    assert engine.evaluate("https://fyers-api.example.test/", test_category="passive").allowed is False
    assert engine.evaluate("https://fyers-api.example.test.evil.example/", test_category="passive").allowed is False
    assert engine.evaluate("https://not-authorized.example", test_category="active").allowed is False


def test_scheme_and_port_validation():
    ok, _ = validate_absolute_http_url("https://fyers-api.example.test/v3")
    assert ok is True
    bad, reason = validate_absolute_http_url("ftp://fyers-api.example.test/v3")
    assert bad is False
    assert "scheme" in reason.lower() or "unsupported" in reason.lower()

    engine = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="p",
                program_url="https://example.invalid",
                target_id="t",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=["https://fyers-api.example.test:8443/"],
                allowed_test_categories=["passive", "active"],
                environment="local",
            )
        ]
    )
    assert engine.evaluate("https://fyers-api.example.test:8443/", test_category="passive").allowed is True
    assert engine.evaluate("https://fyers-api.example.test/", test_category="passive").allowed is False
    assert engine.evaluate("http://fyers-api.example.test:8443/", test_category="passive").allowed is False
    assert engine.evaluate("javascript:alert(1)", test_category="passive").allowed is False


def test_redirect_out_of_scope_rejected():
    ok, reason = validate_redirect_stays_in_scope(
        "https://fyers-api.example.test/a",
        "https://evil.example/steal",
    )
    assert ok is False
    assert "leaves authorized origin" in reason.lower()


def test_bound_approval_expiry_target_binding_and_policy_change():
    store = get_approval_store()
    record = AuthorizationRecord(
        program_name="p",
        program_url="https://example.invalid",
        target_id="synth",
        asset_type="url",
        scope_source="test",
        policy_reference="t",
        allowed_assets=["https://fyers-api.example.test/"],
        allowed_test_categories=["passive"],
        environment="local",
    )
    engine = ScopeEngine([record])
    target = "https://fyers-api.example.test/"
    decision = engine.require(target, test_category="passive")
    plan = execution_plan_hash(tool="headers", target=target, category="passive", profile_id="fyers_non_destructive")
    digest = registry_content_digest("version-1")
    approval = store.issue(
        target=target,
        tool="headers",
        category="passive",
        decision=decision,
        plan_hash=plan,
        profile_id="fyers_non_destructive",
        registry_digest=digest,
        ttl_seconds=60,
        now=datetime(2026, 10, 27, 12, 0, tzinfo=timezone.utc),
    )
    fp = policy_fingerprint(record, registry_digest=digest)

    with pytest.raises(PermissionError, match="expired"):
        store.consume(
            approval.approval_id,
            target=target,
            tool="headers",
            category="passive",
            plan_hash=plan,
            policy_fingerprint_now=fp,
            profile_id="fyers_non_destructive",
            now=datetime(2026, 10, 27, 12, 5, tzinfo=timezone.utc),
        )

    approval2 = store.issue(
        target=target,
        tool="headers",
        category="passive",
        decision=decision,
        plan_hash=plan,
        profile_id="fyers_non_destructive",
        registry_digest=digest,
        ttl_seconds=900,
    )
    with pytest.raises(PermissionError, match="target mismatch"):
        store.consume(
            approval2.approval_id,
            target="https://other.example.test/",
            tool="headers",
            category="passive",
            plan_hash=plan,
            policy_fingerprint_now=fp,
            profile_id="fyers_non_destructive",
        )

    approval3 = store.issue(
        target=target,
        tool="headers",
        category="passive",
        decision=decision,
        plan_hash=plan,
        profile_id="fyers_non_destructive",
        registry_digest=digest,
        ttl_seconds=900,
    )
    with pytest.raises(PermissionError, match="policy changed"):
        store.consume(
            approval3.approval_id,
            target=target,
            tool="headers",
            category="passive",
            plan_hash=plan,
            policy_fingerprint_now=policy_fingerprint(record, registry_digest="version-2"),
            profile_id="fyers_non_destructive",
        )


def test_profile_live_run_blocked_even_with_confirm(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    result = service.run_security_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        dry_run=False,
        confirm_authorized=True,
        assessment_profile="fyers_non_destructive",
    )
    assert result["ok"] is False
    assert "disables live execution" in (result.get("error") or "").lower()


def test_dry_run_with_fyers_profile_zero_live_launch(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    result = service.run_security_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        dry_run=True,
        assessment_profile="fyers_non_destructive",
    )
    assert result.get("assessment_id")
    assert result.get("dry_run") is True


def test_issue_approval_unknown_target_fails():
    result = service.issue_execution_approval(
        tool="headers",
        target="https://fyers-api.example.test/",
        category="passive",
        assessment_profile="fyers_non_destructive",
    )
    assert result["ok"] is False


def test_token_lifecycle_and_otp_safeguards():
    auth = SyntheticAuthService(access_ttl_seconds=1, otp_ttl_seconds=30)
    login = auth.login("TEST_ACCOUNT_A", "synthetic-password")
    assert login["ok"] is True
    assert login["cookie"]["secure"] is True
    assert login["cookie"]["httponly"] is True

    assert auth.authenticate("invalid").get("ok") is False
    assert auth.login("NO_SUCH_USER", "x")["error"] == "authentication_failed"
    assert auth.login("TEST_ACCOUNT_A", "wrong")["error"] == "authentication_failed"

    access = login["access_token"]
    refresh = login["refresh_token"]
    rotated = auth.refresh(refresh)
    assert rotated["ok"] is True
    assert auth.refresh(refresh).get("ok") is False  # reuse rejected

    expired_at = datetime.now(timezone.utc) + timedelta(seconds=5)
    assert auth.authenticate(rotated["access_token"], now=expired_at).get("ok") is False

    login2 = auth.login("TEST_ACCOUNT_A", "synthetic-password")
    otp = auth.start_otp(login2["access_token"], purpose="step_up")
    assert "246801" not in json.dumps(otp)
    assert auth.verify_otp(login2["access_token"], otp["challenge_id"], "000000")["error"] == "otp_invalid"
    for _ in range(5):
        auth.verify_otp(login2["access_token"], otp["challenge_id"], "000000")
    assert auth.verify_otp(login2["access_token"], otp["challenge_id"], "246801")["error"] == "otp_attempts_exceeded"

    login3 = auth.login("TEST_ACCOUNT_A", "synthetic-password")
    otp2 = auth.start_otp(login3["access_token"])
    assert auth.verify_otp(login3["access_token"], otp2["challenge_id"], "246801")["ok"] is True
    assert auth.verify_otp(login3["access_token"], otp2["challenge_id"], "246801")["error"] == "challenge_replay"

    # Access TTL kept longer than OTP TTL so OTP expiry is observable independently.
    auth_otp = SyntheticAuthService(access_ttl_seconds=300, otp_ttl_seconds=1)
    login4 = auth_otp.login("TEST_ACCOUNT_A", "synthetic-password")
    otp3 = auth_otp.start_otp(login4["access_token"])
    assert (
        auth_otp.verify_otp(
            login4["access_token"],
            otp3["challenge_id"],
            "246801",
            now=datetime.now(timezone.utc) + timedelta(seconds=5),
        )["error"]
        == "otp_expired"
    )

    login5 = auth.login("TEST_ACCOUNT_A", "synthetic-password")
    auth.logout(login5["access_token"])
    assert auth.authenticate(login5["access_token"]).get("ok") is False
    assert auth.recovery_start("TEST_ACCOUNT_A")["bypasses_authentication"] is False
    diag = auth.diagnostic_dump(
        auth.login("TEST_ACCOUNT_A", "synthetic-password")["access_token"]
    )
    assert "atk_" not in json.dumps(diag)
    assert "sess_" not in json.dumps(diag)


def test_cross_account_isolation_and_readonly_transactions():
    api = SyntheticFinancialAPI()
    a = api.auth.login("TEST_ACCOUNT_A", "synthetic-password")["access_token"]
    b = api.auth.login("TEST_ACCOUNT_B", "synthetic-password")["access_token"]

    assert api.get_balance(a)["data"]["available"] == 100000.0
    assert api.get_balance(a, account_id="TEST_ACCOUNT_B")["status"] == 403
    assert api.get_order(a, "ORD-B-9")["status"] == 403
    assert api.get_order(a, "ORD-A-1", account_id_in_body="TEST_ACCOUNT_B")["status"] == 403
    assert api.get_holdings(None)["status"] == 401
    assert api.place_order(a, {"symbol": "SYN-AAA", "qty": 1})["error"] == "transactions_disabled"

    api.allow_transactions = True
    api.set_role("TEST_ACCOUNT_A", "readonly")
    assert api.place_order(a, {"symbol": "SYN-AAA", "qty": 1})["error"] == "readonly_role"

    api.set_role("TEST_ACCOUNT_A", "trader")
    first = api.place_order(a, {"symbol": "SYN-AAA", "qty": 1, "account_id": "TEST_ACCOUNT_B"}, idempotency_key="idem-1")
    assert first["status"] == 403
    created = api.place_order(a, {"symbol": "SYN-AAA", "qty": 1}, idempotency_key="idem-2")
    assert created["ok"] is True
    again = api.place_order(a, {"symbol": "SYN-AAA", "qty": 1}, idempotency_key="idem-2")
    assert again["data"]["order_id"] == created["data"]["order_id"]
    assert api.cancel_order(a, "ORD-A-1")["error"] == "invalid_state_transition"

    api.evidence_append("assess-1", "TEST_ACCOUNT_A", {"note": "a", "access_token": "secret"})
    api.evidence_append("assess-1", "TEST_ACCOUNT_B", {"note": "b"})
    export_a = api.evidence_export("assess-1", "TEST_ACCOUNT_A")
    assert export_a["items"][0]["note"] == "a"
    assert "access_token" not in export_a["items"][0]
    assert all(item.get("note") != "b" for item in export_a["items"])
    assert api.cache_is_isolated("TEST_ACCOUNT_A", "TEST_ACCOUNT_B", "balance")


def test_secret_redaction_nested_multiline_query_and_malicious_finding():
    nested = {
        "trace": "Authorization: Bearer SUPERSECRET\nCookie: SYNTH_SESSION=abc\nOTP 246801",
        "url": "https://fyers-api.example.test/callback?access_token=ATOKEN&otp=123456",
        "evidence": {"refresh_token": "RTOKEN", "session_id": "SESS"},
    }
    red = redact_secrets(nested)
    blob = json.dumps(red)
    assert "SUPERSECRET" not in blob
    assert "SYNTH_SESSION=abc" not in blob
    assert "ATOKEN" not in blob
    assert "RTOKEN" not in blob
    assert "SESS" not in blob
    assert "[REDACTED]" in blob
    assert "246801" not in redact_text("otp code 246801 for user")

    finding = normalize_generic_finding(
        title="Injected token=LEAKEDTOKEN and Bearer BADTOKEN",
        category="authorization",
        source_tool="headers",
        asset="https://fyers-api.example.test/",
        expected_behavior="deny cross-account read",
        observed_behavior="returned peer balance",
        evidence={"authorization": "Bearer X", "accounts": ["TEST_ACCOUNT_A", "TEST_ACCOUNT_B"]},
    )
    decision = validate_finding_evidence(
        finding,
        EvidenceContext(
            assessment_id="11111111-1111-4111-8111-111111111111",
            approved_target="https://fyers-api.example.test/",
            source_tool="headers",
            allowed_account_ids=("TEST_ACCOUNT_A",),
        ),
    )
    assert decision["validation_status"] == EvidenceValidationStatus.BLOCKED.value
    assert "LEAKEDTOKEN" not in json.dumps(decision)
    allowlisted = allowlist_finding_fields(finding.to_dict())
    assert "raw_refs" not in allowlisted


def test_evidence_duplicate_and_severity_not_auto_validated():
    finding = normalize_generic_finding(
        title="Missing header",
        category="security-headers",
        source_tool="headers",
        asset="http://127.0.0.1:18080/",
        severity="critical",
        evidence={"header": "x"},
        execution_id="aid",
    )
    ctx = EvidenceContext(
        assessment_id="aid",
        approved_target="http://127.0.0.1:18080/",
        source_tool="headers",
        known_finding_fingerprints=(),
    )
    first = validate_finding_evidence(finding, ctx)
    assert first["validation_status"] == EvidenceValidationStatus.NEEDS_REVIEW.value
    assert first["validation_status"] != EvidenceValidationStatus.VALIDATED.value
    second = validate_finding_evidence(
        finding,
        EvidenceContext(
            assessment_id="aid",
            approved_target="http://127.0.0.1:18080/",
            source_tool="headers",
            known_finding_fingerprints=(first["fingerprint"],),
        ),
    )
    assert second["validation_status"] == EvidenceValidationStatus.DUPLICATE.value


def test_mcp_tools_include_approval_and_profiles():
    result = mcp.list_tools()
    tools = asyncio.run(result) if inspect.iscoroutine(result) else result
    names = {t.name for t in tools}
    assert "issue_execution_approval" in names
    assert "list_assessment_profiles" in names
    listed = service.list_assessment_profiles()
    assert listed["ok"] is True
    assert any(p.get("profile_id") == "fyers_non_destructive" for p in listed["profiles"])


def test_malformed_mcp_assessment_id():
    assert service.get_assessment_status("not-a-uuid")["ok"] is False
    assert service.list_findings("../etc/passwd")["ok"] is False


def test_no_trading_integration_capability_registered():
    from core.capabilities import list_capabilities

    ids = {c["tool_id"] for c in list_capabilities(include_planned=True)}
    assert "fyers_trading" not in ids
    assert "place_order" not in ids


def test_sample_synthetic_scope_yaml_loads():
    path = ROOT / "scopes" / "examples" / "fyers-synthetic.sample.yaml"
    data = yaml.safe_load(path.read_text(encoding="utf-8"))
    assert data["authorizations"][0]["environment"] == "local"
    assert "fyers-api.example.test" in data["authorizations"][0]["allowed_assets"][0]
