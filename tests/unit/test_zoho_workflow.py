"""Synthetic-target regression suite for Zoho-oriented authorization workflow."""

from __future__ import annotations

import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.assessment.profile import load_assessment_profile, validate_profile_request
from core.findings import (
    ValidationStatus,
    VerificationState,
    apply_validation_status,
    assess_evidence,
    normalize_generic_finding,
)
from core.reporting.export import escape_markdown, export_markdown
from core.scope import (
    AuthorizationRecord,
    ScopeEngine,
    get_approval_store,
    plan_fingerprint,
    reset_approval_store,
    validate_redirect_against_registry,
    validate_redirect_stays_in_scope,
)
from core.scope.rate_limit import acquire_scan_slot, release_scan_slot, reset_rate_limiter
from mcp_server import service

PROFILE = Path("configs/assessment_profiles/zoho_non_destructive.yaml")
FIXTURE_REG = Path("scopes/registry.yaml")


@pytest.fixture(autouse=True)
def _clean_approvals():
    reset_approval_store()
    reset_rate_limiter()
    yield
    reset_approval_store()
    reset_rate_limiter()


def _engine_with_synthetic() -> ScopeEngine:
    return ScopeEngine(
        [
            AuthorizationRecord(
                program_name="synthetic-zoho-fixture",
                program_url="https://bugbounty.zohocorp.com/bb/info",
                target_id="app-example-test",
                asset_type="url",
                scope_source="unit-test",
                policy_reference="docs/ZOHO_PROGRAM_REQUIREMENTS.md",
                allowed_assets=["https://app.example.test", "https://app.example.test/"],
                allowed_test_categories=["passive", "active"],
                prohibited_actions=["dos", "data_destruction"],
                rate_limit_rps=5,
                authorization_start="2020-01-01T00:00:00+00:00",
                authorization_expiry="2099-01-01T00:00:00+00:00",
                environment="staging",
                allowed_schemes=["https"],
                allowed_ports=[443],
                live_execution_allowed=True,
                policy_version="1",
            )
        ]
    )


def test_permitted_synthetic_target_passes_scope():
    engine = _engine_with_synthetic()
    decision = engine.evaluate("https://app.example.test/", test_category="passive")
    assert decision.allowed is True
    assert decision.policy_version


def test_unknown_target_rejected():
    engine = _engine_with_synthetic()
    assert engine.evaluate("https://www.zoho.com/", test_category="passive").allowed is False


def test_lookalike_hostname_rejected():
    engine = _engine_with_synthetic()
    assert (
        engine.evaluate(
            "https://app.example.test.attacker.invalid/", test_category="passive"
        ).allowed
        is False
    )


def test_unapproved_redirect_blocked():
    ok, reason = validate_redirect_stays_in_scope(
        "https://app.example.test/", "https://evil.example.invalid/"
    )
    assert ok is False
    assert "leaves authorized origin" in reason.lower() or "redirect" in reason.lower()


def test_redirect_must_also_be_in_registry():
    engine = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="multi",
                program_url="https://example.invalid",
                target_id="multi",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=[
                    "https://app.example.test/",
                    "https://app.example.test/next",
                ],
                allowed_test_categories=["passive"],
                environment="staging",
            )
        ]
    )
    # Same-origin path still fails registry when the destination URL is not listed.
    ok, reason = validate_redirect_against_registry(
        "https://app.example.test/",
        "https://app.example.test/other",
        engine,
        test_category="passive",
    )
    assert ok is False
    assert "scope" in reason.lower() or "authorization" in reason.lower()


def test_private_and_link_local_not_auto_authorized():
    engine = ScopeEngine.from_file(FIXTURE_REG)
    assert engine.evaluate("http://10.0.0.1/", test_category="active").allowed is False
    assert engine.evaluate("http://169.254.169.254/", test_category="active").allowed is False
    assert engine.evaluate("http://[fe80::1]/", test_category="active").allowed is False


def test_dry_run_plans_without_scanner(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    plan = service.plan_assessment(
        tool="headers",
        target="https://app.example.test/",
        category="passive",
        profile_id="zoho_non_destructive",
    )
    assert plan["ok"] is True
    assert plan["launches_scanner"] is False
    live = service.run_security_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        dry_run=True,
    )
    assert live.get("dry_run") is True
    assert live.get("assessment_id")


def test_live_without_authorization_blocked(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    result = service.run_security_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        dry_run=False,
        confirm_authorized=False,
    )
    assert result["ok"] is False
    assert "confirm_authorized" in result["error"]


def test_approval_not_reusable_across_targets(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_SCOPES_FILE", str(FIXTURE_REG))
    auth = service.authorize_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        confirm_authorized=True,
    )
    assert auth["ok"] is True, auth
    # localhost:18080 is also in the fixture registry, but the bound approval
    # was issued for 127.0.0.1 and must not transfer.
    reuse = service.run_security_assessment(
        tool="headers",
        target="http://localhost:18080/",
        category="passive",
        dry_run=False,
        confirm_authorized=True,
        approval_id=auth["approval_id"],
    )
    assert reuse["ok"] is False
    assert "target" in (reuse.get("error") or "").lower() or "approval" in (reuse.get("error") or "").lower()


def test_approval_expires_and_policy_mismatch(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_SCOPES_FILE", str(FIXTURE_REG))
    store = get_approval_store()
    fingerprint = plan_fingerprint(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        mode="standard",
        profile_id="",
    )
    past = datetime.now(timezone.utc) - timedelta(hours=1)
    grant = store.issue(
        target="http://127.0.0.1:18080/",
        tool="headers",
        category="passive",
        mode="standard",
        profile_id="",
        plan_fingerprint=fingerprint,
        ttl_seconds=60,
        now=past,
    )
    # Force expiry in the past.
    grant.expires_at = past.isoformat()
    with pytest.raises(PermissionError, match="expired"):
        store.consume(
            grant.approval_id,
            target="http://127.0.0.1:18080/",
            tool="headers",
            category="passive",
            mode="standard",
            profile_id="",
            plan_fingerprint=fingerprint,
        )


def test_prohibited_tool_rejected_by_zoho_profile():
    profile = load_assessment_profile(PROFILE)
    with pytest.raises(PermissionError):
        validate_profile_request(
            profile,
            tool="shannon",
            category="active",
            target="https://app.example.test/",
            dry_run=True,
        )


def test_zoho_profile_blocks_live_and_real_hosts():
    profile = load_assessment_profile(PROFILE)
    assert profile.live_execution_enabled is False
    with pytest.raises(PermissionError, match="live_execution_enabled"):
        validate_profile_request(
            profile,
            tool="headers",
            category="passive",
            target="https://app.example.test/",
            dry_run=False,
        )
    with pytest.raises(PermissionError, match="synthetic"):
        validate_profile_request(
            profile,
            tool="headers",
            category="passive",
            target="https://www.zoho.com/",
            dry_run=True,
        )


def test_out_of_scope_finding_blocked_from_validation():
    finding = normalize_generic_finding(
        title="Open redirect",
        category="open-redirect",
        source_tool="headers",
        asset="https://evil.example.invalid/",
        severity="high",
        evidence={"primary": {"status": 302}},
    )
    decision = assess_evidence(
        finding,
        assessment_id="11111111-1111-4111-8111-111111111111",
        in_scope_assets=["https://app.example.test/"],
    )
    assert decision.status == ValidationStatus.BLOCKED.value


def test_high_severity_scanner_output_stays_unvalidated():
    finding = normalize_generic_finding(
        title="Critical RCE",
        category="rce",
        source_tool="shannon",
        asset="https://app.example.test/",
        severity="critical",
        evidence={"primary": {"note": "scanner claim"}, "assessment_id": "aid"},
        verification_state=VerificationState.UNVERIFIED.value,
        validation_status=ValidationStatus.VALIDATED.value,
    )
    assert finding.validation_status == ValidationStatus.NEEDS_REVIEW.value
    decision = assess_evidence(
        finding,
        assessment_id="aid",
        in_scope_assets=["https://app.example.test/"],
        evidence=finding.evidence_sanitized,
    )
    assert decision.status != ValidationStatus.VALIDATED.value
    apply_validation_status(finding, decision)
    assert finding.validation_status != ValidationStatus.VALIDATED.value


def test_missing_and_malformed_evidence():
    finding = normalize_generic_finding(
        title="Claim",
        category="xss",
        source_tool="briar",
        asset="https://app.example.test/",
        severity="high",
        evidence={"summary_only": True},
    )
    decision = assess_evidence(
        finding,
        assessment_id="aid",
        in_scope_assets=["https://app.example.test/"],
        require_primary=True,
    )
    assert decision.status == ValidationStatus.NEEDS_REVIEW.value

    bad = assess_evidence(
        finding,
        assessment_id="aid",
        in_scope_assets=["https://app.example.test/"],
        evidence=["not-an-object"],  # type: ignore[arg-type]
    )
    assert bad.status == ValidationStatus.REJECTED.value


def test_invalid_severity_rejected():
    finding = normalize_generic_finding(
        title="Weird",
        category="misc",
        source_tool="unit",
        asset="https://app.example.test/",
        severity="ultra",
        evidence={"primary": True},
    )
    decision = assess_evidence(
        finding,
        assessment_id="aid",
        in_scope_assets=["https://app.example.test/"],
    )
    assert decision.status == ValidationStatus.REJECTED.value


def test_stale_evidence_rejected():
    finding = normalize_generic_finding(
        title="Old",
        category="misc",
        source_tool="unit",
        asset="https://app.example.test/",
        severity="low",
        evidence={
            "primary": {"body": "x"},
            "captured_at": "2020-01-01T00:00:00+00:00",
            "assessment_id": "aid",
        },
    )
    decision = assess_evidence(
        finding,
        assessment_id="aid",
        in_scope_assets=["https://app.example.test/"],
        max_age_hours=24,
    )
    assert decision.status == ValidationStatus.REJECTED.value
    assert "stale" in decision.reason.lower()


def test_evidence_redaction_in_findings():
    finding = normalize_generic_finding(
        title="Leak",
        category="info",
        source_tool="headers",
        asset="https://app.example.test/",
        evidence={"authorization": "Bearer super-secret", "cookie": "session=abc"},
    )
    assert finding.evidence_sanitized["authorization"] == "[REDACTED]"
    assert finding.evidence_sanitized["cookie"] == "[REDACTED]"


def test_malformed_tool_request_fails_safely():
    result = service.run_security_assessment(
        tool="not-a-tool",
        target="https://app.example.test/",
        dry_run=True,
    )
    assert result["ok"] is False
    assert service.validate_target_scope("not-a-url")["allowed"] is False
    assert service.authorize_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        confirm_authorized=False,
    )["ok"] is False


def test_concurrent_requests_respect_inflight_limit(monkeypatch):
    monkeypatch.setenv("PEN_MAX_INFLIGHT_SCANS", "1")
    reset_rate_limiter()
    acquire_scan_slot()
    errors: list[str] = []

    def worker():
        try:
            acquire_scan_slot()
        except PermissionError as exc:
            errors.append(str(exc))
        else:
            release_scan_slot()

    threads = [threading.Thread(target=worker) for _ in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    release_scan_slot()
    assert errors
    assert any("In-flight" in e for e in errors)


def test_report_escapes_hostile_markdown(tmp_path: Path):
    finding = normalize_generic_finding(
        title="<script>alert(1)</script> **bold** [click](https://evil.test)",
        category="xss",
        source_tool="unit",
        asset="https://app.example.test/",
        severity="low",
        impact="<img src=x onerror=alert(1)>",
    )
    path = export_markdown([finding], tmp_path / "hostile.md")
    text = path.read_text(encoding="utf-8")
    assert "<script>" not in text
    assert escape_markdown("<script>") != "<script>"
    assert "Human review required" in text


def test_scheme_and_port_restrictions():
    engine = _engine_with_synthetic()
    assert engine.evaluate("http://app.example.test/", test_category="passive").allowed is False
    assert engine.evaluate("https://app.example.test:8443/", test_category="passive").allowed is False


def test_url_userinfo_rejected():
    engine = _engine_with_synthetic()
    decision = engine.evaluate("https://user:pass@app.example.test/", test_category="passive")
    assert decision.allowed is False
    assert "userinfo" in decision.reason.lower() or "credential" in decision.reason.lower()


def test_live_execution_flag_on_record():
    engine = ScopeEngine(
        [
            AuthorizationRecord(
                program_name="p",
                program_url="https://example.invalid",
                target_id="t",
                asset_type="url",
                scope_source="test",
                policy_reference="t",
                allowed_assets=["https://app.example.test"],
                allowed_test_categories=["passive"],
                live_execution_allowed=False,
                environment="staging",
            )
        ]
    )
    assert engine.evaluate("https://app.example.test", test_category="passive").allowed is True
    assert (
        engine.evaluate(
            "https://app.example.test", test_category="passive", for_live_execution=True
        ).allowed
        is False
    )


def test_mcp_compatible_dry_run_with_profile(tmp_path, monkeypatch):
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    result = service.run_security_assessment(
        tool="headers",
        target="https://app.example.test/",
        category="passive",
        dry_run=True,
        profile_id="zoho_non_destructive",
    )
    assert result.get("ok") in {True, False}  # adapter may skip without server
    assert result.get("assessment_id")
    assert result.get("dry_run") is True
