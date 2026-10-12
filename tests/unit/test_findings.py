import json
from pathlib import Path

import pytest

from core.findings import (
    FINDING_JSON_SCHEMA,
    FindingLifecycle,
    VerificationState,
    normalize_generic_finding,
    redact_secrets,
    validate_finding,
)
from core.reporting import export_json, export_markdown, export_sarif


def test_normalize_and_validate():
    finding = normalize_generic_finding(
        title="Missing CSP",
        category="security-headers",
        source_tool="headers",
        asset="http://127.0.0.1:18080/",
        severity="medium",
        evidence={"authorization": "Bearer super-secret-token"},
    )
    assert finding.lifecycle == FindingLifecycle.CANDIDATE.value
    assert finding.evidence_sanitized["authorization"] == "[REDACTED]"
    assert validate_finding(finding.to_dict()) == []


def test_redact_jwt_and_aws():
    # Construct lookalike material at runtime so static secret scanners ignore fixtures.
    jwt_like = ".".join(["eyJ" + "hbGciOiJIUzI1NiJ9", "aaa", "bbb"])
    aws_like = "AKIA" + "IOSFODNN7EXAMPLE"
    text = f"token={jwt_like} and {aws_like}"
    red = redact_secrets(text)
    assert "eyJ" not in red
    assert "AKIA" not in red


def test_lifecycle_not_auto_confirmed():
    finding = normalize_generic_finding(
        title="Candidate only",
        category="xss",
        source_tool="briar",
        verification_state=VerificationState.UNVERIFIED.value,
    )
    assert finding.verification_state != VerificationState.HUMAN_CONFIRMED.value


def test_export_formats(tmp_path: Path):
    finding = normalize_generic_finding(
        title="Test",
        category="test",
        source_tool="unit",
        severity="low",
    )
    md = export_markdown([finding], tmp_path / "r.md")
    js = export_json([finding], tmp_path / "r.json")
    sarif = export_sarif([finding], tmp_path / "r.sarif")
    assert "Human review required" in md.read_text()
    data = json.loads(js.read_text())
    assert data["findings"][0]["title"] == "Test"
    sarif_data = json.loads(sarif.read_text())
    assert sarif_data["version"] == "2.1.0"
    assert FINDING_JSON_SCHEMA["title"] == "NormalizedSecurityFinding"


def test_invalid_finding_raises():
    with pytest.raises(ValueError):
        normalize_generic_finding(title="", category="x", source_tool="t")
