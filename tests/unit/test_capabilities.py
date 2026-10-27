"""Tests for the implemented-tool capability registry."""

from __future__ import annotations

import json

import pytest

from core.cli import main
from core.capabilities import (
    CAPABILITIES_BY_ID,
    ScanMode,
    TargetType,
    get_capability,
    list_capabilities,
)


def test_registry_matches_currently_integrated_adapters():
    # Keep this expectation explicit: proposed tools must not appear as available.
    assert set(CAPABILITIES_BY_ID) == {"shannon", "briar", "headers", "gitleaks", "trivy"}
    assert all(item.status == "integrated" for item in CAPABILITIES_BY_ID.values())


def test_registry_ids_are_unique_and_output_is_json_serializable():
    records = list_capabilities()
    assert len(records) == len({record["id"] for record in records})
    encoded = json.dumps({"capabilities": records})
    assert '"status": "integrated"' in encoded
    assert '"target_types"' in encoded
    assert '"network_profile"' in encoded


def test_network_targeting_adapters_require_authorization():
    for tool_id in ("shannon", "briar", "headers"):
        capability = get_capability(tool_id)
        assert capability.requires_authorization is True


def test_local_scanners_advertise_only_local_source_paths():
    for tool_id in ("gitleaks", "trivy"):
        capability = get_capability(tool_id)
        assert capability.target_types == (TargetType.LOCAL_SOURCE_PATH,)
        assert capability.requires_authorization is False


def test_capabilities_do_not_overstate_planned_integrations():
    for tool_id in ("zap", "nuclei", "schemathesis", "mobsf", "nmap", "checkov"):
        with pytest.raises(KeyError, match="No integrated capability"):
            get_capability(tool_id)


def test_capability_modes_use_the_shared_mode_vocabulary():
    assert get_capability("headers").modes == (ScanMode.PASSIVE,)
    assert ScanMode.STATIC in get_capability("gitleaks").modes
    assert ScanMode.DEPENDENCY in get_capability("trivy").modes


def test_lookup_is_case_and_whitespace_tolerant():
    assert get_capability(" HEADERS ").id == "headers"


def test_unknown_target_types_are_not_silently_assigned():
    assert TargetType.CIDR.value == "cidr"
    assert TargetType.ANDROID_ARTIFACT.value == "android_artifact"
    assert TargetType.IOS_ARTIFACT.value == "ios_artifact"
    assert TargetType.OPENAPI_DOCUMENT.value == "openapi_document"



def test_cli_capability_command_emits_json(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))

    assert main(["capabilities", "--tool", "headers"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert payload["count"] == 1
    assert payload["capabilities"][0]["id"] == "headers"
    assert payload["capabilities"][0]["modes"] == ["passive"]


def test_cli_capabilities_does_not_claim_planned_tools(monkeypatch, tmp_path, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))

    assert main(["capabilities"]) == 0
    payload = json.loads(capsys.readouterr().out)
    names = {item["id"] for item in payload["capabilities"]}
    assert names == {"shannon", "briar", "headers", "gitleaks", "trivy"}
    assert "zap" not in names
