from core.capabilities import get_capability, integrated_tool_ids, list_capabilities


def test_integrated_registry_matches_existing_adapter_set():
    assert integrated_tool_ids() == {"shannon", "briar", "headers", "gitleaks", "trivy", "checkov", "mobsfscan"}


def test_planned_capabilities_are_not_listed_as_integrated_by_default():
    items = list_capabilities()
    assert {item["tool_id"] for item in items} == integrated_tool_ids()
    assert all(item["implemented"] is True for item in items)
    assert all(item["status"] == "integrated" for item in items)


def test_planned_capabilities_are_visible_only_when_requested():
    items = list_capabilities(include_planned=True)
    by_id = {item["tool_id"]: item for item in items}
    assert by_id["zap"]["status"] == "planned"
    assert by_id["zap"]["implemented"] is False
    assert by_id["mobsf"]["status"] == "planned"
    assert by_id["checkov"]["status"] == "integrated"
    assert by_id["mobsfscan"]["status"] == "integrated"
    assert by_id["nmap"]["status"] == "planned"


def test_capability_source_and_license_metadata_are_present():
    for item in list_capabilities(include_planned=True):
        assert item["source_url"].startswith("https://")
        assert item["license"]
        assert item["target_types"]
        assert item["modes"]


def test_unknown_capability_is_not_guessed():
    assert get_capability("not-a-tool") is None


def test_lookup_returns_a_copy_not_registry_mutable_state():
    item = get_capability("headers")
    assert item is not None
    item["target_types"].append("cidr")
    fresh = get_capability("headers")
    assert fresh is not None
    assert fresh["target_types"] == ["web_url"]

def test_cli_capabilities_command_outputs_json(monkeypatch, capsys, tmp_path):
    import json
    from types import SimpleNamespace

    from core import cli

    cfg = SimpleNamespace(
        ensure_dirs=lambda: None,
        scopes_file=str(tmp_path / "does-not-exist.yaml"),
    )
    monkeypatch.setattr(cli, "load_config", lambda _path: cfg)

    assert cli.main(["capabilities", "--include-planned"]) == 0
    payload = json.loads(capsys.readouterr().out)
    by_id = {item["tool_id"]: item for item in payload["capabilities"]}
    assert by_id["shannon"]["status"] == "integrated"
    assert by_id["zap"]["status"] == "planned"
    assert by_id["zap"]["implemented"] is False

def test_cli_capabilities_tool_selector(monkeypatch, capsys, tmp_path):
    import json
    from types import SimpleNamespace

    from core import cli

    cfg = SimpleNamespace(
        ensure_dirs=lambda: None,
        scopes_file=str(tmp_path / "does-not-exist.yaml"),
    )
    monkeypatch.setattr(cli, "load_config", lambda _path: cfg)

    assert cli.main(["capabilities", "--tool", "checkov"]) == 0
    payload = json.loads(capsys.readouterr().out)
    assert len(payload["capabilities"]) == 1
    assert payload["capabilities"][0]["tool_id"] == "checkov"
    assert payload["capabilities"][0]["implemented"] is True

