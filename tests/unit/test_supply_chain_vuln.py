"""OSV classification and structural SBOM checks. These tests do not call the network."""

from __future__ import annotations

import json
from pathlib import Path
from urllib.error import URLError

from core.supply_chain.sbom import validate_sbom_document
from core.supply_chain.vuln import classify_vulnerability, scan_components


class _Response:
    def __init__(self, payload: dict):
        self._payload = json.dumps(payload).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self):
        return self._payload


def test_classifier_fails_closed_on_unscored_and_ignores_withdrawn():
    high = classify_vulnerability(
        {"id": "GHSA-1", "database_specific": {"severity": "HIGH"}, "summary": "example"}
    )
    low = classify_vulnerability({"id": "GHSA-2", "severity": [{"score": "LOW"}]})
    unscored = classify_vulnerability({"id": "GHSA-3", "severity": [{"score": "CVSS:3.1/AV:N"}]})
    withdrawn = classify_vulnerability({"id": "GHSA-4", "withdrawn": "2026-01-01T00:00:00Z"})
    assert high["blocking"] is True and high["severity"] == "HIGH"
    assert low["blocking"] is False and low["severity"] == "LOW"
    assert unscored["blocking"] is True and unscored["severity"] == "unscored"
    assert withdrawn["withdrawn"] is True and withdrawn["blocking"] is False


def test_scan_reports_blocking_findings_from_a_fixture_response():
    captured = {}

    def opener(request, timeout=30):
        captured["url"] = request.full_url
        captured["body"] = json.loads(request.data.decode("utf-8"))
        captured["timeout"] = timeout
        return _Response(
            {
                "results": [
                    {"vulns": [{"id": "GHSA-9", "database_specific": {"severity": "CRITICAL"}}]},
                    {"vulns": [{"id": "GHSA-8", "withdrawn": "2026-01-01T00:00:00Z"}]},
                ]
            }
        )

    report = scan_components(
        [
            {"name": "pyyaml", "version": "6.0.3"},
            {"name": "jsonschema", "version": "4.26.0"},
            {"name": "unpinned"},
        ],
        opener=opener,
        timeout=5,
    )
    assert report["status"] == "FAIL"
    assert report["ok"] is False
    assert report["blocking_count"] == 1
    assert report["findings"][0]["package"] == "pyyaml"
    assert report["skipped_unpinned"] == ["unpinned"]
    assert captured["url"].endswith("/v1/querybatch")
    assert captured["body"]["queries"][0]["package"]["ecosystem"] == "PyPI"
    assert "vulnerabilities" not in report


def test_scan_is_not_verified_when_the_database_is_unreachable():
    def opener(request, timeout=30):
        raise URLError("network down")

    report = scan_components([{"name": "pyyaml", "version": "6.0.3"}], opener=opener)
    assert report["status"] == "NOT_VERIFIED"
    assert report["ok"] is False
    assert report["findings"] == []


def test_scan_is_not_verified_for_a_malformed_database_response():
    def opener(request, timeout=30):
        return _Response({"results": "nope"})

    report = scan_components([{"name": "pyyaml", "version": "6.0.3"}], opener=opener)
    assert report["status"] == "NOT_VERIFIED"


def test_vuln_cli_exit_codes(monkeypatch, capsys):
    from core.supply_chain.__main__ import main as supply_main

    root = Path(__file__).resolve().parents[2]

    def fake(components):
        return {
            "ok": calls["ok"],
            "status": calls["status"],
            "error": "",
            "queried": [],
            "skipped_unpinned": [],
            "findings": [],
            "blocking_count": 0,
            "database": "fixture",
            "generated_at": "2026-10-17T00:00:00+00:00",
        }

    calls = {"ok": True, "status": "PASS"}
    monkeypatch.setattr("core.supply_chain.__main__.scan_components", fake)
    assert supply_main(["--root", str(root), "vuln"]) == 0
    calls.update(ok=False, status="FAIL")
    assert supply_main(["--root", str(root), "vuln"]) == 1
    calls.update(ok=False, status="NOT_VERIFIED")
    assert supply_main(["--root", str(root), "vuln"]) == 2
    capsys.readouterr()


def test_metadata_sbom_rejects_a_vulnerability_claim():
    document = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "metadata": {"component": {"name": "app", "version": "0"}},
        "components": [
            {"type": "library", "name": "pyyaml", "version": "6.0.3", "purl": "pkg:pypi/pyyaml@6.0.3"}
        ],
        "vulnerabilities": [],
    }
    errors = validate_sbom_document(document)
    assert any("vulnerabilities" in item for item in errors)
