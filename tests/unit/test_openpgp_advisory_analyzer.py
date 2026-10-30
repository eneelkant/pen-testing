"""Regression tests for scripts/verify_openpgp_advisory.py.

Tests the analyzer's handling of:
- Missing scan files (either or both)
- Malformed JSON
- Missing Results array
- Empty Results
- GO-2026-5932 present in both controls (MODULE_LEVEL_REPORTING)
- GO-2026-5932 present only in positive control (IMPORT_SENSITIVE_REPORTING)
- GO-2026-5932 absent from both (unexpected → NOT_VERIFIED)
- GO-2026-5932 present only in negative control (unexpected → NOT_VERIFIED)
- Other vulnerabilities present (not GO-2026-5932)
- Missing arguments (argparse error)
- Null/missing Vulnerabilities key (handled gracefully)
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
SCRIPT = ROOT / "scripts" / "verify_openpgp_advisory.py"


def _run_analyzer(no_openpgp: Path | None, with_openpgp: Path | None) -> tuple[int, str, str]:
    """Run the analyzer with two scan files and return (exit_code, stdout, stderr)."""
    args = [sys.executable, str(SCRIPT)]
    if no_openpgp is not None:
        args += ["--no-openpgp-scan", str(no_openpgp)]
    if with_openpgp is not None:
        args += ["--with-openpgp-scan", str(with_openpgp)]
    result = subprocess.run(args, capture_output=True, text=True, timeout=10)
    return result.returncode, result.stdout, result.stderr


def _write_scan(tmp_path: Path, name: str, data: object) -> Path:
    """Write a Trivy scan JSON to a temp file."""
    p = tmp_path / name
    if isinstance(data, (dict, list)):
        p.write_text(json.dumps(data), encoding="utf-8")
    else:
        p.write_text(str(data), encoding="utf-8")
    return p


def _scan_with_go_2026_5932() -> dict:
    """A scan JSON that contains GO-2026-5932 findings."""
    return {
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "GO-2026-5932",
                "PkgName": "golang.org/x/crypto",
                "InstalledVersion": "v0.31.0",
                "Severity": "UNKNOWN",
                "PkgPath": "",
            }]
        }]
    }


def _scan_without_go_2026_5932() -> dict:
    """A scan JSON with other vulnerabilities but NOT GO-2026-5932."""
    return {
        "Results": [{
            "Vulnerabilities": [{
                "VulnerabilityID": "CVE-2024-12345",
                "PkgName": "some-package",
                "InstalledVersion": "1.0.0",
                "Severity": "HIGH",
            }]
        }]
    }


def _scan_empty_results() -> dict:
    """A scan JSON with an empty Results array."""
    return {"Results": []}


def _scan_null_vulnerabilities() -> dict:
    """A scan JSON with Vulnerabilities=null."""
    return {"Results": [{"Vulnerabilities": None}]}


def _scan_no_vulnerabilities_key() -> dict:
    """A scan JSON without a Vulnerabilities key."""
    return {"Results": [{"Target": "test-binary", "Class": "rootfs"}]}


# --- Missing / malformed evidence ---


def test_missing_no_openpgp_file_returns_not_verified(tmp_path: Path):
    """A missing --no-openpgp-scan file must return exit 2 (NOT_VERIFIED)."""
    with_file = _write_scan(tmp_path, "with.json", _scan_with_go_2026_5932())
    code, _, stderr = _run_analyzer(tmp_path / "nonexistent.json", with_file)
    assert code == 2
    assert "NOT_VERIFIED" in stderr


def test_missing_with_openpgp_file_returns_not_verified(tmp_path: Path):
    """A missing --with-openpgp-scan file must return exit 2 (NOT_VERIFIED)."""
    no_file = _write_scan(tmp_path, "no.json", _scan_without_go_2026_5932())
    code, _, stderr = _run_analyzer(no_file, tmp_path / "nonexistent.json")
    assert code == 2
    assert "NOT_VERIFIED" in stderr


def test_malformed_json_returns_not_verified(tmp_path: Path):
    """Malformed JSON in either scan must return exit 2 (NOT_VERIFIED)."""
    bad = _write_scan(tmp_path, "bad.json", "{ this is not valid json }")
    good = _write_scan(tmp_path, "good.json", _scan_with_go_2026_5932())
    code, _, stderr = _run_analyzer(bad, good)
    assert code == 2
    assert "NOT_VERIFIED" in stderr


def test_missing_results_array_returns_not_verified(tmp_path: Path):
    """A scan without a Results array must return exit 2 (NOT_VERIFIED)."""
    no_results = _write_scan(tmp_path, "no_results.json", {"SchemaVersion": 2})
    good = _write_scan(tmp_path, "good.json", _scan_with_go_2026_5932())
    code, _, stderr = _run_analyzer(no_results, good)
    assert code == 2
    assert "NOT_VERIFIED" in stderr


# --- Recognized result combinations ---


def test_both_controls_report_go_2026_5932_returns_module_level(tmp_path: Path):
    """When GO-2026-5932 is in BOTH scans, result is MODULE_LEVEL_REPORTING (exit 0)."""
    no = _write_scan(tmp_path, "no.json", _scan_with_go_2026_5932())
    with_ = _write_scan(tmp_path, "with.json", _scan_with_go_2026_5932())
    code, stdout, _ = _run_analyzer(no, with_)
    assert code == 0
    assert "MODULE_LEVEL_REPORTING" in stdout


def test_only_positive_control_reports_go_2026_5932(tmp_path: Path):
    """When GO-2026-5932 is only in the positive control, result is IMPORT_SENSITIVE (exit 0)."""
    no = _write_scan(tmp_path, "no.json", _scan_without_go_2026_5932())
    with_ = _write_scan(tmp_path, "with.json", _scan_with_go_2026_5932())
    code, stdout, _ = _run_analyzer(no, with_)
    assert code == 0
    assert "IMPORT_SENSITIVE_REPORTING" in stdout


# --- Unexpected result combinations ---


def test_neither_control_reports_go_2026_5932_returns_not_verified(tmp_path: Path):
    """When GO-2026-5932 is in NEITHER scan, it's unexpected → exit 2."""
    no = _write_scan(tmp_path, "no.json", _scan_without_go_2026_5932())
    with_ = _write_scan(tmp_path, "with.json", _scan_without_go_2026_5932())
    code, _, stderr = _run_analyzer(no, with_)
    assert code == 2
    assert "NOT_VERIFIED" in stderr


def test_only_negative_control_reports_go_2026_5932_returns_not_verified(tmp_path: Path):
    """When GO-2026-5932 is only in the NEGATIVE control, it's unexpected → exit 2."""
    no = _write_scan(tmp_path, "no.json", _scan_with_go_2026_5932())
    with_ = _write_scan(tmp_path, "with.json", _scan_without_go_2026_5932())
    code, _, stderr = _run_analyzer(no, with_)
    assert code == 2
    assert "NOT_VERIFIED" in stderr


# --- Edge cases ---


def test_empty_results_in_both_treated_as_no_findings(tmp_path: Path):
    """Empty Results → no findings in either → unexpected combination → exit 2."""
    no = _write_scan(tmp_path, "no.json", _scan_empty_results())
    with_ = _write_scan(tmp_path, "with.json", _scan_empty_results())
    code, _, stderr = _run_analyzer(no, with_)
    assert code == 2
    assert "NOT_VERIFIED" in stderr


def test_null_vulnerabilities_handled_gracefully(tmp_path: Path):
    """Vulnerabilities=null must be treated as no findings (not crash)."""
    no = _write_scan(tmp_path, "no.json", _scan_null_vulnerabilities())
    with_ = _write_scan(tmp_path, "with.json", _scan_with_go_2026_5932())
    code, stdout, _ = _run_analyzer(no, with_)
    assert code == 0
    assert "IMPORT_SENSITIVE_REPORTING" in stdout


def test_missing_vulnerabilities_key_handled_gracefully(tmp_path: Path):
    """Missing Vulnerabilities key must be treated as no findings (not crash)."""
    no = _write_scan(tmp_path, "no.json", _scan_no_vulnerabilities_key())
    with_ = _write_scan(tmp_path, "with.json", _scan_with_go_2026_5932())
    code, stdout, _ = _run_analyzer(no, with_)
    assert code == 0
    assert "IMPORT_SENSITIVE_REPORTING" in stdout


def test_missing_arguments_returns_usage_error(tmp_path: Path):
    """Calling the analyzer with no arguments must return exit 2 (argparse error)."""
    code, _, stderr = _run_analyzer(None, None)
    assert code == 2
    assert "required" in stderr.lower() or "usage" in stderr.lower()


def test_limitation_notice_in_output(tmp_path: Path):
    """The analyzer must include a LIMITATION notice about production images."""
    no = _write_scan(tmp_path, "no.json", _scan_with_go_2026_5932())
    with_ = _write_scan(tmp_path, "with.json", _scan_with_go_2026_5932())
    code, stdout, _ = _run_analyzer(no, with_)
    assert code == 0
    assert "LIMITATION" in stdout
    assert "production image" in stdout
