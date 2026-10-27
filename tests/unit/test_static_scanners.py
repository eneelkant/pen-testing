"""Tests for local-only Checkov and MobSFScan adapters."""

from __future__ import annotations

import json
from pathlib import Path
from types import SimpleNamespace

from core.config import load_config
from integrations.base import AdapterRequest
from integrations.scanners import CheckovAdapter, MobSFScanAdapter
from integrations.scanners import checkov as checkov_module
from integrations.scanners import mobsfscan as mobsfscan_module


class FakeRunner:
    def __init__(self, *, checkov_report=None, mobsfscan_report=None, returncode=1):
        self.checkov_report = checkov_report or {
            "results": {"failed_checks": [], "parsing_errors": []}
        }
        self.mobsfscan_report = mobsfscan_report or {"results": {}}
        self.returncode = returncode
        self.commands = []

    def which(self, binary: str) -> str:
        return f"/fake/bin/{binary}"

    def run(self, command, *, cwd=None, env=None, timeout=None, log_path=None, input_text=None):
        command = list(command)
        self.commands.append({"command": command, "env": env, "timeout": timeout})
        if command[0].endswith("checkov"):
            output_dir = Path(command[command.index("--output-file-path") + 1])
            output_dir.mkdir(parents=True, exist_ok=True)
            (output_dir / "results_json.json").write_text(
                json.dumps(self.checkov_report), encoding="utf-8"
            )
        elif command[0].endswith("mobsfscan"):
            report = Path(command[command.index("-o") + 1])
            report.parent.mkdir(parents=True, exist_ok=True)
            report.write_text(json.dumps(self.mobsfscan_report), encoding="utf-8")
        return SimpleNamespace(
            command=command,
            returncode=self.returncode,
            stdout="",
            stderr="",
            timed_out=False,
            duration_seconds=0.01,
            ok=self.returncode == 0,
        )


def _config(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    config = load_config()
    config.ensure_dirs()
    return config


def _install_test_versions(monkeypatch):
    monkeypatch.setattr(checkov_module, "version", lambda distribution: "3.3.29")
    monkeypatch.setattr(mobsfscan_module, "version", lambda distribution: "1.0.1")


def test_checkov_normalizes_failed_checks_and_sanitizes_raw_code(tmp_path, monkeypatch):
    config = _config(tmp_path, monkeypatch)
    target = tmp_path / "iac"
    target.mkdir()
    (target / "main.tf").write_text("resource \"aws_s3_bucket\" \"demo\" {}\n", encoding="utf-8")
    secret_marker = "synthetic-secret-marker-do-not-save"
    runner = FakeRunner(
        checkov_report={
            "results": {
                "failed_checks": [
                    {
                        "check_id": "CKV_AWS_20",
                        "check_name": "S3 bucket logging disabled",
                        "severity": "HIGH",
                        "file_path": "main.tf",
                        "resource": "aws_s3_bucket.demo",
                        "code_block": [[5, f"token = {secret_marker}"]],
                        "guideline": "https://docs.example.invalid/check",
                        "check_type": "terraform",
                    }
                ],
                "parsing_errors": [],
            }
        },
        returncode=1,
    )
    _install_test_versions(monkeypatch)
    adapter = CheckovAdapter(config, None, runner=runner)

    result = adapter.run(AdapterRequest(target=str(target), dry_run=False))

    assert result.status == "succeeded"
    assert len(result.findings) == 1
    assert result.findings[0].source_tool == "checkov"
    assert result.findings[0].severity == "high"
    assert result.findings[0].evidence_sanitized["line_numbers"] == [5]
    assert secret_marker not in Path(result.artifacts["report"]).read_text(encoding="utf-8")
    assert "--skip-download" in runner.commands[0]["command"]
    assert runner.commands[0]["env"]["CHECKOV_ENABLE_TELEMETRY"] == "false"


def test_mobsfscan_normalizes_mobile_source_findings_without_code_snippets(tmp_path, monkeypatch):
    config = _config(tmp_path, monkeypatch)
    target = tmp_path / "mobile-src"
    target.mkdir()
    (target / "MainActivity.java").write_text("class MainActivity {}\n", encoding="utf-8")
    secret_marker = "synthetic-match-must-not-be-retained"
    runner = FakeRunner(
        mobsfscan_report={
            "results": {
                "android_logging": {
                    "files": [
                        {
                            "file_path": "MainActivity.java",
                            "match_lines": [14, 14],
                            "match_string": secret_marker,
                        }
                    ],
                    "metadata": {
                        "severity": "WARNING",
                        "description": "Avoid logging sensitive data.",
                        "reference": "https://github.com/MobSF/mobsfscan",
                        "owasp-mobile": "M9",
                        "masvs": "MSTG-STORAGE-3",
                    },
                }
            }
        },
        returncode=0,
    )
    _install_test_versions(monkeypatch)
    adapter = MobSFScanAdapter(config, None, runner=runner)

    result = adapter.run(AdapterRequest(target=str(target), dry_run=False))

    assert result.status == "succeeded"
    assert len(result.findings) == 1
    assert result.findings[0].category == "mobile-source-analysis"
    assert result.findings[0].evidence_sanitized["line_numbers"] == [14]
    saved = Path(result.artifacts["report"]).read_text(encoding="utf-8")
    assert secret_marker not in saved
    assert "match_string" not in saved
    assert runner.commands[0]["env"]["SEMGREP_SEND_METRICS"] == "off"


def test_local_static_scanner_dry_run_does_not_invoke_scanner(tmp_path, monkeypatch):
    config = _config(tmp_path, monkeypatch)
    target = tmp_path / "source"
    target.mkdir()
    _install_test_versions(monkeypatch)
    for adapter_type in (CheckovAdapter, MobSFScanAdapter):
        runner = FakeRunner()
        adapter = adapter_type(config, None, runner=runner)
        result = adapter.run(AdapterRequest(target=str(target), dry_run=True))
        assert result.status == "skipped"
        assert result.metadata["dry_run"] is True
        assert runner.commands == []


def test_local_static_scanners_refuse_paths_outside_allowed_roots(tmp_path, monkeypatch):
    sandbox = tmp_path / "sandbox"
    outside = tmp_path / "outside"
    sandbox.mkdir()
    outside.mkdir()
    config = _config(sandbox, monkeypatch)
    _install_test_versions(monkeypatch)
    for adapter_type in (CheckovAdapter, MobSFScanAdapter):
        runner = FakeRunner()
        adapter = adapter_type(config, None, runner=runner)
        result = adapter.run(AdapterRequest(target=str(outside), dry_run=False))
        assert result.status == "blocked"
        assert runner.commands == []
