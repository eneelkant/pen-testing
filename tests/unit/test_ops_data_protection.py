"""Regression tests for retention, secret handling, file access, and SBOM metadata."""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.findings.redaction import redact_secrets, redact_text
from core.ops.retention import cleanup_expired_files, parse_retention_days
from core.paths import safe_read_text, safe_write_text
from core.reporting import generate_daily_report
from core.supply_chain.audit import audit_dependencies
from core.supply_chain.sbom import build_sbom
from core.supply_chain.__main__ import main as supply_main
from mcp_server import service


def _token(prefix: str, size: int = 36) -> str:
    return prefix + ("a" * size)


def test_redacts_github_slack_and_openai_tokens():
    github = _token("ghp_")
    pat = "github_pat_" + ("a" * 22)
    slack = "xoxb-" + ("1" * 12)
    webhook = "https://hooks.slack.com/services/" + ("T" * 8) + "/B/secret"
    openai = "sk-" + ("b" * 24)
    text = f"values {github} {pat} {slack} {webhook} {openai}"
    red = redact_text(text)
    for secret in (github, pat, slack, webhook, openai):
        assert secret not in red
    blob = redact_secrets({"private_key": github, "note": text})
    assert github not in json.dumps(blob)
    assert blob["private_key"] == "[REDACTED]"


def test_safe_write_refuses_parent_symlink(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(PermissionError, match="symlink"):
        safe_write_text(link / "report.json", "{}")
    assert not (outside / "report.json").exists()


def test_safe_read_refuses_symlink(tmp_path: Path):
    outside = tmp_path / "secret.txt"
    outside.write_text("secret-value", encoding="utf-8")
    link = tmp_path / "alias.txt"
    link.symlink_to(outside)
    with pytest.raises(PermissionError, match="symlink"):
        safe_read_text(link)
    assert outside.read_text(encoding="utf-8") == "secret-value"


def test_daily_report_refuses_symlink_parent(tmp_path: Path):
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "linked"
    link.symlink_to(outside, target_is_directory=True)
    with pytest.raises(PermissionError, match="symlink"):
        generate_daily_report(output_path=link / "daily.md")
    assert not (outside / "daily.md").exists()
    assert not (outside / "daily.json").exists()


def test_cleanup_deletes_old_files_and_skips_symlinks(tmp_path: Path):
    root = tmp_path / "reports"
    root.mkdir()
    old = root / "old.json"
    old.write_text("{}", encoding="utf-8")
    os.utime(old, (1_000_000_000, 1_000_000_000))
    fresh = root / "fresh.json"
    fresh.write_text("{}", encoding="utf-8")
    fresh_ts = datetime(2026, 10, 17, tzinfo=timezone.utc).timestamp()
    os.utime(fresh, (fresh_ts, fresh_ts))
    outside = tmp_path / "outside.json"
    outside.write_text("keep", encoding="utf-8")
    os.utime(outside, (1_000_000_000, 1_000_000_000))
    file_link = root / "link.json"
    file_link.symlink_to(outside)
    outside_dir = tmp_path / "outside-dir"
    outside_dir.mkdir()
    planted = outside_dir / "planted.json"
    planted.write_text("nope", encoding="utf-8")
    os.utime(planted, (1_000_000_000, 1_000_000_000))
    dir_link = root / "subdir"
    dir_link.symlink_to(outside_dir, target_is_directory=True)

    now = datetime(2026, 10, 17, tzinfo=timezone.utc)
    preview = cleanup_expired_files([root], now=now, max_age_days=14, apply=False)
    assert preview["apply"] is False
    assert preview["deleted"] == []
    assert str(old) in preview["candidates"]
    assert old.exists()
    assert preview["skipped_symlinks"] >= 2

    applied = cleanup_expired_files([root], now=now, max_age_days=14, apply=True)
    assert applied["ok"] is True
    assert not old.exists()
    assert fresh.exists()
    assert outside.read_text(encoding="utf-8") == "keep"
    assert file_link.is_symlink()
    assert planted.read_text(encoding="utf-8") == "nope"
    assert str(old) in applied["deleted"]


def test_cleanup_refuses_symlink_root(tmp_path: Path):
    real = tmp_path / "real"
    real.mkdir()
    victim = real / "old.json"
    victim.write_text("{}", encoding="utf-8")
    os.utime(victim, (1_000_000_000, 1_000_000_000))
    link = tmp_path / "root-link"
    link.symlink_to(real, target_is_directory=True)
    report = cleanup_expired_files(
        [link],
        now=datetime(2026, 10, 17, tzinfo=timezone.utc),
        max_age_days=0,
        apply=True,
    )
    assert report["ok"] is False
    assert victim.exists()
    assert report["deleted"] == []


def test_parse_retention_days():
    assert parse_retention_days(None) == 14
    assert parse_retention_days("") == 14
    assert parse_retention_days("off") is None
    assert parse_retention_days("7") == 7
    with pytest.raises(ValueError):
        parse_retention_days("nope")


def test_cli_cleanup_dry_run_then_apply(tmp_path: Path, monkeypatch, capsys):
    from core.cli import main

    work = tmp_path / "work"
    reports = tmp_path / "reports"
    monkeypatch.setenv("PEN_WORK_DIR", str(work))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(reports))
    monkeypatch.delenv("PEN_ASSESSMENT_RETENTION_DAYS", raising=False)
    reports.mkdir()
    old = reports / "stale.md"
    old.write_text("draft", encoding="utf-8")
    os.utime(old, (1_000_000_000, 1_000_000_000))
    code = main(["cleanup", "--days", "14"])
    assert code == 0
    assert old.exists()
    code = main(["cleanup", "--days", "14", "--apply"])
    assert code == 0
    assert not old.exists()
    captured = capsys.readouterr().out
    assert "stale.md" in captured


def test_cli_cleanup_disabled(monkeypatch, capsys):
    from core.cli import main

    monkeypatch.setenv("PEN_ASSESSMENT_RETENTION_DAYS", "off")
    code = main(["cleanup", "--apply"])
    assert code == 0
    data = json.loads(capsys.readouterr().out)
    assert data["enabled"] is False


def test_assessment_save_redacts_and_symlink_is_not_read(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    token = _token("ghp_")
    aid = "12345678-1234-4234-8234-123456789abc"
    service._save_assessment(
        {
            "assessment_id": aid,
            "tool": "headers",
            "error": f"boom {token}",
            "findings": [{"title": f"leak {token}", "api_key": token}],
        }
    )
    stored = (tmp_path / "work" / "assessments" / f"{aid}.json").read_text(encoding="utf-8")
    assert token not in stored
    listed = service.list_findings(aid)
    assert listed["ok"] is True
    assert token not in json.dumps(listed)

    outside = tmp_path / "outside.json"
    outside.write_text('{"status":"leaked","tool":"outside"}', encoding="utf-8")
    other = "12345678-1234-4234-8234-123456789abd"
    link = tmp_path / "work" / "assessments" / f"{other}.json"
    link.symlink_to(outside)
    status = service.get_assessment_status(other)
    assert status["ok"] is False
    assert "symlink" in status["error"].lower()
    assert "leaked" not in json.dumps(status)
    assert outside.read_text(encoding="utf-8").startswith('{"status":"leaked"')
    with pytest.raises(PermissionError, match="symlink"):
        service._save_assessment({"assessment_id": other, "error": "overwrite"})
    assert outside.read_text(encoding="utf-8").startswith('{"status":"leaked"')


def test_corrupt_assessment_fails_closed(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    aid = "12345678-1234-4234-8234-123456789abe"
    directory = tmp_path / "work" / "assessments"
    directory.mkdir(parents=True)
    (directory / f"{aid}.json").write_text("{", encoding="utf-8")
    status = service.get_assessment_status(aid)
    assert status["ok"] is False
    assert "corrupt" in status["error"].lower()


def test_export_refuses_symlink_outdir(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    created = service.run_security_assessment(
        tool="headers",
        target="http://127.0.0.1:18080/",
        category="passive",
        dry_run=True,
    )
    assert created.get("assessment_id")
    aid = created["assessment_id"]
    outside = tmp_path / "outside"
    outside.mkdir()
    link = tmp_path / "reports" / f"export-{aid}"
    link.symlink_to(outside, target_is_directory=True)
    exported = service.export_report(aid)
    assert exported["ok"] is False
    assert "symlink" in exported["error"].lower()
    assert not (outside / "report.md").exists()
    assert not (outside / "report.json").exists()


def test_cli_export_report_confines_paths(tmp_path: Path, monkeypatch, capsys):
    from core.cli import main

    reports = tmp_path / "reports"
    work = tmp_path / "work"
    reports.mkdir()
    work.mkdir()
    monkeypatch.setenv("PEN_REPORTS_DIR", str(reports))
    monkeypatch.setenv("PEN_WORK_DIR", str(work))
    monkeypatch.chdir(tmp_path)
    source = reports / "findings.json"
    source.write_text(json.dumps({"findings": []}), encoding="utf-8")
    code = main(["export-report", "--input", str(source), "--outdir", str(reports / "out")])
    assert code == 0, capsys.readouterr()
    assert (reports / "out" / "report.md").exists()
    escape = Path("/tmp/pen-testing-export-escape")
    code = main(["export-report", "--input", str(source), "--outdir", str(escape)])
    assert code == 2
    assert not (escape / "report.md").exists()


def test_repo_dependency_audit_and_sbom_have_no_cve_claim():
    root = Path(__file__).resolve().parents[2]
    report = audit_dependencies(root)
    assert report["ok"] is True, report
    assert report["note"].startswith("Metadata audit only")
    unpinned = [item["name"] for item in report["findings"] if item["kind"] == "unpinned"]
    assert unpinned == ["rpds-py"]
    assert all(item["blocking"] is False for item in report["findings"] if item["kind"] == "unpinned")
    document = build_sbom(root, timestamp="2026-10-17T00:00:00+00:00")
    assert document["bomFormat"] == "CycloneDX"
    assert "vulnerabilities" not in document
    names = {item["name"]: item for item in document["components"]}
    assert names["pyyaml"]["version"] == "6.0.3"
    assert names["pyyaml"]["purl"] == "pkg:pypi/pyyaml@6.0.3"
    assert names["jsonschema"]["version"] == "4.26.0"
    assert "version" not in names["rpds-py"]
    assert names["rpds-py"]["properties"][0]["value"] == ">=0.30.0"


def test_bare_requirement_is_blocking(tmp_path: Path):
    (tmp_path / "pyproject.toml").write_text(
        """
[project]
name = "sample"
version = "0"
dependencies = ["flask"]
""".strip(),
        encoding="utf-8",
    )
    req = tmp_path / "requirements"
    req.mkdir()
    (req / "base.txt").write_text("flask\n", encoding="utf-8")
    (req / "mcp.txt").write_text("-r base.txt\n", encoding="utf-8")
    (req / "dev.txt").write_text("-r mcp.txt\n", encoding="utf-8")
    report = audit_dependencies(tmp_path)
    assert report["ok"] is False
    assert any(item["kind"] == "unspecified" and item["blocking"] for item in report["findings"])
    document = build_sbom(tmp_path, timestamp="2026-10-17T00:00:00+00:00")
    assert "vulnerabilities" not in document


def test_supply_chain_cli_exit_codes(tmp_path: Path, capsys):
    root = Path(__file__).resolve().parents[2]
    output = tmp_path / "sbom.cdx.json"
    assert supply_main(["--root", str(root), "audit"]) == 0
    assert supply_main(["--root", str(root), "emit", "--output", str(output)]) == 0
    document = json.loads(output.read_text(encoding="utf-8"))
    assert document["bomFormat"] == "CycloneDX"
    assert "vulnerabilities" not in document
    capsys.readouterr()


def test_platform_status_does_not_echo_secrets_or_delete(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("OPENAI_API_KEY", "sk-" + ("c" * 24))
    reports = tmp_path / "reports"
    reports.mkdir()
    kept = reports / "fresh.json"
    kept.write_text("{}", encoding="utf-8")
    status = service.platform_status()
    blob = json.dumps(status)
    assert "sk-" not in blob
    assert status["retention"]["automatic"] is False
    assert kept.exists()
