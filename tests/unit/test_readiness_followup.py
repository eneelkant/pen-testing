"""Regression tests for 0.2.0a15 operator, encryption, backup, and image-scan controls."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from uuid import uuid4

import pytest
from cryptography.fernet import Fernet

from core.cli import main
from core.ops.backup import create_backup, restore_backup
from core.ops.crypto import protect_text, reveal_text
from core.ops.retention import cleanup_expired_files
from core.results import ExecutionResult
from core.supply_chain.images import PINNED_IMAGES, classify_trivy_document, scan_pinned_images
from mcp_server import service


def _key() -> str:
    return Fernet.generate_key().decode("ascii")


def test_cli_defaults_to_dry_run(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    target = tmp_path / "repo"
    target.mkdir()
    code = main(["run", "--tool", "gitleaks", "--target", str(target)])
    assert code == 0
    assert "skipped" in capsys.readouterr().out
    code = main(["run", "--tool", "gitleaks", "--target", str(target), "--live", "--dry-run"])
    assert code == 2


def test_execution_result_redacts_logs():
    secret = "ghp_" + ("a" * 36)
    result = ExecutionResult(
        tool="headers",
        execution_id="x",
        status="failed",
        error=f"upstream said {secret}",
        logs=[f"token {secret}"],
        metadata={"note": secret},
    )
    blob = json.dumps(result.to_dict())
    assert secret not in blob


def test_assessment_record_is_encrypted_at_rest(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    assessment_id = str(uuid4())
    secret = "ghp_" + ("b" * 36)
    path = service._save_assessment(
        {"assessment_id": assessment_id, "note": secret, "status": "succeeded"}
    )
    stored = path.read_text(encoding="utf-8")
    assert stored.startswith("PENENC1")
    assert secret not in stored
    loaded = service._load_assessment(assessment_id)
    assert secret not in json.dumps(loaded)
    monkeypatch.delenv("PEN_DATA_KEY")
    with pytest.raises(PermissionError, match="PEN_DATA_KEY"):
        service._load_assessment(assessment_id)


def test_required_encryption_rejects_plaintext(monkeypatch):
    monkeypatch.setenv("PEN_REQUIRE_DATA_ENCRYPTION", "1")
    monkeypatch.delenv("PEN_DATA_KEY", raising=False)
    with pytest.raises(PermissionError, match="PEN_DATA_KEY"):
        protect_text("hello")
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    sealed = protect_text("hello")
    assert reveal_text(sealed) == "hello"
    with pytest.raises(PermissionError, match="plaintext"):
        reveal_text("not encrypted")


def test_backup_skips_symlinks_and_restores_checksum(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    source = tmp_path / "assessments"
    source.mkdir()
    (source / "note.json").write_text('{"ok": true}\n', encoding="utf-8")
    outside = tmp_path / "secret.json"
    outside.write_text('{"secret": true}\n', encoding="utf-8")
    (source / "link.json").symlink_to(outside)
    archive = tmp_path / "archive"
    planned = create_backup([source], archive, apply=False)
    assert planned["apply"] is False
    assert not archive.exists()
    written = create_backup([source], archive, apply=True)
    assert written["written"] == 1
    names = {item["name"] for item in written["files"]}
    assert "assessments/note.json" in names
    assert all("link.json" not in name for name in names)
    dest = tmp_path / "restored"
    dest.mkdir()
    report = restore_backup(archive, {"assessments": dest}, apply=True)
    assert (dest / "note.json").read_text(encoding="utf-8") == '{"ok": true}\n'
    assert report["apply"] is True
    manifest = json.loads((archive / "manifest.json").read_text(encoding="utf-8"))
    manifest["files"].append({"name": "../escaped.json", "sha256": "0", "bytes": 1})
    (archive / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    with pytest.raises(PermissionError, match="Refusing restore path"):
        restore_backup(archive, {"assessments": dest}, apply=True)


def test_cleanup_apply_removes_expired_file(tmp_path: Path):
    root = tmp_path / "reports"
    root.mkdir()
    old = root / "old.json"
    old.write_text("secret-bytes", encoding="utf-8")
    old.touch()
    import os

    os.utime(old, (1_000_000_000, 1_000_000_000))
    report = cleanup_expired_files(
        [root],
        now=datetime(2026, 10, 18, tzinfo=timezone.utc),
        max_age_days=1,
        apply=True,
    )
    assert report["ok"] is True
    assert not old.exists()
    assert str(old) in report["deleted"]


def test_doctor_strict_fails_when_encryption_is_required(tmp_path: Path, monkeypatch, capsys):
    monkeypatch.setenv("PEN_DOCTOR_STRICT", "1")
    monkeypatch.setenv("PEN_REQUIRE_DATA_ENCRYPTION", "1")
    monkeypatch.delenv("PEN_DATA_KEY", raising=False)
    monkeypatch.setenv("PEN_SCOPES_FILE", str(tmp_path / "missing.yaml"))
    monkeypatch.setenv("PEN_WORK_DIR", str(tmp_path / "work"))
    monkeypatch.setenv("PEN_REPORTS_DIR", str(tmp_path / "reports"))
    code = main(["doctor"])
    assert code == 1
    text = capsys.readouterr().out
    assert "required-missing" in text
    assert "encryption key missing" in text


def test_image_scan_classifies_fixed_findings_and_missing_tools(monkeypatch):
    assert all("@sha256:" in item["ref"] for item in PINNED_IMAGES)
    document = {
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-2026-0001",
                        "PkgName": "example",
                        "InstalledVersion": "1",
                        "FixedVersion": "2",
                        "Severity": "CRITICAL",
                    },
                    {
                        "VulnerabilityID": "CVE-2026-0002",
                        "PkgName": "base",
                        "InstalledVersion": "1",
                        "FixedVersion": "",
                        "Severity": "HIGH",
                    },
                ]
            }
        ]
    }
    report = classify_trivy_document(document, image="example@sha256:abc")
    assert report["status"] == "FAIL"
    assert report["blocking_count"] == 1
    assert report["unfixed_count"] == 1

    class _Completed:
        returncode = 0
        stdout = "{}"
        stderr = ""

    scanned = scan_pinned_images(
        runner=lambda args, timeout=600: _Completed(),
        images=({"name": "one", "ref": PINNED_IMAGES[0]["ref"]},),
    )
    assert scanned["status"] == "PASS"
    monkeypatch.setattr("core.supply_chain.images.shutil.which", lambda _name: None)
    missing = scan_pinned_images()
    assert missing["status"] == "NOT_VERIFIED"
