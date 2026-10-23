"""Regression tests for atomic backup/restore and fail-closed image evidence."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

import pytest
from cryptography.fernet import Fernet

from core.ops.backup import create_backup, restore_backup
from core.ops.crypto import protect_text
from core.paths import safe_write_text
from core.supply_chain.images import PINNED_IMAGES, classify_trivy_document, scan_pinned_images

PIN = PINNED_IMAGES[0]["ref"]
DIGEST = PIN.split("@", 1)[1]
NOW = datetime(2026, 10, 18, tzinfo=timezone.utc)


def _key() -> str:
    return Fernet.generate_key().decode("ascii")


def _trivy_doc(*, artifact: str = PIN, vulns: list | None = None, created_at: str = "2026-10-18T01:22:03Z") -> dict:
    return {
        "SchemaVersion": 2,
        "ArtifactName": artifact,
        "CreatedAt": created_at,
        "Metadata": {
            "RepoDigests": [f"python@{DIGEST}"],
            "ImageConfig": {"architecture": "amd64", "os": "linux"},
            "VulnerabilityDB": {
                "UpdatedAt": "2026-10-17T18:34:28Z",
                "NextUpdate": "2026-10-18T18:34:28Z",
            },
            "Trivy": {"Version": "0.76.0"},
        },
        "Results": [{"Vulnerabilities": vulns or []}],
    }


def test_safe_write_failure_preserves_existing_bytes(tmp_path: Path, monkeypatch):
    target = tmp_path / "record.json"
    target.write_text('{"ok": true}\n', encoding="utf-8")

    def boom(*_args, **_kwargs):
        raise OSError("disk full")

    monkeypatch.setattr("core.paths.os.replace", boom)
    with pytest.raises(OSError, match="disk full"):
        safe_write_text(target, '{"ok": false}\n')
    assert target.read_text(encoding="utf-8") == '{"ok": true}\n'
    assert list(tmp_path.glob(".record.json.tmp-*")) == []


def test_restore_wrong_key_multi_file_writes_nothing(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    source = tmp_path / "assessments"
    source.mkdir()
    (source / "a.json").write_text('{"a": 1}\n', encoding="utf-8")
    (source / "b.json").write_text('{"b": 2}\n', encoding="utf-8")
    archive = tmp_path / "archive"
    create_backup([source], archive, apply=True)
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    dest = tmp_path / "restored"
    dest.mkdir()
    (dest / "keep.json").write_text('{"keep": true}\n', encoding="utf-8")
    with pytest.raises(PermissionError, match="could not be opened"):
        restore_backup(archive, {"assessments": dest}, apply=True)
    assert not (dest / "a.json").exists()
    assert not (dest / "b.json").exists()
    assert (dest / "keep.json").read_text(encoding="utf-8") == '{"keep": true}\n'


def test_restore_checksum_failure_writes_nothing(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    source = tmp_path / "assessments"
    source.mkdir()
    (source / "a.json").write_text('{"a": 1}\n', encoding="utf-8")
    (source / "b.json").write_text('{"b": 2}\n', encoding="utf-8")
    archive = tmp_path / "archive"
    create_backup([source], archive, apply=True)
    manifest = json.loads((archive / "manifest.json").read_text(encoding="utf-8"))
    for item in manifest["files"]:
        if item["name"].endswith("b.json"):
            item["sha256"] = "0" * 64
    (archive / "manifest.json").write_text(json.dumps(manifest), encoding="utf-8")
    dest = tmp_path / "restored"
    dest.mkdir()
    with pytest.raises(ValueError, match="checksum mismatch"):
        restore_backup(archive, {"assessments": dest}, apply=True)
    assert not (dest / "a.json").exists()
    assert not (dest / "b.json").exists()


def test_restore_commit_failure_leaves_no_partial_members(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    source = tmp_path / "assessments"
    source.mkdir()
    (source / "a.json").write_text('{"a": 1}\n', encoding="utf-8")
    (source / "b.json").write_text('{"b": 2}\n', encoding="utf-8")
    archive = tmp_path / "archive"
    create_backup([source], archive, apply=True)
    dest = tmp_path / "restored"
    dest.mkdir()
    real_replace = __import__("os").replace
    calls = {"n": 0}

    def flaky(src, dst):
        calls["n"] += 1
        # Fail on the first commit replace of a restore member (after staging writes).
        if calls["n"] >= 3 and str(dst).endswith("a.json"):
            raise OSError("commit failed")
        return real_replace(src, dst)

    monkeypatch.setattr("core.ops.backup.os.replace", flaky)
    with pytest.raises(OSError, match="commit failed"):
        restore_backup(archive, {"assessments": dest}, apply=True)
    assert not (dest / "a.json").exists()
    assert not (dest / "b.json").exists()
    assert list(dest.glob(".*.restore-*")) == []


def test_create_backup_failure_preserves_existing_archive(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    source = tmp_path / "assessments"
    source.mkdir()
    (source / "a.json").write_text('{"a": 1}\n', encoding="utf-8")
    (source / "b.json").write_text('{"b": 2}\n', encoding="utf-8")
    archive = tmp_path / "archive"
    create_backup([source], archive, apply=True)
    original_manifest = (archive / "manifest.json").read_text(encoding="utf-8")
    (source / "a.json").write_text('{"a": "changed"}\n', encoding="utf-8")

    calls = {"n": 0}
    real_protect = protect_text

    def flaky(text: str) -> str:
        calls["n"] += 1
        if calls["n"] >= 2:
            raise PermissionError("PEN_DATA_KEY is not a valid Fernet key")
        return real_protect(text)

    monkeypatch.setattr("core.ops.backup.protect_text", flaky)
    with pytest.raises(PermissionError, match="valid Fernet"):
        create_backup([source], archive, apply=True)
    assert (archive / "manifest.json").read_text(encoding="utf-8") == original_manifest
    dest = tmp_path / "restored"
    dest.mkdir()
    monkeypatch.setattr("core.ops.backup.protect_text", real_protect)
    restore_backup(archive, {"assessments": dest}, apply=True)
    assert (dest / "a.json").read_text(encoding="utf-8") == '{"a": 1}\n'


def test_required_encryption_blocks_backup_before_write(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_REQUIRE_DATA_ENCRYPTION", "1")
    monkeypatch.delenv("PEN_DATA_KEY", raising=False)
    source = tmp_path / "assessments"
    source.mkdir()
    (source / "a.json").write_text("{}\n", encoding="utf-8")
    archive = tmp_path / "archive"
    with pytest.raises(PermissionError, match="PEN_DATA_KEY"):
        create_backup([source], archive, apply=True)
    assert not archive.exists()


def test_restore_rejects_mixed_plaintext_when_manifest_encrypted(tmp_path: Path, monkeypatch):
    monkeypatch.setenv("PEN_DATA_KEY", _key())
    source = tmp_path / "assessments"
    source.mkdir()
    (source / "a.json").write_text('{"a": 1}\n', encoding="utf-8")
    archive = tmp_path / "archive"
    create_backup([source], archive, apply=True)
    digest = __import__("hashlib").sha256(b"assessments/a.json").hexdigest()
    member = archive / "files" / f"{digest}.txt"
    member.write_text('{"a": 1}\n', encoding="utf-8")
    dest = tmp_path / "restored"
    dest.mkdir()
    with pytest.raises(PermissionError, match="plaintext backup member"):
        restore_backup(archive, {"assessments": dest}, apply=True)
    assert not (dest / "a.json").exists()


def test_image_mismatched_digest_is_not_verified():
    doc = _trivy_doc(artifact="evil/image:latest@sha256:" + ("f" * 64))
    doc["Metadata"]["RepoDigests"] = ["evil/image@sha256:" + ("f" * 64)]
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"
    assert "digest" in report["error"]


def test_image_stale_created_at_is_not_verified():
    doc = _trivy_doc(created_at="2019-01-01T00:00:00Z")
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"
    assert "stale" in report["error"]


def test_image_stale_database_is_not_verified():
    doc = _trivy_doc()
    doc["Metadata"]["VulnerabilityDB"]["UpdatedAt"] = "2019-01-01T00:00:00Z"
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"
    assert "database" in report["error"].lower()


def test_image_nonzero_exit_with_unfixed_only_is_not_verified():
    doc = _trivy_doc(
        vulns=[
            {
                "VulnerabilityID": "CVE-2026-1",
                "PkgName": "pkg",
                "InstalledVersion": "1",
                "FixedVersion": "",
                "Severity": "HIGH",
            }
        ]
    )
    report = classify_trivy_document(doc, image=PIN, now=NOW, exit_code=1)
    assert report["status"] == "NOT_VERIFIED"
    assert report["exit_code"] == 1


def test_image_unique_cve_count_distinct_from_rows():
    doc = _trivy_doc(
        vulns=[
            {
                "VulnerabilityID": "CVE-2026-1",
                "PkgName": "a",
                "InstalledVersion": "1",
                "FixedVersion": "",
                "Severity": "HIGH",
            },
            {
                "VulnerabilityID": "CVE-2026-1",
                "PkgName": "b",
                "InstalledVersion": "1",
                "FixedVersion": "",
                "Severity": "HIGH",
            },
        ]
    )
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "PASS"
    assert report["finding_row_count"] == 2
    assert report["unique_cve_count"] == 1
    assert report["platform"] == "linux/amd64"
    assert report["scanner_version"] == "0.76.0"
    assert report["digest"] == DIGEST


def test_scan_records_exit_code_and_rejects_empty_json():
    class _Empty:
        returncode = 1
        stdout = ""
        stderr = "pull failed"

    scanned = scan_pinned_images(
        runner=lambda args, timeout=600: _Empty(),
        images=({"name": "one", "ref": PIN},),
        now=NOW,
    )
    assert scanned["status"] == "NOT_VERIFIED"
    assert scanned["images"][0]["status"] == "NOT_VERIFIED"
