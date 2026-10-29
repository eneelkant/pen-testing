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


def test_image_empty_digests_are_not_verified_for_digest_pins():
    doc = _trivy_doc(artifact="")
    doc["Metadata"]["RepoDigests"] = []
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"
    assert "digest" in report["error"]


def test_image_tag_only_artifact_is_not_verified_for_digest_pins():
    # Tag/name match without digest evidence must fail closed.
    tag_only = PIN.split("@", 1)[0]
    doc = _trivy_doc(artifact=tag_only)
    doc["Metadata"]["RepoDigests"] = []
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"
    assert "digest" in report["error"]


def test_image_artifact_carrying_digest_without_repodigests_is_accepted():
    doc = _trivy_doc(artifact=PIN, vulns=[])
    doc["Metadata"]["RepoDigests"] = []
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "PASS"
    assert report["blocking_count"] == 0


def _pin_digest() -> str:
    return PIN.split("@", 1)[1]


def _no_manifest_evidence_doc():
    doc = _trivy_doc(artifact=PIN.split("@", 1)[0], vulns=[])
    doc["Metadata"]["RepoDigests"] = []
    return doc


def test_image_config_digest_is_not_manifest_identity():
    # ImageID is the config digest; equality with the pin must not count.
    doc = _no_manifest_evidence_doc()
    doc["Metadata"]["ImageID"] = _pin_digest()
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"
    assert "digest" in report["error"]


def test_image_layer_diffid_is_not_manifest_identity():
    doc = _no_manifest_evidence_doc()
    doc["Metadata"]["DiffIDs"] = [_pin_digest()]
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"


@pytest.mark.parametrize(
    "artifact",
    [
        # Suffix/prefix tricks must not satisfy an exact digest comparison.
        "evil/image@sha256:" + "0" * 64 + "-" + "x",
        "evil/image:" + "sha256-" + "@sha256:" + "f" * 64,
        "evil/image:tag-" + PIN.split("@", 1)[1].split(":", 1)[1],
        "evil/image@" + PIN.split("@", 1)[1] + "0",
        "evil/image@" + PIN.split("@", 1)[1].upper(),
        PIN.split("@", 1)[1],  # bare digest without "@" is not a manifest reference
    ],
)
def test_image_digest_lookalikes_are_not_verified(artifact):
    doc = _trivy_doc(artifact=artifact, vulns=[])
    doc["Metadata"]["RepoDigests"] = []
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED", artifact


@pytest.mark.parametrize(
    "mutate",
    [
        lambda d: d["Metadata"].__setitem__("RepoDigests", "x@" + PIN.split("@", 1)[1]),
        lambda d: d["Metadata"].__setitem__("RepoDigests", [None, 7, {"d": PIN}]),
        lambda d: d.__setitem__("Metadata", "not-a-dict"),
        lambda d: d.__setitem__("Metadata", None),
        lambda d: d.__setitem__("ArtifactName", ["not", "a", "string"]),
    ],
)
def test_image_malformed_identity_fields_fail_closed(mutate):
    doc = _no_manifest_evidence_doc()
    mutate(doc)
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"


@pytest.mark.parametrize("document", [None, [], "{}", {}, {"SchemaVersion": 2}, {"Results": []}])
def test_image_malformed_report_is_not_verified(document):
    report = classify_trivy_document(document, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"


def test_image_valid_identity_from_repodigests_only_is_accepted():
    doc = _trivy_doc(artifact=PIN.split("@", 1)[0], vulns=[])
    doc["Metadata"]["RepoDigests"] = ["other/name@sha256:" + "a" * 64, "x/y@" + _pin_digest()]
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "PASS"
    assert report["blocking_count"] == 0


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


def _version_ok():
    return type(
        "V",
        (),
        {
            "returncode": 0,
            "stdout": json.dumps(
                {
                    "Version": "0.76.0",
                    "VulnerabilityDB": {
                        "UpdatedAt": "2026-10-17T18:34:28Z",
                        "NextUpdate": "2026-10-18T18:34:28Z",
                        "DownloadedAt": "2026-10-18T01:00:00Z",
                    },
                }
            ),
            "stderr": "",
        },
    )()


def _download_ok():
    return type("D", (), {"returncode": 0, "stdout": "", "stderr": ""})()


def test_scan_records_exit_code_and_rejects_empty_json():
    class _Empty:
        returncode = 1
        stdout = ""
        stderr = "pull failed"

    def _runner(args, timeout=600):
        if "--download-db-only" in args:
            return _download_ok()
        if "version" in args:
            return _version_ok()
        return _Empty()

    scanned = scan_pinned_images(
        runner=_runner,
        images=({"name": "one", "ref": PIN},),
        now=NOW,
    )
    assert scanned["status"] == "NOT_VERIFIED"
    assert scanned["images"][0]["status"] == "NOT_VERIFIED"


def test_missing_database_updated_at_is_not_verified():
    doc = _trivy_doc()
    del doc["Metadata"]["VulnerabilityDB"]
    report = classify_trivy_document(doc, image=PIN, now=NOW)
    assert report["status"] == "NOT_VERIFIED"
    assert "UpdatedAt is missing" in report["error"]


def test_version_document_injects_database_metadata():
    from core.supply_chain.images import read_trivy_version_document

    version, db = read_trivy_version_document(
        {
            "Version": "0.76.0",
            "VulnerabilityDB": {
                "UpdatedAt": "2026-10-17T18:34:28Z",
                "NextUpdate": "2026-10-18T18:34:28Z",
                "DownloadedAt": "2026-10-18T01:00:00Z",
            },
        }
    )
    assert version == "0.76.0"
    doc = _trivy_doc()
    del doc["Metadata"]["VulnerabilityDB"]
    report = classify_trivy_document(doc, image=PIN, now=NOW, database=db)
    assert report["status"] == "PASS"
    assert report["database"]["updated_at"] == "2026-10-17T18:34:28Z"


def test_scan_injects_trivy_version_database_into_image_reports():
    image_doc = {
        "SchemaVersion": 2,
        "ArtifactName": PIN,
        "CreatedAt": "2026-10-18T01:22:03Z",
        "Metadata": {
            "RepoDigests": [f"python@{DIGEST}"],
            "ImageConfig": {"architecture": "amd64", "os": "linux"},
        },
        "Trivy": {"Version": "0.76.0"},
        "Results": [],
    }
    seen: list[str] = []

    def _runner(args, timeout=600):
        if "--download-db-only" in args:
            seen.append("download")
            return _download_ok()
        if "version" in args:
            seen.append("version")
            return _version_ok()
        seen.append("image")
        return type("C", (), {"returncode": 0, "stdout": json.dumps(image_doc), "stderr": ""})()

    scanned = scan_pinned_images(
        runner=_runner,
        images=({"name": "python-3.12-probe", "ref": PIN},),
        now=NOW,
    )
    assert seen[:2] == ["download", "version"]
    assert scanned["status"] == "PASS"
    assert scanned["tool_version"] == "0.76.0"
    assert scanned["database"]["updated_at"] == "2026-10-17T18:34:28Z"
    assert scanned["images"][0]["database"]["updated_at"] == "2026-10-17T18:34:28Z"


def test_scan_without_version_database_is_not_verified():
    def _runner(args, timeout=600):
        if "--download-db-only" in args:
            return _download_ok()
        if "version" in args:
            return type("V", (), {"returncode": 0, "stdout": json.dumps({"Version": "0.76.0"}), "stderr": ""})()
        raise AssertionError("image scan must not run without database UpdatedAt")

    scanned = scan_pinned_images(
        runner=_runner,
        images=({"name": "python-3.12-probe", "ref": PIN},),
        now=NOW,
    )
    assert scanned["status"] == "NOT_VERIFIED"
    assert "UpdatedAt is missing" in (scanned.get("error") or "")
    assert scanned["images"] == []


def test_scan_download_db_failure_is_not_verified():
    def _runner(args, timeout=600):
        if "--download-db-only" in args:
            return type("D", (), {"returncode": 1, "stdout": "", "stderr": "network"})()
        raise AssertionError("version/image must not run after download failure")

    scanned = scan_pinned_images(
        runner=_runner,
        images=({"name": "python-3.12-probe", "ref": PIN},),
        now=NOW,
    )
    assert scanned["status"] == "NOT_VERIFIED"
    assert "download" in (scanned.get("error") or "").lower()


def test_ci_separates_docker_runtime_from_image_scan_gate():
    root = Path(__file__).resolve().parents[2]
    text = "\n".join(
        (root / ".github/workflows" / name).read_text(encoding="utf-8")
        for name in ("ci.yml", "image-gates.yml")
    )
    assert "name: Docker build and runtime" in text
    assert "name: Pinned image vulnerability scans" in text
    assert "Enforce pinned image scan gates" in text
    assert "PYTHON_IMAGE_SCAN_EXIT" in text
    assert "UPSTREAM_IMAGE_SCAN_EXIT" in text
    assert "Pinned upstream image vulnerability scan" in text
    # Image scans must not live inside the Docker runtime job.
    docker_job = text.split("docker-runtime:")[1].split("image-scan:")[0]
    assert "image-scan-python.json" not in docker_job
    assert "docker_runtime_verify.sh" in docker_job
    # Upstream must not be skipped solely because the Python scan failed.
    upstream_idx = text.index("Pinned upstream image vulnerability scan")
    assert "if: always()" in text[upstream_idx : upstream_idx + 200]
    assert "pluggy==1.7.0" in (Path(__file__).resolve().parents[2] / "requirements/dev.txt").read_text(
        encoding="utf-8"
    )
