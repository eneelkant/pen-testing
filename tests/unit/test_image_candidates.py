"""Unit tests for the official image candidate monitor."""

from __future__ import annotations

import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.supply_chain.candidates import (
    CANDIDATE_WATCH,
    REQUIRED_PLATFORM,
    REQUIRED_SCANNER_VERSION,
    evidence_reusable,
    monitor_candidates,
    resolve_hub_tag,
    validate_live_database,
    verify_fresh_scan,
)
from core.supply_chain.images import PINNED_IMAGES, scan_pinned_images


NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)
DIGEST_PIN = PINNED_IMAGES[0]["ref"].split("@", 1)[1]
LIVE_DB = {"updated_at": "2026-10-24T01:18:19Z"}


def _hub(digest: str, last_updated: str = "2026-10-24T00:00:00.000000Z") -> dict:
    return {
        "name": "tag",
        "last_updated": last_updated,
        "images": [{"architecture": "amd64", "os": "linux", "digest": digest}],
    }


def _vuln(vid: str, severity: str, fixed: str = "") -> dict:
    return {
        "VulnerabilityID": vid,
        "PkgName": "pkg",
        "InstalledVersion": "1.0.0",
        "FixedVersion": fixed,
        "Severity": severity,
    }


def _raw_trivy(
    ref: str,
    *,
    vulns: list | None = None,
    arch: str = "amd64",
    os_name: str = "linux",
    version: str | None = "0.76.0",
    created_at: str = "2026-10-24T01:00:00Z",
    repo_digest: str | None = None,
    artifact: str | None = None,
) -> dict:
    """Minimal raw ``trivy image --format json`` document for ``ref``."""
    digest = ref.split("@", 1)[1]
    repo = ref.split("@", 1)[0].rsplit(":", 1)[0]
    document = {
        "SchemaVersion": 2,
        "CreatedAt": created_at,
        "ArtifactName": artifact if artifact is not None else ref,
        "ArtifactType": "container_image",
        "Metadata": {
            "ImageConfig": {"architecture": arch, "os": os_name},
            "RepoDigests": [f"{repo}@{repo_digest or digest}"],
        },
        "Results": [{"Target": "image", "Vulnerabilities": list(vulns or [])}],
    }
    if version is not None:
        document["Trivy"] = {"Version": version}
    return document


def _unscored_vulns(count: int) -> list:
    return [_vuln(f"CVE-UNSCORED-{index}", "UNKNOWN") for index in range(count)]


def _pass_row(ref: str) -> dict:
    identity_digest = ref.split("@", 1)[1]
    return {
        "ok": True,
        "status": "PASS",
        "image": ref,
        "digest": identity_digest,
        "blocking_count": 0,
        "unscored_count": 0,
        "finding_row_count": 0,
        "unique_cve_count": 0,
        "created_at": "2026-10-24T01:00:00Z",
        "platform": "linux/amd64",
        "scanner_version": "0.76.0",
        "database": {"updated_at": "2026-10-24T01:18:19Z"},
        "tool_version": "0.76.0",
        "error": "",
        "raw_document": _raw_trivy(ref),
    }


def _fail_row(ref: str, *, blocking: int = 1) -> dict:
    row = _pass_row(ref)
    row.update(ok=False, status="FAIL", blocking_count=blocking, unscored_count=blocking)
    row["raw_document"] = _raw_trivy(ref, vulns=_unscored_vulns(blocking))
    return row


def _watch(name: str = "python-tip", tag: str = "3.12-slim-bookworm", image: str = "python") -> tuple:
    return (
        {
            "name": name,
            "hub_repository": f"library/{image}" if image == "python" else image,
            "tag": tag,
            "image": image,
        },
    )


def test_resolve_hub_tag_selects_amd64_digest():
    resolved = resolve_hub_tag(
        "library/python",
        "3.12-slim-bookworm",
        fetcher=lambda _url: {
            "images": [
                {"architecture": "arm64", "os": "linux", "digest": DIGEST_B},
                {"architecture": "amd64", "os": "linux", "digest": DIGEST_A},
            ],
            "last_updated": "2026-10-24T00:00:00Z",
        },
    )
    assert resolved["ok"] is True
    assert resolved["digest"] == DIGEST_A


def test_resolve_hub_failure_is_not_ok():
    def boom(_url):
        raise TimeoutError("hub down")

    resolved = resolve_hub_tag("library/python", "3.12-slim-bookworm", fetcher=boom)
    assert resolved["ok"] is False
    assert "hub down" in resolved["error"]


def test_monitor_reports_no_acceptable_candidate_without_rescanning_known_digest(tmp_path: Path):
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    (evidence / "prior.json").write_text(json.dumps(_fail_row(ref, blocking=3)), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"
    assert report["ok"] is False
    assert calls == []
    assert report["candidates"][0]["reused_evidence"] is True
    assert report["candidates"][0]["blocking_count"] == 3
    assert report["tool_version"] == REQUIRED_SCANNER_VERSION


def test_monitor_scans_new_digest_and_can_report_acceptable():
    watch = (
        {
            "name": "trivy-tip",
            "hub_repository": "aquasec/trivy",
            "tag": "latest",
            "image": "aquasec/trivy",
        },
    )
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_B),
        scanner=lambda ref: calls.append(ref) or _pass_row(ref),
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [f"aquasec/trivy:latest@{DIGEST_B}"]
    assert report["status"] == "ACCEPTABLE_CANDIDATE"
    assert report["ok"] is True
    assert report["acceptable"][0]["digest"] == DIGEST_B
    assert "never updates PINNED_IMAGES" in report["policy"]


def test_monitor_skips_current_pin_digest():
    watch = _watch(name="python-pin")
    calls: list[str] = []
    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_PIN),
        scanner=lambda ref: calls.append(ref) or _pass_row(ref),
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == []
    assert report["candidates"][0]["status"] == "SKIPPED_PINNED"
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"


def test_monitor_hub_failure_is_not_verified():
    watch = _watch()
    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: (_ for _ in ()).throw(TimeoutError("no hub")),
        scanner=lambda ref: _pass_row(ref),
        now=NOW,
        database=LIVE_DB,
    )
    assert report["status"] == "NOT_VERIFIED"
    assert report["candidates"][0]["status"] == "NOT_VERIFIED"


def test_monitor_stale_reused_evidence_is_not_verified(tmp_path: Path):
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    stale = _fail_row(ref)
    stale["database"] = {"updated_at": "2019-01-01T00:00:00Z"}
    stale["created_at"] = "2019-01-01T00:00:00Z"
    (evidence / "stale.json").write_text(json.dumps(stale), encoding="utf-8")
    calls: list[str] = []

    def scan(ref: str) -> dict:
        calls.append(ref)
        return {
            "ok": False,
            "status": "NOT_VERIFIED",
            "image": ref,
            "digest": DIGEST_A,
            "error": "scanner unavailable",
            "blocking_count": 0,
            "database": {},
            "platform": "",
        }

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=scan,
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [ref]
    assert report["status"] == "NOT_VERIFIED"


def test_watch_list_covers_pinned_families():
    names = {item["name"] for item in CANDIDATE_WATCH}
    assert "python-3.12-slim-bookworm" in names
    assert "shannon-latest" in names
    assert "temporal-latest" in names
    assert "gitleaks-latest" in names
    assert "trivy-latest" in names


def test_cli_candidates_writes_report(tmp_path: Path, monkeypatch):
    from core.supply_chain import __main__ as main_mod
    import shutil
    import subprocess

    output = tmp_path / "out.json"
    seen: dict = {}

    def fake_monitor(**kwargs):
        seen.update(kwargs)
        return {
            "ok": False,
            "status": "NO_ACCEPTABLE_CANDIDATE",
            "candidates": [],
            "acceptable": [],
            "note": "none",
            "policy": "pins unchanged",
        }

    class Completed:
        returncode = 0
        stdout = json.dumps(
            {
                "Version": "0.76.0",
                "VulnerabilityDB": {"UpdatedAt": "2026-10-24T01:18:19Z"},
            }
        )

    monkeypatch.setattr(main_mod, "monitor_candidates", fake_monitor)
    monkeypatch.setattr(shutil, "which", lambda name: "/usr/bin/trivy" if name == "trivy" else None)
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: Completed())
    code = main_mod.main(["candidates", "--output", str(output)])
    assert code == 1
    assert seen.get("require_live_database") is True
    assert (seen.get("database") or {}).get("updated_at") == "2026-10-24T01:18:19Z"
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "NO_ACCEPTABLE_CANDIDATE"


def test_cli_without_live_db_probe_is_not_verified(tmp_path: Path, monkeypatch):
    from core.supply_chain import __main__ as main_mod
    import shutil

    output = tmp_path / "out.json"
    calls: list[str] = []

    def fake_monitor(**_kwargs):
        calls.append("monitor")
        return {"ok": True, "status": "ACCEPTABLE_CANDIDATE", "candidates": [], "acceptable": [{"x": 1}]}

    monkeypatch.setattr(main_mod, "monitor_candidates", fake_monitor)
    monkeypatch.setattr(shutil, "which", lambda _name: None)
    code = main_mod.main(["candidates", "--output", str(output)])
    assert code == 2
    assert calls == []
    payload = json.loads(output.read_text(encoding="utf-8"))
    assert payload["status"] == "NOT_VERIFIED"
    assert payload["acceptable"] == []
    assert "live" in payload["error"].lower()

def test_workflow_is_manual_and_scheduled_not_on_pull_request():
    text = (Path(__file__).resolve().parents[2] / ".github/workflows/image-candidate-monitor.yml").read_text(
        encoding="utf-8"
    )
    assert "workflow_dispatch" in text
    assert "schedule:" in text
    assert "pull_request" not in text
    assert "Never updates pins" in text
    assert "core.supply_chain candidates" in text
    rejects = Path(__file__).resolve().parents[2] / "core/supply_chain/candidate_rejects.json"
    assert rejects.is_file()
    payload = json.loads(rejects.read_text(encoding="utf-8"))
    assert isinstance(payload, list) and payload
    assert all(item.get("digest", "").startswith("sha256:") for item in payload)


def test_evidence_reusable_requires_digest_platform_scanner_and_freshness():
    base = _fail_row(f"python:3.12-slim-bookworm@{DIGEST_A}", blocking=2)
    ok, reason = evidence_reusable(
        base, digest=DIGEST_A, now=NOW, max_age=timedelta(days=7), live_database=LIVE_DB
    )
    assert ok is True
    assert reason == ""

    mismatched = dict(base, digest=DIGEST_B)
    ok, reason = evidence_reusable(
        mismatched, digest=DIGEST_A, now=NOW, max_age=timedelta(days=7), live_database=LIVE_DB
    )
    assert ok is False
    assert "digest" in reason

    wrong_platform = dict(base, platform="linux/arm64")
    ok, reason = evidence_reusable(
        wrong_platform, digest=DIGEST_A, now=NOW, max_age=timedelta(days=7), live_database=LIVE_DB
    )
    assert ok is False
    assert "platform" in reason

    missing_platform = dict(base)
    missing_platform.pop("platform")
    ok, reason = evidence_reusable(
        missing_platform, digest=DIGEST_A, now=NOW, max_age=timedelta(days=7), live_database=LIVE_DB
    )
    assert ok is False
    assert "platform is missing" in reason

    wrong_scanner = dict(base, scanner_version="0.75.0")
    ok, reason = evidence_reusable(
        wrong_scanner, digest=DIGEST_A, now=NOW, max_age=timedelta(days=7), live_database=LIVE_DB
    )
    assert ok is False
    assert "scanner_version" in reason

    stale = dict(base, created_at="2019-01-01T00:00:00Z", database={"updated_at": "2019-01-01T00:00:00Z"})
    ok, reason = evidence_reusable(
        stale, digest=DIGEST_A, now=NOW, max_age=timedelta(days=7), live_database=LIVE_DB
    )
    assert ok is False
    assert "stale" in reason


def test_evidence_reusable_rejects_older_than_live_database_within_age_limit():
    base = _fail_row(f"python:3.12-slim-bookworm@{DIGEST_A}")
    # Within 7-day age window relative to NOW, but older than the live probe.
    base["database"] = {"updated_at": "2026-10-23T01:00:00Z"}
    base["created_at"] = "2026-10-23T02:00:00Z"
    ok, reason = evidence_reusable(
        base,
        digest=DIGEST_A,
        now=NOW,
        max_age=timedelta(days=7),
        live_database={"updated_at": "2026-10-24T01:18:19Z"},
    )
    assert ok is False
    assert "older than the live" in reason


def test_evidence_reusable_requires_live_database_probe():
    base = _fail_row(f"python:3.12-slim-bookworm@{DIGEST_A}")
    ok, reason = evidence_reusable(
        base, digest=DIGEST_A, now=NOW, max_age=timedelta(days=7), live_database=None
    )
    assert ok is False
    assert "live probe required" in reason


def test_monitor_rescans_when_scanner_metadata_mismatches(tmp_path: Path):
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    prior = _fail_row(ref, blocking=9)
    prior["scanner_version"] = "0.58.1"
    (evidence / "prior.json").write_text(json.dumps(prior), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=2),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [ref]
    assert report["candidates"][0]["reused_evidence"] is False
    assert "scanner_version" in report["candidates"][0]["reuse_rejected"]
    assert report["candidates"][0]["blocking_count"] == 2
    assert report["required_platform"] == REQUIRED_PLATFORM


def test_monitor_rescans_when_platform_mismatches(tmp_path: Path):
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    prior = _fail_row(ref, blocking=9)
    prior["platform"] = "linux/arm64"
    (evidence / "prior.json").write_text(json.dumps(prior), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=5),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [ref]
    assert report["candidates"][0]["reused_evidence"] is False
    assert "platform" in report["candidates"][0]["reuse_rejected"]
    assert report["candidates"][0]["blocking_count"] == 5


def test_monitor_rescans_when_digest_mismatches_recorded_evidence(tmp_path: Path):
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    # Index under DIGEST_A via filename content, but recorded digest is DIGEST_B.
    prior = _fail_row(f"python:3.12-slim-bookworm@{DIGEST_B}", blocking=9)
    prior["digest"] = DIGEST_B
    # Force index key to DIGEST_A by also listing it under images — _index_document
    # uses digest field; write with digest A in a wrapper that indexes A but body says B.
    # Put digest A in ArtifactName-style and B as primary — simplest: store under digest A
    # key by setting digest to A in index but evidence_reusable compares document digest.
    planted = dict(prior)
    planted["digest"] = DIGEST_B
    # Manually place so index key is DIGEST_A:
    planted_for_index = dict(planted)
    planted_for_index["digest"] = DIGEST_A
    # After load, change file to have wrong digest while still keyed... evidence index
    # uses document digest field as key. So write document with digest=A in file for
    # indexing then the reusable check uses recorded digest — we need recorded != resolved.
    # Resolve to A; evidence document.digest = B but also include A in images so indexed under A.
    planted = {
        **_fail_row(f"python:3.12-slim-bookworm@{DIGEST_B}", blocking=9),
        "digest": DIGEST_B,
        "images": [{"digest": DIGEST_A}],
    }
    (evidence / "prior.json").write_text(json.dumps(planted), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=1),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [f"python:3.12-slim-bookworm@{DIGEST_A}"]
    assert report["candidates"][0]["reused_evidence"] is False
    assert "digest" in report["candidates"][0]["reuse_rejected"]


def test_monitor_fresh_scan_path_when_no_evidence():
    watch = _watch()
    calls: list[str] = []
    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=4),
        evidence_dir=Path("/tmp/no-such-evidence-dir-for-monitor"),
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [f"python:3.12-slim-bookworm@{DIGEST_A}"]
    assert report["candidates"][0]["reused_evidence"] is False
    assert report["candidates"][0]["blocking_count"] == 4
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"


def test_monitor_rejects_scan_missing_platform_as_not_verified():
    watch = _watch()

    def scan(ref: str) -> dict:
        row = _pass_row(ref)
        row["raw_document"]["Metadata"]["ImageConfig"] = {}
        return row

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_B),
        scanner=scan,
        now=NOW,
        database=LIVE_DB,
    )
    assert report["status"] == "NOT_VERIFIED"
    assert report["candidates"][0]["platform"] == ""
    assert "platform" in report["candidates"][0]["error"]


def test_monitor_without_live_database_is_not_verified():
    watch = _watch()
    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: _pass_row(ref),
        now=NOW,
        database=None,
        require_live_database=True,
    )
    assert report["status"] == "NOT_VERIFIED"
    assert report["acceptable"] == []
    assert "live vulnerability database" in report["error"]


def test_failing_candidate_with_unscored_is_not_acceptable():
    watch = _watch()

    def scan(ref: str) -> dict:
        row = _fail_row(ref, blocking=2)
        row["unscored_count"] = 2
        row["blocking_count"] = 2
        return row

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=scan,
        now=NOW,
        database=LIVE_DB,
    )
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"
    assert report["acceptable"] == []
    assert report["candidates"][0]["status"] == "FAIL"
    assert report["candidates"][0]["unscored_count"] == 2


def test_pass_row_with_unscored_count_is_rejected():
    watch = (
        {
            "name": "trivy-tip",
            "hub_repository": "aquasec/trivy",
            "tag": "latest",
            "image": "aquasec/trivy",
        },
    )

    def scan(ref: str) -> dict:
        row = _pass_row(ref)
        row["raw_document"] = _raw_trivy(ref, vulns=_unscored_vulns(3))
        row.pop("blocking_count")
        row.pop("unscored_count")
        return row

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_B),
        scanner=scan,
        now=NOW,
        database=LIVE_DB,
    )
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"
    assert report["acceptable"] == []
    assert report["candidates"][0]["status"] == "FAIL"


def test_preclassified_pass_without_raw_results_is_not_reused(tmp_path: Path):
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    planted = _pass_row(ref)
    assert "Results" not in planted
    (evidence / "planted-pass.json").write_text(json.dumps(planted), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=7),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [ref]
    assert report["candidates"][0]["reused_evidence"] is False
    assert "PASS" in report["candidates"][0]["reuse_rejected"]
    assert report["candidates"][0]["blocking_count"] == 7
    assert report["acceptable"] == []


def test_preclassified_pass_with_blocking_findings_forces_fresh_scan(tmp_path: Path):
    """Stored PASS is never trusted, even when findings claim blockers."""
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    planted = _pass_row(ref)
    planted["findings"] = [
        {
            "id": "CVE-TEST-1",
            "severity": "CRITICAL",
            "fixed": "1.2.3",
            "class": "fixed",
            "blocking": True,
        }
    ]
    planted["blocking_count"] = 0
    planted["unscored_count"] = 0
    (evidence / "planted.json").write_text(json.dumps(planted), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=99),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [ref]
    assert report["candidates"][0]["reused_evidence"] is False
    assert report["acceptable"] == []
    assert report["candidates"][0]["blocking_count"] == 99


def test_planted_empty_results_pass_is_not_accepted_via_reuse(tmp_path: Path):
    """Empty Trivy Results + stored metadata must not become ACCEPTABLE via reuse."""
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    planted = _pass_row(ref)
    planted["Results"] = []
    planted["ArtifactName"] = ref
    planted["CreatedAt"] = planted["created_at"]
    (evidence / "empty-results.json").write_text(json.dumps(planted), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=4),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [ref]
    assert report["candidates"][0]["reused_evidence"] is False
    assert report["acceptable"] == []
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"


def test_raw_trivy_results_fail_is_reclassified_not_trusting_stored_counts(tmp_path: Path):
    """Raw Results go through classify_trivy_document; planted PASS counts are ignored."""
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    raw = {
        "ArtifactName": ref,
        "CreatedAt": "2026-10-24T01:00:00Z",
        "digest": DIGEST_A,
        "platform": "linux/amd64",
        "scanner_version": "0.76.0",
        "database": {"updated_at": "2026-10-24T01:18:19Z"},
        # Misleading stored gate fields — classifier must ignore these.
        "status": "PASS",
        "blocking_count": 0,
        "unscored_count": 0,
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-PLANT-1",
                        "PkgName": "openssl",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "CRITICAL",
                    }
                ]
            }
        ],
    }
    (evidence / "raw.json").write_text(json.dumps(raw), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=1),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    # status PASS on the document blocks reuse entirely → fresh scan.
    assert calls == [ref]
    assert report["candidates"][0]["reused_evidence"] is False
    assert report["acceptable"] == []


def test_raw_trivy_results_without_pass_status_are_reclassified(tmp_path: Path):
    """Raw Trivy JSON without a stored PASS status is classified canonically."""
    watch = _watch()
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    raw = {
        "ArtifactName": ref,
        "CreatedAt": "2026-10-24T01:00:00Z",
        "digest": DIGEST_A,
        "platform": "linux/amd64",
        "scanner_version": "0.76.0",
        "database": {"updated_at": "2026-10-24T01:18:19Z"},
        "Results": [
            {
                "Vulnerabilities": [
                    {
                        "VulnerabilityID": "CVE-RAW-1",
                        "PkgName": "curl",
                        "InstalledVersion": "1.0.0",
                        "FixedVersion": "1.0.1",
                        "Severity": "HIGH",
                    }
                ]
            }
        ],
    }
    (evidence / "raw-fail.json").write_text(json.dumps(raw), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=50),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == []
    assert report["candidates"][0]["reused_evidence"] is True
    assert report["candidates"][0]["status"] == "FAIL"
    assert report["candidates"][0]["blocking_count"] == 1
    assert report["acceptable"] == []


def test_acceptable_only_after_fresh_exact_digest_pass():
    watch = (
        {
            "name": "trivy-tip",
            "hub_repository": "aquasec/trivy",
            "tag": "latest",
            "image": "aquasec/trivy",
        },
    )
    calls: list[str] = []

    def scan(ref: str) -> dict:
        calls.append(ref)
        row = _pass_row(ref)
        assert row["digest"] == DIGEST_B
        assert row["scanner_version"] == REQUIRED_SCANNER_VERSION
        assert row["platform"] == REQUIRED_PLATFORM
        assert row["blocking_count"] == 0
        assert row["unscored_count"] == 0
        return row

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_B),
        scanner=scan,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [f"aquasec/trivy:latest@{DIGEST_B}"]
    assert report["status"] == "ACCEPTABLE_CANDIDATE"
    assert len(report["acceptable"]) == 1
    assert report["acceptable"][0]["digest"] == DIGEST_B
    assert report["acceptable"][0]["reused_evidence"] is False


def test_ci_keeps_python_and_upstream_image_gates_separate():
    text = (Path(__file__).resolve().parents[2] / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "Pinned base image vulnerability scan" in text
    assert "Pinned upstream image vulnerability scan" in text
    assert "image-scan-python" in text
    assert "image-scan-upstream" in text
    assert "PYTHON_IMAGE_SCAN_EXIT" in text
    assert "UPSTREAM_IMAGE_SCAN_EXIT" in text
    assert "Enforce pinned image scan gates" in text


def test_production_pins_remain_digest_pinned():
    for item in PINNED_IMAGES:
        assert "@sha256:" in item["ref"], item
        assert not item["ref"].endswith(":latest")
        assert ":latest@" not in item["ref"]


def test_reject_inventory_includes_python_31213_and_temporal_173():
    rejects = Path(__file__).resolve().parents[2] / "core/supply_chain/candidate_rejects.json"
    payload = json.loads(rejects.read_text(encoding="utf-8"))
    digests = {item["digest"] for item in payload}
    assert "sha256:6e13e65c55e33adf203d77ee371cf8bf5d81bd4902ef07565721f46bf44917af" in digests
    assert "sha256:1683f097876c2af71ba833bd9418910601be12d4a25422f2c4ebec45113e1bc2" in digests
    for item in payload:
        assert item.get("status") == "FAIL"
        assert int(item.get("blocking_count") or 0) > 0
        assert item.get("platform") == "linux/amd64"
        assert item.get("scanner_version") == REQUIRED_SCANNER_VERSION
        assert (item.get("database") or {}).get("updated_at")


# --- Regression tests: fresh-scan acceptance must come from raw findings ---------------

TRIVY_WATCH = (
    {
        "name": "trivy-tip",
        "hub_repository": "aquasec/trivy",
        "tag": "latest",
        "image": "aquasec/trivy",
    },
)
REF_B = f"aquasec/trivy:latest@{DIGEST_B}"


def _run(scan, *, database=LIVE_DB, **kwargs):
    return monitor_candidates(
        watch=TRIVY_WATCH,
        fetcher=lambda _url: _hub(DIGEST_B),
        scanner=scan,
        now=NOW,
        database=database,
        **kwargs,
    )


def _assert_not_accepted(report, *, status="NOT_VERIFIED", error_fragment=""):
    assert report["status"] == status
    assert report["ok"] is False
    assert report["acceptable"] == []
    if error_fragment:
        assert error_fragment in report["candidates"][0]["error"], report["candidates"][0]["error"]


def test_summary_pass_without_raw_findings_is_not_accepted():
    def scan(ref):
        row = _pass_row(ref)
        row.pop("raw_document")
        return row

    _assert_not_accepted(_run(scan), error_fragment="raw Trivy findings are missing")


def test_summary_pass_with_raw_fixed_critical_is_reclassified_fail():
    def scan(ref):
        row = _pass_row(ref)
        row.pop("blocking_count")
        row.pop("unscored_count")
        row["raw_document"] = _raw_trivy(ref, vulns=[_vuln("CVE-CRIT-1", "CRITICAL", fixed="1.2.3")])
        return row

    report = _run(scan)
    _assert_not_accepted(report, status="NO_ACCEPTABLE_CANDIDATE")
    assert report["candidates"][0]["status"] == "FAIL"
    assert report["candidates"][0]["blocking_count"] == 1


def test_summary_counts_disagreeing_with_raw_fail_closed():
    def scan(ref):
        row = _pass_row(ref)  # claims blocking_count=0
        row["raw_document"] = _raw_trivy(ref, vulns=[_vuln("CVE-HIGH-1", "HIGH", fixed="2.0")])
        return row

    _assert_not_accepted(_run(scan), error_fragment="disagrees with raw reclassification")


def test_summary_findings_list_is_ignored_in_favor_of_raw():
    def scan(ref):
        row = _pass_row(ref)
        row["findings"] = [{"id": "CVE-X", "severity": "CRITICAL", "fixed": "1", "blocking": True}]
        row.pop("raw_document")
        return row

    _assert_not_accepted(_run(scan), error_fragment="raw Trivy findings are missing")


def test_raw_wrong_scanner_version_is_not_verified():
    def scan(ref):
        row = _pass_row(ref)
        row["tool_version"] = "0.75.0"
        row["raw_document"] = _raw_trivy(ref, version="0.75.0")
        return row

    _assert_not_accepted(_run(scan), error_fragment="does not match required '0.76.0'")


def test_raw_scanner_version_disagreeing_with_probe_is_not_verified():
    def scan(ref):
        row = _pass_row(ref)
        row["raw_document"] = _raw_trivy(ref, version="0.76.1")
        return row

    _assert_not_accepted(_run(scan), error_fragment="disagrees with probed scanner")


def test_custom_scanner_missing_raw_trivy_version_rejects_probe_fallback():
    """Injected scanners must not accept a candidate via tool_version alone."""

    def scan(ref):
        row = _pass_row(ref)
        row["tool_version"] = "0.76.0"
        row["scanner_version"] = "0.76.0"
        row["raw_document"] = _raw_trivy(ref, version=None)
        return row

    _assert_not_accepted(_run(scan), error_fragment="scanner version is missing")


def test_summary_scanner_version_cannot_override_raw():
    def scan(ref):
        row = _pass_row(ref)
        row["tool_version"] = ""
        row["scanner_version"] = ""
        row["raw_document"] = _raw_trivy(ref, version="0.58.1")
        return row

    _assert_not_accepted(_run(scan), error_fragment="'0.58.1'")


def test_raw_wrong_platform_is_not_verified_even_if_summary_says_amd64():
    def scan(ref):
        row = _pass_row(ref)
        row["platform"] = "linux/amd64"
        row["raw_document"] = _raw_trivy(ref, arch="arm64")
        return row

    _assert_not_accepted(_run(scan), error_fragment="'linux/arm64' does not match")


def test_raw_report_with_other_digest_is_not_verified():
    def scan(ref):
        row = _pass_row(ref)
        other = f"aquasec/trivy:latest@{DIGEST_A}"
        row["raw_document"] = _raw_trivy(other)
        return row

    _assert_not_accepted(_run(scan), error_fragment="exact resolved digest")


def test_raw_report_without_any_digest_is_not_verified():
    def scan(ref):
        row = _pass_row(ref)
        raw = _raw_trivy(ref, artifact="aquasec/trivy:latest")
        raw["Metadata"].pop("RepoDigests")
        row["raw_document"] = raw
        return row

    _assert_not_accepted(_run(scan), error_fragment="exact resolved digest")


def test_digest_only_in_layer_ids_does_not_count_as_identity():
    def scan(ref):
        row = _pass_row(ref)
        raw = _raw_trivy(ref, artifact="aquasec/trivy:latest")
        raw["Metadata"].pop("RepoDigests")
        raw["Metadata"]["DiffIDs"] = [DIGEST_B]
        raw["Metadata"]["ImageID"] = DIGEST_B
        row["raw_document"] = raw
        return row

    _assert_not_accepted(_run(scan), error_fragment="exact resolved digest")


def test_scan_database_stale_is_not_verified():
    def scan(ref):
        row = _pass_row(ref)
        row["database"] = {"updated_at": "2026-09-01T00:00:00Z"}
        return row

    _assert_not_accepted(_run(scan), error_fragment="stale")


def test_scan_database_older_than_live_probe_is_not_verified():
    def scan(ref):
        row = _pass_row(ref)
        row["database"] = {"updated_at": "2026-10-23T01:18:19Z"}
        return row

    _assert_not_accepted(_run(scan), error_fragment="older than the live")


def test_raw_created_at_missing_or_stale_is_not_verified():
    def missing(ref):
        row = _pass_row(ref)
        row["raw_document"].pop("CreatedAt")
        return row

    def stale(ref):
        row = _pass_row(ref)
        row["raw_document"]["CreatedAt"] = "2026-09-01T00:00:00Z"
        return row

    _assert_not_accepted(_run(missing), error_fragment="CreatedAt")
    _assert_not_accepted(_run(stale), error_fragment="CreatedAt is stale")


def test_live_probe_failures_are_not_verified():
    for database in (None, {}, {"updated_at": ""}, {"updated_at": "not-a-date"},
                     {"updated_at": "2026-09-01T00:00:00Z"}, {"updated_at": "2027-01-01T00:00:00Z"}):
        calls: list[str] = []
        report = _run(lambda ref: calls.append(ref) or _pass_row(ref), database=database)
        assert report["status"] == "NOT_VERIFIED", database
        assert report["acceptable"] == [], database
        assert calls == [], database


def test_validate_live_database_reasons():
    ok, error = validate_live_database(LIVE_DB, now=NOW, max_age=timedelta(days=7))
    assert ok is not None and error == ""
    assert "not a valid timestamp" in validate_live_database(
        {"updated_at": "garbage"}, now=NOW, max_age=timedelta(days=7))[1]
    assert "stale" in validate_live_database(
        {"updated_at": "2026-09-01T00:00:00Z"}, now=NOW, max_age=timedelta(days=7))[1]
    assert "future" in validate_live_database(
        {"updated_at": "2026-10-25T12:00:00Z"}, now=NOW, max_age=timedelta(days=7))[1]


def test_live_probe_optional_mode_can_never_accept():
    report = _run(lambda ref: _pass_row(ref), database=None, require_live_database=False)
    _assert_not_accepted(report, error_fragment="live probe required before accepting")


def test_missing_or_malformed_raw_results_are_not_verified():
    mutations = {
        "no Results": lambda raw: raw.pop("Results"),
        "Results not a list": lambda raw: raw.__setitem__("Results", {"x": 1}),
        "non-object result": lambda raw: raw.__setitem__("Results", ["oops"]),
        "Vulnerabilities not a list": lambda raw: raw["Results"][0].__setitem__("Vulnerabilities", "x"),
        "finding without id": lambda raw: raw["Results"][0].__setitem__(
            "Vulnerabilities", [{"Severity": "LOW"}]),
    }
    for label, mutate in mutations.items():
        def scan(ref, mutate=mutate):
            row = _pass_row(ref)
            mutate(row["raw_document"])
            return row

        report = _run(scan)
        assert report["status"] == "NOT_VERIFIED", label
        assert report["acceptable"] == [], label


def test_nonzero_scanner_exit_with_clean_raw_is_not_verified():
    def scan(ref):
        row = _pass_row(ref)
        row["exit_code"] = 1
        return row

    _assert_not_accepted(_run(scan), error_fragment="nonzero")


def test_scanner_exception_fails_closed():
    def scan(_ref):
        raise ValueError("unexpected scanner payload")

    _assert_not_accepted(_run(scan), error_fragment="scanner error: ValueError")


def test_scanner_returning_non_object_fails_closed():
    _assert_not_accepted(_run(lambda _ref: ["not", "a", "dict"]), error_fragment="non-object")


def test_unscored_raw_finding_blocks_acceptance():
    def scan(ref):
        row = _pass_row(ref)
        row.pop("blocking_count")
        row.pop("unscored_count")
        row["raw_document"] = _raw_trivy(ref, vulns=[_vuln("CVE-NEW-1", "UNKNOWN")])
        return row

    report = _run(scan)
    _assert_not_accepted(report, status="NO_ACCEPTABLE_CANDIDATE")
    assert report["candidates"][0]["unscored_count"] == 1


def test_unfixed_high_does_not_block_but_stays_visible():
    def scan(ref):
        row = _pass_row(ref)
        row.pop("blocking_count")
        row.pop("unscored_count")
        row["raw_document"] = _raw_trivy(ref, vulns=[_vuln("CVE-UNFIXED-1", "HIGH")])
        return row

    report = _run(scan)
    assert report["status"] == "ACCEPTABLE_CANDIDATE"
    assert report["candidates"][0]["finding_row_count"] == 1


def test_reused_fail_evidence_rejects_and_never_accepts(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    (evidence / "prior.json").write_text(json.dumps(_fail_row(REF_B, blocking=2)), encoding="utf-8")
    calls: list[str] = []
    report = monitor_candidates(
        watch=TRIVY_WATCH,
        fetcher=lambda _url: _hub(DIGEST_B),
        scanner=lambda ref: calls.append(ref) or _pass_row(ref),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == []
    assert report["candidates"][0]["reused_evidence"] is True
    _assert_not_accepted(report, status="NO_ACCEPTABLE_CANDIDATE")


def test_reused_raw_pass_evidence_forces_fresh_scan(tmp_path: Path):
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    planted = {
        **_raw_trivy(REF_B),
        "digest": DIGEST_B,
        "platform": "linux/amd64",
        "scanner_version": "0.76.0",
        "created_at": "2026-10-24T01:00:00Z",
        "database": {"updated_at": "2026-10-24T01:18:19Z"},
    }
    (evidence / "raw-pass.json").write_text(json.dumps(planted), encoding="utf-8")
    calls: list[str] = []
    report = monitor_candidates(
        watch=TRIVY_WATCH,
        fetcher=lambda _url: _hub(DIGEST_B),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=3),
        evidence_dir=evidence,
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == [REF_B]
    assert report["candidates"][0]["reused_evidence"] is False
    assert "rescanning" in report["candidates"][0]["reuse_rejected"]
    assert report["candidates"][0]["blocking_count"] == 3


def test_verify_fresh_scan_ignores_summary_status():
    from datetime import datetime as _dt

    live = _dt(2026, 10, 24, 1, 18, 19, tzinfo=timezone.utc)
    row = _fail_row(REF_B, blocking=0)
    row.update(status="FAIL", ok=False)  # summary says FAIL, raw is clean and consistent
    classified = verify_fresh_scan(
        row, ref=REF_B, digest=DIGEST_B, now=NOW, max_age=timedelta(days=7), live_updated=live
    )
    assert classified["status"] == "PASS"


def test_scan_pinned_images_include_raw_attaches_unmodified_document():
    raw = _raw_trivy(REF_B)

    class Done:
        def __init__(self, stdout, returncode=0):
            self.stdout = stdout
            self.returncode = returncode

    def runner(args, timeout=600):
        if "--download-db-only" in args:
            return Done("")
        if "version" in args:
            return Done(json.dumps({"Version": "0.76.0", "VulnerabilityDB": {"UpdatedAt": "2026-10-24T01:18:19Z"}}))
        return Done(json.dumps(raw))

    with_raw = scan_pinned_images(runner=runner, images=({"name": "c", "ref": REF_B},), now=NOW, include_raw=True)
    without = scan_pinned_images(runner=runner, images=({"name": "c", "ref": REF_B},), now=NOW)
    assert with_raw["images"][0]["raw_document"] == raw
    assert "raw_document" not in without["images"][0]
