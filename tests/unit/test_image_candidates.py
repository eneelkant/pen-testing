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
)
from core.supply_chain.images import PINNED_IMAGES


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
        "error": "",
    }


def _fail_row(ref: str, *, blocking: int = 1) -> dict:
    row = _pass_row(ref)
    row.update(ok=False, status="FAIL", blocking_count=blocking, unscored_count=blocking)
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
    assert "live vulnerability database probe is required" in reason


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
        row.pop("platform")
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
        row["unscored_count"] = 3
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
