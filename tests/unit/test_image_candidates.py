"""Unit tests for the official image candidate monitor."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path

from core.supply_chain.candidates import CANDIDATE_WATCH, monitor_candidates, resolve_hub_tag
from core.supply_chain.images import PINNED_IMAGES


NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
DIGEST_A = "sha256:" + ("a" * 64)
DIGEST_B = "sha256:" + ("b" * 64)
DIGEST_PIN = PINNED_IMAGES[0]["ref"].split("@", 1)[1]


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
    watch = (
        {
            "name": "python-tip",
            "hub_repository": "library/python",
            "tag": "3.12-slim-bookworm",
            "image": "python",
        },
    )
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
        database={"updated_at": "2026-10-24T01:18:19Z"},
    )
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"
    assert report["ok"] is False
    assert calls == []
    assert report["candidates"][0]["reused_evidence"] is True
    assert report["candidates"][0]["blocking_count"] == 3


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
        database={"updated_at": "2026-10-24T01:18:19Z"},
    )
    assert calls == [f"aquasec/trivy:latest@{DIGEST_B}"]
    assert report["status"] == "ACCEPTABLE_CANDIDATE"
    assert report["ok"] is True
    assert report["acceptable"][0]["digest"] == DIGEST_B
    assert "never updates PINNED_IMAGES" in report["policy"]


def test_monitor_skips_current_pin_digest():
    watch = (
        {
            "name": "python-pin",
            "hub_repository": "library/python",
            "tag": "3.12-slim-bookworm",
            "image": "python",
        },
    )
    calls: list[str] = []
    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_PIN),
        scanner=lambda ref: calls.append(ref) or _pass_row(ref),
        now=NOW,
    )
    assert calls == []
    assert report["candidates"][0]["status"] == "SKIPPED_PINNED"
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"


def test_monitor_hub_failure_is_not_verified():
    watch = (
        {
            "name": "python-tip",
            "hub_repository": "library/python",
            "tag": "3.12-slim-bookworm",
            "image": "python",
        },
    )
    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: (_ for _ in ()).throw(TimeoutError("no hub")),
        scanner=lambda ref: _pass_row(ref),
        now=NOW,
    )
    assert report["status"] == "NOT_VERIFIED"
    assert report["candidates"][0]["status"] == "NOT_VERIFIED"


def test_monitor_stale_reused_evidence_is_not_verified(tmp_path: Path):
    watch = (
        {
            "name": "python-tip",
            "hub_repository": "library/python",
            "tag": "3.12-slim-bookworm",
            "image": "python",
        },
    )
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
        }

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=scan,
        evidence_dir=evidence,
        now=NOW,
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

    output = tmp_path / "out.json"

    def fake_monitor(**_kwargs):
        return {
            "ok": False,
            "status": "NO_ACCEPTABLE_CANDIDATE",
            "candidates": [],
            "acceptable": [],
            "note": "none",
            "policy": "pins unchanged",
        }

    monkeypatch.setattr(main_mod, "monitor_candidates", fake_monitor)
    code = main_mod.main(["candidates", "--output", str(output)])
    assert code == 1
    assert json.loads(output.read_text(encoding="utf-8"))["status"] == "NO_ACCEPTABLE_CANDIDATE"


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


def test_failing_candidate_with_unscored_is_not_acceptable():
    watch = (
        {
            "name": "python-tip",
            "hub_repository": "library/python",
            "tag": "3.12-slim-bookworm",
            "image": "python",
        },
    )

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
        database={"updated_at": "2026-10-24T01:18:19Z"},
    )
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"
    assert report["acceptable"] == []
    assert report["candidates"][0]["status"] == "FAIL"
    assert report["candidates"][0]["unscored_count"] == 2


def test_pass_row_with_unscored_count_is_rejected():
    """A mis-labeled PASS that still reports unscored findings must not be adopted."""
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
        database={"updated_at": "2026-10-24T01:18:19Z"},
    )
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"
    assert report["acceptable"] == []
    assert report["candidates"][0]["status"] == "FAIL"


def test_reused_evidence_missing_platform_or_scanner_is_not_fresh(tmp_path: Path):
    watch = (
        {
            "name": "python-tip",
            "hub_repository": "library/python",
            "tag": "3.12-slim-bookworm",
            "image": "python",
        },
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    incomplete = _fail_row(ref, blocking=1)
    incomplete.pop("platform", None)
    incomplete["scanner_version"] = ""
    (evidence / "incomplete.json").write_text(json.dumps(incomplete), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=4),
        evidence_dir=evidence,
        now=NOW,
        database={"updated_at": "2026-10-24T01:18:19Z"},
    )
    assert calls == [ref]
    assert report["candidates"][0]["reused_evidence"] is False
    assert report["candidates"][0]["blocking_count"] == 4
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"


def test_reused_evidence_older_than_live_db_probe_is_rescanned(tmp_path: Path):
    watch = (
        {
            "name": "python-tip",
            "hub_repository": "library/python",
            "tag": "3.12-slim-bookworm",
            "image": "python",
        },
    )
    evidence = tmp_path / "evidence"
    evidence.mkdir()
    ref = f"python:3.12-slim-bookworm@{DIGEST_A}"
    prior = _fail_row(ref, blocking=1)
    prior["database"] = {"updated_at": "2026-10-20T00:00:00Z"}
    prior["created_at"] = "2026-10-20T01:00:00Z"
    (evidence / "older.json").write_text(json.dumps(prior), encoding="utf-8")
    calls: list[str] = []

    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: _hub(DIGEST_A),
        scanner=lambda ref: calls.append(ref) or _fail_row(ref, blocking=9),
        evidence_dir=evidence,
        now=NOW,
        database={"updated_at": "2026-10-24T01:18:19Z"},
    )
    assert calls == [ref]
    assert report["candidates"][0]["reused_evidence"] is False
    assert report["candidates"][0]["blocking_count"] == 9


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
        assert item.get("scanner_version")
        assert (item.get("database") or {}).get("updated_at")
