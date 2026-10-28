"""Regression tests for pinned-image identity, platform, and raw-evidence defects.

Defects covered (found while diagnosing CI run 40073683459):

1. Pins are multi-platform OCI index digests, but Docker Hub's tags API returns
   per-platform digests. The candidate monitor compared the two, so the pinned
   image itself was rescanned and recorded as a "moved" candidate.
2. Pinned scans of an index ref did not force or verify linux/amd64; the same
   index scanned as arm64 reports identical RepoDigests.
3. CI kept only classified summaries; raw Trivy JSON was discarded.
4. Unscored findings (no vendor severity, no CVSS) must keep blocking even when
   no fix exists; nothing may downgrade them.
"""

from __future__ import annotations

import hashlib
import json
from datetime import datetime, timezone
from pathlib import Path

import pytest

from core.supply_chain import candidates as candidates_mod
from core.supply_chain.candidates import monitor_candidates
from core.supply_chain.images import (
    PINNED_IMAGES,
    REQUIRED_PLATFORM,
    REQUIRED_SCANNER_VERSION,
    classify_trivy_document,
    parse_image_ref,
    scan_pinned_images,
    write_raw_evidence,
)

NOW = datetime(2026, 10, 24, 12, tzinfo=timezone.utc)
LIVE_DB = {"updated_at": "2026-10-24T01:18:19Z"}
ROOT = Path(__file__).resolve().parents[2]


def _pin(name: str) -> dict:
    return next(item for item in PINNED_IMAGES if item["name"] == name)


def _image_doc(ref: str, *, arch: str = "amd64", os_name: str = "linux", vulns=None, version="0.76.0",
               image_config: bool = True) -> dict:
    metadata = {"RepoDigests": [f"{parse_image_ref(ref)['repository']}@{parse_image_ref(ref)['digest']}"]}
    if image_config:
        metadata["ImageConfig"] = {"architecture": arch, "os": os_name}
    document = {
        "SchemaVersion": 2,
        "CreatedAt": "2026-10-24T07:00:00Z",
        "ArtifactName": ref,
        "Metadata": metadata,
        "Results": [{"Target": "x", "Class": "os-pkgs", "Vulnerabilities": list(vulns or [])}],
    }
    if version is not None:
        document["Trivy"] = {"Version": version}
    return document


def _runner_for(document: dict, seen: list | None = None, probe_version: str = "0.76.0"):
    class Done:
        def __init__(self, stdout: str = "", returncode: int = 0):
            self.stdout, self.returncode, self.stderr = stdout, returncode, ""

    def runner(args, timeout=600):
        if seen is not None:
            seen.append(list(args))
        if "--download-db-only" in args:
            return Done()
        if "version" in args:
            return Done(json.dumps({"Version": probe_version, "VulnerabilityDB": {"UpdatedAt": LIVE_DB["updated_at"]}}))
        return Done(json.dumps(document))

    return runner


# --- 1. index digest vs per-platform digest -------------------------------------------


def test_every_pin_records_a_distinct_linux_amd64_platform_digest():
    for item in PINNED_IMAGES:
        child = item.get("platform_digest", "")
        assert child.startswith("sha256:") and len(child) == 71, item["name"]
        assert child != parse_image_ref(item["ref"])["digest"], item["name"]


@pytest.mark.parametrize("pin_name", ["shannon-worker", "trivy-scanner", "temporal", "python-3.12-probe"])
def test_hub_platform_digest_of_a_pin_is_skipped_not_rescanned(pin_name: str):
    pin = _pin(pin_name)
    identity = parse_image_ref(pin["ref"])
    repo = identity["repository"]
    watch = ({
        "name": f"{pin_name}-tip",
        "hub_repository": repo if "/" in repo else f"library/{repo}",
        "tag": identity["tag"],
        "image": repo,
    },)
    calls: list[str] = []
    report = monitor_candidates(
        watch=watch,
        fetcher=lambda _url: {"images": [{"architecture": "amd64", "os": "linux", "digest": pin["platform_digest"]}]},
        scanner=lambda ref: calls.append(ref) or {},
        now=NOW,
        database=LIVE_DB,
    )
    assert calls == []
    assert report["candidates"][0]["status"] == "SKIPPED_PINNED"
    assert report["status"] == "NO_ACCEPTABLE_CANDIDATE"


def test_candidate_module_reuses_gate_constants_from_images():
    assert candidates_mod.REQUIRED_PLATFORM is REQUIRED_PLATFORM
    assert candidates_mod.REQUIRED_SCANNER_VERSION is REQUIRED_SCANNER_VERSION
    assert REQUIRED_PLATFORM == "linux/amd64"
    assert REQUIRED_SCANNER_VERSION == "0.76.0"


# --- 2. pinned scans force and verify linux/amd64 + scanner version ------------------


def test_pinned_scan_passes_platform_flag_to_trivy():
    pin = _pin("trivy-scanner")
    seen: list = []
    scan_pinned_images(runner=_runner_for(_image_doc(pin["ref"]), seen), images=(pin,), now=NOW)
    image_calls = [args for args in seen if "image" in args and "--download-db-only" not in args]
    assert image_calls, seen
    args = image_calls[0]
    assert args[args.index("--platform") + 1] == "linux/amd64"
    assert args[-1] == pin["ref"]


def test_pinned_scan_of_wrong_platform_is_not_verified_even_when_clean():
    pin = _pin("trivy-scanner")
    report = scan_pinned_images(runner=_runner_for(_image_doc(pin["ref"], arch="arm64")), images=(pin,), now=NOW)
    assert report["status"] == "NOT_VERIFIED"
    assert "linux/arm64" in report["images"][0]["error"]


def test_pinned_scan_of_wrong_platform_with_findings_is_not_verified_not_fail():
    pin = _pin("trivy-scanner")
    vulns = [{"VulnerabilityID": "CVE-1", "PkgName": "p", "InstalledVersion": "1", "FixedVersion": "2",
              "Severity": "HIGH"}]
    report = scan_pinned_images(runner=_runner_for(_image_doc(pin["ref"], arch="arm64", vulns=vulns)),
                                images=(pin,), now=NOW)
    assert report["images"][0]["status"] == "NOT_VERIFIED"


def test_pinned_scan_without_image_config_is_not_verified():
    pin = _pin("trivy-scanner")
    report = scan_pinned_images(runner=_runner_for(_image_doc(pin["ref"], image_config=False)),
                                images=(pin,), now=NOW)
    assert report["status"] == "NOT_VERIFIED"
    assert "platform is missing" in report["images"][0]["error"]


@pytest.mark.parametrize(
    ("report_version", "probe_version", "expected_status"),
    [
        # Missing report version must fail closed even when the probe matches.
        (None, "0.76.0", "NOT_VERIFIED"),
        # Missing report version with a mismatched probe.
        (None, "0.76.1", "NOT_VERIFIED"),
        # Explicit correct report version keeps the existing classification.
        ("0.76.0", "0.76.0", "PASS"),
        # Explicit incorrect report version, even with a matching probe.
        ("0.75.0", "0.76.0", "NOT_VERIFIED"),
    ],
    ids=["missing-report+matching-probe", "missing-report+mismatched-probe",
         "correct-report", "incorrect-report"],
)
def test_pinned_scan_requires_scanner_version_from_the_report(report_version, probe_version, expected_status):
    pin = _pin("trivy-scanner")
    report = scan_pinned_images(
        runner=_runner_for(_image_doc(pin["ref"], version=report_version), probe_version=probe_version),
        images=(pin,),
        now=NOW,
    )
    row = report["images"][0]
    assert report["status"] == expected_status
    assert row["status"] == expected_status
    if report_version is None:
        assert "scanner version is missing" in row["error"]
        assert row["scanner_version"] == ""
    elif expected_status == "NOT_VERIFIED":
        assert report_version in row["error"]
    else:
        assert row["scanner_version"] == report_version


def test_probe_version_is_recorded_as_diagnostic_only():
    pin = _pin("trivy-scanner")
    report = scan_pinned_images(
        runner=_runner_for(_image_doc(pin["ref"], version=None), probe_version="0.76.0"),
        images=(pin,),
        now=NOW,
    )
    row = report["images"][0]
    assert report["status"] == "NOT_VERIFIED"
    assert row["scanner_version"] == ""


def test_probe_version_is_kept_on_verified_rows():
    pin = _pin("trivy-scanner")
    report = scan_pinned_images(runner=_runner_for(_image_doc(pin["ref"])), images=(pin,), now=NOW)
    assert report["images"][0]["probe_scanner_version"] == "0.76.0"
    assert report["images"][0]["scanner_version"] == "0.76.0"


def test_pinned_scan_on_correct_identity_still_classifies():
    pin = _pin("trivy-scanner")
    report = scan_pinned_images(runner=_runner_for(_image_doc(pin["ref"])), images=(pin,), now=NOW)
    assert report["status"] == "PASS"
    assert report["images"][0]["platform"] == "linux/amd64"


# --- 3. raw evidence is preserved with a hash -----------------------------------------


def test_write_raw_evidence_round_trips_and_strips_inline_raw(tmp_path: Path):
    pin = _pin("trivy-scanner")
    raw = _image_doc(pin["ref"])
    report = scan_pinned_images(runner=_runner_for(raw), images=(pin,), now=NOW, include_raw=True)
    assert report["images"][0]["raw_document"] == raw
    write_raw_evidence(report, tmp_path / "raw")
    row = report["images"][0]
    assert "raw_document" not in row
    evidence = row["raw_evidence"]
    payload = Path(evidence["path"]).read_bytes()
    # SHA-256 covers the exact bytes on disk.
    assert hashlib.sha256(payload).hexdigest() == evidence["sha256"]
    assert evidence["bytes"] == len(payload)
    # Files hold canonical JSON serialized from the parsed document, not Trivy stdout.
    assert payload == json.dumps(raw, indent=1, sort_keys=True).encode("utf-8")
    assert json.loads(payload) == raw


def test_write_raw_evidence_marks_missing_raw_explicitly(tmp_path: Path):
    report = {"images": [{"pin_name": "x", "status": "NOT_VERIFIED"}]}
    write_raw_evidence(report, tmp_path)
    assert report["images"][0]["raw_evidence"] is None


def test_cli_images_raw_dir_writes_hashed_evidence(tmp_path: Path, monkeypatch):
    from core.supply_chain import __main__ as main_mod

    pin = _pin("trivy-scanner")
    raw = _image_doc(pin["ref"])
    real_scan = main_mod.scan_pinned_images

    def fake_scan(**kwargs):
        return real_scan(runner=_runner_for(raw), now=NOW, **kwargs)

    monkeypatch.setattr(main_mod, "scan_pinned_images", fake_scan)
    output = tmp_path / "report.json"
    code = main_mod.main(["images", "--name", "trivy-scanner", "--raw-dir", str(tmp_path / "raw"),
                          "--output", str(output)])
    assert code == 0
    report = json.loads(output.read_text(encoding="utf-8"))
    evidence = report["images"][0]["raw_evidence"]
    assert json.loads(Path(evidence["path"]).read_text(encoding="utf-8")) == raw
    assert "raw_document" not in report["images"][0]


def test_ci_uploads_raw_trivy_evidence_for_both_gates():
    text = "\n".join(
        (ROOT / ".github/workflows" / name).read_text(encoding="utf-8")
        for name in ("ci.yml", "image-gates.yml")
    )
    assert "--raw-dir image-scan-raw/python" in text
    assert "--raw-dir image-scan-raw/upstream" in text
    assert "name: image-scan-raw" in text
    assert "path: image-scan-raw/" in text


# --- 4. unscored findings keep blocking ------------------------------------------------


@pytest.mark.parametrize(
    "vuln",
    [
        # Shapes copied from real 2026-10-24 reports: no VendorSeverity, no CVSS.
        {"VulnerabilityID": "CVE-2026-82560", "PkgName": "perl-base", "InstalledVersion": "5.36.0-7+deb12u4",
         "Severity": "UNKNOWN", "Status": "affected"},
        {"VulnerabilityID": "DLA-4845-1", "PkgName": "ca-certificates", "InstalledVersion": "20250419~deb12u1",
         "FixedVersion": "20250419~deb12u2", "Severity": "UNKNOWN", "Status": "fixed"},
        {"VulnerabilityID": "GO-2026-5932", "PkgName": "golang.org/x/crypto", "InstalledVersion": "v0.57.0",
         "Severity": "UNKNOWN", "Status": "affected"},
    ],
)
def test_unscored_findings_block_with_or_without_fix(vuln):
    ref = _pin("python-3.12-probe")["ref"]
    classified = classify_trivy_document(_image_doc(ref, vulns=[vuln]), image=ref, now=NOW, database=LIVE_DB)
    assert classified["status"] == "FAIL"
    assert classified["blocking_count"] == 1
    assert classified["unscored_count"] == 1


def test_unscored_finding_is_not_downgraded_by_vendor_severity_hints():
    ref = _pin("python-3.12-probe")["ref"]
    vuln = {"VulnerabilityID": "CVE-X", "PkgName": "p", "InstalledVersion": "1", "Severity": "UNKNOWN",
            "VendorSeverity": {"debian": 1}}
    classified = classify_trivy_document(_image_doc(ref, vulns=[vuln]), image=ref, now=NOW, database=LIVE_DB)
    assert classified["unscored_count"] == 1
    assert classified["status"] == "FAIL"


def test_production_pins_match_reviewed_values():
    refs = {item["name"]: item["ref"] for item in PINNED_IMAGES}
    assert refs["python-3.12-probe"].endswith("b658b05ce9c4eb97ec6fc19424818a1f31993659c2b505a532f470e83807815d")
    assert refs["shannon-worker"].endswith("4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e")
    assert refs["temporal"].endswith("9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4")
    assert refs["gitleaks"].endswith("0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46")
    assert refs["trivy-scanner"].endswith("2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222")
