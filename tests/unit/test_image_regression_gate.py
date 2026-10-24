"""Merge regression gate (policy Option B) against a reviewed image baseline.

The absolute gate is the release gate and must never be reported as PASS while
blocking findings exist; these tests pin that behaviour alongside the baseline
rules (exact digests, expiry, provenance, approval, new findings fail).
"""

from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.supply_chain import baseline as bl
from core.supply_chain.images import PINNED_IMAGES, scan_pinned_images, write_raw_evidence

ROOT = Path(__file__).resolve().parents[2]
NOW = datetime(2026, 10, 24, 18, 30, tzinfo=timezone.utc)
DB = "2026-10-24T13:07:23Z"
SCANNED = "2026-10-24T18:10:00Z"
PIN = next(item for item in PINNED_IMAGES if item["name"] == "trivy-scanner")
CLEAN_PIN = next(item for item in PINNED_IMAGES if item["name"] == "python-3.12-probe")


def _vuln(vid, pkg="libexpat", installed="2.8.5-r0", fixed="2.9.0-r0", severity="HIGH"):
    return {"VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": installed, "FixedVersion": fixed, "Severity": severity}


def _raw(ref, os_vulns=(), go_vulns=(), arch="amd64", created=SCANNED, version="0.76.0"):
    identity = ref.split("@", 1)
    return {
        "SchemaVersion": 2,
        "CreatedAt": created,
        "ArtifactName": ref,
        "Trivy": {"Version": version},
        "Metadata": {
            "RepoDigests": [f"{identity[0].rsplit(':', 1)[0]}@{identity[1]}"],
            "ImageConfig": {"architecture": arch, "os": "linux"},
        },
        "Results": [
            {"Target": f"{ref} (alpine 3.24.2)", "Class": "os-pkgs", "Type": "alpine", "Vulnerabilities": list(os_vulns)},
            {"Target": "usr/local/bin/trivy", "Class": "lang-pkgs", "Type": "gobinary", "Vulnerabilities": list(go_vulns)},
        ],
    }


BASE_OS = [_vuln("CVE-2026-0001"), _vuln("CVE-2026-0002", pkg="brotli-libs", installed="1.2.0-r1", fixed="1.2.1-r0")]
BASE_GO = [_vuln("GO-2026-5932", pkg="golang.org/x/crypto", installed="v0.57.0", fixed="", severity="UNKNOWN")]
LOW_ROW = _vuln("CVE-2026-0003", severity="LOW")


def _scan(raw_by_ref, *, db=DB, probe="0.76.0", images=(PIN,)):
    class Done:
        def __init__(self, stdout="", returncode=0):
            self.stdout, self.returncode, self.stderr = stdout, returncode, ""

    def runner(args, timeout=600):
        if "--download-db-only" in args:
            return Done()
        if "version" in args:
            return Done(json.dumps({"Version": probe, "VulnerabilityDB": {"UpdatedAt": db}}))
        return Done(json.dumps(raw_by_ref[args[-1]]))

    return scan_pinned_images(runner=runner, images=images, now=NOW, include_raw=True)


def _approval(**overrides):
    approval = {
        "approved_by": "eneelkant",
        "approval_ref": "https://github.com/eneelkant/pen-testing/pull/28",
        "approved_at": "2026-10-24T18:20:00+00:00",
        "expires_at": "2026-11-20T18:20:00+00:00",
        "reviewed_commit_sha": "b" * 40,
    }
    approval.update(overrides)
    return approval


def _entry(raw, pin=PIN, **overrides):
    report = _scan({pin["ref"]: raw}, images=(pin,))
    row = report["images"][0]
    entry = {
        "pin_name": pin["name"],
        "ref": pin["ref"],
        "platform": "linux/amd64",
        "platform_digest": pin["platform_digest"],
        "scanner_version": "0.76.0",
        "db_updated_at": DB,
        "scanned_at": SCANNED,
        "source": {
            "repository": "eneelkant/pen-testing",
            "ci_run_id": 40119376385,
            "commit": "f7cbcc0b8dd219cd9dde15a0e3653bb00663c745",
            "artifact": "image-scan-raw",
            "raw_path": "upstream/03-trivy-scanner.trivy.json",
            "raw_sha256": "a" * 64,
        },
        "approval": _approval(),
        "findings": bl.blocking_findings(row["raw_document"], row),
    }
    entry.update(overrides)
    return entry


def _doc(*entries):
    return {"schema_version": 1, "description": "test baseline", "entries": list(entries)}


BASE_RAW = _raw(PIN["ref"], BASE_OS + [LOW_ROW], BASE_GO)


def _evaluate(raw=BASE_RAW, document=None, **scan_kwargs):
    document = _doc(_entry(BASE_RAW)) if document is None else document
    report = _scan({PIN["ref"]: raw}, **scan_kwargs)
    return report, bl.evaluate_regression_gate(report, document, now=NOW, pinned=(PIN,))


# ------------------------------------------------------------------ core outcomes


def test_clean_image_passes_both_gates_without_entry():
    report = _scan({CLEAN_PIN["ref"]: _raw(CLEAN_PIN["ref"], [LOW_ROW])}, images=(CLEAN_PIN,))
    result = bl.evaluate_regression_gate(report, _doc(), now=NOW, pinned=(CLEAN_PIN,))
    assert report["status"] == "PASS"
    assert result["absolute"]["status"] == "PASS"
    assert result["regression_gate"]["status"] == "PASS"


def test_inherited_findings_pass_regression_while_absolute_stays_fail():
    report, result = _evaluate()
    assert report["status"] == "FAIL" and report["blocking_count"] == 3
    assert result["absolute"]["status"] == "FAIL"
    assert result["absolute"]["blocking_count"] == 3
    assert result["regression_gate"]["status"] == "PASS"
    image = result["images"][0]
    assert image["absolute_status"] == "FAIL"
    assert image["reason"].startswith("INHERITED_ONLY")
    assert len(image["inherited_blocking"]) == 3
    assert image["baseline_expires_at"] == _approval()["expires_at"]
    assert {item["remediation_status"] for item in image["inherited_blocking"]} == {
        "awaiting-upstream-release", "no-fixed-version-published"}


def test_new_blocking_finding_fails():
    raw = _raw(PIN["ref"], BASE_OS + [_vuln("CVE-2026-9999", pkg="musl", installed="1.2.6-r2", fixed="1.2.6-r3")], BASE_GO)
    _, result = _evaluate(raw)
    assert result["regression_gate"]["status"] == "FAIL"
    assert "NEW_BLOCKING" in result["images"][0]["reason"]
    assert [f["key"]["vulnerability_id"] for f in result["images"][0]["new_blocking"]] == ["CVE-2026-9999"]


def test_database_update_adding_finding_to_unchanged_image_fails():
    newer_db = "2026-10-24T19:07:23Z"
    raw = _raw(PIN["ref"], BASE_OS + [_vuln("CVE-2026-4242", severity="UNKNOWN", fixed="")], BASE_GO)
    _, result = _evaluate(raw, db=newer_db)
    assert result["regression_gate"]["status"] == "FAIL"
    assert result["images"][0]["new_blocking"][0]["gate_reason"] == "unscored"


def test_existing_finding_whose_installed_version_changes_is_new():
    moved = [_vuln("CVE-2026-0001", installed="2.8.6-r0")] + BASE_OS[1:]
    _, result = _evaluate(_raw(PIN["ref"], moved, BASE_GO))
    assert result["regression_gate"]["status"] == "FAIL"


def test_changed_severity_or_fix_metadata_on_existing_finding_requires_review():
    raw = copy.deepcopy(BASE_RAW)
    raw["Results"][0]["Vulnerabilities"][0]["Severity"] = "CRITICAL"
    _, result = _evaluate(raw)
    assert result["regression_gate"]["status"] == "FAIL"
    assert result["regression_gate"]["changed_blocking_count"] == 1
    assert "CHANGED_BLOCKING" in result["images"][0]["reason"]


def test_removed_inherited_finding_is_reported_resolved():
    _, result = _evaluate(_raw(PIN["ref"], BASE_OS[1:], BASE_GO))
    assert result["regression_gate"]["status"] == "PASS"
    resolved = result["images"][0]["resolved_baseline_findings"]
    assert [f["key"]["vulnerability_id"] for f in resolved] == ["CVE-2026-0001"]
    assert any("tighten the baseline" in w for w in result["regression_gate"]["warnings"])


def test_absolute_pass_with_leftover_entry_recommends_removal():
    _, result = _evaluate(_raw(PIN["ref"], [LOW_ROW]))
    assert result["regression_gate"]["status"] == "PASS"
    assert result["absolute"]["status"] == "PASS"
    assert any("can be removed" in w for w in result["regression_gate"]["warnings"])


# ---------------------------------------------------------- identity changes


def test_changed_index_digest_does_not_inherit_old_entry():
    old = _entry(BASE_RAW, ref=PIN["ref"].split("@")[0] + "@sha256:" + "1" * 64)
    _, result = _evaluate(document=_doc(old))
    assert result["regression_gate"]["status"] == "FAIL"
    assert result["images"][0]["reason"].startswith("UNRECOGNISED_DIGEST")
    assert any("does not match a current pin" in w for w in result["regression_gate"]["warnings"])


def test_failing_image_without_entry_fails():
    _, result = _evaluate(document=_doc())
    assert result["regression_gate"]["status"] == "FAIL"
    assert "UNRECOGNISED_DIGEST" in result["images"][0]["reason"]
    assert len(result["images"][0]["new_blocking"]) == 3


def test_platform_digest_mismatch_fails():
    _, result = _evaluate(document=_doc(_entry(BASE_RAW, platform_digest="sha256:" + "2" * 64)))
    assert result["regression_gate"]["status"] == "FAIL"
    assert "PLATFORM_DIGEST_MISMATCH" in result["images"][0]["reason"]


def test_platform_mismatch_in_scan_is_not_verified():
    _, result = _evaluate(_raw(PIN["ref"], BASE_OS, BASE_GO, arch="arm64"))
    assert result["regression_gate"]["status"] == "NOT_VERIFIED"


def test_scanner_version_change_requires_re_review():
    _, result = _evaluate(document=_doc(_entry(BASE_RAW, scanner_version="0.75.0")))
    assert result["regression_gate"]["status"] == "FAIL"
    assert "SCANNER_CHANGED" in result["images"][0]["reason"]


def test_not_verified_scan_fails_closed():
    _, result = _evaluate(_raw(PIN["ref"], BASE_OS, BASE_GO, version=None))
    assert result["regression_gate"]["status"] == "NOT_VERIFIED"
    assert result["images"][0]["regression_status"] == "NOT_VERIFIED"


def test_stale_scan_database_fails_closed():
    _, result = _evaluate(db="2026-09-01T00:00:00Z")
    assert result["regression_gate"]["status"] == "NOT_VERIFIED"


def test_misaligned_raw_evidence_fails_closed():
    report = _scan({PIN["ref"]: BASE_RAW})
    report["images"][0]["raw_document"] = _raw(PIN["ref"], BASE_OS[:1], BASE_GO)
    result = bl.evaluate_regression_gate(report, _doc(_entry(BASE_RAW)), now=NOW, pinned=(PIN,))
    assert result["regression_gate"]["status"] == "NOT_VERIFIED"


def test_entry_for_image_no_longer_pinned_is_flagged_not_fatal():
    other = _entry(BASE_RAW, pin_name="retired-image", ref="example/retired:1@sha256:" + "3" * 64)
    _, result = _evaluate(document=_doc(_entry(BASE_RAW), other))
    assert result["regression_gate"]["status"] == "PASS"
    assert any("retired-image" in w for w in result["regression_gate"]["warnings"])


# ------------------------------------------------------------ baseline validity


def _errors_for(entry=None, document=None):
    document = document if document is not None else _doc(entry)
    return bl.validate_baseline(document, now=NOW)


def test_valid_entry_has_no_errors():
    assert _errors_for(_entry(BASE_RAW)) == []


def test_expired_baseline_fails_gate():
    entry = _entry(BASE_RAW, approval=_approval(approved_at="2026-10-24T18:12:00+00:00", expires_at="2026-10-24T18:25:00+00:00"))
    assert any("expired" in e for e in _errors_for(entry))
    _, result = _evaluate(document=_doc(entry))
    assert result["regression_gate"]["status"] == "FAIL"


def test_expiry_longer_than_31_days_is_rejected():
    entry = _entry(BASE_RAW, approval=_approval(expires_at="2026-11-25T18:21:00+00:00"))
    assert any("31-day maximum" in e for e in _errors_for(entry))


@pytest.mark.parametrize("approval, fragment", [
    (None, "candidate entries are not authoritative"),
    ({"approved_by": "", "approval_ref": "https://github.com/eneelkant/pen-testing/pull/28",
      "approved_at": "2026-10-24T18:20:00+00:00", "expires_at": "2026-11-20T18:20:00+00:00"}, "approved_by"),
    ({"approved_by": "eneelkant", "approval_ref": "approved in chat",
      "approved_at": "2026-10-24T18:20:00+00:00", "expires_at": "2026-11-20T18:20:00+00:00"}, "approval_ref"),
    ({"approved_by": "eneelkant", "approval_ref": "https://github.com/eneelkant/pen-testing/pull/28",
      "expires_at": "2026-11-20T18:20:00+00:00"}, "missing field"),
])
def test_missing_or_invalid_approval_is_rejected(approval, fragment):
    assert any(fragment in e for e in _errors_for(_entry(BASE_RAW, approval=approval)))


def test_approval_on_stale_evidence_or_before_scan_is_rejected():
    stale = _approval(approved_at="2026-11-02T00:00:00+00:00", expires_at="2026-11-20T00:00:00+00:00")
    assert any("stale scan evidence" in e for e in bl.validate_baseline(
        _doc(_entry(BASE_RAW, approval=stale)), now=datetime(2026, 11, 3, tzinfo=timezone.utc)))
    early = _approval(approved_at="2026-10-24T17:00:00+00:00")
    assert any("precedes the scan" in e for e in _errors_for(_entry(BASE_RAW, approval=early)))


@pytest.mark.parametrize("value", ["", "A" * 64, "abc", None, "g" * 64])
def test_missing_or_invalid_raw_sha256_is_rejected(value):
    entry = _entry(BASE_RAW)
    entry["source"]["raw_sha256"] = value
    assert any("raw_sha256" in e for e in _errors_for(entry))


def test_missing_provenance_fields_are_rejected():
    entry = _entry(BASE_RAW)
    del entry["source"]["ci_run_id"]
    assert any("missing field" in e for e in _errors_for(entry))
    entry = _entry(BASE_RAW)
    entry["source"]["commit"] = "f7cbcc0"
    assert any("40-hex" in e for e in _errors_for(entry))


@pytest.mark.parametrize("field, value, fragment", [
    ("db_updated_at", None, "db_updated_at"),
    ("db_updated_at", "2026-10-01T00:00:00Z", "stale vulnerability database"),
    ("db_updated_at", "2026-10-25T00:00:00Z", "after scanned_at"),
    ("scanned_at", "not-a-time", "scanned_at"),
    ("ref", "aquasec/trivy:0.76.0", "immutable reference"),
    ("platform_digest", "sha256:XYZ", "platform_digest"),
    ("platform", "linux/arm64", "platform"),
])
def test_invalid_entry_fields_are_rejected(field, value, fragment):
    assert any(fragment in e for e in _errors_for(_entry(BASE_RAW, **{field: value})))


def test_unknown_or_missing_fields_and_schema_are_rejected():
    entry = _entry(BASE_RAW)
    entry["waiver"] = True
    assert any("unsupported field" in e for e in _errors_for(entry))
    document = _doc(_entry(BASE_RAW))
    document["schema_version"] = 2
    assert any("schema_version" in e for e in _errors_for(document=document))
    assert _errors_for(document={"entries": []})
    assert _errors_for(document=[])


def test_duplicate_finding_identities_and_entries_are_rejected():
    entry = _entry(BASE_RAW)
    entry["findings"].append(copy.deepcopy(entry["findings"][0]))
    assert any("duplicate finding identity" in e for e in _errors_for(entry))
    assert any("duplicate entry" in e for e in _errors_for(document=_doc(_entry(BASE_RAW), _entry(BASE_RAW))))


def test_inconsistent_finding_classification_is_rejected():
    entry = _entry(BASE_RAW)
    entry["findings"][0]["gate_reason"] = "fixed-high-critical"
    entry["findings"][0]["severity"] = "LOW"
    assert any("fixed-high-critical requires" in e for e in _errors_for(entry))
    entry = _entry(BASE_RAW)
    entry["findings"][0]["remediation_status"] = "accepted"
    assert any("remediation_status" in e for e in _errors_for(entry))


def test_empty_findings_entry_is_rejected():
    assert any("non-empty list" in e for e in _errors_for(_entry(BASE_RAW, findings=[])))


def test_malformed_or_missing_baseline_file_fails_gate(tmp_path: Path):
    missing, errors = bl.load_baseline(tmp_path / "nope.json")
    assert missing is None and errors
    (tmp_path / "bad.json").write_text("{not json", encoding="utf-8")
    bad, errors_bad = bl.load_baseline(tmp_path / "bad.json")
    assert bad is None and errors_bad
    report = _scan({PIN["ref"]: BASE_RAW})
    result = bl.evaluate_regression_gate(report, None, now=NOW, pinned=(PIN,), baseline_errors=errors_bad)
    assert result["regression_gate"]["status"] == "FAIL"


def test_invalid_baseline_fails_even_when_images_are_clean():
    report = _scan({CLEAN_PIN["ref"]: _raw(CLEAN_PIN["ref"], [LOW_ROW])}, images=(CLEAN_PIN,))
    result = bl.evaluate_regression_gate(report, {"schema_version": 1}, now=NOW, pinned=(CLEAN_PIN,))
    assert result["regression_gate"]["status"] == "FAIL"


# ------------------------------------------------------------------ reporting


def test_report_keeps_every_inherited_finding_and_never_claims_clean():
    _, result = _evaluate()
    lines = "\n".join(bl.summary_lines(result))
    assert "regression_gate: PASS" in lines
    assert "absolute_image_gate: FAIL blocking=3" in lines
    assert "absolute_image_gate: PASS" not in lines
    for banned in ("clean", "vulnerability-free", "no vulnerabilities"):
        assert banned not in lines.lower().replace("free of vulnerabilities", "")
    assert "does not mean the images are free of vulnerabilities" in lines
    inherited = {f["key"]["vulnerability_id"] for f in result["images"][0]["inherited_blocking"]}
    assert inherited == {"CVE-2026-0001", "CVE-2026-0002", "GO-2026-5932"}


def test_cli_images_baseline_exit_codes_and_output(tmp_path: Path, monkeypatch):
    from core.supply_chain import __main__ as main_mod

    real_scan = main_mod.scan_pinned_images
    monkeypatch.setattr(main_mod, "scan_pinned_images",
                        lambda **kw: real_scan(runner=_scan_runner({PIN["ref"]: BASE_RAW}), now=NOW, **kw))
    baseline_path = tmp_path / "baseline.json"
    entry = _entry(BASE_RAW, approval=_approval(approved_at=(datetime.now(timezone.utc) - timedelta(minutes=1)).isoformat(),
                                                expires_at=(datetime.now(timezone.utc) + timedelta(days=30)).isoformat()))
    entry["scanned_at"] = (datetime.now(timezone.utc) - timedelta(minutes=2)).isoformat()
    entry["db_updated_at"] = (datetime.now(timezone.utc) - timedelta(hours=1)).isoformat()
    baseline_path.write_text(json.dumps(_doc(entry)), encoding="utf-8")
    out = tmp_path / "out.json"
    code = main_mod.main(["images", "--name", "trivy-scanner", "--baseline", str(baseline_path),
                          "--raw-dir", str(tmp_path / "raw"), "--output", str(out)])
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert code == 0, payload["regression_gate"]
    assert payload["regression_gate"]["status"] == "PASS"
    assert payload["absolute"]["status"] == "FAIL"
    assert payload["absolute_report"]["status"] == "FAIL"
    assert "raw_document" not in payload["absolute_report"]["images"][0]
    baseline_path.write_text(json.dumps(_doc()), encoding="utf-8")
    assert main_mod.main(["images", "--name", "trivy-scanner", "--baseline", str(baseline_path)]) == 1


def _scan_runner(raw_by_ref):
    class Done:
        def __init__(self, stdout="", returncode=0):
            self.stdout, self.returncode, self.stderr = stdout, returncode, ""

    def runner(args, timeout=600):
        if "--download-db-only" in args:
            return Done()
        if "version" in args:
            return Done(json.dumps({"Version": "0.76.0", "VulnerabilityDB": {"UpdatedAt": DB}}))
        return Done(json.dumps(raw_by_ref[args[-1]]))

    return runner


# --------------------------------------------------------- candidate + approval


def _artifact(tmp_path: Path, raw=BASE_RAW, db=DB):
    report = scan_pinned_images(runner=_scan_runner_db({PIN["ref"]: raw}, db), images=(PIN,), now=NOW, include_raw=True)
    write_raw_evidence(report, tmp_path / "raw")
    return report


def _scan_runner_db(raw_by_ref, db):
    class Done:
        def __init__(self, stdout="", returncode=0):
            self.stdout, self.returncode, self.stderr = stdout, returncode, ""

    def runner(args, timeout=600):
        if "--download-db-only" in args:
            return Done()
        if "version" in args:
            return Done(json.dumps({"Version": "0.76.0", "VulnerabilityDB": {"UpdatedAt": db}}))
        return Done(json.dumps(raw_by_ref[args[-1]]))

    return runner


def _candidates(summary, tmp_path):
    return bl.build_candidate_entries(summary, tmp_path / "raw", repository="eneelkant/pen-testing",
                                      ci_run_id=1, commit="a" * 40, artifact="image-scan-raw", raw_prefix="upstream/")


def test_candidate_entries_come_only_from_verified_artifacts(tmp_path: Path):
    entries = _candidates(_artifact(tmp_path), tmp_path)
    assert len(entries) == 1
    entry = entries[0]
    assert entry["approval"] is None
    assert len(entry["findings"]) == 3
    assert entry["platform_digest"] == PIN["platform_digest"]
    assert entry["source"]["raw_sha256"] == hashlib.sha256(
        (tmp_path / "raw" / Path(entry["source"]["raw_path"]).name).read_bytes()).hexdigest()
    errors = bl.validate_baseline(_doc(entry), now=NOW)
    assert errors and all("not authoritative" in e for e in errors)


def test_candidate_rejects_tampered_raw_file(tmp_path: Path):
    summary = _artifact(tmp_path)
    raw_file = Path(summary["images"][0]["raw_evidence"]["path"])
    raw_file.write_text(raw_file.read_text(encoding="utf-8").replace("CVE-2026-0001", "CVE-2026-0009"), encoding="utf-8")
    with pytest.raises(bl.BaselineEvidenceError, match="sha256"):
        _candidates(summary, tmp_path)


def test_candidate_rejects_not_verified_or_stale_evidence(tmp_path: Path):
    summary = _artifact(tmp_path)
    with pytest.raises(bl.BaselineEvidenceError):
        _candidates({**summary, "status": "NOT_VERIFIED"}, tmp_path)
    stale = copy.deepcopy(summary)
    stale["database"]["updated_at"] = "2026-10-01T00:00:00Z"
    with pytest.raises(bl.BaselineEvidenceError, match="stale"):
        _candidates(stale, tmp_path)
    tampered = copy.deepcopy(summary)
    tampered["images"][0]["blocking_count"] = 1
    with pytest.raises(bl.BaselineEvidenceError, match="disagrees"):
        _candidates(tampered, tmp_path)


def test_clean_image_produces_no_candidate_entry(tmp_path: Path):
    assert _candidates(_artifact(tmp_path, raw=_raw(PIN["ref"], [LOW_ROW])), tmp_path) == []


def test_approve_entries_enforces_limits():
    document = _doc(_entry(BASE_RAW, approval=None))
    with pytest.raises(ValueError):
        bl.approve_entries(document, approved_by="eneelkant", approval_ref="https://github.com/eneelkant/pen-testing/pull/28",
                           expires_in_days=32, reviewed_commit_sha="b" * 40, now=NOW)
    with pytest.raises(ValueError):
        bl.approve_entries(document, approved_by="eneelkant", approval_ref="ok", expires_in_days=30, reviewed_commit_sha="b" * 40, now=NOW)
    assert bl.approve_entries(document, approved_by="eneelkant",
                              approval_ref="https://github.com/eneelkant/pen-testing/pull/28", expires_in_days=31, reviewed_commit_sha="b" * 40, now=NOW) == 1
    assert bl.validate_baseline(document, now=NOW + timedelta(minutes=1)) == []
    assert bl.validate_baseline(document, now=NOW + timedelta(days=31)) != []


# ---------------------------------------------------------------------- guard


def test_guard_rejects_pin_and_baseline_change_together():
    base = {"temporal": "t@sha256:" + "1" * 64}
    head = {"temporal": "t@sha256:" + "2" * 64}
    before = _doc(_entry(BASE_RAW, pin_name="temporal", ref=base["temporal"]))
    after = _doc(_entry(BASE_RAW, pin_name="temporal", ref=head["temporal"]))
    assert bl.guard_pin_and_baseline(base, head, before, after)
    assert bl.guard_pin_and_baseline(base, head, before, before) == []
    assert bl.guard_pin_and_baseline(base, base, before, after) == []
    assert bl.guard_pin_and_baseline(base, head, None, None) == []


def test_guard_against_git_ref_detects_combined_change(tmp_path: Path):
    def git(*args):
        subprocess.run(["git", *args], cwd=tmp_path, check=True, capture_output=True)

    images = tmp_path / "core/supply_chain/images.py"
    images.parent.mkdir(parents=True)
    images.write_text('PINNED_IMAGES = ({"name": "temporal", "ref": "t@sha256:' + "1" * 64 + '"},)\n', encoding="utf-8")
    git("init", "-q"); git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "--allow-empty", "-m", "root")
    git("add", "."); git("-c", "user.email=t@t", "-c", "user.name=t", "commit", "-q", "-m", "base")
    images.write_text(images.read_text(encoding="utf-8").replace("1" * 64, "2" * 64), encoding="utf-8")
    (tmp_path / "core/supply_chain/image_baseline.json").write_text(
        json.dumps(_doc(_entry(BASE_RAW, pin_name="temporal", ref="t@sha256:" + "2" * 64))), encoding="utf-8")
    result = bl.guard_against_git_ref("HEAD", root=tmp_path)
    assert result["ok"] is False and "temporal" in result["errors"][0]


def test_pinned_refs_parse_from_real_images_module():
    refs = bl.pinned_refs_from_source((ROOT / "core/supply_chain/images.py").read_text(encoding="utf-8"))
    assert refs == {item["name"]: item["ref"] for item in PINNED_IMAGES}


# ------------------------------------------------------- repository wiring


def test_committed_baseline_matches_current_pins_and_evidence_rules():
    document = json.loads((ROOT / "core/supply_chain/image_baseline.json").read_text(encoding="utf-8"))
    pins = {item["name"]: item for item in PINNED_IMAGES}
    for entry in document["entries"]:
        pin = pins[entry["pin_name"]]
        assert entry["ref"] == pin["ref"] and entry["platform_digest"] == pin["platform_digest"]
    from core.supply_chain.images import _parse_time

    # Validate as of just after the latest approval (or scan), so the test is not a time bomb.
    reference_now = max(
        _parse_time((entry["approval"] or {}).get("approved_at") or entry["scanned_at"])
        for entry in document["entries"]
    ) + timedelta(minutes=1)
    errors = bl.validate_baseline(document, now=reference_now)
    # Only acceptable problem: entries still awaiting owner approval.
    assert all("not authoritative until an owner approves" in e for e in errors), errors
    assert "python-3.12-probe" not in {e["pin_name"] for e in document["entries"]}


def test_codeowners_protects_baseline_and_gate():
    text = (ROOT / ".github/CODEOWNERS").read_text(encoding="utf-8")
    assert "/core/supply_chain/image_baseline.json @eneelkant" in text
    assert "/core/supply_chain/baseline.py @eneelkant" in text
    assert "/.github/ @eneelkant" in text


def test_ci_runs_regression_gate_as_separate_fail_closed_job():
    text = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    assert "name: Pinned image regression gate" in text
    assert "--baseline core/supply_chain/image_baseline.json" in text
    assert "baseline guard --base-ref" in text
    assert "continue-on-error" not in text
    assert "name: Pinned image vulnerability scans" in text  # absolute gate stays visible


def test_release_requires_absolute_image_gate():
    text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "needs: [absolute-image-gate]" in text
    assert "python -m core.supply_chain images --raw-dir" in text
    assert "--baseline" not in text
    assert "continue-on-error" not in text
