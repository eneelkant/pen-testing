"""Self-built image candidate pipeline: evidence verifier, build script, workflow.

Fixtures mirror real `trivy image --format json` (Trivy 0.76.0) documents as used
in the existing image-gate tests: ArtifactName, Metadata.ImageID/RepoDigests/
ImageConfig, Trivy.Version, CreatedAt and Results[].Vulnerabilities[]. The
vulnerability DB metadata comes from a separate `trivy version --format json`
probe, exactly as the build script captures it.
"""

from __future__ import annotations

import importlib.util
import json
import re
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from core.supply_chain.images import PINNED_IMAGES

ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("verify_image_candidate", ROOT / "scripts/verify_image_candidate.py")
vic = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(vic)

NOW = datetime(2026, 10, 26, 12, 0, tzinfo=timezone.utc)
DB_UPDATED = "2026-10-26T07:15:18.945937093Z"
SCANNED = "2026-10-26T11:52:30Z"
LOCAL_REF = "local/trivy-scanner-candidate:82a05e384478"
LOCAL_ID = "sha256:" + "4" * 64
DIGEST = "sha256:" + "d" * 64
PUBLISHED_REF = f"ghcr.io/eneelkant/pen-testing-trivy-candidate@{DIGEST}"
REQUIREMENTS = ROOT / "docker/candidates/requirements.json"


def _vuln(vid, pkg, installed, fixed, severity):
    return {"VulnerabilityID": vid, "PkgName": pkg, "InstalledVersion": installed, "FixedVersion": fixed,
            "Severity": severity, "Status": "fixed" if fixed else "affected", "DataSource": {"ID": "alpine"}}


CLEAN_ROWS = [_vuln("CVE-2026-107929", "libcurl", "8.23.0-r0", "", "LOW")]
FIXED_HIGH = _vuln("CVE-2026-92392", "libcurl", "8.22.0-r0", "8.23.0-r0", "HIGH")
UNSCORED = _vuln("GO-2026-5932", "golang.org/x/crypto", "v0.57.0", "", "UNKNOWN")


def _report(ref=LOCAL_REF, rows=CLEAN_ROWS, *, image_id=LOCAL_ID, repo_digests=None, arch="amd64",
            version="0.76.0", created=SCANNED):
    document = {
        "SchemaVersion": 2,
        "CreatedAt": created,
        "ArtifactName": ref,
        "ArtifactType": "container_image",
        "Metadata": {
            "OS": {"Family": "alpine", "Name": "3.24.2"},
            "ImageID": image_id,
            "RepoDigests": repo_digests or [],
            "ImageConfig": {"architecture": arch, "os": "linux"},
        },
        "Results": [{"Target": f"{ref} (alpine 3.24.2)", "Class": "os-pkgs", "Type": "alpine",
                     "Vulnerabilities": list(rows)}],
    }
    if version is not None:
        document["Trivy"] = {"Version": version}
    if created is None:
        del document["CreatedAt"]
    return document


def _published(rows=CLEAN_ROWS, **kw):
    return _report(PUBLISHED_REF, rows, repo_digests=[f"ghcr.io/eneelkant/pen-testing-trivy-candidate@{DIGEST}"], **kw)


def _probe(updated=DB_UPDATED, version="0.76.0"):
    return {"Version": version, "VulnerabilityDB": {"Version": 2, "UpdatedAt": updated,
                                                     "NextUpdate": "2026-10-27T07:15:18Z", "DownloadedAt": "2026-10-26T11:52:04Z"}}


def _write(tmp_path: Path, name: str, payload) -> Path:
    path = tmp_path / name
    path.write_text(payload if isinstance(payload, str) else json.dumps(payload), encoding="utf-8")
    return path


def _run(tmp_path, document, *, ref=LOCAL_REF, image_id=LOCAL_ID, probe=None, now=NOW, exit_code=0):
    report = _write(tmp_path, "scan.json", document)
    probe_path = _write(tmp_path, "probe.json", probe if probe is not None else _probe())
    return vic.verify(report, ref, db_probe=probe_path, image_id=image_id, now=now, exit_code=exit_code)


def _packages(tmp_path, candidate="trivy", state="satisfied", drop=None, override=None):
    spec = json.loads(REQUIREMENTS.read_text(encoding="utf-8"))["candidates"][candidate]["packages"]
    lines = []
    for name, item in sorted(spec.items()):
        if name == drop:
            continue
        installed = "-" if state == "missing" else item["minimum"]
        lines.append("\t".join([name, item["minimum"], installed, state]))
    if override:
        lines.append(override)
    return _write(tmp_path, "packages.tsv", "\n".join(lines) + "\n")


# --------------------------------------------------------------------- valid paths


def test_valid_local_report_passes_with_identity_bound_to_image_id(tmp_path):
    result = _run(tmp_path, _report())
    assert result["status"] == "PASS"
    assert result["identity"] == "local-image-id" and result["expected_image_id"] == LOCAL_ID
    assert result["blocking_count"] == 0 and result["unscored_count"] == 0
    assert result["database_updated_at"] == DB_UPDATED
    assert re.fullmatch(r"[0-9a-f]{64}", result["raw_report_sha256"])


def test_valid_published_report_uses_canonical_candidate_policy(tmp_path):
    result = _run(tmp_path, _published(), ref=PUBLISHED_REF, image_id="")
    assert result["status"] == "PASS"
    assert result["identity"] == "published-digest"
    assert DIGEST in result["reported_manifest_digests"]


def test_local_and_published_paths_agree_on_the_same_findings(tmp_path):
    for rows in (CLEAN_ROWS, CLEAN_ROWS + [FIXED_HIGH], [UNSCORED]):
        local = _run(tmp_path, _report(rows=rows))
        published = _run(tmp_path, _published(rows=rows), ref=PUBLISHED_REF, image_id="")
        assert (local["status"], local["blocking_count"], local["unscored_count"]) == \
               (published["status"], published["blocking_count"], published["unscored_count"])


def test_real_findings_are_reported_and_block(tmp_path):
    result = _run(tmp_path, _report(rows=CLEAN_ROWS + [FIXED_HIGH, UNSCORED]))
    assert result["status"] == "FAIL"
    assert result["blocking_count"] == 2 and result["unscored_count"] == 1
    ids = {row["id"] for row in result["blocking_findings"]}
    assert ids == {"CVE-2026-92392", "GO-2026-5932"}


def test_unscored_finding_alone_blocks(tmp_path):
    result = _run(tmp_path, _report(rows=[UNSCORED]))
    assert result["status"] == "FAIL" and result["unscored_count"] == 1


# ------------------------------------------------------------- not verified paths


def _assert_not_verified(result, fragment):
    assert result["status"] == "NOT_VERIFIED", result
    assert result["acceptable"] is False
    assert result["blocking_count"] is None and result["unscored_count"] is None
    assert fragment in result["error"], result["error"]


def test_missing_report_file(tmp_path):
    probe = _write(tmp_path, "probe.json", _probe())
    _assert_not_verified(vic.verify(tmp_path / "nope.json", LOCAL_REF, db_probe=probe, image_id=LOCAL_ID, now=NOW),
                         "not found")


@pytest.mark.parametrize("payload, fragment", [
    ("{not json", "not valid JSON"),
    ("[]", "not a JSON object"),
    (json.dumps({"status": "PASS", "blocking_count": 0}), "no raw Results"),
    (json.dumps({**_report(), "Results": "oops"}), "Results is missing or not a list"),
    (json.dumps({**_report(), "Results": [{"Vulnerabilities": [{"Severity": "HIGH"}]}]}), "VulnerabilityID"),
])
def test_malformed_or_summary_only_reports(tmp_path, payload, fragment):
    _assert_not_verified(_run(tmp_path, payload), fragment)


def test_wrong_published_digest(tmp_path):
    other = _report(PUBLISHED_REF, repo_digests=["ghcr.io/eneelkant/pen-testing-trivy-candidate@sha256:" + "e" * 64])
    other["ArtifactName"] = "ghcr.io/eneelkant/pen-testing-trivy-candidate:candidate"
    _assert_not_verified(_run(tmp_path, other, ref=PUBLISHED_REF, image_id=""), "exact resolved digest")


def test_local_candidate_requires_image_id(tmp_path):
    _assert_not_verified(_run(tmp_path, _report(), image_id=""), "--image-id")


def test_local_candidate_wrong_image_id(tmp_path):
    _assert_not_verified(_run(tmp_path, _report(image_id="sha256:" + "5" * 64)), "Metadata.ImageID")


def test_local_candidate_wrong_artifact_name(tmp_path):
    document = _report()
    document["ArtifactName"] = "local/trivy-scanner-candidate:other"
    _assert_not_verified(_run(tmp_path, document), "ArtifactName")


@pytest.mark.parametrize("published", [False, True])
def test_wrong_platform(tmp_path, published):
    if published:
        result = _run(tmp_path, _published(arch="arm64"), ref=PUBLISHED_REF, image_id="")
    else:
        result = _run(tmp_path, _report(arch="arm64"))
    _assert_not_verified(result, "platform")


@pytest.mark.parametrize("report_version, probe_version, fragment", [
    ("0.75.0", "0.76.0", "disagrees"),
    ("0.76.0", "0.75.0", "is not the required"),
    (None, "0.76.0", "scanner"),
])
def test_scanner_version_mismatch(tmp_path, report_version, probe_version, fragment):
    result = _run(tmp_path, _report(version=report_version), probe=_probe(version=probe_version))
    _assert_not_verified(result, fragment)


@pytest.mark.parametrize("created, fragment", [
    # A 25-day-old scan cannot have used the fresh probed DB: rejected as inconsistent evidence.
    ("2026-10-01T00:00:00Z", "newer than the scan"),
    ("2026-10-26T13:00:00Z", "future"),
    (None, "CreatedAt"),
])
def test_report_timestamps(tmp_path, created, fragment):
    _assert_not_verified(_run(tmp_path, _report(created=created)), fragment)


@pytest.mark.parametrize("probe, fragment", [
    ("{bad", "not valid JSON"),
    ({"Version": "0.76.0"}, "UpdatedAt is missing"),
    ({"VulnerabilityDB": {"UpdatedAt": DB_UPDATED}}, "no scanner Version"),
    (_probe(updated="2026-10-01T00:00:00Z"), "stale"),
    (_probe(updated="2026-10-27T00:00:00Z"), "future"),
    (_probe(updated="2026-10-26T11:59:00Z"), "newer than the scan"),
])
def test_database_probe_failures(tmp_path, probe, fragment):
    _assert_not_verified(_run(tmp_path, _report(), probe=probe), fragment)


def test_missing_database_probe(tmp_path):
    report = _write(tmp_path, "scan.json", _report())
    _assert_not_verified(vic.verify(report, LOCAL_REF, db_probe=None, image_id=LOCAL_ID, now=NOW), "probe")
    _assert_not_verified(vic.verify(report, LOCAL_REF, db_probe=tmp_path / "missing.json", image_id=LOCAL_ID, now=NOW),
                         "not found")


def test_nonzero_scanner_exit_with_clean_body_is_not_verified(tmp_path):
    _assert_not_verified(_run(tmp_path, _report(), exit_code=1), "nonzero")


# ---------------------------------------------------------------- package minimums


def _final(tmp_path, document=None, package_path=None, candidate="trivy"):
    result = _run(tmp_path, document or _report())
    rows, error = vic.load_package_check(package_path or _packages(tmp_path, candidate), candidate, REQUIREMENTS)
    return vic.finalise(vic.apply_package_requirements(result, rows, error))


def test_clean_scan_and_satisfied_requirements_is_acceptable(tmp_path):
    result = _final(tmp_path)
    assert result["acceptable"] is True
    assert result["unmet_package_requirements"] == []


@pytest.mark.parametrize("state", ["unsatisfied", "missing", "unknown"])
def test_unmet_requirement_blocks_even_a_clean_scan(tmp_path, state):
    result = _final(tmp_path, package_path=_packages(tmp_path, state=state))
    assert result["status"] == "PASS"
    assert result["acceptable"] is False
    assert result["unmet_package_requirements"]


def test_clean_requirements_do_not_rescue_a_failing_scan(tmp_path):
    result = _final(tmp_path, document=_report(rows=[FIXED_HIGH]))
    assert result["acceptable"] is False and result["status"] == "FAIL"


@pytest.mark.parametrize("kwargs, fragment", [
    ({"drop": "libcurl"}, "exactly the required packages"),
    ({"override": "libcurl\t8.23.0-r0\t8.23.0-r0\tsatisfied"}, "more than once"),
    ({"override": "bogus line"}, "malformed"),
    ({"override": "extra-pkg\t1\t1\tsatisfied"}, "exactly the required packages"),
])
def test_incomplete_or_malformed_package_check_is_not_verified(tmp_path, kwargs, fragment):
    result = _final(tmp_path, package_path=_packages(tmp_path, **kwargs))
    _assert_not_verified(result, fragment)


def test_package_check_with_wrong_minimum_is_not_verified(tmp_path):
    path = _write(tmp_path, "pk.tsv", "\n".join(
        ["brotli-libs\t1.2.1-r0\t1.2.1-r0\tsatisfied", "libcurl\t8.22.0-r0\t8.23.0-r0\tsatisfied",
         "libexpat\t2.9.0-r0\t2.9.0-r0\tsatisfied", "musl\t1.2.6-r3\t1.2.6-r3\tsatisfied",
         "musl-utils\t1.2.6-r3\t1.2.6-r3\tsatisfied"]) + "\n")
    _assert_not_verified(_final(tmp_path, package_path=path), "required '8.23.0-r0'")


def test_missing_package_check_file_is_not_verified(tmp_path):
    _assert_not_verified(_final(tmp_path, package_path=tmp_path / "absent.tsv"), "not found")


# ---------------------------------------------------------------------- CLI


def _cli(tmp_path, monkeypatch, document, *, extra=(), state="satisfied"):
    now = datetime.now(timezone.utc)
    document = json.loads(json.dumps(document))
    document["CreatedAt"] = (now - timedelta(minutes=2)).isoformat()
    probe = _probe(updated=(now - timedelta(hours=2)).isoformat())
    summary_md = tmp_path / "step-summary.md"
    monkeypatch.setenv("GITHUB_STEP_SUMMARY", str(summary_md))
    monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
    args = ["--candidate", "trivy", "--image-ref", LOCAL_REF, "--image-id", LOCAL_ID,
            "--report", str(_write(tmp_path, "scan.json", document)), "--db-probe", str(_write(tmp_path, "probe.json", probe)),
            "--package-check", str(_packages(tmp_path, state=state)), "--summary", str(tmp_path / "out.json"), *extra]
    code = vic.main(args)
    return code, json.loads((tmp_path / "out.json").read_text(encoding="utf-8")), summary_md.read_text(encoding="utf-8")


def test_cli_exit_codes(tmp_path, monkeypatch):
    assert _cli(tmp_path, monkeypatch, _report())[0] == 0
    assert _cli(tmp_path, monkeypatch, _report(rows=[FIXED_HIGH]))[0] == 0
    assert _cli(tmp_path, monkeypatch, _report(rows=[FIXED_HIGH]), extra=["--require-clean"])[0] == 1
    assert _cli(tmp_path, monkeypatch, _report(), extra=["--require-clean"], state="unsatisfied")[0] == 1
    assert _cli(tmp_path, monkeypatch, _report(), extra=["--require-clean"])[0] == 0
    assert _cli(tmp_path, monkeypatch, _report(image_id="sha256:" + "6" * 64))[0] == 2


def test_cli_not_verified_reports_unknown_counts_not_zero(tmp_path, monkeypatch):
    code, payload, step_summary = _cli(tmp_path, monkeypatch, _report(image_id="sha256:" + "6" * 64))
    assert code == 2
    assert payload["blocking_count"] is None and payload["acceptable"] is False
    assert "Blocking findings: unknown" in step_summary
    assert "Acceptable: **NO**" in step_summary


def test_cli_never_writes_github_output(tmp_path, monkeypatch):
    out = tmp_path / "gh-output"
    monkeypatch.setenv("GITHUB_OUTPUT", str(out))
    now = datetime.now(timezone.utc)
    document = _report(created=(now - timedelta(minutes=2)).isoformat())
    vic.main(["--candidate", "trivy", "--image-ref", LOCAL_REF, "--image-id", LOCAL_ID,
              "--report", str(_write(tmp_path, "scan.json", document)),
              "--db-probe", str(_write(tmp_path, "probe.json", _probe(updated=(now - timedelta(hours=1)).isoformat()))),
              "--package-check", str(_packages(tmp_path))])
    assert not out.exists()


# ------------------------------------------------- Dockerfiles and requirements


def _from_line(path):
    return re.search(r"^FROM\s+(\S+)", (ROOT / path).read_text(encoding="utf-8"), re.M).group(1)


def test_candidates_build_on_the_current_production_pins():
    pins = {item["name"]: item["ref"] for item in PINNED_IMAGES}
    requirements = json.loads(REQUIREMENTS.read_text(encoding="utf-8"))["candidates"]
    assert _from_line("docker/candidates/shannon/Dockerfile") == requirements["shannon"]["base"] == pins["shannon-worker"]
    assert _from_line("docker/candidates/trivy/Dockerfile") == requirements["trivy"]["base"] == pins["trivy-scanner"]


def test_candidate_dockerfiles_are_digest_pinned_and_never_skip_signatures():
    for path in ("docker/candidates/shannon/Dockerfile", "docker/candidates/trivy/Dockerfile"):
        text = (ROOT / path).read_text(encoding="utf-8")
        assert re.search(r"^FROM \S+@sha256:[0-9a-f]{64}\s*$", text, re.M), path
        assert "--allow-untrusted" not in text and "--no-verify" not in text, path
        assert "apk add --no-cache" in text
        assert "nodejs.org" not in text, "upstream node tarballs bypass apk metadata and the scanner"


def test_shannon_candidate_uses_only_already_trusted_signing_keys():
    text = (ROOT / "docker/candidates/shannon/Dockerfile").read_text(encoding="utf-8")
    assert "https://packages.wolfi.dev/os" in text
    assert "test -f /etc/apk/keys/wolfi-signing.rsa.pub" in text
    assert "/etc/apk/keys/" not in text.replace("test -f /etc/apk/keys/wolfi-signing.rsa.pub", "")


def test_requirements_cover_the_findings_the_candidates_target():
    data = json.loads(REQUIREMENTS.read_text(encoding="utf-8"))
    shannon, trivy = data["candidates"]["shannon"]["packages"], data["candidates"]["trivy"]["packages"]
    assert shannon["nodejs-22"]["minimum"] == "22.23.4-r0"
    assert {shannon[p]["minimum"] for p in ("curl", "libcurl-openssl4")} == {"8.23.0-r0"}
    assert trivy["libcurl"]["minimum"] == "8.23.0-r0"
    for spec in list(shannon.values()) + list(trivy.values()):
        assert re.fullmatch(r"[0-9][0-9A-Za-z._]*-r[0-9]+", spec["minimum"])


# --------------------------------------------------------- script and workflow


def _code(path):
    """File content without comment lines, so prose cannot satisfy or trip a check."""
    lines = (ROOT / path).read_text(encoding="utf-8").splitlines()
    return "\n".join(line for line in lines if not line.lstrip().startswith("#")) + "\n"


SCRIPT = _code("scripts/verify_self_built_candidates.sh")
WORKFLOW = _code(".github/workflows/self-built-image-candidates.yml")


def test_docker_build_has_an_explicit_context():
    """Regression: `docker build ... --tag X` without a context fails ('requires 1 argument')."""
    builds = re.findall(r"docker build(?:[^\n]*\\\n)*[^\n]*", SCRIPT)
    assert builds
    for command in builds:
        assert command.rstrip().endswith("docker/candidates 2>&1 | tee \"$REPORTS/$name-build.log\"; then") or \
            re.search(r"\sdocker/candidates(\s|$)", command), command


def test_script_binds_scans_to_exact_images_and_probes_the_database():
    assert "--image-src \"$source\"" in SCRIPT and "--platform linux/amd64" in SCRIPT
    assert "docker image inspect --format '{{.Id}}'" in SCRIPT
    assert "version --format json" in SCRIPT
    assert "--package-check" in SCRIPT and "--db-probe" in SCRIPT


def test_script_runtime_tests_the_candidate_not_the_original_worker():
    assert 'docker tag "$SHANNON_IMAGE" "$SHANNON_CLI_WORKER_TAG"' in SCRIPT
    assert 'PEN_SHANNON_EXPECT_WORKER_IMAGE_ID="$SHANNON_ID"' in SCRIPT
    assert "SHANNON_E2E_WORKER_IMAGE_ID_VERIFIED $SHANNON_ID" in SCRIPT
    e2e = (ROOT / "scripts/shannon_e2e_verify.sh").read_text(encoding="utf-8")
    assert "PEN_SHANNON_EXPECT_WORKER_IMAGE_ID" in e2e and "SHANNON_E2E_WORKER_IMAGE_ID_VERIFIED" in e2e


def test_script_writes_acceptance_outputs_only_after_runtime_validation():
    output_at = SCRIPT.index('>> "$GITHUB_OUTPUT"')
    assert SCRIPT.index("bash scripts/shannon_e2e_verify.sh") < output_at
    assert SCRIPT.index("scan_and_verify trivy") < output_at
    assert SCRIPT.count("GITHUB_OUTPUT") == 2  # the guard and the single write


def test_publication_requires_main_opt_in_and_both_candidates_acceptable():
    publish = WORKFLOW[WORKFLOW.index("publish-clean-candidates:"):]
    condition = publish[:publish.index("runs-on:")]
    for clause in ("github.event_name == 'workflow_dispatch'", "inputs.publish_candidates == true",
                   "github.ref == 'refs/heads/main'", "needs.build-and-scan.outputs.shannon_acceptable == 'true'",
                   "needs.build-and-scan.outputs.trivy_acceptable == 'true'"):
        assert clause in condition
    assert "--require-clean" in publish
    assert "--image-src remote" in publish and "--require-clean" in publish[publish.index("verify_published()"):]


def test_workflow_never_touches_production_pins_or_weakens_checks():
    for forbidden in ("core/supply_chain/images.py", "image_baseline.json", "continue-on-error", "--allow-untrusted",
                      "trivyignore"):
        assert forbidden not in WORKFLOW
        assert forbidden not in SCRIPT
    assert "packages: write" not in WORKFLOW[:WORKFLOW.index("publish-clean-candidates:")]
