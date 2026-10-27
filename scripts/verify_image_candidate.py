#!/usr/bin/env python3
"""Fail-closed verification of a raw Trivy report for a self-built image candidate.

The project's canonical policy is reused rather than re-implemented:

* published candidates (``name@sha256:...``) go through
  ``core.supply_chain.candidates.verify_fresh_scan``, the same check the image
  candidate monitor uses (exact manifest digest, raw findings re-classified with
  ``classify_trivy_document``, ``linux/amd64``, report ``Trivy.Version`` equal to
  the probe and to the pinned scanner, fresh CreatedAt, DB not older than the
  live probe);
* local candidates (a tag that exists only in the build host's Docker daemon)
  have no registry digest, so their identity is bound to the exact local image
  ID (``Metadata.ImageID``) and exact ``ArtifactName``; every other step uses the
  same building blocks (``classify_trivy_document``, ``_enforce_scan_identity``,
  ``validate_live_database``, ``_raw_findings_error``).

The vulnerability database metadata comes from a ``trivy version --format json``
probe taken with the same cache immediately after the scan; raw image JSON does
not embed it. Missing, malformed, stale, future-dated, or mismatched evidence is
``NOT_VERIFIED``. ``NOT_VERIFIED`` never reports zero findings: counts are
``null`` (unknown).

A candidate is ``acceptable`` only when the verified classification is PASS
(zero fixed HIGH/CRITICAL and zero unscored findings) **and** every required
package minimum from ``docker/candidates/requirements.json`` is satisfied.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from core.supply_chain.candidates import (  # noqa: E402
    _manifest_digests,
    _raw_findings_error,
    validate_live_database,
    verify_fresh_scan,
)
from core.supply_chain.images import (  # noqa: E402
    REQUIRED_PLATFORM,
    REQUIRED_SCANNER_VERSION,
    _MAX_EVIDENCE_AGE,
    _enforce_scan_identity,
    _parse_time,
    _scanner_version,
    classify_trivy_document,
    parse_image_ref,
    read_trivy_version_document,
)

CLOCK_SKEW = timedelta(minutes=5)
PACKAGE_STATES = {"satisfied", "unsatisfied", "missing", "unknown"}
DEFAULT_REQUIREMENTS = ROOT / "docker" / "candidates" / "requirements.json"
_HEX64 = set("0123456789abcdef")


def not_verified(image: str, reason: str, **extra: Any) -> dict[str, Any]:
    """Unverifiable evidence. Counts are unknown, not zero."""
    payload: dict[str, Any] = {
        "status": "NOT_VERIFIED",
        "acceptable": False,
        "image": image,
        "blocking_count": None,
        "unscored_count": None,
        "finding_row_count": None,
        "error": reason,
    }
    payload.update(extra)
    return payload


def _is_image_id(value: str) -> bool:
    return value.startswith("sha256:") and len(value) == 71 and set(value[7:]) <= _HEX64


def load_db_probe(path: Path | None) -> tuple[str, dict[str, str], str]:
    """Return (scanner_version, database, error) from a ``trivy version --format json`` file."""
    if path is None:
        return "", {}, "vulnerability database probe (trivy version --format json) was not supplied"
    if not path.is_file():
        return "", {}, f"vulnerability database probe not found: {path}"
    try:
        document = json.loads(path.read_bytes())
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        return "", {}, f"vulnerability database probe is not valid JSON: {exc}"
    if not isinstance(document, dict):
        return "", {}, "vulnerability database probe is not a JSON object"
    version, database = read_trivy_version_document(document)
    if not version:
        return "", database, "vulnerability database probe has no scanner Version"
    return version, database, ""


def load_package_check(path: Path, candidate: str, requirements_path: Path) -> tuple[list[dict[str, str]], str]:
    """Parse the in-image requirement check (TSV: name, minimum, installed, state)."""
    try:
        requirements = json.loads(requirements_path.read_text(encoding="utf-8"))
        required = requirements["candidates"][candidate]["packages"]
    except (OSError, KeyError, TypeError, json.JSONDecodeError) as exc:
        return [], f"package requirements for {candidate!r} could not be read: {exc}"
    if not isinstance(required, dict) or not required:
        return [], f"package requirements for {candidate!r} are empty"
    if not path.is_file():
        return [], f"package check not found: {path}"
    rows: list[dict[str, str]] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        if not line.strip():
            continue
        fields = line.split("\t")
        if len(fields) != 4 or fields[3] not in PACKAGE_STATES or not fields[0]:
            return [], f"package check line {number} is malformed: {line!r}"
        rows.append({"package": fields[0], "minimum": fields[1], "installed": fields[2], "state": fields[3]})
    seen = {row["package"]: row for row in rows}
    if len(seen) != len(rows):
        return [], "package check lists a package more than once"
    expected = {name: str(spec.get("minimum") or "") for name, spec in required.items()}
    if set(seen) != set(expected):
        return [], f"package check does not cover exactly the required packages {sorted(expected)}"
    for name, minimum in expected.items():
        if seen[name]["minimum"] != minimum:
            return [], f"package check for {name} used minimum {seen[name]['minimum']!r}, required {minimum!r}"
    return rows, ""


def _summarise(classified: dict[str, Any], **extra: Any) -> dict[str, Any]:
    blockers = [
        {key: row.get(key) for key in ("id", "package", "installed", "fixed", "severity", "class")}
        for row in classified.get("findings") or []
        if row.get("blocking")
    ]
    database = classified.get("database") if isinstance(classified.get("database"), dict) else {}
    return {
        "status": classified.get("status"),
        "platform": classified.get("platform") or "",
        "scanner_version": classified.get("scanner_version") or "",
        "created_at": classified.get("created_at") or "",
        "database_updated_at": database.get("updated_at") or "",
        "finding_row_count": int(classified.get("finding_row_count") or 0),
        "unique_cve_count": int(classified.get("unique_cve_count") or 0),
        "blocking_count": int(classified.get("blocking_count") or 0),
        "unscored_count": int(classified.get("unscored_count") or 0),
        "blocking_findings": blockers,
        **extra,
    }


def _verify_local(
    document: dict[str, Any],
    *,
    image: str,
    image_id: str,
    now: datetime,
    probe_version: str,
    database: dict[str, str],
    live_updated: datetime,
    exit_code: int | None,
) -> dict[str, Any]:
    """Local tag: identity is the exact image ID; the rest mirrors verify_fresh_scan."""
    metadata = document.get("Metadata") if isinstance(document.get("Metadata"), dict) else {}
    if str(metadata.get("ImageID") or "") != image_id:
        return not_verified(image, "report Metadata.ImageID does not equal the built image ID",
                            expected_image_id=image_id, reported_image_id=str(metadata.get("ImageID") or ""))
    if str(document.get("ArtifactName") or "") != image:
        return not_verified(image, "report ArtifactName does not equal the local candidate tag",
                            reported_artifact=str(document.get("ArtifactName") or ""))
    classified = classify_trivy_document(
        document, image=image, now=now, max_age=_MAX_EVIDENCE_AGE, exit_code=exit_code, database=database
    )
    if classified.get("status") == "NOT_VERIFIED":
        return not_verified(image, str(classified.get("error") or "classification not verified"))
    created = _parse_time(str(classified.get("created_at") or ""))
    if created is None:
        return not_verified(image, "raw Trivy report CreatedAt is missing or invalid")
    if created - now > CLOCK_SKEW:
        return not_verified(image, "raw Trivy report CreatedAt is in the future")
    raw_version = _scanner_version(document)
    if raw_version and raw_version != probe_version:
        return not_verified(image, f"raw report scanner {raw_version!r} disagrees with probed scanner {probe_version!r}")
    classified["scanner_version"] = raw_version
    classified = _enforce_scan_identity(
        classified, image=image, required_platform=REQUIRED_PLATFORM, required_scanner_version=REQUIRED_SCANNER_VERSION
    )
    if classified.get("status") == "NOT_VERIFIED":
        return not_verified(image, str(classified.get("error") or "scan identity not verified"))
    db_updated = _parse_time(str((classified.get("database") or {}).get("updated_at") or ""))
    if db_updated is None or db_updated < live_updated:
        return not_verified(image, "scan vulnerability database UpdatedAt is missing or older than the live probe")
    return classified


def verify(
    report_path: Path,
    image: str,
    *,
    db_probe: Path | None,
    image_id: str = "",
    exit_code: int | None = 0,
    now: datetime | None = None,
) -> dict[str, Any]:
    clock = now or datetime.now(timezone.utc)
    if not report_path.is_file():
        return not_verified(image, f"Trivy report not found: {report_path}")
    try:
        raw_bytes = report_path.read_bytes()
    except OSError as exc:
        return not_verified(image, f"unable to read Trivy report: {exc}")
    evidence = {"raw_report_sha256": hashlib.sha256(raw_bytes).hexdigest(), "raw_report_bytes": len(raw_bytes)}
    try:
        document = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return not_verified(image, f"Trivy report is not valid JSON: {exc}", **evidence)
    if not isinstance(document, dict):
        return not_verified(image, "Trivy report is not a JSON object", **evidence)
    if "Results" not in document:
        return not_verified(image, "Trivy report has no raw Results (a pre-classified summary is not evidence)", **evidence)
    raw_error = _raw_findings_error(document)
    if raw_error:
        return not_verified(image, raw_error, **evidence)

    probe_version, database, probe_error = load_db_probe(db_probe)
    if probe_error:
        return not_verified(image, probe_error, **evidence)
    if probe_version != REQUIRED_SCANNER_VERSION:
        return not_verified(image, f"probed scanner {probe_version!r} is not the required {REQUIRED_SCANNER_VERSION!r}", **evidence)
    live_updated, live_error = validate_live_database(database, now=clock, max_age=_MAX_EVIDENCE_AGE)
    if live_updated is None:
        return not_verified(image, live_error, **evidence)
    created = _parse_time(str(document.get("CreatedAt") or ""))
    if created is not None and live_updated - created > CLOCK_SKEW:
        return not_verified(image, "vulnerability database probe is newer than the scan; it does not describe the scan's database", **evidence)

    digest = parse_image_ref(image).get("digest") or ""
    if digest:
        classified = verify_fresh_scan(
            {"raw_document": document, "database": database, "tool_version": probe_version, "exit_code": exit_code},
            ref=image, digest=digest, now=clock, max_age=_MAX_EVIDENCE_AGE, live_updated=live_updated,
        )
        identity = {"identity": "published-digest", "expected_digest": digest,
                    "reported_manifest_digests": sorted(_manifest_digests(document))}
    else:
        if not _is_image_id(image_id):
            return not_verified(image, "a local candidate requires --image-id sha256:<64 hex> from docker image inspect", **evidence)
        classified = _verify_local(document, image=image, image_id=image_id, now=clock, probe_version=probe_version,
                                   database=database, live_updated=live_updated, exit_code=exit_code)
        identity = {"identity": "local-image-id", "expected_image_id": image_id}
    if classified.get("status") == "NOT_VERIFIED":
        out = not_verified(image, str(classified.get("error") or "not verified"), **evidence, **identity)
        return out
    return {"image": image, **_summarise(classified), **evidence, **identity}


def apply_package_requirements(result: dict[str, Any], rows: list[dict[str, str]] | None, error: str) -> dict[str, Any]:
    if result.get("status") == "NOT_VERIFIED":
        return result
    if error:
        return not_verified(result["image"], error, raw_report_sha256=result.get("raw_report_sha256"))
    unmet = [row for row in rows or [] if row["state"] != "satisfied"]
    result["package_requirements"] = rows or []
    result["unmet_package_requirements"] = unmet
    return result


def finalise(result: dict[str, Any]) -> dict[str, Any]:
    verified = result.get("status") in {"PASS", "FAIL"}
    result["acceptable"] = bool(
        verified
        and result.get("status") == "PASS"
        and result.get("blocking_count") == 0
        and result.get("unscored_count") == 0
        and "package_requirements" in result
        and not result.get("unmet_package_requirements")
    )
    result["note"] = (
        "acceptable=true is candidate evidence only. Adopting a candidate still needs a published-digest rescan, "
        "the Shannon runtime test, and a separate reviewed pin PR."
    )
    return result


def _fmt(value: Any) -> str:
    return "unknown" if value is None else str(value)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--image-ref", required=True, help="Exact local tag or published name@sha256:<digest>")
    parser.add_argument("--report", required=True, type=Path, help="Raw `trivy image --format json` output")
    parser.add_argument("--db-probe", type=Path, help="`trivy version --format json` taken right after the scan")
    parser.add_argument("--image-id", default="", help="Local candidates: exact image ID from docker image inspect")
    parser.add_argument("--trivy-exit-code", type=int, default=0)
    parser.add_argument("--candidate", required=True, help="Key in docker/candidates/requirements.json")
    parser.add_argument("--package-check", required=True, type=Path, help="In-image requirement check TSV")
    parser.add_argument("--requirements", type=Path, default=DEFAULT_REQUIREMENTS)
    parser.add_argument("--summary", type=Path, help="Write the JSON summary here")
    parser.add_argument("--require-clean", action="store_true", help="Exit 1 unless the candidate is acceptable")
    args = parser.parse_args(argv)

    result = verify(args.report, args.image_ref, db_probe=args.db_probe, image_id=args.image_id,
                    exit_code=args.trivy_exit_code)
    rows, package_error = load_package_check(args.package_check, args.candidate, args.requirements)
    result = finalise(apply_package_requirements(result, rows, package_error))
    result["candidate"] = args.candidate

    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(rendered, encoding="utf-8")
    print(rendered, end="")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(
                f"\n### Candidate scan: {args.candidate} ({args.image_ref})\n\n"
                f"- Status: **{_fmt(result.get('status'))}**\n"
                f"- Acceptable: **{'YES' if result.get('acceptable') else 'NO'}**\n"
                f"- Blocking findings: {_fmt(result.get('blocking_count'))}\n"
                f"- Unscored findings: {_fmt(result.get('unscored_count'))}\n"
                f"- Unmet package requirements: {len(result.get('unmet_package_requirements') or []) if 'unmet_package_requirements' in result else 'unknown'}\n"
                f"- Raw scan SHA-256: `{_fmt(result.get('raw_report_sha256'))}`\n"
            )
            for row in result.get("unmet_package_requirements") or []:
                handle.write(f"  - `{row['package']}` needs >= {row['minimum']}, installed {row['installed']} ({row['state']})\n")
            if result.get("error"):
                handle.write(f"- Verification error: {result['error']}\n")

    if result.get("status") == "NOT_VERIFIED":
        return 2
    if args.require_clean and not result.get("acceptable"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
