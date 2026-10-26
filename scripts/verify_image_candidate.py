#!/usr/bin/env python3
"""Fail-closed validation and evidence summary for self-built image candidates.

A local tag is evidence for candidate testing only. A published candidate must
be rescanned by immutable digest before it can be considered for pinning.
A verified FAIL is reported as unacceptable but is not an evidence-collection
error unless --require-clean is supplied. NOT_VERIFIED always exits nonzero.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any

from core.supply_chain.images import (
    REQUIRED_PLATFORM,
    REQUIRED_SCANNER_VERSION,
    _enforce_scan_identity,
    _parse_time,
    _report_digests,
    classify_trivy_document,
    parse_image_ref,
)

MAX_AGE = timedelta(days=7)
CLOCK_SKEW = timedelta(minutes=5)


def not_verified(image: str, reason: str) -> dict[str, Any]:
    return {
        "status": "NOT_VERIFIED",
        "acceptable": False,
        "image": image,
        "blocking_count": 0,
        "unscored_count": 0,
        "error": reason,
    }


def verify(report_path: Path, image: str) -> dict[str, Any]:
    raw_bytes = report_path.read_bytes()
    raw_sha256 = hashlib.sha256(raw_bytes).hexdigest()
    try:
        document = json.loads(raw_bytes)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        return not_verified(image, f"Trivy report is not valid JSON: {exc}")

    if not isinstance(document, dict) or "Results" not in document:
        return not_verified(image, "Trivy report is missing its Results array")
    artifact = str(document.get("ArtifactName") or "")
    if not artifact:
        return not_verified(image, "Trivy report is missing ArtifactName")

    identity = parse_image_ref(image)
    reported_digests = _report_digests(document)
    expected_digest = identity.get("digest") or ""
    if expected_digest:
        if expected_digest not in reported_digests:
            return not_verified(
                image,
                "digest-pinned candidate report does not contain the exact expected digest",
            )
    elif artifact != image:
        return not_verified(
            image,
            f"local candidate report identity mismatch: expected {image!r}, got {artifact!r}",
        )

    now = datetime.now(timezone.utc)
    created_at = str(document.get("CreatedAt") or "")
    created = _parse_time(created_at)
    if created is None:
        return not_verified(image, "Trivy report CreatedAt is missing or invalid")
    if created - now > CLOCK_SKEW:
        return not_verified(image, "Trivy report CreatedAt is in the future")
    if now - created > MAX_AGE:
        return not_verified(image, "Trivy report CreatedAt is stale")

    classified = classify_trivy_document(
        document,
        image=image,
        now=now,
        max_age=MAX_AGE,
        exit_code=0,
    )
    if classified.get("status") == "NOT_VERIFIED":
        return {
            **classified,
            "acceptable": False,
            "raw_report_sha256": raw_sha256,
        }

    database = classified.get("database") if isinstance(classified.get("database"), dict) else {}
    db_updated_raw = str(database.get("updated_at") or "")
    db_updated = _parse_time(db_updated_raw)
    if db_updated is None:
        return not_verified(image, "Trivy vulnerability database UpdatedAt is missing or invalid")
    if db_updated - now > CLOCK_SKEW:
        return not_verified(image, "Trivy vulnerability database timestamp is in the future")
    if now - db_updated > MAX_AGE:
        return not_verified(image, "Trivy vulnerability database is stale")

    classified = _enforce_scan_identity(
        classified,
        image=image,
        required_platform=REQUIRED_PLATFORM,
        required_scanner_version=REQUIRED_SCANNER_VERSION,
    )
    if classified.get("status") == "NOT_VERIFIED":
        return {
            **classified,
            "acceptable": False,
            "raw_report_sha256": raw_sha256,
        }

    blockers = [
        {
            "id": row.get("id"),
            "package": row.get("package"),
            "installed": row.get("installed"),
            "fixed": row.get("fixed"),
            "severity": row.get("severity"),
            "class": row.get("class"),
        }
        for row in classified.get("findings", [])
        if row.get("blocking")
    ]
    status = str(classified.get("status") or "NOT_VERIFIED")
    return {
        "status": status,
        "acceptable": status == "PASS"
        and int(classified.get("blocking_count") or 0) == 0
        and int(classified.get("unscored_count") or 0) == 0,
        "image": image,
        "artifact": artifact,
        "expected_digest": expected_digest,
        "reported_digests": sorted(reported_digests),
        "platform": classified.get("platform") or "",
        "scanner_version": classified.get("scanner_version") or "",
        "created_at": created_at,
        "database_updated_at": db_updated_raw,
        "raw_report_sha256": raw_sha256,
        "finding_row_count": int(classified.get("finding_row_count") or 0),
        "unique_cve_count": int(classified.get("unique_cve_count") or 0),
        "blocking_count": int(classified.get("blocking_count") or 0),
        "unscored_count": int(classified.get("unscored_count") or 0),
        "findings": blockers[:50],
        "note": (
            "PASS is candidate-scan evidence only. Production pin changes also require "
            "immutable published-digest evidence and runtime regression validation."
        ),
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--image-ref", required=True, help="Exact local tag or published image@sha256 digest")
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--summary", type=Path, help="Optional JSON summary output path")
    parser.add_argument("--output-name", help="Optional GITHUB_OUTPUT boolean key")
    parser.add_argument("--require-clean", action="store_true", help="Exit nonzero unless the scan is acceptable")
    args = parser.parse_args()

    if not args.report.is_file():
        result = not_verified(args.image_ref, f"Trivy report not found: {args.report}")
    else:
        try:
            result = verify(args.report, args.image_ref)
        except OSError as exc:
            result = not_verified(args.image_ref, f"Unable to read Trivy report: {exc}")

    rendered = json.dumps(result, indent=2, sort_keys=True) + "\n"
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(rendered, encoding="utf-8")
    print(rendered, end="")

    if args.output_name:
        output_path = os.environ.get("GITHUB_OUTPUT")
        if output_path:
            with open(output_path, "a", encoding="utf-8") as handle:
                handle.write(f"{args.output_name}={'true' if result.get('acceptable') else 'false'}\n")

    summary_path = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary_path:
        status = str(result.get("status") or "NOT_VERIFIED")
        accepted = "YES" if result.get("acceptable") else "NO"
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(
                f"\n### Candidate scan: {args.image_ref}\n\n"
                f"- Status: **{status}**\n"
                f"- Acceptable for candidate progression: **{accepted}**\n"
                f"- Blocking findings: {result.get('blocking_count', 'unknown')}\n"
                f"- Unscored findings: {result.get('unscored_count', 'unknown')}\n"
                f"- Raw scan SHA-256: `{result.get('raw_report_sha256', 'unavailable')}`\n"
            )
            if result.get("error"):
                handle.write(f"- Verification error: {result['error']}\n")

    if result.get("status") == "NOT_VERIFIED":
        return 2
    if args.require_clean and not result.get("acceptable"):
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
