#!/usr/bin/env python3
"""Compare Trivy's GO-2026-5932 result for controlled Go binaries.

This experiment evaluates scanner reporting granularity only. It does not
prove that any production image does or does not contain affected code.

Exit codes:
  0: Both valid scans show a recognized, interpretable result.
  2: Missing/malformed scan data or an inconclusive result combination.
"""
import argparse
import json
import sys
from pathlib import Path
from typing import Any

ADVISORY_ID = "GO-2026-5932"


def load_findings(scan_path: str) -> list[dict[str, Any]]:
    """Load and validate Trivy JSON; never treat missing data as no findings."""
    path = Path(scan_path)
    if not path.is_file():
        raise ValueError(f"scan file does not exist: {path}")
    try:
        document = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        raise ValueError(f"scan file is unreadable or invalid JSON: {path}: {exc}") from exc
    if not isinstance(document, dict) or not isinstance(document.get("Results"), list):
        raise ValueError(f"scan JSON has no valid Results array: {path}")

    findings: list[dict[str, Any]] = []
    for result in document["Results"]:
        if not isinstance(result, dict):
            raise ValueError(f"malformed result entry in {path}")
        vulnerabilities = result.get("Vulnerabilities") or []
        if not isinstance(vulnerabilities, list):
            raise ValueError(f"malformed Vulnerabilities entry in {path}")
        for vulnerability in vulnerabilities:
            if not isinstance(vulnerability, dict):
                raise ValueError(f"malformed vulnerability entry in {path}")
            if vulnerability.get("VulnerabilityID") == ADVISORY_ID:
                findings.append(vulnerability)
    return findings


def describe(label: str, findings: list[dict[str, Any]]) -> None:
    print(f"{label}: {ADVISORY_ID} reported: {'YES' if findings else 'NO'}")
    for finding in findings[:3]:
        print(
            "  PkgName={pkg} InstalledVersion={version} Severity={severity} "
            "PkgPath={path}".format(
                pkg=finding.get("PkgName", "?"),
                version=finding.get("InstalledVersion", "?"),
                severity=finding.get("Severity", "?"),
                path=finding.get("PkgPath") or "(empty)",
            )
        )


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--no-openpgp-scan", required=True)
    parser.add_argument("--with-openpgp-scan", required=True)
    args = parser.parse_args()

    try:
        no_openpgp = load_findings(args.no_openpgp_scan)
        with_openpgp = load_findings(args.with_openpgp_scan)
    except ValueError as exc:
        print(f"NOT_VERIFIED: {exc}", file=sys.stderr)
        return 2

    print("=" * 64)
    print("GO-2026-5932 controlled-binary comparison")
    print("=" * 64)
    describe("Negative control (bcrypt; no openpgp import)", no_openpgp)
    describe("Positive control (openpgp import)", with_openpgp)

    if no_openpgp and with_openpgp:
        print("\nRESULT: MODULE_LEVEL_REPORTING")
        print(
            "Trivy reports the advisory for both controls. This demonstrates "
            "module-level reporting for this test and a potential false "
            "positive for the negative-control binary."
        )
    elif not no_openpgp and with_openpgp:
        print("\nRESULT: IMPORT_SENSITIVE_REPORTING")
        print(
            "The advisory appears only for the positive control in this test."
        )
    else:
        print(
            "\nNOT_VERIFIED: unexpected result combination "
            f"(negative_control={bool(no_openpgp)}, "
            f"positive_control={bool(with_openpgp)}).",
            file=sys.stderr,
        )
        return 2

    print(
        "\nLIMITATION: This controlled experiment does not establish the "
        "package contents or reachability of Temporal, Trivy, or any other "
        "production image. Those artifacts require separate evidence."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
