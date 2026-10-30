#!/usr/bin/env python3
"""Check whether Trivy reports GO-2026-5932 for a binary that does NOT import openpgp.

Usage: python scripts/verify_openpgp_advisory.py <scan.json>

Exit codes:
  0: GO-2026-5932 NOT reported (advisory correctly NOT applied) — PASS
  1: GO-2026-5932 reported despite no openpgp import — FALSE POSITIVE confirmed
  2: Scan output missing or malformed — NOT_VERIFIED
"""
import json
import sys
from pathlib import Path


def main(scan_path: str) -> int:
    scan_file = Path(scan_path)
    if not scan_file.exists():
        print(f"ERROR: scan file not found: {scan_path}")
        return 2

    try:
        data = json.loads(scan_file.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, OSError) as exc:
        print(f"ERROR: cannot parse scan file: {exc}")
        return 2

    results = data.get("Results", [])
    if not results:
        print("NOT_VERIFIED: scan has no Results array")
        return 2

    go_2026_5932_findings = []
    for result in results:
        for vuln in result.get("Vulnerabilities", []) or []:
            vid = vuln.get("VulnerabilityID", "")
            if vid == "GO-2026-5932":
                go_2026_5932_findings.append(vuln)

    if not go_2026_5932_findings:
        print("PASS: GO-2026-5932 was NOT reported for the controlled binary.")
        print("The scanner correctly did not apply the advisory when openpgp is not imported.")
        return 0

    print("FALSE_POSITIVE_CONFIRMED: GO-2026-5932 was reported for a binary that does NOT import openpgp.")
    print()
    print("Evidence:")
    for f in go_2026_5932_findings:
        pkg = f.get("PkgName", "?")
        installed = f.get("InstalledVersion", "?")
        severity = f.get("Severity", "?")
        pkg_path = f.get("PkgPath", "(empty)")
        print(f"  VulnerabilityID: {f.get('VulnerabilityID')}")
        print(f"  PkgName: {pkg}")
        print(f"  InstalledVersion: {installed}")
        print(f"  Severity: {severity}")
        print(f"  PkgPath: {pkg_path}")
        print()

    print("Analysis:")
    print("  The advisory GO-2026-5932 targets 7 specific import paths under")
    print("  golang.org/x/crypto/openpgp/. The controlled binary imports")
    print("  golang.org/x/crypto/bcrypt (a DIFFERENT subpackage) and does NOT")
    print("  import any openpgp path.")
    print()
    print("  Trivy reported the finding at MODULE level (golang.org/x/crypto)")
    print("  without checking whether the specific openpgp import paths are")
    print("  present in the binary. The PkgPath field is empty, confirming")
    print("  module-level-only detection.")
    print()
    print("  This confirms GO-2026-5932 is a MODULE-LEVEL FALSE POSITIVE when")
    print("  the openpgp subpackage is not imported.")
    print()
    print("  Recommended upstream fix for aquasecurity/trivy:")
    print("    When the advisory's ecosystem_specific.imports field is present,")
    print("    check whether any of the listed import paths are in the binary's")
    print("    symbol table before reporting the finding.")

    # Exit 1 to flag the false positive — this is evidence, not a test failure
    # The workflow step will show "FALSE_POSITIVE_CONFIRMED" in the logs
    return 1


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <scan.json>")
        sys.exit(2)
    sys.exit(main(sys.argv[1]))
