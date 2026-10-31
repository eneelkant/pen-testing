#!/usr/bin/env python3
"""Evaluate a stable image-gate status context from upstream job results."""
from __future__ import annotations

import argparse
import os


def evaluate_gate(detect_result: str, needs_image_gate: str, scan_result: str) -> tuple[int, str]:
    """Return (exit code, summary); unknown or inconsistent states fail closed."""
    if detect_result != "success":
        return 1, f"FAIL: change detection concluded {detect_result!r}; classification is unsafe."
    if needs_image_gate not in {"true", "false"}:
        return 1, f"FAIL: needs_image_gate has invalid value {needs_image_gate!r}."
    valid_results = {"success", "failure", "cancelled", "skipped", "timed_out", "action_required", "neutral"}
    if scan_result not in valid_results:
        return 1, f"FAIL: scan job returned missing or unknown result {scan_result!r}."
    if needs_image_gate == "true":
        if scan_result == "success":
            return 0, "PASS: image-sensitive changes were detected and the scan completed successfully."
        return 1, f"FAIL: image scanning was required but the scan concluded {scan_result!r}."
    if scan_result == "skipped":
        return 0, (
            "NOT_APPLICABLE: no image-sensitive files changed. This is NOT a security scan pass "
            "and must not be used as release evidence; the absolute release image gate remains separate."
        )
    if scan_result == "success":
        return 0, "PASS: the scan ran and succeeded although the detector classified the change as non-sensitive."
    return 1, f"FAIL: an unexpected scan ran and concluded {scan_result!r}."


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--gate", choices=("regression", "absolute"), required=True)
    parser.add_argument("--detect-result", default=os.getenv("DETECT_RESULT", ""))
    parser.add_argument("--needs-image-gate", default=os.getenv("NEEDS_IMAGE_GATE", ""))
    parser.add_argument("--scan-result", default=os.getenv("SCAN_RESULT", ""))
    args = parser.parse_args()
    code, summary = evaluate_gate(args.detect_result, args.needs_image_gate, args.scan_result)
    label = "Pinned image regression gate" if args.gate == "regression" else "Pinned image vulnerability scans"
    print(f"{label}: {summary}")
    summary_path = os.getenv("GITHUB_STEP_SUMMARY")
    if summary_path:
        with open(summary_path, "a", encoding="utf-8") as handle:
            handle.write(f"## {label}\n\n{summary}\n\n")
    return code


if __name__ == "__main__":
    raise SystemExit(main())
