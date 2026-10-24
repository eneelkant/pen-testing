"""CLI: ``python -m core.supply_chain audit|emit``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.paths import safe_write_text
from core.supply_chain.audit import audit_dependencies
from core.supply_chain.sbom import build_sbom, validate_sbom_document
from core.supply_chain.candidates import monitor_candidates
from core.supply_chain.images import PINNED_IMAGES, scan_pinned_images, write_raw_evidence
from core.supply_chain.vuln import scan_components


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m core.supply_chain")
    parser.add_argument("--root", default=".", help="Repository root containing pyproject.toml")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit", help="Check requirement metadata (not a CVE scan)")
    emit = sub.add_parser("emit", help="Write a CycloneDX SBOM")
    emit.add_argument("--output", required=True)
    vuln = sub.add_parser("vuln", help="Query OSV for pinned Python components")
    vuln.add_argument("--output", help="Write the JSON report to this path")
    images = sub.add_parser("images", help="Scan pinned container images with Trivy when available")
    images.add_argument("--output", help="Write the JSON report to this path")
    images.add_argument("--name", action="append", default=[], help="Scan only this pinned image name")
    images.add_argument(
        "--raw-dir",
        help="Write each image's parsed Trivy document as canonical JSON here and record the sha256 of the written bytes",
    )
    images.add_argument(
        "--baseline",
        help=(
            "Merge regression gate: also evaluate findings against this reviewed baseline. "
            "Exit status reflects the regression gate; the absolute result is reported unchanged."
        ),
    )
    baseline = sub.add_parser("baseline", help="Create, approve, or guard the reviewed image baseline")
    baseline_sub = baseline.add_subparsers(dest="baseline_command", required=True)
    candidate = baseline_sub.add_parser("candidate", help="Build candidate entries from CI image-scan artifacts")
    candidate.add_argument("--summary", action="append", required=True, help="image-scan-*.json from CI (repeatable)")
    candidate.add_argument("--raw-dir", action="append", required=True, help="Matching raw directory (same order)")
    candidate.add_argument("--raw-prefix", action="append", default=[], help="Path prefix inside the artifact (same order)")
    candidate.add_argument("--repository", required=True)
    candidate.add_argument("--ci-run-id", type=int, required=True)
    candidate.add_argument("--commit", required=True)
    candidate.add_argument("--artifact", default="image-scan-raw")
    candidate.add_argument("--output", required=True)
    approve = baseline_sub.add_parser("approve", help="Record an owner approval on pending entries (human reviewer only)")
    approve.add_argument("--baseline", required=True)
    approve.add_argument("--approved-by", required=True)
    approve.add_argument("--approval-ref", required=True)
    approve.add_argument("--expires-in-days", type=int, required=True)
    approve.add_argument("--name", action="append", default=[])
    guard = baseline_sub.add_parser("guard", help="Reject a change set that moves a pin and edits its baseline entry")
    guard.add_argument("--base-ref", required=True)
    candidates = sub.add_parser(
        "candidates",
        help="Watch official image tags for digests that pass the fail-closed gate (never updates pins)",
    )
    candidates.add_argument("--output", required=True, help="Write the JSON monitor report to this path")
    candidates.add_argument(
        "--evidence-dir",
        help="Directory of prior Trivy/classified JSON reports to reuse for unchanged digests",
    )
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if args.command == "audit":
        report = audit_dependencies(root)
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1
    if args.command == "emit":
        document = build_sbom(root)
        problems = validate_sbom_document(document)
        if problems:
            print(json.dumps({"ok": False, "errors": problems}, indent=2))
            return 1
        safe_write_text(args.output, json.dumps(document, indent=2) + "\n")
        print(json.dumps({"output": str(Path(args.output)), "components": len(document["components"])}))
        return 0
    if args.command == "vuln":
        document = build_sbom(root)
        report = scan_components(document["components"])
        text = json.dumps(report, indent=2)
        if args.output:
            safe_write_text(args.output, text + "\n")
        print(text)
        if report["status"] == "NOT_VERIFIED":
            return 2
        return 0 if report["ok"] else 1
    if args.command == "images":
        selected = PINNED_IMAGES
        if args.name:
            selected = tuple(item for item in PINNED_IMAGES if item["name"] in set(args.name))
            if len(selected) != len(set(args.name)):
                print(json.dumps({"ok": False, "error": "unknown image name", "names": args.name}))
                return 2
        report = scan_pinned_images(images=selected, include_raw=bool(args.raw_dir or args.baseline))
        if args.baseline:
            from core.supply_chain.baseline import evaluate_regression_gate, load_baseline, summary_lines

            document, load_errors = load_baseline(args.baseline)
            result = evaluate_regression_gate(report, document, pinned=selected, baseline_errors=load_errors)
            if args.raw_dir:
                write_raw_evidence(report, args.raw_dir)
            else:
                for row in report.get("images") or []:
                    row.pop("raw_document", None)
            result["absolute_report"] = report
            text = json.dumps(result, indent=2)
            if args.output:
                safe_write_text(args.output, text + "\n")
            print("\n".join(summary_lines(result)))
            status = result["regression_gate"]["status"]
            return 0 if status == "PASS" else 2 if status == "NOT_VERIFIED" else 1
        if args.raw_dir:
            write_raw_evidence(report, args.raw_dir)
        text = json.dumps(report, indent=2)
        if args.output:
            safe_write_text(args.output, text + "\n")
        print(text)
        if report["status"] == "NOT_VERIFIED":
            return 2
        return 0 if report["ok"] else 1
    if args.command == "baseline":
        from core.supply_chain import baseline as bl

        if args.baseline_command == "candidate":
            if len(args.summary) != len(args.raw_dir) or (args.raw_prefix and len(args.raw_prefix) != len(args.summary)):
                print(json.dumps({"ok": False, "error": "--summary, --raw-dir and --raw-prefix must pair up"}))
                return 2
            entries = []
            try:
                for index, summary_path in enumerate(args.summary):
                    summary = json.loads(Path(summary_path).read_text(encoding="utf-8"))
                    entries += bl.build_candidate_entries(
                        summary,
                        args.raw_dir[index],
                        repository=args.repository,
                        ci_run_id=args.ci_run_id,
                        commit=args.commit,
                        artifact=args.artifact,
                        raw_prefix=args.raw_prefix[index] if args.raw_prefix else "",
                    )
            except (bl.BaselineEvidenceError, OSError, json.JSONDecodeError) as exc:
                print(json.dumps({"ok": False, "error": str(exc)}))
                return 2
            document = {
                "schema_version": bl.BASELINE_SCHEMA_VERSION,
                "description": (
                    "Reviewed inherited-risk baseline for the merge regression gate. Not a waiver: "
                    "listed findings remain open and the absolute release gate still fails on them."
                ),
                "entries": entries,
            }
            safe_write_text(args.output, bl.dump_baseline(document))
            print(json.dumps({"ok": True, "entries": len(entries), "pending_approval": len(entries), "output": args.output}))
            return 0
        if args.baseline_command == "approve":
            document, load_errors = bl.load_baseline(args.baseline)
            if load_errors:
                print(json.dumps({"ok": False, "errors": load_errors}))
                return 2
            try:
                count = bl.approve_entries(
                    document,
                    approved_by=args.approved_by,
                    approval_ref=args.approval_ref,
                    expires_in_days=args.expires_in_days,
                    pin_names=args.name or None,
                )
            except ValueError as exc:
                print(json.dumps({"ok": False, "error": str(exc)}))
                return 2
            errors = bl.validate_baseline(document)
            if errors:
                print(json.dumps({"ok": False, "approved": count, "errors": errors}, indent=2))
                return 1
            safe_write_text(args.baseline, bl.dump_baseline(document))
            print(json.dumps({"ok": True, "approved": count}))
            return 0
        if args.baseline_command == "guard":
            result = bl.guard_against_git_ref(args.base_ref, root=root)
            print(json.dumps(result, indent=2))
            return 0 if result["ok"] else 1
    if args.command == "candidates":
        import shutil
        import subprocess

        from core.supply_chain.candidates import load_version_database
        from core.supply_chain.images import _trivy_invoke_prefix

        evidence = Path(args.evidence_dir).resolve() if args.evidence_dir else None
        # Probe the live Trivy DB. Age-only reuse is not allowed; a failed probe
        # fails closed as NOT_VERIFIED (no candidate may be accepted).
        database: dict[str, str] = {}
        prefix: list[str] | None = None
        if shutil.which("trivy"):
            prefix = ["trivy"]
        elif shutil.which("docker"):
            prefix = _trivy_invoke_prefix(use_docker=True)
        if prefix is not None:
            try:
                subprocess.run(
                    [*prefix, "image", "--download-db-only"],
                    capture_output=True,
                    text=True,
                    timeout=300,
                    check=False,
                )
                completed = subprocess.run(
                    [*prefix, "version", "--format", "json"],
                    capture_output=True,
                    text=True,
                    timeout=120,
                    check=False,
                )
                if completed.returncode == 0 and completed.stdout.strip():
                    database = load_version_database(json.loads(completed.stdout))
            except (OSError, TimeoutError, json.JSONDecodeError, ValueError):
                database = {}
        if not database.get("updated_at"):
            report = {
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "live trivy vulnerability database probe failed or UpdatedAt is missing",
                "candidates": [],
                "acceptable": [],
                "database": database,
                "note": "Incomplete live DB metadata is not treated as clean; no candidate accepted.",
            }
        else:
            report = monitor_candidates(
                evidence_dir=evidence,
                database=database,
                require_live_database=True,
            )
        text = json.dumps(report, indent=2)
        safe_write_text(args.output, text + "\n")
        print(text)
        if report["status"] == "NOT_VERIFIED":
            return 2
        if report["status"] == "ACCEPTABLE_CANDIDATE":
            return 0
        return 1
    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
