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
from core.supply_chain.images import PINNED_IMAGES, scan_pinned_images
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
        report = scan_pinned_images(images=selected)
        text = json.dumps(report, indent=2)
        if args.output:
            safe_write_text(args.output, text + "\n")
        print(text)
        if report["status"] == "NOT_VERIFIED":
            return 2
        return 0 if report["ok"] else 1
    if args.command == "candidates":
        evidence = Path(args.evidence_dir).resolve() if args.evidence_dir else None
        report = monitor_candidates(evidence_dir=evidence)
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
