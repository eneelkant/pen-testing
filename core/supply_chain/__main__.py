"""CLI: ``python -m core.supply_chain audit|emit``."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from core.paths import safe_write_text
from core.supply_chain.audit import audit_dependencies
from core.supply_chain.sbom import build_sbom


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="python -m core.supply_chain")
    parser.add_argument("--root", default=".", help="Repository root containing pyproject.toml")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("audit", help="Check requirement metadata (not a CVE scan)")
    emit = sub.add_parser("emit", help="Write a CycloneDX SBOM")
    emit.add_argument("--output", required=True)
    args = parser.parse_args(argv)
    root = Path(args.root).resolve()
    if args.command == "audit":
        report = audit_dependencies(root)
        print(json.dumps(report, indent=2))
        return 0 if report["ok"] else 1
    if args.command == "emit":
        document = build_sbom(root)
        safe_write_text(args.output, json.dumps(document, indent=2) + "\n")
        print(json.dumps({"output": str(Path(args.output)), "components": len(document["components"])}))
        return 0
    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
