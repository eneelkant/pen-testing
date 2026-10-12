"""Command-line entrypoint for the pen-testing platform."""

from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path

from core import __version__
from core.config import load_config
from core.net import redact_url_userinfo
from core.reporting import export_json, export_markdown, export_sarif, generate_daily_report
from core.scope import ScopeEngine
from integrations.briar import BriarAdapter
from integrations.scanners import GitleaksAdapter, HeadersAdapter, TrivyAdapter
from integrations.shannon import ShannonAdapter
from integrations.base import AdapterRequest
from providers import list_provider_status


def _skip_scope_allowed() -> bool:
    return os.environ.get("PEN_ALLOW_SKIP_SCOPE", "").strip().lower() in {"1", "true", "yes"}


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="pen-testing",
        description="Authorized security testing orchestration platform",
    )
    parser.add_argument("--version", action="version", version=__version__)
    parser.add_argument("--config", help="Path to platform YAML config")
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("doctor", help="Run environment diagnostics")
    sub.add_parser("providers", help="Show AI provider configuration status (no secrets)")

    p_scope = sub.add_parser("scope-check", help="Validate a target against the authorization registry")
    p_scope.add_argument("--target", required=True)
    p_scope.add_argument("--category", default="active")
    p_scope.add_argument("--scopes-file")

    p_health = sub.add_parser("health", help="Adapter health checks")
    p_health.add_argument("--tool", choices=["shannon", "briar", "headers", "gitleaks", "trivy", "all"], default="all")

    p_run = sub.add_parser("run", help="Run an adapter (requires authorization for active tools)")
    p_run.add_argument("--tool", required=True, choices=["shannon", "briar", "headers", "gitleaks", "trivy"])
    p_run.add_argument("--target", required=True, help="URL, host, or local path depending on tool")
    p_run.add_argument("--repo")
    p_run.add_argument("--mode", default="standard", help="Briar: quick|standard|deep")
    p_run.add_argument("--category", default="active")
    p_run.add_argument("--output")
    p_run.add_argument("--timeout", type=int)
    p_run.add_argument("--dry-run", action="store_true")
    p_run.add_argument("--demo", action="store_true", help="Briar built-in demo only")
    p_run.add_argument(
        "--skip-scope-check",
        action="store_true",
        help="Fixtures/tests only; also requires PEN_ALLOW_SKIP_SCOPE=1",
    )

    p_report = sub.add_parser("export-report", help="Export findings JSON to Markdown/SARIF")
    p_report.add_argument("--input", required=True, help="Findings JSON from a previous run")
    p_report.add_argument("--outdir", required=True)

    p_daily = sub.add_parser("daily-report", help="Generate a local daily research report stub")
    p_daily.add_argument("--output", default="reports/out/daily-report.md")

    return parser


def _adapters(config, scope):
    return {
        "shannon": ShannonAdapter(config, scope),
        "briar": BriarAdapter(config, scope),
        "headers": HeadersAdapter(config, scope),
        "gitleaks": GitleaksAdapter(config, scope),
        "trivy": TrivyAdapter(config, scope),
    }


def main(argv: list[str] | None = None) -> int:
    parser = _build_parser()
    args = parser.parse_args(argv)
    config = load_config(args.config)
    config.ensure_dirs()
    scope = None
    scopes_file = Path(getattr(args, "scopes_file", None) or config.scopes_file)
    if scopes_file.exists():
        scope = ScopeEngine.from_file(scopes_file)

    if args.command == "doctor":
        from core.diagnostics import run_doctor

        return run_doctor(config)

    if args.command == "providers":
        print(json.dumps(list_provider_status(), indent=2))
        return 0

    if args.command == "scope-check":
        if scope is None:
            print(f"ERROR: scopes file not found: {scopes_file}", file=sys.stderr)
            return 2
        decision = scope.evaluate(args.target, test_category=args.category)
        print(json.dumps(decision.to_dict(), indent=2))
        return 0 if decision.allowed else 1

    if args.command == "health":
        adapters = _adapters(config, scope)
        selected = adapters.keys() if args.tool == "all" else [args.tool]
        report = {name: adapters[name].healthcheck() for name in selected}
        print(json.dumps(report, indent=2))
        return 0

    if args.command == "run":
        if args.skip_scope_check and not _skip_scope_allowed():
            print(
                "ERROR: --skip-scope-check requires PEN_ALLOW_SKIP_SCOPE=1 "
                "(fixtures/tests only).",
                file=sys.stderr,
            )
            return 2
        if scope is None and not args.skip_scope_check and config.require_scope_for_active:
            if args.tool in {"shannon", "briar", "headers"}:
                print(
                    f"ERROR: authorization registry required for tool '{args.tool}' "
                    f"(missing {scopes_file})",
                    file=sys.stderr,
                )
                return 2
        adapters = _adapters(config, scope)
        adapter = adapters[args.tool]
        request = AdapterRequest(
            target=args.target,
            repo_path=args.repo,
            mode=args.mode,
            test_category=args.category,
            output_dir=args.output,
            timeout_seconds=args.timeout,
            dry_run=args.dry_run,
            skip_scope_check=bool(args.skip_scope_check and _skip_scope_allowed()),
            extra={"demo": bool(args.demo)},
        )
        result = adapter.run(request)
        # Avoid echoing credentials that may appear in URL userinfo.
        if isinstance(result.metadata, dict) and "target" in result.metadata:
            result.metadata["target"] = redact_url_userinfo(str(result.metadata["target"]))
        out = Path(args.output or config.reports_dir) / f"{args.tool}-{result.execution_id}.json"
        if args.output:
            out = Path(args.output)
            if out.is_dir() or str(args.output).endswith("/"):
                out = Path(args.output) / f"{args.tool}-{result.execution_id}.json"
        export_json(result.findings, out, metadata=result.to_dict())
        print(json.dumps({"status": result.status, "execution_id": result.execution_id, "report": str(out), "findings": len(result.findings), "error": result.error}, indent=2))
        return 0 if result.status in {"succeeded", "skipped"} else 1

    if args.command == "export-report":
        data = json.loads(Path(args.input).read_text(encoding="utf-8"))
        from core.findings import Finding

        findings_data = data.get("findings", data if isinstance(data, list) else [])
        findings = [Finding.from_dict(x) for x in findings_data]
        outdir = Path(args.outdir)
        md = export_markdown(findings, outdir / "report.md", metadata=data.get("metadata"))
        js = export_json(findings, outdir / "report.json", metadata=data.get("metadata"))
        sarif = export_sarif(findings, outdir / "report.sarif")
        print(json.dumps({"markdown": str(md), "json": str(js), "sarif": str(sarif)}, indent=2))
        return 0

    if args.command == "daily-report":
        path = generate_daily_report(output_path=args.output)
        print(json.dumps({"report": str(path)}, indent=2))
        return 0

    parser.error(f"Unknown command: {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
