#!/usr/bin/env python3
"""Gemini client configuration helper.

Gemini surfaces differ (Gemini CLI vs IDE extensions vs web). This script emits
verified local stdio MCP snippets and optional Gemini CLI settings merge when
~/.gemini/settings.json exists. It does not assume all Gemini products share one format.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from client_config import (  # type: ignore
    SERVER_NAME,
    load_json,
    merge_mcp_servers,
    stdio_server_entry,
    write_json,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Configure Gemini MCP/settings for pen-testing")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--print-only", action="store_true")
    parser.add_argument("--apply-gemini-cli", action="store_true", help="Merge into ~/.gemini/settings.json if present/created")
    args = parser.parse_args(argv)

    repo = args.repo_root.resolve()
    entry = stdio_server_entry(args.python, repo)
    # Common local MCP-style shape used by several Gemini CLI builds
    gemini_settings_snippet = {
        "mcpServers": {
            SERVER_NAME: entry,
        }
    }

    guidance = {
        "intended_client": "Gemini CLI / local MCP-capable Gemini tooling",
        "not_covered": [
            "Gemini web chat does not load local stdio MCP from this file",
            "IDE-specific Gemini extensions may use different manifests",
        ],
        "manual_steps": [
            "Confirm your Gemini client documents MCP or extensions support",
            "Use the printed mcpServers entry with that client's required schema",
            "Prefer stdio local process; do not expose unauthenticated HTTP to the internet",
        ],
        "snippet": gemini_settings_snippet,
    }
    print(json.dumps(guidance, indent=2))

    if args.apply_gemini_cli:
        path = Path.home() / ".gemini" / "settings.json"
        existing = load_json(path)
        # Some Gemini CLI versions nest under mcpServers similarly to Claude.
        merged = merge_mcp_servers(existing, SERVER_NAME, entry)
        result = write_json(path, merged, do_backup=True)
        print(json.dumps({"wrote": result}, indent=2), file=sys.stderr)
        print("Verify against your installed Gemini CLI docs; schema may vary by version.", file=sys.stderr)
    elif not args.print_only:
        print("\n# Printed only. Use --apply-gemini-cli to write ~/.gemini/settings.json with backup.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
