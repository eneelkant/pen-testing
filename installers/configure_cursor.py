#!/usr/bin/env python3
"""Configure Cursor project or global MCP entry for pen-testing."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from client_config import (  # type: ignore  # same directory when run as a script
    SERVER_NAME,
    cursor_server_entry,
    load_json,
    merge_mcp_servers,
    write_json,
)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Configure Cursor MCP for pen-testing")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--global", dest="global_cfg", action="store_true", help="Write ~/.cursor/mcp.json")
    parser.add_argument("--print-only", action="store_true")
    parser.add_argument("--apply", action="store_true", help="Write config (with backup)")
    args = parser.parse_args(argv)

    repo = args.repo_root.resolve()
    entry = cursor_server_entry(args.python, repo)
    snippet = {"mcpServers": {SERVER_NAME: entry}}

    if args.print_only or not args.apply:
        print(json.dumps(snippet, indent=2))
        if not args.apply:
            print("\n# Dry view only. Re-run with --apply to write (creates backups).", file=sys.stderr)
        if args.print_only and not args.apply:
            return 0

    if args.global_cfg:
        path = Path.home() / ".cursor" / "mcp.json"
    else:
        path = repo / ".cursor" / "mcp.json"

    existing = load_json(path)
    merged = merge_mcp_servers(existing, SERVER_NAME, entry)
    result = write_json(path, merged, do_backup=True)
    print(json.dumps({"wrote": result, "server": SERVER_NAME}, indent=2))
    print("Restart Cursor or reload MCP after applying.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
