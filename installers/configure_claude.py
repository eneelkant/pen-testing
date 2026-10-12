#!/usr/bin/env python3
"""Configure Claude Desktop local MCP (claude_desktop_config.json)."""

from __future__ import annotations

import argparse
import json
import os
import platform
import sys
from pathlib import Path

from client_config import (  # type: ignore
    SERVER_NAME,
    load_json,
    merge_mcp_servers,
    stdio_server_entry,
    write_json,
)


def default_claude_config_path() -> Path:
    system = platform.system()
    if system == "Darwin":
        return Path.home() / "Library/Application Support/Claude/claude_desktop_config.json"
    if system == "Windows":
        appdata = os.environ.get("APPDATA") or str(Path.home() / "AppData/Roaming")
        return Path(appdata) / "Claude" / "claude_desktop_config.json"
    # Linux / other: common fallback used by some builds
    return Path.home() / ".config/Claude/claude_desktop_config.json"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Configure Claude Desktop MCP for pen-testing")
    parser.add_argument("--repo-root", type=Path, default=Path(__file__).resolve().parents[1])
    parser.add_argument("--python", default=sys.executable)
    parser.add_argument("--config", type=Path, help="Override claude_desktop_config.json path")
    parser.add_argument("--print-only", action="store_true")
    parser.add_argument("--apply", action="store_true")
    args = parser.parse_args(argv)

    repo = args.repo_root.resolve()
    entry = stdio_server_entry(args.python, repo)
    snippet = {"mcpServers": {SERVER_NAME: entry}}
    path = args.config or default_claude_config_path()

    if args.print_only or not args.apply:
        print(json.dumps({"target": str(path), "snippet": snippet}, indent=2))
        if not args.apply:
            print("\n# Claude web app does not use this file; Desktop only.", file=sys.stderr)
            print("# Fully quit and reopen Claude Desktop after --apply.", file=sys.stderr)
        if args.print_only and not args.apply:
            return 0

    existing = load_json(path)
    merged = merge_mcp_servers(existing, SERVER_NAME, entry)
    result = write_json(path, merged, do_backup=True)
    print(json.dumps({"wrote": result, "server": SERVER_NAME}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
