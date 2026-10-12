"""Shared helpers for AI client MCP configuration (backup + merge)."""

from __future__ import annotations

import json
import shutil
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


SERVER_NAME = "pen-testing"


def stdio_server_entry(python_exe: str, repo_root: Path) -> dict[str, Any]:
    return {
        "command": python_exe,
        "args": ["-m", "mcp_server.server"],
        "env": {
            "PYTHONPATH": str(repo_root),
            "PEN_SCOPES_FILE": str(repo_root / "scopes" / "registry.yaml"),
        },
    }


def cursor_server_entry(python_exe: str, repo_root: Path) -> dict[str, Any]:
    entry = stdio_server_entry(python_exe, repo_root)
    entry["type"] = "stdio"
    entry["envFile"] = str(repo_root / ".env")
    return entry


def backup_file(path: Path) -> Path | None:
    if not path.exists():
        return None
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    backup = path.with_name(f"{path.name}.bak.{stamp}")
    shutil.copy2(path, backup)
    return backup


def merge_mcp_servers(existing: dict[str, Any], name: str, entry: dict[str, Any]) -> dict[str, Any]:
    data = dict(existing) if existing else {}
    servers = dict(data.get("mcpServers") or {})
    # Preserve unrelated servers; replace only our named entry.
    servers[name] = entry
    data["mcpServers"] = servers
    return data


def write_json(path: Path, data: dict[str, Any], *, do_backup: bool = True) -> dict[str, Any]:
    path.parent.mkdir(parents=True, exist_ok=True)
    backup = backup_file(path) if do_backup else None
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return {"path": str(path), "backup": str(backup) if backup else None}


def load_json(path: Path) -> dict[str, Any]:
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))
