"""MCP server configuration helpers."""

from __future__ import annotations

import os
from pathlib import Path

from core.config import PlatformConfig, load_config
from core.paths import assert_no_symlink_in_chain


def repo_root() -> Path:
    return Path(__file__).resolve().parents[1]


def resolve_platform_config() -> PlatformConfig:
    cfg_path = os.environ.get("PEN_PLATFORM_CONFIG")
    cfg = load_config(cfg_path)
    # Prefer repo-relative defaults when running from a clone
    root = repo_root()
    if not Path(cfg.scopes_file).is_absolute() and not Path(cfg.scopes_file).exists():
        candidate = root / cfg.scopes_file
        if candidate.exists():
            cfg.scopes_file = candidate
    cfg.ensure_dirs()
    return cfg


def assessments_dir(cfg: PlatformConfig | None = None) -> Path:
    cfg = cfg or resolve_platform_config()
    path = assert_no_symlink_in_chain(Path(cfg.work_dir) / "assessments")
    path.mkdir(parents=True, exist_ok=True)
    if path.is_symlink():
        raise PermissionError(f"Refusing symlink path component: {path}")
    return path
