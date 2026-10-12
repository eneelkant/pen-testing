"""Filesystem confinement helpers for scanners and exports."""

from __future__ import annotations

import os
from pathlib import Path


def is_under_roots(path: Path, roots: list[Path]) -> bool:
    resolved = path.expanduser().resolve()
    for root in roots:
        root_r = root.expanduser().resolve()
        if resolved == root_r or root_r in resolved.parents:
            return True
    return False


def confine_path(path: str | Path, roots: list[Path]) -> Path:
    """Resolve path and require it to stay under one of the allowed roots."""
    candidate = Path(path).expanduser().resolve()
    if not is_under_roots(candidate, roots):
        allowed = ", ".join(str(r.resolve()) for r in roots)
        raise PermissionError(f"Path {candidate} is outside allowed roots: {allowed}")
    return candidate


def safe_write_text(path: str | Path, data: str, *, encoding: str = "utf-8") -> Path:
    """Write text without following a final-path symlink (O_NOFOLLOW).

    Parent directories are created normally. If `path` already exists as a symlink,
    the write is refused so exports cannot be redirected outside intended dirs.
    """
    dest = Path(path)
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        raise PermissionError(f"Refusing to write through symlink: {dest}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(dest), flags, 0o644)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(data)
    except Exception:
        # fd is owned by fdopen on success; on open failure we never get here.
        raise
    return dest
