"""Filesystem confinement helpers for scanners and exports."""

from __future__ import annotations

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
