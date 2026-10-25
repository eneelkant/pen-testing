"""Filesystem confinement helpers for scanners and exports."""

from __future__ import annotations

import os
import uuid
from pathlib import Path


def assert_no_symlink_in_chain(path: str | Path) -> Path:
    """Return an absolute path whose existing components are not symlinks.

    `O_NOFOLLOW` only applies to the final path component. Parent-directory
    symlinks still redirect writes and reads, so every existing component is
    rejected before open or mkdir.
    """
    absolute = Path(path).expanduser()
    if not absolute.is_absolute():
        absolute = Path.cwd() / absolute
    current = Path(absolute.anchor)
    for part in absolute.parts[1:]:
        if part in {"", "."}:
            continue
        if part == "..":
            parent = current.parent
            current = parent if str(parent) else current
            continue
        current = current / part
        try:
            if current.is_symlink():
                raise PermissionError(f"Refusing symlink path component: {current}")
        except PermissionError:
            raise
        except OSError as exc:
            raise PermissionError(f"Refusing unreadable path component: {current}") from exc
    return current


def is_under_roots(path: Path, roots: list[Path]) -> bool:
    resolved = path.expanduser().resolve()
    for root in roots:
        root_r = root.expanduser().resolve()
        if resolved == root_r or root_r in resolved.parents:
            return True
    return False


def confine_path(path: str | Path, roots: list[Path]) -> Path:
    """Resolve path and require it to stay under one of the allowed roots.

    Symlink components are refused before resolution so a link inside an allowed
    root cannot retarget the path outside that root.
    """
    candidate = assert_no_symlink_in_chain(path)
    if not is_under_roots(candidate, roots):
        allowed = ", ".join(str(r.resolve()) for r in roots)
        raise PermissionError(f"Path {candidate} is outside allowed roots: {allowed}")
    return candidate


def _write_temp_text(dest: Path, data: str, *, encoding: str = "utf-8") -> Path:
    """Write ``data`` to a new temp file beside ``dest`` without replacing ``dest``."""
    dest.parent.mkdir(parents=True, exist_ok=True)
    if dest.parent.is_symlink():
        raise PermissionError(f"Refusing to write through symlink: {dest}")
    tmp = dest.parent / f".{dest.name}.tmp-{uuid.uuid4().hex}"
    if tmp.exists() or tmp.is_symlink():
        raise PermissionError(f"Refusing to reuse temp path: {tmp}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(tmp), flags, 0o644)
    try:
        with os.fdopen(fd, "w", encoding=encoding) as handle:
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return tmp


def safe_write_text(path: str | Path, data: str, *, encoding: str = "utf-8") -> Path:
    """Atomically replace a regular file without following symlink path components.

    Bytes are written to a same-directory temp file, then ``os.replace`` commits
    them. A failure leaves the previous destination intact and removes only the
    temp file.
    """
    dest = assert_no_symlink_in_chain(path)
    if dest.is_symlink() or dest.parent.is_symlink():
        raise PermissionError(f"Refusing to write through symlink: {dest}")
    tmp = _write_temp_text(dest, data, encoding=encoding)
    try:
        os.replace(str(tmp), str(dest))
    except Exception:
        try:
            tmp.unlink(missing_ok=True)
        except OSError:
            pass
        raise
    return dest


def safe_read_text(path: str | Path, *, encoding: str = "utf-8") -> str:
    """Read a regular file without following a symlink in the path."""
    dest = assert_no_symlink_in_chain(path)
    if dest.is_symlink():
        raise PermissionError(f"Refusing to read through symlink: {dest}")
    if not dest.is_file():
        raise FileNotFoundError(dest)
    flags = os.O_RDONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(dest), flags)
    try:
        with os.fdopen(fd, "r", encoding=encoding) as handle:
            return handle.read()
    except Exception:
        raise
