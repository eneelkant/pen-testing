"""Delete expired local artifacts without following symlinks.

Cleanup is explicit. Nothing here runs from status checks or MCP tools.
"""

from __future__ import annotations

import os
import stat
from datetime import datetime, timedelta, timezone
from pathlib import Path

from core.paths import assert_no_symlink_in_chain

DEFAULT_RETENTION_DAYS = 14
_ARTIFACT_SUFFIXES = {".json", ".md", ".sarif", ".log"}
_DISABLED = {"off", "disabled", "none"}


def _secure_unlink(path: Path) -> None:
    """Overwrite a regular file, then unlink it.

    ``O_NOFOLLOW`` refuses a final-component symlink. Overwrite reduces leftover
    plaintext on some filesystems. It is not a guarantee on SSDs, snapshots, or
    copies that already left this directory.
    """
    flags = os.O_WRONLY
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    fd = os.open(str(path), flags)
    try:
        size = os.fstat(fd).st_size
        remaining = size
        chunk = b"\0" * 65536
        while remaining > 0:
            written = os.write(fd, chunk[: min(len(chunk), remaining)])
            if written <= 0:
                raise OSError(f"short write while erasing {path}")
            remaining -= written
        os.fsync(fd)
    finally:
        os.close(fd)
    path.unlink()


def parse_retention_days(raw: str | None) -> int | None:
    """Return a day count, or None when retention cleanup is disabled.

    Empty input uses the default. ``off`` / ``disabled`` / ``none`` disables
    cleanup. ``0`` expires every matching file immediately.
    """
    if raw is None or raw.strip() == "":
        return DEFAULT_RETENTION_DAYS
    if raw.strip().lower() in _DISABLED:
        return None
    try:
        days = int(raw.strip())
    except ValueError as exc:
        raise ValueError(
            "PEN_ASSESSMENT_RETENTION_DAYS must be an integer from 0 to 3650, or off"
        ) from exc
    if days < 0 or days > 3650:
        raise ValueError(
            "PEN_ASSESSMENT_RETENTION_DAYS must be an integer from 0 to 3650, or off"
        )
    return days


def cleanup_expired_files(
    roots: list[Path],
    *,
    now: datetime,
    max_age_days: int,
    apply: bool,
) -> dict:
    """Remove regular artifact files under ``roots`` older than ``max_age_days``.

    Symlinks are skipped, not followed and not unlinked. Directory symlinks are
    not descended into. A root that is itself a symlink is reported as an error
    and left untouched.
    """
    if now.tzinfo is None:
        raise ValueError("now must be timezone-aware")
    if max_age_days < 0:
        raise ValueError("max_age_days must be >= 0")
    cutoff = now - timedelta(days=max_age_days)
    candidates: list[str] = []
    deleted: list[str] = []
    kept = 0
    skipped_symlinks = 0
    errors: list[str] = []

    for root in roots:
        try:
            checked = assert_no_symlink_in_chain(root)
        except PermissionError as exc:
            errors.append(str(exc))
            continue
        if not checked.exists():
            continue
        if not checked.is_dir():
            errors.append(f"Retention root is not a directory: {checked}")
            continue
        for dirpath, dirnames, filenames in os.walk(checked, followlinks=False):
            current = Path(dirpath)
            # Do not descend through a directory symlink if one appears.
            kept_dirs = []
            for name in dirnames:
                child = current / name
                if child.is_symlink():
                    skipped_symlinks += 1
                else:
                    kept_dirs.append(name)
            dirnames[:] = kept_dirs
            for name in filenames:
                full = current / name
                if full.is_symlink():
                    skipped_symlinks += 1
                    continue
                if full.suffix.lower() not in _ARTIFACT_SUFFIXES:
                    continue
                try:
                    st = full.lstat()
                except OSError as exc:
                    errors.append(f"{full}: {exc}")
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                mtime = datetime.fromtimestamp(st.st_mtime, timezone.utc)
                if mtime > cutoff:
                    kept += 1
                    continue
                try:
                    assert_no_symlink_in_chain(full)
                except PermissionError:
                    skipped_symlinks += 1
                    continue
                candidates.append(str(full))
                if not apply:
                    continue
                try:
                    _secure_unlink(full)
                    deleted.append(str(full))
                except OSError as exc:
                    errors.append(f"{full}: {exc}")

    return {
        "ok": not errors,
        "apply": apply,
        "max_age_days": max_age_days,
        "candidates": candidates,
        "deleted": deleted,
        "kept": kept,
        "skipped_symlinks": skipped_symlinks,
        "errors": errors,
    }
