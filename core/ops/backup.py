"""Backup and restore of local assessment and report files.

The archive is a directory of regular files plus ``manifest.json``. Symlinks
are not copied or restored. Paths in the manifest must stay relative. Restore
writes only under the caller-supplied roots. When ``PEN_DATA_KEY`` is set, file
bytes in the archive are encrypted. Nothing here deletes the source tree.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path

from core.ops.crypto import protect_text, reveal_text
from core.paths import assert_no_symlink_in_chain, confine_path, safe_read_text, safe_write_text

_ARTIFACT_SUFFIXES = {".json", ".md", ".sarif", ".log"}


def _iter_files(roots: list[Path]) -> list[tuple[Path, Path, str]]:
    found: list[tuple[Path, Path, str]] = []
    for root in roots:
        checked = assert_no_symlink_in_chain(root)
        if not checked.exists():
            continue
        if not checked.is_dir():
            raise PermissionError(f"Backup root is not a directory: {checked}")
        label = checked.name
        for path in sorted(checked.rglob("*")):
            if path.is_symlink():
                continue
            if not path.is_file():
                continue
            if path.suffix.lower() not in _ARTIFACT_SUFFIXES:
                continue
            relative = path.relative_to(checked)
            if any(part in {"..", ""} for part in relative.parts):
                raise PermissionError(f"Refusing backup path: {relative}")
            found.append((checked, path, f"{label}/{relative.as_posix()}"))
    return found


def create_backup(roots: list[Path], destination: Path, *, apply: bool) -> dict:
    """Write an archive under ``destination``. Dry-run unless ``apply`` is true."""
    dest = assert_no_symlink_in_chain(destination)
    if dest.exists() and not dest.is_dir():
        raise PermissionError("Backup destination must be a directory")
    files = _iter_files(roots)
    planned = []
    texts: list[str] = []
    for _root, path, name in files:
        raw = path.read_text(encoding="utf-8")
        texts.append(raw)
        planned.append(
            {
                "name": name,
                "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "bytes": len(raw.encode("utf-8")),
            }
        )
    report = {"ok": True, "apply": apply, "files": planned, "destination": str(dest)}
    if not apply:
        return report
    dest.mkdir(parents=True, exist_ok=True)
    manifest = {"files": planned, "encrypted": False}
    file_dir = dest / "files"
    file_dir.mkdir(parents=True, exist_ok=True)
    for (_root, path, name), raw in zip(files, texts):
        sealed = protect_text(raw)
        manifest["encrypted"] = sealed.startswith("PENENC1")
        safe_write_text(file_dir / f"{hashlib.sha256(name.encode()).hexdigest()}.txt", sealed)
    safe_write_text(dest / "manifest.json", json.dumps(manifest, indent=2) + "\n")
    report["written"] = len(planned)
    return report


def restore_backup(archive: Path, roots_by_label: dict[str, Path], *, apply: bool) -> dict:
    """Restore archive members into the matching root. Dry-run unless ``apply``."""
    archive_dir = assert_no_symlink_in_chain(archive)
    manifest_path = archive_dir / "manifest.json"
    manifest = json.loads(safe_read_text(manifest_path))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("Backup manifest is corrupt")
    planned: list[str] = []
    for item in manifest["files"]:
        name = str(item.get("name") or "")
        if not name or name.startswith("/") or ".." in Path(name).parts:
            raise PermissionError(f"Refusing restore path: {name}")
        label, _sep, relative = name.partition("/")
        if not relative or label not in roots_by_label:
            raise PermissionError(f"Refusing restore path: {name}")
        target_root = assert_no_symlink_in_chain(roots_by_label[label])
        target = confine_path(target_root / relative, [target_root])
        planned.append(str(target))
        if not apply:
            continue
        digest = hashlib.sha256(name.encode()).hexdigest()
        payload = reveal_text(safe_read_text(archive_dir / "files" / f"{digest}.txt"))
        actual = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if actual != item.get("sha256"):
            raise ValueError(f"Backup checksum mismatch for {name}")
        safe_write_text(target, payload)
    return {"ok": True, "apply": apply, "files": planned}
