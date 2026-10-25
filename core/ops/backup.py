"""Backup and restore of local assessment and report files.

The archive is a directory of regular files plus ``manifest.json``. Symlinks
are not copied or restored. Paths in the manifest must stay relative. Restore
writes only under the caller-supplied roots. When ``PEN_DATA_KEY`` is set, file
bytes in the archive are encrypted. Nothing here deletes the source tree.

Create and restore are all-or-nothing for member contents: encryption and
checksum checks run before any destination file is replaced. A failed write
removes staging only and does not delete an existing valid archive.
"""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import uuid
from pathlib import Path

from core.ops.crypto import MAGIC, encryption_required, encryption_status, protect_text, reveal_text
from core.paths import (
    assert_no_symlink_in_chain,
    confine_path,
    safe_read_text,
    safe_write_text,
)

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


def _require_encryption_ready() -> dict[str, bool | str]:
    status = encryption_status()
    if status["state"] == "required-missing":
        raise PermissionError("PEN_REQUIRE_DATA_ENCRYPTION is set but PEN_DATA_KEY is missing")
    if status["state"] == "invalid-key":
        raise PermissionError("PEN_DATA_KEY is not a valid Fernet key")
    return status


def _replace_directory(staging: Path, dest: Path) -> None:
    """Commit ``staging`` onto ``dest``. On failure, restore the previous tree if possible."""
    backup: Path | None = None
    if dest.exists():
        backup = dest.parent / f".{dest.name}.prev-{uuid.uuid4().hex}"
        os.rename(str(dest), str(backup))
    try:
        os.rename(str(staging), str(dest))
    except Exception:
        if backup is not None and backup.exists() and not dest.exists():
            os.rename(str(backup), str(dest))
        raise
    if backup is not None:
        shutil.rmtree(backup, ignore_errors=True)


def create_backup(roots: list[Path], destination: Path, *, apply: bool) -> dict:
    """Write an archive under ``destination``. Dry-run unless ``apply`` is true."""
    dest = assert_no_symlink_in_chain(destination)
    if dest.exists() and not dest.is_dir():
        raise PermissionError("Backup destination must be a directory")
    _require_encryption_ready()
    files = _iter_files(roots)
    planned = []
    texts: list[str] = []
    for _root, path, name in files:
        raw = safe_read_text(path)
        texts.append(raw)
        planned.append(
            {
                "name": name,
                "sha256": hashlib.sha256(raw.encode("utf-8")).hexdigest(),
                "bytes": len(raw.encode("utf-8")),
            }
        )
    sealed_members = [protect_text(raw) for raw in texts]
    encrypted = bool(sealed_members) and all(item.startswith(MAGIC) for item in sealed_members)
    if sealed_members and encryption_status()["enabled"] and not encrypted:
        raise PermissionError("Backup members were not encrypted while PEN_DATA_KEY is set")
    report = {
        "ok": True,
        "apply": apply,
        "files": planned,
        "destination": str(dest),
        "encrypted": encrypted,
    }
    if not apply:
        return report

    staging = dest.parent / f".{dest.name}.staging-{uuid.uuid4().hex}"
    try:
        staging.mkdir(parents=True, exist_ok=False)
        file_dir = staging / "files"
        file_dir.mkdir(parents=True, exist_ok=False)
        manifest = {"files": planned, "encrypted": encrypted}
        for (_root, _path, name), sealed in zip(files, sealed_members):
            digest = hashlib.sha256(name.encode()).hexdigest()
            safe_write_text(file_dir / f"{digest}.txt", sealed)
        safe_write_text(staging / "manifest.json", json.dumps(manifest, indent=2) + "\n")
        _replace_directory(staging, dest)
    except Exception:
        if staging.exists():
            shutil.rmtree(staging, ignore_errors=True)
        raise
    report["written"] = len(planned)
    return report


def restore_backup(archive: Path, roots_by_label: dict[str, Path], *, apply: bool) -> dict:
    """Restore archive members into the matching root. Dry-run unless ``apply``.

    Every member is path-checked, decrypted, and checksum-verified before any
    destination file is replaced. Commit writes staging temps first, then
    ``os.replace`` each member. A failure before commit leaves live trees unchanged.
    """
    archive_dir = assert_no_symlink_in_chain(archive)
    manifest_path = archive_dir / "manifest.json"
    manifest = json.loads(safe_read_text(manifest_path))
    if not isinstance(manifest, dict) or not isinstance(manifest.get("files"), list):
        raise ValueError("Backup manifest is corrupt")
    if encryption_status()["state"] in {"required-missing", "invalid-key"}:
        _require_encryption_ready()
    require_cipher = bool(manifest.get("encrypted")) or encryption_required()

    planned: list[str] = []
    pending: list[tuple[Path, str]] = []
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
        digest = hashlib.sha256(name.encode()).hexdigest()
        sealed = safe_read_text(archive_dir / "files" / f"{digest}.txt")
        if require_cipher and not sealed.startswith(MAGIC):
            raise PermissionError(f"Refusing plaintext backup member while encryption is required: {name}")
        payload = reveal_text(sealed)
        actual = hashlib.sha256(payload.encode("utf-8")).hexdigest()
        if actual != item.get("sha256"):
            raise ValueError(f"Backup checksum mismatch for {name}")
        pending.append((target, payload))

    if not apply:
        return {"ok": True, "apply": apply, "files": planned}

    staged: list[Path] = []
    try:
        prepared: list[tuple[Path, Path]] = []
        for target, payload in pending:
            tmp = target.parent / f".{target.name}.restore-{uuid.uuid4().hex}"
            assert_no_symlink_in_chain(tmp.parent / tmp.name)
            safe_write_text(tmp, payload)
            staged.append(tmp)
            prepared.append((tmp, target))
        for tmp, target in prepared:
            os.replace(str(tmp), str(target))
            staged.remove(tmp)
    except Exception:
        for tmp in staged:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        raise
    return {"ok": True, "apply": apply, "files": planned}
