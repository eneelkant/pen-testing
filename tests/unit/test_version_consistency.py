"""Release metadata stays on one version after the 0.2.0a13 merge."""

from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
_MARKERS = ("<<<<<<<", "=======", ">>>>>>>")


def test_package_mcp_and_changelog_versions_match():
    from core import __version__
    from mcp_server import __version__ as mcp_package_version
    from mcp_server.server import mcp

    project = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    assert project["project"]["version"] == "0.2.0a16"
    assert __version__ == "0.2.0a16"
    assert mcp_package_version == __version__
    assert mcp._lowlevel_server.version == __version__
    assert (
        changelog.index("## 0.2.0a16")
        < changelog.index("## 0.2.0a15")
        < changelog.index("## 0.2.0a14")
        < changelog.index("## 0.2.0a13")
    )
    assert "destination policy" in changelog
    assert "PEN_ALLOW_SHANNON_FULL_PIPELINE" in changelog


def test_repository_text_has_no_conflict_markers():
    offenders: list[str] = []
    for path in ROOT.rglob("*"):
        if not path.is_file():
            continue
        if any(part in {".git", ".venv", "__pycache__", "node_modules"} for part in path.parts):
            continue
        if path.suffix.lower() not in {".py", ".md", ".toml", ".yml", ".yaml", ".txt", ".sh"}:
            continue
        text = path.read_text(encoding="utf-8", errors="replace")
        for line in text.splitlines():
            if line.startswith(_MARKERS):
                offenders.append(f"{path.relative_to(ROOT)}: {line[:40]}")
                break
    assert offenders == []
