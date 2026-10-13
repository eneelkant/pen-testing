"""Unit tests for Briar Compose execution helpers."""

from __future__ import annotations

from pathlib import Path

import pytest

from core.isolation.briar_exec import (
    build_compose_briar_command,
    find_compose_dir,
    resolve_briar_exec_mode,
    rewrite_paths_for_compose,
)


def test_resolve_briar_exec_mode_default(monkeypatch):
    monkeypatch.delenv("PEN_BRIAR_EXEC", raising=False)
    assert resolve_briar_exec_mode() == "compose"


def test_resolve_briar_exec_mode_invalid():
    with pytest.raises(ValueError, match="PEN_BRIAR_EXEC"):
        resolve_briar_exec_mode("containers")


def test_find_compose_dir_repo_root():
    root = Path(__file__).resolve().parents[2]
    assert find_compose_dir(root) == root


def test_build_compose_briar_command_live(tmp_path: Path):
    root = Path(__file__).resolve().parents[2]
    out = tmp_path / "out"
    cmd = build_compose_briar_command(
        briar_args=["scan", "-u", "http://fixture-headers:8080/", "-o", "/work/out"],
        out_dir=out,
        live=True,
        compose_dir=root,
    )
    assert cmd[:2] == ["docker", "compose"]
    assert "--profile" in cmd and "live-workers" in cmd
    assert "briar-live" in cmd
    assert f"{out.resolve()}:/work/out" in " ".join(cmd)


def test_build_compose_briar_command_isolated(tmp_path: Path):
    root = Path(__file__).resolve().parents[2]
    cmd = build_compose_briar_command(
        briar_args=["demo"],
        out_dir=tmp_path / "out",
        live=False,
        compose_dir=root,
    )
    assert "workers" in cmd
    assert "briar" in cmd
    assert "briar-live" not in cmd


def test_rewrite_paths_for_compose(tmp_path: Path):
    out = (tmp_path / "reports").resolve()
    out.mkdir()
    json_out = out / "findings.json"
    args = ["scan", "-u", "http://x/", "-o", str(out), "--output-json", str(json_out)]
    rewritten = rewrite_paths_for_compose(args, out_dir=out, json_out=json_out)
    assert rewritten[rewritten.index("-o") + 1] == "/work/out"
    assert rewritten[rewritten.index("--output-json") + 1] == "/work/out/findings.json"
