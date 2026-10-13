"""Briar execution-mode helpers (Compose network vs uncontained host).

Compose mode places the Briar process on platform networks (`pen-scanner-isolated`
or `pen-scanner-live`). Host mode shares the operator host network namespace and is
fail-closed unless explicitly acknowledged.
"""

from __future__ import annotations

import os
from pathlib import Path
from typing import Literal

BriarExecMode = Literal["compose", "host"]


def resolve_briar_exec_mode(raw: str | None = None) -> BriarExecMode:
    value = (raw if raw is not None else os.environ.get("PEN_BRIAR_EXEC", "compose") or "compose")
    mode = value.strip().lower()
    if mode not in {"compose", "host"}:
        raise ValueError(
            f"Invalid PEN_BRIAR_EXEC={value!r}; expected 'compose' (default) or 'host'"
        )
    return mode  # type: ignore[return-value]


def find_compose_dir(explicit: str | Path | None = None) -> Path:
    if explicit is not None:
        root = Path(explicit).resolve()
    else:
        env = os.environ.get("PEN_COMPOSE_DIR")
        root = Path(env).resolve() if env else Path.cwd().resolve()
    compose = root / "docker-compose.yml"
    if not compose.is_file():
        raise FileNotFoundError(
            f"docker-compose.yml not found under {root}. "
            "Set PEN_COMPOSE_DIR to the repository root."
        )
    return root


def build_compose_briar_command(
    *,
    briar_args: list[str],
    out_dir: Path,
    live: bool,
    compose_dir: Path | None = None,
) -> list[str]:
    """Build `docker compose run …` argv for the Briar worker image.

    Live scans use profile `live-workers` / service `briar-live` (pen-scanner-live).
    Non-live (demo / isolated smoke) uses profile `workers` / service `briar`
    (pen-scanner-isolated, internal:true).
    """
    root = find_compose_dir(compose_dir)
    out_dir = out_dir.resolve()
    out_dir.mkdir(parents=True, exist_ok=True)
    profile = "live-workers" if live else "workers"
    service = "briar-live" if live else "briar"
    # Bind-mount the host output directory so findings land on the host without
    # relying on the anonymous pen_reports volume alone.
    return [
        "docker",
        "compose",
        "--project-directory",
        str(root),
        "--profile",
        profile,
        "run",
        "--rm",
        "--no-deps",
        "-v",
        f"{out_dir}:/work/out",
        service,
        *briar_args,
    ]


def rewrite_paths_for_compose(briar_args: list[str], *, out_dir: Path, json_out: Path) -> list[str]:
    """Rewrite -o / --output-json host paths to the in-container bind mount."""
    out_dir = out_dir.resolve()
    json_out = json_out.resolve()
    container_out = "/work/out"
    container_json = f"/work/out/{json_out.name}"
    rewritten: list[str] = []
    i = 0
    while i < len(briar_args):
        arg = briar_args[i]
        if arg in {"-o", "--output"} and i + 1 < len(briar_args):
            rewritten.extend([arg, container_out])
            i += 2
            continue
        if arg == "--output-json" and i + 1 < len(briar_args):
            rewritten.extend([arg, container_json])
            i += 2
            continue
        # Skip host absolute paths that match out_dir when passed positionally.
        if arg == str(out_dir):
            rewritten.append(container_out)
            i += 1
            continue
        if arg == str(json_out):
            rewritten.append(container_json)
            i += 1
            continue
        rewritten.append(arg)
        i += 1
    return rewritten
