#!/usr/bin/env python3
"""Detect image-sensitive changes without hiding required GitHub status contexts.

The workflow itself runs on every PR/push. This classifier gates only expensive
image scan jobs; an unknown comparison base triggers a full scan.
"""
from __future__ import annotations

import argparse
import json
import subprocess
import sys
from pathlib import PurePosixPath
from typing import Iterable

SENSITIVE_EXACT_PATHS = frozenset(
    {
        "Dockerfile",
        ".dockerignore",
        "docker-compose.yml",
        "pyproject.toml",
        "uv.lock",
        "poetry.lock",
        "Pipfile.lock",
        "package-lock.json",
        "pnpm-lock.yaml",
        "yarn.lock",
        "go.mod",
        "go.sum",
        "Cargo.lock",
        "scripts/docker_runtime_verify.sh",
        "scripts/verify_image_candidate.py",
        "scripts/verify_self_built_candidates.sh",
        "scripts/shannon_e2e_verify.sh",
        "scripts/shannon_net_prepare.sh",
        "scripts/detect_image_sensitive_changes.py",
        "scripts/image_gate_status.py",
        ".github/workflows/image-gates.yml",
        ".github/workflows/release.yml",
        ".github/workflows/self-built-image-candidates.yml",
        "tests/unit/test_image_gate_workflow_helpers.py",
    }
)
SENSITIVE_PREFIXES = (
    "docker/",
    "core/supply_chain/",
    "requirements/",
    "integrations/scanners/",
    "integrations/shannon/",
    "integrations/briar/",
    ".github/actions/",
)


def normalize_path(value: str) -> str:
    """Normalize a Git path without resolving it against the host filesystem."""
    path = value.replace("\\", "/").strip()
    while path.startswith("./"):
        path = path[2:]
    return path.lstrip("/")


def is_image_sensitive_path(value: str) -> bool:
    path = normalize_path(value)
    if not path or path in {".", ".."}:
        return False
    if path.startswith("<unknown-base:"):
        return True
    if path in SENSITIVE_EXACT_PATHS:
        return True
    if path.startswith(SENSITIVE_PREFIXES):
        return True
    if path.startswith("docker-compose.") and path.endswith((".yml", ".yaml")):
        return True
    name = PurePosixPath(path).name.lower()
    if "/" not in path and name.startswith("requirements") and name.endswith((".txt", ".in")):
        return True
    return False


def classify_paths(paths: Iterable[str]) -> tuple[bool, list[str]]:
    matched: list[str] = []
    seen: set[str] = set()
    for raw in paths:
        path = normalize_path(raw)
        if path and path not in seen and is_image_sensitive_path(path):
            seen.add(path)
            matched.append(path)
    return bool(matched), matched


def changed_paths(base_sha: str, head_sha: str) -> list[str]:
    if not base_sha or not head_sha:
        raise ValueError("Both base and head commit SHAs are required")
    if not head_sha.strip() or set(head_sha) == {"0"}:
        raise ValueError("Head SHA is missing or is the all-zero sentinel")
    if set(base_sha) == {"0"}:
        # First push/new branch: no reliable comparison base. Run the full gate.
        return ["<unknown-base:full-image-gate-required>"]
    completed = subprocess.run(
        ["git", "diff", "--name-only", "--no-renames", "-z", base_sha, head_sha],
        check=True,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    return [
        part.decode("utf-8", errors="surrogateescape")
        for part in completed.stdout.split(b"\0")
        if part
    ]


def write_github_output(path: str, needs_gate: bool, matched: list[str]) -> None:
    with open(path, "a", encoding="utf-8") as handle:
        handle.write(f"needs_image_gate={'true' if needs_gate else 'false'}\n")
        handle.write(f"changed_sensitive_files_json={json.dumps(matched, ensure_ascii=True)}\n")


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--base", required=True, help="Base/before commit SHA")
    parser.add_argument("--head", required=True, help="Head/after commit SHA")
    parser.add_argument("--github-output", help="Append outputs to a GitHub Actions output file")
    args = parser.parse_args()
    try:
        paths = changed_paths(args.base, args.head)
    except (ValueError, subprocess.CalledProcessError) as exc:
        print(f"::error::Unable to determine changed files safely: {exc}", file=sys.stderr)
        return 2
    needs_gate, matched = classify_paths(paths)
    print(f"needs_image_gate={'true' if needs_gate else 'false'}")
    print(f"changed_sensitive_files={json.dumps(matched, ensure_ascii=True)}")
    if args.github_output:
        write_github_output(args.github_output, needs_gate, matched)
    if not needs_gate:
        print("No image-sensitive paths changed; scan jobs are not applicable.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
