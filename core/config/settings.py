"""Shared configuration loading for the platform."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml


@dataclass
class PlatformConfig:
    work_dir: Path = field(default_factory=lambda: Path("workspaces"))
    reports_dir: Path = field(default_factory=lambda: Path("reports/out"))
    scopes_file: Path = field(default_factory=lambda: Path("scopes/registry.yaml"))
    default_timeout_seconds: int = 3600
    shannon_package: str = "@keygraph/shannon@3.4.0"
    briar_package: str = "briar-pentest==0.4.62"
    require_scope_for_active: bool = True
    allow_production_active: bool = False
    max_log_bytes: int = 2_000_000
    env: dict[str, str] = field(default_factory=dict)

    def ensure_dirs(self) -> None:
        self.work_dir.mkdir(parents=True, exist_ok=True)
        self.reports_dir.mkdir(parents=True, exist_ok=True)


def _env(name: str, default: str | None = None) -> str | None:
    value = os.environ.get(name)
    if value is None or value == "":
        return default
    return value


def load_config(path: str | Path | None = None) -> PlatformConfig:
    data: dict[str, Any] = {}
    if path:
        cfg_path = Path(path)
        if cfg_path.exists():
            loaded = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
            if not isinstance(loaded, dict):
                raise ValueError("Config root must be a mapping")
            data = loaded

    cfg = PlatformConfig(
        work_dir=Path(_env("PEN_WORK_DIR", data.get("work_dir", "workspaces"))),
        reports_dir=Path(_env("PEN_REPORTS_DIR", data.get("reports_dir", "reports/out"))),
        scopes_file=Path(_env("PEN_SCOPES_FILE", data.get("scopes_file", "scopes/registry.yaml"))),
        default_timeout_seconds=int(
            _env("PEN_DEFAULT_TIMEOUT", str(data.get("default_timeout_seconds", 3600)))
        ),
        shannon_package=_env("PEN_SHANNON_PACKAGE", data.get("shannon_package", "@keygraph/shannon@3.4.0"))
        or "@keygraph/shannon@3.4.0",
        briar_package=_env("PEN_BRIAR_PACKAGE", data.get("briar_package", "briar-pentest==0.4.62"))
        or "briar-pentest==0.4.62",
        require_scope_for_active=str(
            _env("PEN_REQUIRE_SCOPE", str(data.get("require_scope_for_active", True)))
        ).lower()
        in {"1", "true", "yes"},
        allow_production_active=str(
            _env("PEN_ALLOW_PRODUCTION_ACTIVE", str(data.get("allow_production_active", False)))
        ).lower()
        in {"1", "true", "yes"},
        max_log_bytes=int(_env("PEN_MAX_LOG_BYTES", str(data.get("max_log_bytes", 2_000_000)))),
    )

    # Capture provider-related env names without storing secret values in logs by default.
    for key in (
        "ANTHROPIC_API_KEY",
        "OPENAI_API_KEY",
        "XAI_API_KEY",
        "AWS_ACCESS_KEY_ID",
        "AWS_SECRET_ACCESS_KEY",
        "DEEPSEEK_API_KEY",
        "GROQ_API_KEY",
        "MISTRAL_API_KEY",
        "GOOGLE_API_KEY",
        "OPENROUTER_API_KEY",
        "TOGETHER_API_KEY",
        "OLLAMA_HOST",
    ):
        if os.environ.get(key):
            cfg.env[key] = "[SET]"
    return cfg
