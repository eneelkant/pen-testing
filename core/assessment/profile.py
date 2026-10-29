"""Assessment profiles constrain which capabilities may be planned or executed.

Profiles do not authorize targets by themselves. Scope registry checks remain
mandatory for remote/active tools. Live execution remains disabled unless a
profile explicitly sets ``live_execution_enabled: true`` *and* a bound approval
is presented at runtime.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

DEFAULT_PROFILES_DIR = Path("configs/assessment_profiles")


@dataclass(frozen=True)
class AssessmentProfile:
    profile_id: str
    display_name: str
    description: str = ""
    live_execution_enabled: bool = False
    program_reference: str = ""
    allowed_tools: tuple[str, ...] = ()
    allowed_capabilities: tuple[str, ...] = ()
    prohibited_capabilities: tuple[str, ...] = ()
    allowed_categories: tuple[str, ...] = ("passive",)
    prohibited_actions: tuple[str, ...] = ()
    require_synthetic_targets: bool = True
    synthetic_target_suffixes: tuple[str, ...] = (".test", ".invalid", ".localhost", ".local")
    max_timeout_seconds: int = 120
    notes: str = ""
    policy_version: str = "1"

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["allowed_tools"] = list(self.allowed_tools)
        data["allowed_capabilities"] = list(self.allowed_capabilities)
        data["prohibited_capabilities"] = list(self.prohibited_capabilities)
        data["allowed_categories"] = list(self.allowed_categories)
        data["prohibited_actions"] = list(self.prohibited_actions)
        data["synthetic_target_suffixes"] = list(self.synthetic_target_suffixes)
        return data


def _as_tuple(value: Any, *, field_name: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        raise ValueError(f"{field_name} must be a list")
    out: list[str] = []
    for item in value:
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{field_name} entries must be non-empty strings")
        out.append(item.strip().lower())
    return tuple(out)


def load_assessment_profile(path: str | Path) -> AssessmentProfile:
    cfg_path = Path(path)
    if not cfg_path.exists():
        raise FileNotFoundError(f"Assessment profile not found: {cfg_path}")
    raw = yaml.safe_load(cfg_path.read_text(encoding="utf-8")) or {}
    if not isinstance(raw, dict):
        raise ValueError("Assessment profile root must be a mapping")
    profile_id = str(raw.get("profile_id") or "").strip().lower()
    if not profile_id:
        raise ValueError("profile_id is required")
    display_name = str(raw.get("display_name") or profile_id).strip()
    return AssessmentProfile(
        profile_id=profile_id,
        display_name=display_name,
        description=str(raw.get("description") or ""),
        live_execution_enabled=bool(raw.get("live_execution_enabled", False)),
        program_reference=str(raw.get("program_reference") or ""),
        allowed_tools=_as_tuple(raw.get("allowed_tools"), field_name="allowed_tools"),
        allowed_capabilities=_as_tuple(
            raw.get("allowed_capabilities"), field_name="allowed_capabilities"
        ),
        prohibited_capabilities=_as_tuple(
            raw.get("prohibited_capabilities"), field_name="prohibited_capabilities"
        ),
        allowed_categories=_as_tuple(raw.get("allowed_categories"), field_name="allowed_categories")
        or ("passive",),
        prohibited_actions=_as_tuple(raw.get("prohibited_actions"), field_name="prohibited_actions"),
        require_synthetic_targets=bool(raw.get("require_synthetic_targets", True)),
        synthetic_target_suffixes=_as_tuple(
            raw.get("synthetic_target_suffixes"), field_name="synthetic_target_suffixes"
        )
        or (".test", ".invalid", ".localhost", ".local"),
        max_timeout_seconds=int(raw.get("max_timeout_seconds", 120)),
        notes=str(raw.get("notes") or ""),
        policy_version=str(raw.get("policy_version") or "1"),
    )


def resolve_profile_path(profile_id: str, *, profiles_dir: str | Path | None = None) -> Path:
    root = Path(profiles_dir) if profiles_dir else DEFAULT_PROFILES_DIR
    safe = (profile_id or "").strip().lower()
    if not safe or "/" in safe or "\\" in safe or ".." in safe:
        raise ValueError("Invalid profile_id")
    path = root / f"{safe}.yaml"
    if not path.exists():
        # Allow .yml as a secondary convention.
        alt = root / f"{safe}.yml"
        if alt.exists():
            return alt
        raise FileNotFoundError(f"Assessment profile not found: {path}")
    return path


def _host_from_target(target: str) -> str | None:
    text = (target or "").strip().lower()
    if text.startswith(("http://", "https://")):
        from urllib.parse import urlparse

        return (urlparse(text).hostname or "").lower().rstrip(".")
    return None


def validate_profile_request(
    profile: AssessmentProfile,
    *,
    tool: str,
    category: str,
    target: str,
    capability: str | None = None,
    dry_run: bool = True,
    timeout_seconds: int | None = None,
) -> None:
    """Raise PermissionError when a request violates the assessment profile."""
    tool_l = (tool or "").strip().lower()
    category_l = (category or "").strip().lower()
    if profile.allowed_tools and tool_l not in profile.allowed_tools:
        raise PermissionError(f"Tool '{tool_l}' is not permitted by profile '{profile.profile_id}'")
    if category_l not in {c.lower() for c in profile.allowed_categories}:
        raise PermissionError(
            f"Category '{category_l}' is not permitted by profile '{profile.profile_id}'"
        )
    cap = (capability or f"{tool_l}.{category_l}").strip().lower()
    if profile.prohibited_capabilities and cap in profile.prohibited_capabilities:
        raise PermissionError(f"Capability '{cap}' is prohibited by profile '{profile.profile_id}'")
    if profile.allowed_capabilities and cap not in profile.allowed_capabilities:
        # Also accept tool-level capability ids such as "headers".
        if tool_l not in profile.allowed_capabilities and cap not in profile.allowed_capabilities:
            raise PermissionError(
                f"Capability '{cap}' is not listed in profile '{profile.profile_id}'"
            )
    if not dry_run and not profile.live_execution_enabled:
        raise PermissionError(
            f"Profile '{profile.profile_id}' has live_execution_enabled=false"
        )
    if timeout_seconds is not None and timeout_seconds > profile.max_timeout_seconds:
        raise PermissionError(
            f"timeout_seconds exceeds profile maximum ({profile.max_timeout_seconds})"
        )
    if profile.require_synthetic_targets:
        host = _host_from_target(target)
        if host:
            # Loopback literals are treated as synthetic for local fixtures.
            if host in {"localhost", "127.0.0.1", "::1"}:
                return
            if not any(host == suf.lstrip(".") or host.endswith(suf) for suf in profile.synthetic_target_suffixes):
                raise PermissionError(
                    f"Profile '{profile.profile_id}' only permits synthetic fixture targets"
                )
