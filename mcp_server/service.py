"""Business logic for MCP tools — no arbitrary shell/network exposure."""

from __future__ import annotations

import json
import platform
import re
import shutil
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from uuid import UUID, uuid4

from core import __version__
from core.assessment.profile import (
    AssessmentProfile,
    load_assessment_profile,
    resolve_profile_path,
    validate_profile_request,
)
from core.capabilities import get_capability, list_capabilities
from core.config import PlatformConfig
from core.diagnostics import collect_diagnostics
from core.findings import Finding, ValidationStatus
from core.findings.evidence import assess_evidence
from core.findings.redaction import redact_secrets, redact_text
from core.net import redact_url_userinfo
from core.ops.retention import parse_retention_days
from core.scope.rate_limit import acquire_scan_slot, release_scan_slot
from core.ops.crypto import protect_text, reveal_text
from core.paths import assert_no_symlink_in_chain, confine_path, is_under_roots, safe_read_text, safe_write_text
from core.reporting import export_json, export_markdown, export_sarif
from core.results import ExecutionResult
from core.scope import (
    ScopeEngine,
    get_approval_store,
    plan_fingerprint,
)
from integrations.base import AdapterRequest
from integrations.briar import BriarAdapter
from integrations.scanners import CheckovAdapter, GitleaksAdapter, HeadersAdapter, MobSFScanAdapter, TrivyAdapter
from integrations.shannon import ShannonAdapter
from mcp_server.config import assessments_dir, resolve_platform_config
from providers import list_provider_status

ACTIVE_TOOLS = {"shannon", "briar", "headers"}
LOCAL_PATH_TOOLS = {"gitleaks", "trivy", "checkov", "mobsfscan"}
ALLOWED_TOOLS = ACTIVE_TOOLS | LOCAL_PATH_TOOLS
_ASSESSMENT_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def _utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def _safe_assessment_id(assessment_id: str) -> str | None:
    if not assessment_id or not _ASSESSMENT_ID_RE.match(assessment_id.strip()):
        return None
    try:
        return str(UUID(assessment_id.strip()))
    except ValueError:
        return None


def _safe_outdir(cfg: PlatformConfig, outdir: str | None, assessment_id: str) -> Path | dict[str, Any]:
    """Confine report exports under reports_dir / work_dir without following symlinks."""
    try:
        reports_root = assert_no_symlink_in_chain(Path(cfg.reports_dir))
        work_root = assert_no_symlink_in_chain(Path(cfg.work_dir))
        if outdir is None:
            dest = reports_root / f"export-{assessment_id}"
        else:
            dest = Path(outdir).expanduser()
        dest = assert_no_symlink_in_chain(dest)
    except PermissionError as exc:
        return {"ok": False, "error": str(exc)}
    if not is_under_roots(dest, [reports_root, work_root]):
        return {
            "ok": False,
            "error": f"outdir must be inside reports_dir ({reports_root}) or work_dir ({work_root})",
        }
    dest.mkdir(parents=True, exist_ok=True)
    if dest.is_symlink():
        return {"ok": False, "error": f"Refusing symlink path component: {dest}"}
    return dest


def _looks_like_url_or_path(target: str, tool: str | None = None) -> tuple[bool, str]:
    text = (target or "").strip()
    if not text:
        return False, "Target is empty"
    # Local scanners may accept filesystem paths under confined roots only.
    if tool in LOCAL_PATH_TOOLS:
        if text.startswith(("http://", "https://")):
            return False, "Local scanners require a filesystem path, not an http(s) URL"
        return True, "ok"
    parsed = urlparse(text)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False, "Target must be an absolute http(s) URL with a hostname"
    return True, "ok"


def _confine_local_scan_path(cfg: PlatformConfig, target: str, repo_path: str | None) -> str | dict[str, Any]:
    # MCP must not treat the process cwd as an authorized scan root. Operators
    # scanning arbitrary trees use the CLI adapters, which keep their own roots.
    roots = [Path(cfg.work_dir), Path(cfg.reports_dir)]
    try:
        return str(confine_path(repo_path or target, roots))
    except PermissionError as exc:
        return {"ok": False, "error": str(exc)}


def _adapters(cfg: PlatformConfig, scope: ScopeEngine | None) -> dict[str, Any]:
    return {
        "shannon": ShannonAdapter(cfg, scope),
        "briar": BriarAdapter(cfg, scope),
        "headers": HeadersAdapter(cfg, scope),
        "gitleaks": GitleaksAdapter(cfg, scope),
        "trivy": TrivyAdapter(cfg, scope),
        "checkov": CheckovAdapter(cfg, scope),
        "mobsfscan": MobSFScanAdapter(cfg, scope),
    }


def platform_status() -> dict[str, Any]:
    cfg = resolve_platform_config()
    diag = collect_diagnostics(cfg)
    deps = check_dependencies()
    # Preserve the full diagnostics collector output while adding a stable,
    # machine-readable readiness summary for MCP clients.
    diag = dict(diag)
    diag.update({
        # Keep collect_diagnostics()["tools"] intact: it includes daemon and
        # Compose health, not just executable paths.
        "dependency_tools": deps["present"],
        "core_ok": deps["core_ok"],
        "active_engines_ready": deps["active_engines_ready"],
        "missing_core": deps["missing_core"],
        "missing_engines": deps["missing_engines"],
        "optional_absent": deps["optional_absent"],
        "engines": deps["engines"],
        # Compatibility: this legacy field has always been engine-oriented
        # in this endpoint. The scope is now explicit; use all_dependency_failures
        # for a combined core + engine list.
        "dependency_failures": deps["missing_engines"],
        "dependency_failures_scope": "engine_prerequisites_only",
        "core_dependency_failures": deps["missing_core"],
        "all_dependency_failures": [*deps["missing_core"], *deps["missing_engines"]],
        "unhealthy_integrations": [
            name for name, healthy in deps["engines"].items() if not healthy
        ],
    })
    return {
        "ok": True,
        "platform_version": __version__,
        "python": sys.version.split()[0],
        "system": platform.system(),
        "machine": platform.machine(),
        "diagnostics": diag,
        "providers": list_provider_status(),
        "retention": _retention_status(),
        "note": "Active scans are never started by status checks. Status does not delete artifacts.",
    }


def _retention_status() -> dict[str, Any]:
    import os

    raw = os.environ.get("PEN_ASSESSMENT_RETENTION_DAYS")
    try:
        days = parse_retention_days(raw)
    except ValueError as exc:
        return {"enabled": False, "error": str(exc)}
    return {
        "enabled": days is not None,
        "days": days,
        "automatic": False,
        "note": "Operator CLI `pen-testing cleanup` is dry-run unless --apply is set.",
    }


def check_dependencies() -> dict[str, Any]:
    """Report core MCP runtime requirements separately from engine prerequisites.

    Executable paths are resolved independently; a missing binary never inherits
    the path of a different executable. This is a PATH/prerequisite check, not a
    guarantee that the Docker daemon is running or that a live assessment works.
    """
    tools = {
        "python3": sys.executable,
        "git": shutil.which("git"),
        "node": shutil.which("node"),
        "npx": shutil.which("npx"),
        "docker": shutil.which("docker"),
    }
    present: dict[str, Any] = dict(tools)
    missing_core: list[str] = []
    missing_engines: list[str] = []
    optional_absent: list[str] = []

    if not sys.executable:
        missing_core.append("python3 executable missing")

    if not present["git"]:
        optional_absent.append("git is missing from PATH (optional)")
    for name in ("docker", "node", "npx"):
        if not present[name]:
            missing_engines.append(f"{name} is missing from PATH")

    # These imports are part of the MCP runtime, unlike optional scanner CLIs.
    for module, display in (
        ("yaml", "pyyaml"),
        ("jsonschema", "jsonschema"),
        ("mcp", "mcp"),
    ):
        try:
            __import__(module)
            present[display] = True
        except ImportError:
            present[display] = False
            missing_core.append(
                f"{display} is unavailable (install the MCP runtime dependencies)"
            )

    shannon_status = check_shannon_health()
    briar_status = check_briar_health()
    engines = {
        "shannon": bool(shannon_status.get("healthy", False)),
        "briar": bool(briar_status.get("healthy", False)),
    }
    core_ok = not missing_core
    active_engines_ready = all(engines.values())
    recommendations: list[str] = []
    if missing_engines:
        recommendations.append(
            f"Install missing engine binaries: {', '.join(missing_engines)}"
        )
    if not active_engines_ready:
        recommendations.append("Check Shannon and Briar engine prerequisites")

    return {
        # Legacy fields remain available to existing clients.
        "ok": core_ok,
        "present": present,
        "missing": [*missing_core, *missing_engines],
        "shannon": shannon_status,
        "briar": briar_status,
        "recommendations": recommendations,
        # Additive readiness fields.
        "core_ok": core_ok,
        "active_engines_ready": active_engines_ready,
        "missing_core": missing_core,
        "missing_engines": missing_engines,
        "optional_absent": optional_absent,
        "engines": engines,
        "note": (
            "ok indicates core MCP runtime readiness; active_engines_ready "
            "indicates Shannon/Briar executable prerequisites are present."
        ),
    }


def check_shannon_health() -> dict[str, Any]:
    """Check PATH prerequisites for the Shannon worker launcher."""
    has_docker = shutil.which("docker") is not None
    has_node = shutil.which("node") is not None
    has_npx = shutil.which("npx") is not None
    healthy = has_docker and has_node and has_npx
    missing = [
        name for name, available in (
            ("docker", has_docker), ("node", has_node), ("npx", has_npx)
        ) if not available
    ]
    return {
        "healthy": healthy,
        "details": "Ready" if healthy else f"Missing from PATH: {', '.join(missing)}",
    }


def check_briar_health() -> dict[str, Any]:
    """Check the Docker executable prerequisite for Briar."""
    has_docker = shutil.which("docker") is not None
    return {
        "healthy": has_docker,
        "details": "Ready" if has_docker else "Docker required for live execution",
    }


def validate_target_scope(target: str, category: str = "active") -> dict[str, Any]:
    ok, reason = _looks_like_url_or_path(target)
    if not ok:
        return {
            "allowed": False,
            "reason": reason,
            "target": target,
            "category": category,
            "policy_reference": "",
            "decided_at": _utcnow(),
            "matched_record": None,
        }
    cfg = resolve_platform_config()
    scopes = Path(cfg.scopes_file)
    if not scopes.exists():
        return {
            "allowed": False,
            "reason": f"Authorization registry not found: {scopes}",
            "target": target,
            "category": category,
            "policy_reference": "",
            "decided_at": _utcnow(),
            "matched_record": None,
        }
    engine = ScopeEngine.from_file(scopes)
    decision = engine.evaluate(target, test_category=category)
    return {"target": target, "category": category, **decision.to_dict()}


def list_integrations() -> dict[str, Any]:
    cfg = resolve_platform_config()
    scope = ScopeEngine.from_file(cfg.scopes_file) if Path(cfg.scopes_file).exists() else ScopeEngine([])
    adapters = _adapters(cfg, scope)
    items = {}
    for name, adapter in adapters.items():
        health = adapter.healthcheck()
        capability = get_capability(name) or {
            "tool_id": name,
            "status": "unregistered",
            "implemented": False,
            "target_types": [],
            "modes": [],
            "source_url": "",
            "license": "unknown",
            "notes": "Adapter is not represented in the capability registry.",
        }
        items[name] = {
            **capability,
            "name": name,
            "version_pin": getattr(adapter, "version_pin", "unknown"),
            "requires_active_scope": getattr(adapter, "requires_active_scope", True),
            "health": health,
        }
    planned = [
        item for item in list_capabilities(include_planned=True)
        if item["status"] == "planned"
    ]
    return {
        "integrations": items,
        "planned_capabilities": planned,
        "note": "Planned entries are informational only and cannot be dispatched. Runtime availability is determined by each adapter health check.",
    }


def run_local_diagnostics() -> dict[str, Any]:
    status = platform_status()
    deps = check_dependencies()
    integrations = list_integrations()
    return {
        "ok": True,
        "status": status,
        "dependencies": deps,
        "integrations": {
            name: {
                "healthy": data["health"].get("healthy"),
                "errors": data["health"].get("errors", []),
            }
            for name, data in integrations["integrations"].items()
        },
        "destructive": False,
    }


def _load_optional_profile(
    profile_id: str | None,
) -> tuple[AssessmentProfile | None, dict[str, Any] | None]:
    if not profile_id:
        return None, None
    try:
        path = resolve_profile_path(profile_id)
        return load_assessment_profile(path), None
    except (OSError, ValueError) as exc:
        return None, {"ok": False, "error": redact_text(str(exc))}


def plan_assessment(
    *,
    tool: str,
    target: str,
    category: str = "active",
    mode: str = "standard",
    profile_id: str | None = None,
    repo_path: str | None = None,
    timeout_seconds: int | None = 120,
) -> dict[str, Any]:
    """Build an execution plan without launching any scanner."""
    tool = (tool or "").lower().strip()
    if tool not in ALLOWED_TOOLS:
        return {"ok": False, "error": f"Unsupported tool '{tool}'. Allowed: {sorted(ALLOWED_TOOLS)}"}
    ok_target, target_reason = _looks_like_url_or_path(target, tool=tool)
    if not ok_target:
        return {"ok": False, "error": target_reason}
    if timeout_seconds is not None and (timeout_seconds < 1 or timeout_seconds > 86_400):
        return {"ok": False, "error": "timeout_seconds must be between 1 and 86400"}

    profile, profile_err = _load_optional_profile(profile_id)
    if profile_err:
        return profile_err
    if profile is not None:
        try:
            validate_profile_request(
                profile,
                tool=tool,
                category=category,
                target=target,
                dry_run=True,
                timeout_seconds=timeout_seconds,
            )
        except PermissionError as exc:
            return {"ok": False, "error": redact_text(str(exc))}

    cfg = resolve_platform_config()
    scope_decision = None
    if tool in ACTIVE_TOOLS and Path(cfg.scopes_file).exists():
        engine = ScopeEngine.from_file(cfg.scopes_file)
        scope_decision = engine.evaluate(target, test_category=category).to_dict()

    fingerprint = plan_fingerprint(
        tool=tool,
        target=target,
        category=category,
        mode=mode,
        profile_id=(profile.profile_id if profile else "") or "",
    )
    return {
        "ok": True,
        "launches_scanner": False,
        "dry_run_default": True,
        "tool": tool,
        "target": redact_url_userinfo(target),
        "category": category,
        "mode": mode,
        "profile_id": profile.profile_id if profile else None,
        "timeout_seconds": timeout_seconds,
        "repo_path_provided": bool(repo_path),
        "scope": scope_decision,
        "plan_fingerprint": fingerprint,
        "note": "Planning never starts a scanner. Live execution requires authorize_assessment + confirm_authorized.",
    }


def authorize_assessment(
    *,
    tool: str,
    target: str,
    category: str = "active",
    mode: str = "standard",
    profile_id: str | None = None,
    ttl_seconds: int = 900,
    confirm_authorized: bool = False,
) -> dict[str, Any]:
    """Issue a bound, single-use live-execution approval after scope/profile checks."""
    if not confirm_authorized:
        return {
            "ok": False,
            "error": "authorize_assessment requires confirm_authorized=true after a successful scope check",
        }
    tool = (tool or "").lower().strip()
    if tool not in ALLOWED_TOOLS:
        return {"ok": False, "error": f"Unsupported tool '{tool}'. Allowed: {sorted(ALLOWED_TOOLS)}"}
    ok_target, target_reason = _looks_like_url_or_path(target, tool=tool)
    if not ok_target:
        return {"ok": False, "error": target_reason}

    profile, profile_err = _load_optional_profile(profile_id)
    if profile_err:
        return profile_err
    resolved_profile_id = profile.profile_id if profile else ""
    if profile is not None:
        try:
            validate_profile_request(
                profile,
                tool=tool,
                category=category,
                target=target,
                dry_run=False,
            )
        except PermissionError as exc:
            return {"ok": False, "error": redact_text(str(exc))}

    cfg = resolve_platform_config()
    scope_target_id = ""
    if tool in ACTIVE_TOOLS:
        if not Path(cfg.scopes_file).exists():
            return {"ok": False, "error": "Authorization registry required for active assessments"}
        engine = ScopeEngine.from_file(cfg.scopes_file)
        try:
            decision = engine.require(
                target,
                test_category=category,
                require_non_production=not cfg.allow_production_active,
                for_live_execution=True,
            )
        except PermissionError as exc:
            return {"ok": False, "error": redact_text(str(exc))}
        scope_target_id = decision.matched_record.target_id if decision.matched_record else ""

    fingerprint = plan_fingerprint(
        tool=tool,
        target=target,
        category=category,
        mode=mode,
        profile_id=resolved_profile_id,
    )
    try:
        grant = get_approval_store().issue(
            target=target,
            tool=tool,
            category=category,
            mode=mode,
            profile_id=resolved_profile_id,
            plan_fingerprint=fingerprint,
            ttl_seconds=ttl_seconds,
            scope_target_id=scope_target_id,
        )
    except (ValueError, PermissionError) as exc:
        return {"ok": False, "error": redact_text(str(exc))}
    return {
        "ok": True,
        "approval_id": grant.approval_id,
        "expires_at": grant.expires_at,
        "plan_fingerprint": grant.plan_fingerprint,
        "tool": grant.tool,
        "target": grant.target,
        "category": grant.category,
        "mode": grant.mode,
        "profile_id": grant.profile_id or None,
        "single_use": grant.single_use,
        "note": "Approval is bound to this plan and expires. It cannot be reused for another target or tool.",
    }


def _postprocess_findings(
    findings: list[dict[str, Any]],
    *,
    assessment_id: str,
    target: str,
    scope: ScopeEngine | None,
    category: str,
) -> list[dict[str, Any]]:
    """Enforce validation_status defaults and block out-of-scope assets from reporting."""
    in_scope: list[str] | None = None
    if scope is not None:
        decision = scope.evaluate(target, test_category=category)
        if decision.matched_record is not None:
            in_scope = list(decision.matched_record.allowed_assets)

    processed: list[dict[str, Any]] = []
    for raw in findings:
        finding = Finding.from_dict(raw)
        finding.assessment_id = assessment_id
        if finding.validation_status == ValidationStatus.VALIDATED.value:
            # Scanner output must not self-validate.
            finding.validation_status = ValidationStatus.NEEDS_REVIEW.value
        evidence_decision = assess_evidence(
            finding,
            assessment_id=assessment_id,
            in_scope_assets=in_scope,
            require_primary=False,
        )
        if evidence_decision.status == ValidationStatus.BLOCKED.value:
            finding.validation_status = ValidationStatus.BLOCKED.value
        elif finding.validation_status == ValidationStatus.CANDIDATE.value:
            # Keep candidate unless evidence policy raised needs_review/rejected.
            if evidence_decision.status in {
                ValidationStatus.NEEDS_REVIEW.value,
                ValidationStatus.REJECTED.value,
            }:
                finding.validation_status = evidence_decision.status
        processed.append(finding.to_dict())
    return processed


def _save_assessment(record: dict[str, Any]) -> Path:
    cfg = resolve_platform_config()
    safe_id = _safe_assessment_id(str(record.get("assessment_id", "")))
    if not safe_id:
        raise ValueError("assessment_id must be a UUID")
    record = redact_secrets(dict(record))
    record["assessment_id"] = safe_id
    path = assessments_dir(cfg) / f"{safe_id}.json"
    safe_write_text(path, protect_text(json.dumps(record, indent=2)))
    return path


def _load_assessment(assessment_id: str) -> dict[str, Any] | None:
    safe_id = _safe_assessment_id(assessment_id)
    if not safe_id:
        raise ValueError("assessment_id must be a UUID")
    path = assessments_dir() / f"{safe_id}.json"
    if not path.is_symlink() and not path.exists():
        return None
    try:
        raw = reveal_text(safe_read_text(path))
    except PermissionError:
        raise
    except FileNotFoundError:
        return None
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise ValueError("Assessment record is corrupt") from exc
    if not isinstance(data, dict):
        raise ValueError("Assessment record is corrupt")
    return data


def _assessment_error(exc: Exception) -> dict[str, Any]:
    if isinstance(exc, PermissionError):
        return {"ok": False, "error": "Refusing to access assessment path through a symlink"}
    if isinstance(exc, ValueError):
        return {"ok": False, "error": str(exc)}
    return {"ok": False, "error": "Assessment record could not be read"}


def run_security_assessment(
    *,
    tool: str,
    target: str,
    category: str = "active",
    mode: str = "standard",
    repo_path: str | None = None,
    dry_run: bool = True,
    confirm_authorized: bool = False,
    demo: bool = False,
    timeout_seconds: int | None = 120,
    profile_id: str | None = None,
    approval_id: str | None = None,
) -> dict[str, Any]:
    tool = tool.lower().strip()
    if tool not in ALLOWED_TOOLS:
        return {"ok": False, "error": f"Unsupported tool '{tool}'. Allowed: {sorted(ALLOWED_TOOLS)}"}

    # demo=true is a Briar-only local smoke path; it must not waive confirm_authorized
    # for Shannon/headers/other active tools.
    briar_demo = bool(demo and tool == "briar")
    if not dry_run and not confirm_authorized and not briar_demo:
        return {
            "ok": False,
            "error": "Non-dry-run assessments require confirm_authorized=true after a successful scope check.",
        }

    ok_target, target_reason = _looks_like_url_or_path(target, tool=tool)
    if not ok_target:
        return {"ok": False, "error": target_reason}

    if timeout_seconds is not None and (timeout_seconds < 1 or timeout_seconds > 86_400):
        return {"ok": False, "error": "timeout_seconds must be between 1 and 86400"}

    profile, profile_err = _load_optional_profile(profile_id)
    if profile_err:
        return profile_err
    resolved_profile_id = profile.profile_id if profile else ""
    if profile is not None:
        try:
            validate_profile_request(
                profile,
                tool=tool,
                category=category,
                target=target,
                dry_run=dry_run,
                timeout_seconds=timeout_seconds,
            )
        except PermissionError as exc:
            return {"ok": False, "error": redact_text(str(exc))}

    cfg = resolve_platform_config()
    scope = None
    if Path(cfg.scopes_file).exists():
        scope = ScopeEngine.from_file(cfg.scopes_file)

    fingerprint = plan_fingerprint(
        tool=tool,
        target=target,
        category=category,
        mode=mode,
        profile_id=resolved_profile_id,
    )

    safe_target = redact_url_userinfo(target)
    scan_path = None
    if tool in LOCAL_PATH_TOOLS:
        confined = _confine_local_scan_path(cfg, target, repo_path)
        if isinstance(confined, dict):
            return confined
        scan_path = confined
        safe_target = scan_path

    assessment_id = str(uuid4())

    # Preflight scope for active/remote tools before consuming a bound approval.
    if tool in ACTIVE_TOOLS and not briar_demo and not dry_run:
        if scope is None:
            return {"ok": False, "error": "Authorization registry required for active assessments"}
        try:
            scope.require(
                target,
                test_category=category,
                require_non_production=not cfg.allow_production_active,
                for_live_execution=True,
            )
        except PermissionError as exc:
            record = {
                "assessment_id": assessment_id,
                "tool": tool,
                "target": target,
                "status": "blocked",
                "error": str(exc),
                "created_at": _utcnow(),
                "findings": [],
            }
            try:
                _save_assessment(record)
            except (PermissionError, ValueError) as save_exc:
                failure = _assessment_error(save_exc)
                failure.update({"assessment_id": assessment_id, "status": "blocked"})
                return failure
            return {
                "ok": False,
                "assessment_id": assessment_id,
                "status": "blocked",
                "error": redact_text(str(exc)),
            }

    if not dry_run and not briar_demo:
        try:
            get_approval_store().consume(
                approval_id or "",
                target=target,
                tool=tool,
                category=category,
                mode=mode,
                profile_id=resolved_profile_id,
                plan_fingerprint=fingerprint,
            )
        except PermissionError as exc:
            return {
                "ok": False,
                "assessment_id": assessment_id,
                "error": redact_text(str(exc)),
                "hint": "Call plan_assessment then authorize_assessment to obtain a bound approval_id.",
            }

    adapters = _adapters(cfg, scope)
    adapter = adapters[tool]
    # Confine generated artifacts under reports_dir.
    out_dir = Path(cfg.reports_dir).resolve() / f"mcp-{assessment_id}"
    request = AdapterRequest(
        target=scan_path or target,
        test_category=category,
        mode=mode,
        repo_path=scan_path or repo_path,
        dry_run=dry_run,
        timeout_seconds=timeout_seconds,
        skip_scope_check=briar_demo,
        extra={"demo": briar_demo, "profile_id": resolved_profile_id or None},
        output_dir=str(out_dir),
    )

    slot = False
    if not dry_run:
        try:
            acquire_scan_slot()
            slot = True
        except PermissionError as exc:
            return {"ok": False, "assessment_id": assessment_id, "error": redact_text(str(exc))}
    try:
        result = adapter.run(request)
        findings = _postprocess_findings(
            [f.to_dict() for f in result.findings],
            assessment_id=assessment_id,
            target=scan_path or target,
            scope=scope,
            category=category,
        )
        record = {
            "assessment_id": assessment_id,
            "tool": tool,
            "target": safe_target,
            "category": category,
            "mode": mode,
            "profile_id": resolved_profile_id or None,
            "approval_id": approval_id,
            "plan_fingerprint": fingerprint,
            "dry_run": dry_run,
            "demo": briar_demo,
            "status": result.status,
            "error": redact_text(result.error) if isinstance(result.error, str) else result.error,
            "execution_id": result.execution_id,
            "artifacts": result.artifacts,
            "metadata": result.metadata,
            "findings": findings,
            "created_at": _utcnow(),
            "updated_at": _utcnow(),
        }
        try:
            _save_assessment(record)
        except (PermissionError, ValueError) as exc:
            failure = _assessment_error(exc)
            failure["assessment_id"] = assessment_id
            return failure
        return {
            "ok": result.status in {"succeeded", "skipped"},
            "assessment_id": assessment_id,
            "status": result.status,
            "error": redact_text(result.error) if isinstance(result.error, str) else result.error,
            "findings_count": len(findings),
            "dry_run": dry_run,
            "profile_id": resolved_profile_id or None,
            "note": "Upstream engines may navigate beyond the initial URL; scope preflight is not full containment.",
        }
    finally:
        if slot:
            release_scan_slot()


def get_assessment_status(assessment_id: str) -> dict[str, Any]:
    safe_id = _safe_assessment_id(assessment_id)
    if not safe_id:
        return {"ok": False, "error": "assessment_id must be a UUID"}
    try:
        record = _load_assessment(safe_id)
    except (PermissionError, ValueError) as exc:
        return _assessment_error(exc)
    if not record:
        return {"ok": False, "error": f"Assessment not found: {safe_id}"}
    return {
        "ok": True,
        "assessment_id": safe_id,
        "status": record.get("status"),
        "tool": record.get("tool"),
        "target": record.get("target"),
        "dry_run": record.get("dry_run"),
        "error": record.get("error"),
        "findings_count": len(record.get("findings") or []),
        "created_at": record.get("created_at"),
        "updated_at": record.get("updated_at"),
        "artifacts": record.get("artifacts") or {},
    }


def list_findings(assessment_id: str) -> dict[str, Any]:
    safe_id = _safe_assessment_id(assessment_id)
    if not safe_id:
        return {"ok": False, "error": "assessment_id must be a UUID"}
    try:
        record = _load_assessment(safe_id)
    except (PermissionError, ValueError) as exc:
        return _assessment_error(exc)
    if not record:
        return {"ok": False, "error": f"Assessment not found: {safe_id}"}
    return {
        "ok": True,
        "assessment_id": safe_id,
        "status": record.get("status"),
        "findings": record.get("findings") or [],
    }


def export_report(assessment_id: str, outdir: str | None = None) -> dict[str, Any]:
    safe_id = _safe_assessment_id(assessment_id)
    if not safe_id:
        return {"ok": False, "error": "assessment_id must be a UUID"}
    try:
        record = _load_assessment(safe_id)
    except (PermissionError, ValueError) as exc:
        return _assessment_error(exc)
    if not record:
        return {"ok": False, "error": f"Assessment not found: {safe_id}"}
    cfg = resolve_platform_config()
    dest = _safe_outdir(cfg, outdir, safe_id)
    if isinstance(dest, dict):
        return dest
    findings = [Finding.from_dict(f) for f in record.get("findings") or []]
    metadata = {
        "assessment_id": safe_id,
        "tool": record.get("tool"),
        "tool_version": (record.get("metadata") or {}).get("tool_version"),
        "profile_id": record.get("profile_id"),
        "scope": record.get("target"),
        "dry_run": record.get("dry_run"),
        "limitations": (
            "Upstream engines may navigate beyond the initial URL. "
            "Do not auto-submit. Scanner severity is not confirmation."
        ),
        "untested_areas": (
            "Only the selected tool/profile capabilities were exercised. "
            "Excluded Zoho program categories and unapproved hosts were not tested."
        ),
    }
    md = export_markdown(findings, dest / "report.md", metadata=metadata)
    js = export_json(findings, dest / "report.json", metadata=metadata)
    sarif = export_sarif(findings, dest / "report.sarif")
    return {
        "ok": True,
        "assessment_id": safe_id,
        "markdown": str(md),
        "json": str(js),
        "sarif": str(sarif),
        "human_review_required": True,
        "auto_submit": False,
    }
