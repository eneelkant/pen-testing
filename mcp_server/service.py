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
from core.config import PlatformConfig
from core.diagnostics import collect_diagnostics
from core.findings import Finding
from core.findings.redaction import redact_secrets, redact_text
from core.net import redact_url_userinfo
from core.ops.retention import parse_retention_days
from core.scope.rate_limit import acquire_scan_slot, release_scan_slot
from core.paths import assert_no_symlink_in_chain, confine_path, is_under_roots, safe_read_text, safe_write_text
from core.reporting import export_json, export_markdown, export_sarif
from core.results import ExecutionResult
from core.scope import ScopeEngine
from integrations.base import AdapterRequest
from integrations.briar import BriarAdapter
from integrations.scanners import GitleaksAdapter, HeadersAdapter, TrivyAdapter
from integrations.shannon import ShannonAdapter
from mcp_server.config import assessments_dir, resolve_platform_config
from providers import list_provider_status

ACTIVE_TOOLS = {"shannon", "briar", "headers"}
LOCAL_PATH_TOOLS = {"gitleaks", "trivy"}
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
    roots = [Path(cfg.work_dir), Path(cfg.reports_dir), Path.cwd()]
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
    }


def platform_status() -> dict[str, Any]:
    cfg = resolve_platform_config()
    diag = collect_diagnostics(cfg)
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
    cfg = resolve_platform_config()
    missing: list[str] = []
    present: dict[str, Any] = {}
    for name in ("python3", "git", "node", "npx", "docker"):
        path = shutil.which(name if name != "python3" else "python3") or shutil.which("python")
        if name == "python3":
            path = sys.executable
        present[name] = path
        if name in {"docker"} and not path:
            missing.append("docker (required for Shannon workers)")
        if name in {"node", "npx"} and not path:
            missing.append(f"{name} (required for Shannon launcher)")
    try:
        import yaml  # noqa: F401
        import jsonschema  # noqa: F401

        present["pyyaml"] = True
        present["jsonschema"] = True
    except ImportError as exc:
        missing.append(str(exc))
    mcp_ok = False
    try:
        import mcp  # noqa: F401

        mcp_ok = True
    except ImportError:
        missing.append("mcp (install with: pip install 'pen-testing-platform[mcp]')")
    present["mcp"] = mcp_ok
    briar = BriarAdapter(cfg).healthcheck()
    shannon = ShannonAdapter(cfg).healthcheck()
    return {
        "ok": len(missing) == 0,
        "present": present,
        "missing": missing,
        "shannon": shannon,
        "briar": briar,
        "recommendations": collect_diagnostics(cfg).get("recommendations", []),
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
        items[name] = {
            "name": name,
            "version_pin": getattr(adapter, "version_pin", "unknown"),
            "requires_active_scope": getattr(adapter, "requires_active_scope", True),
            "health": health,
        }
    return {"integrations": items}


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


def _save_assessment(record: dict[str, Any]) -> Path:
    cfg = resolve_platform_config()
    safe_id = _safe_assessment_id(str(record.get("assessment_id", "")))
    if not safe_id:
        raise ValueError("assessment_id must be a UUID")
    record = redact_secrets(dict(record))
    record["assessment_id"] = safe_id
    path = assessments_dir(cfg) / f"{safe_id}.json"
    safe_write_text(path, json.dumps(record, indent=2))
    return path


def _load_assessment(assessment_id: str) -> dict[str, Any] | None:
    safe_id = _safe_assessment_id(assessment_id)
    if not safe_id:
        raise ValueError("assessment_id must be a UUID")
    path = assessments_dir() / f"{safe_id}.json"
    if not path.is_symlink() and not path.exists():
        return None
    try:
        raw = safe_read_text(path)
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

    cfg = resolve_platform_config()
    scope = None
    if Path(cfg.scopes_file).exists():
        scope = ScopeEngine.from_file(cfg.scopes_file)

    safe_target = redact_url_userinfo(target)
    scan_path = None
    if tool in LOCAL_PATH_TOOLS:
        confined = _confine_local_scan_path(cfg, target, repo_path)
        if isinstance(confined, dict):
            return confined
        scan_path = confined
        safe_target = scan_path

    assessment_id = str(uuid4())
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
        extra={"demo": briar_demo},
        output_dir=str(out_dir),
    )

    # Preflight scope for active/remote tools unless dry_run already handled inside adapter
    if tool in ACTIVE_TOOLS and not briar_demo and not dry_run:
        if scope is None:
            return {"ok": False, "error": "Authorization registry required for active assessments"}
        try:
            scope.require(
                target,
                test_category=category,
                require_non_production=not cfg.allow_production_active,
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

    slot = False
    if not dry_run:
        try:
            acquire_scan_slot()
            slot = True
        except PermissionError as exc:
            return {"ok": False, "assessment_id": assessment_id, "error": redact_text(str(exc))}
    try:
        result = adapter.run(request)
        findings = [f.to_dict() for f in result.findings]
        record = {
            "assessment_id": assessment_id,
            "tool": tool,
            "target": safe_target,
            "category": category,
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
    md = export_markdown(findings, dest / "report.md", metadata={"assessment_id": safe_id})
    js = export_json(findings, dest / "report.json", metadata={"assessment_id": safe_id})
    sarif = export_sarif(findings, dest / "report.sarif")
    return {
        "ok": True,
        "assessment_id": safe_id,
        "markdown": str(md),
        "json": str(js),
        "sarif": str(sarif),
        "human_review_required": True,
    }
