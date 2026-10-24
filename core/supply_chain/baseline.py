"""Merge regression gate for pinned images (policy Option B).

The absolute gate (``python -m core.supply_chain images``) is unchanged and is
the release gate (Option A): any fixed HIGH/CRITICAL or unscored finding fails
it. This module adds a *separate* merge check that fails only on blocking
findings that are not recorded in a reviewed, digest-bound, expiring baseline.

A baseline entry records inherited risk. It is not a waiver, does not declare a
finding harmless or fixed, and never changes the absolute result. Reports list
every inherited finding with its baseline expiry.

Fail-closed rules (every one turns the regression gate red):

* the scan is NOT_VERIFIED, or its raw Trivy document is missing or does not
  align with the canonical classifier output;
* the baseline file is missing, malformed, has unknown/duplicate fields or
  findings, lacks provenance or owner approval, was approved on stale evidence,
  is valid for more than 31 days, or has expired;
* a failing image has no entry for its exact index digest, or the entry's
  platform digest / platform / scanner version differ from the scan;
* any current blocking finding is not in the entry (including findings added by
  a vulnerability-database update).

Images that pass the absolute gate need no entry. A changed digest never
inherits an older entry: entries match on the exact pinned reference.
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import subprocess
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable

from core.supply_chain.images import (
    PINNED_IMAGES,
    REQUIRED_PLATFORM,
    _KNOWN_SEVERITY,
    _MAX_EVIDENCE_AGE,
    _parse_time,
    classify_trivy_document,
    parse_image_ref,
)

BASELINE_SCHEMA_VERSION = 1
MAX_BASELINE_TTL = timedelta(days=31)
DEFAULT_BASELINE_PATH = Path(__file__).resolve().parent / "image_baseline.json"
IMAGES_MODULE_PATH = "core/supply_chain/images.py"
BASELINE_REPO_PATH = "core/supply_chain/image_baseline.json"
_CLOCK_SKEW = timedelta(minutes=5)

KEY_FIELDS = (
    "vulnerability_id",
    "pkg_name",
    "pkg_path",
    "installed_version",
    "result_class",
    "result_type",
    "target",
)
_TOP_FIELDS = {"schema_version", "description", "entries"}
_ENTRY_FIELDS = {
    "pin_name",
    "ref",
    "platform",
    "platform_digest",
    "scanner_version",
    "db_updated_at",
    "scanned_at",
    "source",
    "approval",
    "findings",
}
_SOURCE_FIELDS = {"repository", "ci_run_id", "commit", "artifact", "raw_path", "raw_sha256"}
_APPROVAL_FIELDS = {"approved_by", "approval_ref", "approved_at", "expires_at"}
_FINDING_FIELDS = {"key", "severity", "fixed_version", "gate_reason", "remediation_status"}
GATE_REASONS = {"fixed-high-critical", "unscored"}
REMEDIATION_STATUSES = {
    # A fixed version is published; an upstream image rebuild/release is needed.
    "awaiting-upstream-release",
    # No fixed version is published for this finding.
    "no-fixed-version-published",
}

_DIGEST_RE = re.compile(r"^sha256:[0-9a-f]{64}$")
_HEX64_RE = re.compile(r"^[0-9a-f]{64}$")
_COMMIT_RE = re.compile(r"^[0-9a-f]{40}$")
_REPO_RE = re.compile(r"^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$")
_LOGIN_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,37}[A-Za-z0-9])?$")
_APPROVAL_REF_RE = re.compile(r"^https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+/(?:pull|issues)/[1-9][0-9]*$")

STATEMENT = (
    "regression_gate PASS means no blocking finding exists beyond the reviewed, unexpired baseline "
    "for the exact pinned digests. It does not mean the images are free of vulnerabilities. "
    "The absolute image gate is unchanged and remains the release gate."
)


class BaselineEvidenceError(ValueError):
    """Raised when raw evidence cannot be tied to the canonical classification."""


# --------------------------------------------------------------------------- keys


def finding_key(result: dict[str, Any], vuln: dict[str, Any]) -> dict[str, str]:
    """Stable identity of one Trivy finding row.

    OS-package result targets embed the scanned image reference, so they are
    normalised to ``""``; language-package targets are file paths inside the
    image and are kept. ``Fingerprint`` is not used because its inputs are not
    documented as stable across scanner versions.
    """
    result_class = str(result.get("Class") or "")
    return {
        "vulnerability_id": str(vuln.get("VulnerabilityID") or ""),
        "pkg_name": str(vuln.get("PkgName") or ""),
        "pkg_path": str(vuln.get("PkgPath") or ""),
        "installed_version": str(vuln.get("InstalledVersion") or ""),
        "result_class": result_class,
        "result_type": str(result.get("Type") or ""),
        "target": "" if result_class == "os-pkgs" else str(result.get("Target") or ""),
    }


def key_tuple(key: dict[str, str]) -> tuple[str, ...]:
    return tuple(key[name] for name in KEY_FIELDS)


def blocking_findings(raw_document: dict[str, Any], classified: dict[str, Any]) -> list[dict[str, Any]]:
    """Blocking rows of ``raw_document`` as judged by ``classify_trivy_document``.

    The canonical classifier's verdict is reused, not re-implemented: raw rows
    are paired 1:1, in order, with ``classified["findings"]``. Any mismatch is a
    ``BaselineEvidenceError`` (callers treat it as NOT_VERIFIED).
    """
    if not isinstance(raw_document, dict) or not isinstance(classified, dict):
        raise BaselineEvidenceError("raw document or classification is missing")
    rows: list[tuple[dict[str, Any], dict[str, Any]]] = []
    for result in raw_document.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for vuln in result.get("Vulnerabilities") or []:
            if isinstance(vuln, dict):
                rows.append((result, vuln))
    findings = classified.get("findings")
    if not isinstance(findings, list) or len(findings) != len(rows):
        raise BaselineEvidenceError("raw Trivy rows do not align with the classified findings")
    out: list[dict[str, Any]] = []
    for (result, vuln), finding in zip(rows, findings):
        if vuln.get("VulnerabilityID") != finding.get("id") or vuln.get("PkgName") != finding.get("package"):
            raise BaselineEvidenceError("raw Trivy rows do not align with the classified findings")
        if not finding.get("blocking"):
            continue
        severity = str(finding.get("severity") or "")
        fixed = str(finding.get("fixed") or "")
        out.append(
            {
                "key": finding_key(result, vuln),
                "severity": severity,
                "fixed_version": fixed,
                "gate_reason": "unscored" if finding.get("class") == "unscored" else "fixed-high-critical",
                "remediation_status": "awaiting-upstream-release" if fixed else "no-fixed-version-published",
            }
        )
    keys = [key_tuple(item["key"]) for item in out]
    if len(keys) != len(set(keys)):
        raise BaselineEvidenceError("duplicate blocking finding identity in raw Trivy report")
    return out


# --------------------------------------------------------------------- validation


def _exact_fields(value: Any, fields: set[str], where: str, errors: list[str]) -> bool:
    if not isinstance(value, dict):
        errors.append(f"{where}: must be an object")
        return False
    missing = sorted(fields - set(value))
    unknown = sorted(set(value) - fields)
    if missing:
        errors.append(f"{where}: missing field(s) {missing}")
    if unknown:
        errors.append(f"{where}: unsupported field(s) {unknown}")
    return not missing and not unknown


def _time(value: Any, where: str, errors: list[str]) -> datetime | None:
    parsed = _parse_time(value) if isinstance(value, str) else None
    if parsed is None:
        errors.append(f"{where}: missing or invalid timestamp")
    return parsed


def _validate_entry(entry: Any, index: int, now: datetime, errors: list[str]) -> None:
    where = f"entries[{index}]"
    if not _exact_fields(entry, _ENTRY_FIELDS, where, errors):
        return
    name = entry["pin_name"]
    if not isinstance(name, str) or not name:
        errors.append(f"{where}.pin_name: must be a non-empty string")
    else:
        where = f"entries[{index}] ({name})"
    ref = entry["ref"]
    if not isinstance(ref, str) or not _DIGEST_RE.match(parse_image_ref(ref).get("digest") or ""):
        errors.append(f"{where}.ref: must be an immutable reference ending in @sha256:<64 hex>")
    if entry["platform"] != REQUIRED_PLATFORM:
        errors.append(f"{where}.platform: must be {REQUIRED_PLATFORM!r}")
    if not isinstance(entry["platform_digest"], str) or not _DIGEST_RE.match(entry["platform_digest"]):
        errors.append(f"{where}.platform_digest: must be sha256:<64 hex>")
    if not isinstance(entry["scanner_version"], str) or not entry["scanner_version"]:
        errors.append(f"{where}.scanner_version: must be a non-empty string")
    db_updated = _time(entry["db_updated_at"], f"{where}.db_updated_at", errors)
    scanned = _time(entry["scanned_at"], f"{where}.scanned_at", errors)
    if db_updated and scanned:
        if db_updated - scanned > _CLOCK_SKEW:
            errors.append(f"{where}: db_updated_at is after scanned_at")
        elif scanned - db_updated > _MAX_EVIDENCE_AGE:
            errors.append(f"{where}: scan used a stale vulnerability database")

    source = entry["source"]
    if _exact_fields(source, _SOURCE_FIELDS, f"{where}.source", errors):
        if not isinstance(source["repository"], str) or not _REPO_RE.match(source["repository"]):
            errors.append(f"{where}.source.repository: must be owner/repo")
        if not isinstance(source["ci_run_id"], int) or isinstance(source["ci_run_id"], bool) or source["ci_run_id"] <= 0:
            errors.append(f"{where}.source.ci_run_id: must be a positive integer")
        if not isinstance(source["commit"], str) or not _COMMIT_RE.match(source["commit"]):
            errors.append(f"{where}.source.commit: must be a 40-hex commit")
        if not isinstance(source["artifact"], str) or not source["artifact"]:
            errors.append(f"{where}.source.artifact: must be a non-empty string")
        raw_path = source["raw_path"]
        if not isinstance(raw_path, str) or not raw_path or raw_path.startswith("/") or ".." in raw_path.split("/"):
            errors.append(f"{where}.source.raw_path: must be a relative path inside the artifact")
        if not isinstance(source["raw_sha256"], str) or not _HEX64_RE.match(source["raw_sha256"]):
            errors.append(f"{where}.source.raw_sha256: must be 64 lowercase hex characters")

    approval = entry["approval"]
    if approval is None:
        errors.append(f"{where}.approval: missing; candidate entries are not authoritative until an owner approves them")
    elif _exact_fields(approval, _APPROVAL_FIELDS, f"{where}.approval", errors):
        if not isinstance(approval["approved_by"], str) or not _LOGIN_RE.match(approval["approved_by"]):
            errors.append(f"{where}.approval.approved_by: must be a GitHub login")
        if not isinstance(approval["approval_ref"], str) or not _APPROVAL_REF_RE.match(approval["approval_ref"]):
            errors.append(f"{where}.approval.approval_ref: must be a GitHub pull request URL")
        if not isinstance(approval["reviewed_commit_sha"], str) or not _COMMIT_RE.match(approval["reviewed_commit_sha"]):
            errors.append(f"{where}.approval.reviewed_commit_sha: must be a 40-hex reviewed commit")
        approved = _time(approval["approved_at"], f"{where}.approval.approved_at", errors)
        expires = _time(approval["expires_at"], f"{where}.approval.expires_at", errors)
        if approved:
            if approved - now > _CLOCK_SKEW:
                errors.append(f"{where}.approval.approved_at: is in the future")
            if scanned and scanned - approved > _CLOCK_SKEW:
                errors.append(f"{where}.approval.approved_at: precedes the scan it approves")
            if scanned and approved - scanned > _MAX_EVIDENCE_AGE:
                errors.append(f"{where}.approval: approved on stale scan evidence (older than {_MAX_EVIDENCE_AGE.days} days)")
        if approved and expires:
            if expires <= approved:
                errors.append(f"{where}.approval.expires_at: must be after approved_at")
            elif expires - approved > MAX_BASELINE_TTL:
                errors.append(f"{where}.approval.expires_at: exceeds the {MAX_BASELINE_TTL.days}-day maximum")
            if now >= expires:
                errors.append(f"{where}: baseline entry expired at {approval['expires_at']}")

    findings = entry["findings"]
    if not isinstance(findings, list) or not findings:
        errors.append(f"{where}.findings: must be a non-empty list (clean images need no entry)")
        return
    seen: set[tuple[str, ...]] = set()
    for f_index, finding in enumerate(findings):
        fwhere = f"{where}.findings[{f_index}]"
        if not _exact_fields(finding, _FINDING_FIELDS, fwhere, errors):
            continue
        key = finding["key"]
        if not _exact_fields(key, set(KEY_FIELDS), f"{fwhere}.key", errors):
            continue
        if not all(isinstance(key[name], str) for name in KEY_FIELDS):
            errors.append(f"{fwhere}.key: every field must be a string")
            continue
        for required in ("vulnerability_id", "pkg_name", "installed_version", "result_class", "result_type"):
            if not key[required]:
                errors.append(f"{fwhere}.key.{required}: must not be empty")
        identity = key_tuple(key)
        if identity in seen:
            errors.append(f"{fwhere}: duplicate finding identity {identity}")
        seen.add(identity)
        severity, fixed = finding["severity"], finding["fixed_version"]
        if not isinstance(severity, str) or not isinstance(fixed, str):
            errors.append(f"{fwhere}: severity and fixed_version must be strings")
            continue
        reason = finding["gate_reason"]
        if reason not in GATE_REASONS:
            errors.append(f"{fwhere}.gate_reason: must be one of {sorted(GATE_REASONS)}")
        elif reason == "fixed-high-critical" and (severity not in {"HIGH", "CRITICAL"} or not fixed):
            errors.append(f"{fwhere}: fixed-high-critical requires HIGH/CRITICAL with a fixed_version")
        elif reason == "unscored" and severity in _KNOWN_SEVERITY:
            errors.append(f"{fwhere}: unscored findings cannot carry a known severity")
        status = finding["remediation_status"]
        if status not in REMEDIATION_STATUSES:
            errors.append(f"{fwhere}.remediation_status: must be one of {sorted(REMEDIATION_STATUSES)}")
        elif (status == "awaiting-upstream-release") != bool(fixed):
            errors.append(f"{fwhere}.remediation_status: inconsistent with fixed_version")


def validate_baseline(document: Any, *, now: datetime | None = None) -> list[str]:
    """Return every problem in ``document``; an empty list means valid."""
    clock = now or datetime.now(timezone.utc)
    errors: list[str] = []
    if not _exact_fields(document, _TOP_FIELDS, "baseline", errors):
        return errors
    if document["schema_version"] != BASELINE_SCHEMA_VERSION or isinstance(document["schema_version"], bool):
        errors.append(f"baseline.schema_version: must be {BASELINE_SCHEMA_VERSION}")
    if not isinstance(document["description"], str):
        errors.append("baseline.description: must be a string")
    entries = document["entries"]
    if not isinstance(entries, list):
        errors.append("baseline.entries: must be a list")
        return errors
    seen: set[tuple[str, str]] = set()
    for index, entry in enumerate(entries):
        _validate_entry(entry, index, clock, errors)
        if isinstance(entry, dict):
            pair = (str(entry.get("pin_name")), str(entry.get("ref")))
            if pair in seen:
                errors.append(f"entries[{index}]: duplicate entry for {pair}")
            seen.add(pair)
    return errors


def load_baseline(path: str | Path) -> tuple[Any, list[str]]:
    target = Path(path)
    if not target.is_file():
        return None, [f"baseline file not found: {target}"]
    try:
        return json.loads(target.read_text(encoding="utf-8")), []
    except (OSError, json.JSONDecodeError, UnicodeDecodeError) as exc:
        return None, [f"baseline file is not valid JSON: {exc}"]


# ---------------------------------------------------------------------- evaluator


def evaluate_regression_gate(
    report: dict[str, Any],
    baseline: Any,
    *,
    now: datetime | None = None,
    pinned: Iterable[dict[str, str]] = PINNED_IMAGES,
    baseline_errors: list[str] | None = None,
) -> dict[str, Any]:
    """Evaluate a ``scan_pinned_images(include_raw=True)`` report against ``baseline``.

    The absolute result in ``report`` is copied, never altered.
    """
    clock = now or datetime.now(timezone.utc)
    pins = {item["name"]: item for item in pinned}
    errors = list(baseline_errors or [])
    if baseline is not None and not errors:
        errors = validate_baseline(baseline, now=clock)
    elif baseline is None and not errors:
        errors = ["baseline is missing"]
    entries = baseline.get("entries") if isinstance(baseline, dict) and isinstance(baseline.get("entries"), list) else []
    entries = [entry for entry in entries if isinstance(entry, dict)]

    warnings: list[str] = []
    current_refs = {(item["name"], item["ref"]) for item in pins.values()}
    for entry in entries:
        pair = (entry.get("pin_name"), entry.get("ref"))
        if pair not in current_refs:
            warnings.append(
                f"baseline entry for {pair[0]} @ {pair[1]} does not match a current pin; review and remove it"
            )

    images_out: list[dict[str, Any]] = []
    statuses: list[str] = []
    rows = report.get("images") if isinstance(report.get("images"), list) else []
    if report.get("status") == "NOT_VERIFIED" or not rows:
        statuses.append("NOT_VERIFIED")
    for row in rows:
        name = str(row.get("pin_name") or "")
        pin = pins.get(name)
        item: dict[str, Any] = {
            "pin_name": name,
            "ref": pin["ref"] if pin else row.get("image"),
            "absolute_status": row.get("status"),
            "absolute_blocking_count": int(row.get("blocking_count") or 0),
            "absolute_unscored_count": int(row.get("unscored_count") or 0),
            "regression_status": "",
            "reason": "",
            "baseline_expires_at": None,
            "new_blocking": [],
            "inherited_blocking": [],
            "resolved_baseline_findings": [],
        }
        images_out.append(item)
        if pin is None:
            item.update(regression_status="FAIL", reason="scanned image is not a current pin")
            statuses.append("FAIL")
            continue
        if row.get("status") == "NOT_VERIFIED":
            item.update(regression_status="NOT_VERIFIED", reason=str(row.get("error") or "scan not verified"))
            statuses.append("NOT_VERIFIED")
            continue
        try:
            current = blocking_findings(row.get("raw_document"), row)
        except BaselineEvidenceError as exc:
            item.update(regression_status="NOT_VERIFIED", reason=str(exc))
            statuses.append("NOT_VERIFIED")
            continue
        if len(current) != item["absolute_blocking_count"]:
            item.update(regression_status="NOT_VERIFIED", reason="blocking findings disagree with the scan summary")
            statuses.append("NOT_VERIFIED")
            continue
        exact = [entry for entry in entries if entry.get("pin_name") == name and entry.get("ref") == pin["ref"]]
        if not current:
            item.update(regression_status="PASS", reason="absolute gate passed; no baseline entry needed")
            if exact:
                warnings.append(f"{name}: image passes the absolute gate; its baseline entry can be removed")
            statuses.append("PASS")
            continue
        if not exact:
            others = [entry.get("ref") for entry in entries if entry.get("pin_name") == name]
            item.update(
                regression_status="FAIL",
                reason="UNRECOGNISED_DIGEST: no reviewed baseline entry for this exact image"
                + (f" (entries exist only for {others})" if others else ""),
                new_blocking=current,
            )
            statuses.append("FAIL")
            continue
        entry = exact[0]
        approval = entry.get("approval") if isinstance(entry.get("approval"), dict) else {}
        item["baseline_expires_at"] = approval.get("expires_at")
        problems: list[str] = []
        if entry.get("platform_digest") != pin.get("platform_digest"):
            problems.append("PLATFORM_DIGEST_MISMATCH: baseline platform_digest differs from the pin")
        if entry.get("platform") != row.get("platform"):
            problems.append(f"PLATFORM_MISMATCH: scan platform {row.get('platform')!r}")
        if entry.get("scanner_version") != row.get("scanner_version"):
            problems.append(
                f"SCANNER_CHANGED: scan used {row.get('scanner_version')!r}, baseline {entry.get('scanner_version')!r}; re-review required"
            )
        baseline_by_key = {
            key_tuple(finding["key"]): finding
            for finding in entry.get("findings") or []
            if isinstance(finding, dict) and isinstance(finding.get("key"), dict) and set(finding["key"]) == set(KEY_FIELDS)
        }
        current_keys = {key_tuple(finding["key"]) for finding in current}
        new = [finding for finding in current if key_tuple(finding["key"]) not in baseline_by_key]
        inherited = [
            {**finding, "remediation_status": baseline_by_key[key_tuple(finding["key"])].get("remediation_status"),
             "baseline_expires_at": approval.get("expires_at")}
            for finding in current
            if key_tuple(finding["key"]) in baseline_by_key
        ]
        resolved = [finding for key, finding in baseline_by_key.items() if key not in current_keys]
        item.update(new_blocking=new, inherited_blocking=inherited, resolved_baseline_findings=resolved)
        if new:
            problems.append(f"NEW_BLOCKING: {len(new)} blocking finding(s) not in the reviewed baseline")
        if resolved:
            warnings.append(f"{name}: {len(resolved)} baseline finding(s) no longer present; tighten the baseline")
        if problems:
            item.update(regression_status="FAIL", reason="; ".join(problems))
            statuses.append("FAIL")
        else:
            item.update(
                regression_status="PASS",
                reason=f"INHERITED_ONLY: {len(inherited)} inherited blocking finding(s) remain (absolute gate FAIL)",
            )
            statuses.append("PASS")

    if errors:
        statuses.append("FAIL")
    if "NOT_VERIFIED" in statuses:
        overall = "NOT_VERIFIED"
    elif "FAIL" in statuses:
        overall = "FAIL"
    else:
        overall = "PASS"
    absolute_blocking = int(report.get("blocking_count") or 0)
    return {
        "ok": overall == "PASS",
        "regression_gate": {
            "status": overall,
            "baseline_errors": errors,
            "warnings": warnings,
            "new_blocking_count": sum(len(item["new_blocking"]) for item in images_out),
            "inherited_blocking_count": sum(len(item["inherited_blocking"]) for item in images_out),
            "resolved_baseline_count": sum(len(item["resolved_baseline_findings"]) for item in images_out),
        },
        "absolute": {
            "status": report.get("status"),
            "blocking_count": absolute_blocking,
            "tool_version": report.get("tool_version"),
            "database": report.get("database"),
            "scan_timestamp": report.get("scan_timestamp"),
            "note": "Absolute image gate result, unchanged by the baseline. This is the release gate.",
        },
        "images": images_out,
        "statement": STATEMENT,
        "evaluated_at": clock.isoformat(),
    }


def summary_lines(result: dict[str, Any]) -> list[str]:
    """Human-readable lines; never claims the images are clean when they are not."""
    gate = result["regression_gate"]
    absolute = result["absolute"]
    lines = [
        f"regression_gate: {gate['status']}  new_blocking={gate['new_blocking_count']} "
        f"inherited_blocking={gate['inherited_blocking_count']} resolved_baseline={gate['resolved_baseline_count']}",
        f"absolute_image_gate: {absolute['status']} blocking={absolute['blocking_count']} "
        "(release gate; unchanged by the baseline)",
    ]
    for item in result["images"]:
        lines.append(
            f"  {item['pin_name']}: regression={item['regression_status']} absolute={item['absolute_status']} "
            f"blocking={item['absolute_blocking_count']} inherited={len(item['inherited_blocking'])} "
            f"new={len(item['new_blocking'])} resolved={len(item['resolved_baseline_findings'])} "
            f"expires={item['baseline_expires_at']} | {item['reason']}"
        )
    for error in gate["baseline_errors"]:
        lines.append(f"  baseline_error: {error}")
    for warning in gate["warnings"]:
        lines.append(f"  warning: {warning}")
    lines.append(STATEMENT)
    return lines


# ----------------------------------------------------------------- candidates


def build_candidate_entries(
    summary: dict[str, Any],
    raw_dir: str | Path,
    *,
    repository: str,
    ci_run_id: int,
    commit: str,
    artifact: str,
    raw_prefix: str = "",
    pinned: Iterable[dict[str, str]] = PINNED_IMAGES,
) -> list[dict[str, Any]]:
    """Candidate entries from a CI ``images --raw-dir`` summary plus its raw files.

    Every value is derived from verified evidence: raw-file sha256 must match the
    summary, the raw document is re-classified with the canonical classifier and
    must agree with the summary, identity must match the current pin, and the
    database used must be fresh relative to the scan. Entries are produced with
    ``approval: None`` and are not authoritative until an owner approves them.
    """
    pins = {item["name"]: item for item in pinned}
    if not isinstance(summary, dict) or summary.get("status") == "NOT_VERIFIED":
        raise BaselineEvidenceError("summary is missing or NOT_VERIFIED")
    database = summary.get("database") if isinstance(summary.get("database"), dict) else {}
    db_updated = _parse_time(str(database.get("updated_at") or ""))
    if db_updated is None:
        raise BaselineEvidenceError("summary vulnerability database UpdatedAt is missing")
    entries: list[dict[str, Any]] = []
    for row in summary.get("images") or []:
        name = str(row.get("pin_name") or "")
        pin = pins.get(name)
        if pin is None:
            raise BaselineEvidenceError(f"{name or '<unnamed>'}: not a current pin")
        if row.get("status") == "NOT_VERIFIED":
            raise BaselineEvidenceError(f"{name}: scan is NOT_VERIFIED")
        evidence = row.get("raw_evidence")
        if not isinstance(evidence, dict) or not _HEX64_RE.match(str(evidence.get("sha256") or "")):
            raise BaselineEvidenceError(f"{name}: raw_evidence sha256 missing")
        raw_file = Path(raw_dir) / Path(str(evidence.get("path") or "")).name
        payload = raw_file.read_bytes() if raw_file.is_file() else b""
        if hashlib.sha256(payload).hexdigest() != evidence["sha256"]:
            raise BaselineEvidenceError(f"{name}: raw file missing or sha256 mismatch ({raw_file})")
        raw = json.loads(payload)
        scanned = _parse_time(str(raw.get("CreatedAt") or ""))
        if scanned is None:
            raise BaselineEvidenceError(f"{name}: raw CreatedAt missing")
        if scanned - db_updated > _MAX_EVIDENCE_AGE or db_updated - scanned > _CLOCK_SKEW:
            raise BaselineEvidenceError(f"{name}: database UpdatedAt is stale or after the scan")
        classified = classify_trivy_document(raw, image=pin["ref"], now=scanned, database=database)
        scanner = str(((raw.get("Trivy") or {}).get("Version")) or "")
        if classified.get("status") == "NOT_VERIFIED":
            raise BaselineEvidenceError(f"{name}: raw report does not verify: {classified.get('error')}")
        if classified.get("platform") != REQUIRED_PLATFORM or row.get("platform") != REQUIRED_PLATFORM:
            raise BaselineEvidenceError(f"{name}: platform is not {REQUIRED_PLATFORM}")
        if not scanner or scanner != row.get("scanner_version"):
            raise BaselineEvidenceError(f"{name}: report scanner version missing or disagrees with summary")
        if pin["ref"] != row.get("image"):
            raise BaselineEvidenceError(f"{name}: summary image does not match the current pin")
        blocking = blocking_findings(raw, classified)
        if len(blocking) != int(row.get("blocking_count") or 0):
            raise BaselineEvidenceError(f"{name}: re-classified blocking count disagrees with summary")
        if not blocking:
            continue
        entries.append(
            {
                "pin_name": name,
                "ref": pin["ref"],
                "platform": REQUIRED_PLATFORM,
                "platform_digest": pin["platform_digest"],
                "scanner_version": scanner,
                "db_updated_at": str(database["updated_at"]),
                "scanned_at": str(raw["CreatedAt"]),
                "source": {
                    "repository": repository,
                    "ci_run_id": int(ci_run_id),
                    "commit": commit,
                    "artifact": artifact,
                    "raw_path": f"{raw_prefix}{raw_file.name}",
                    "raw_sha256": evidence["sha256"],
                },
                "approval": None,
                "findings": sorted(blocking, key=lambda finding: key_tuple(finding["key"])),
            }
        )
    return entries



# ------------------------------------------------------------ GitHub approval proof



def _without_approval(entry: dict[str, Any]) -> dict[str, Any]:
    result = dict(entry)
    result["approval"] = None
    return result


def verify_github_approvals(
    document: Any,
    *,
    token: str | None,
    repository: str | None,
    required: bool,
    fetch_json: Any = None,
) -> list[str]:
    """Verify a baseline entry against a real review of its exact reviewed content.

    Approval metadata alone is never accepted as proof. The named approver must
    have an APPROVED review for reviewed_commit_sha, the commit must be an
    ancestor of the current PR head, and the entry at that reviewed commit must
    match the current entry except for its approval metadata.
    """
    if not required:
        return []
    errors: list[str] = []
    if not isinstance(document, dict) or not isinstance(document.get("entries"), list):
        return ["GitHub review verification: baseline document or entries are missing"]
    if not token:
        return ["GitHub review verification: GITHUB_TOKEN is missing"]
    if not isinstance(repository, str) or not _REPO_RE.match(repository):
        return ["GitHub review verification: GITHUB_REPOSITORY is missing or invalid"]

    if fetch_json is None:
        def fetch_json(url: str) -> Any:
            request = urllib.request.Request(
                url,
                headers={
                    "Authorization": f"Bearer {token}",
                    "Accept": "application/vnd.github+json",
                    "X-GitHub-Api-Version": "2022-11-28",
                    "User-Agent": "pen-testing-image-baseline-gate",
                },
            )
            with urllib.request.urlopen(request, timeout=15) as response:
                return json.loads(response.read().decode("utf-8"))

    api_root = "https://api.github.com"
    pull_cache: dict[tuple[str, int], tuple[dict[str, Any], list[dict[str, Any]]]] = {}
    baseline_cache: dict[tuple[str, str], Any] = {}
    compare_cache: dict[tuple[str, str, str], dict[str, Any]] = {}
    for index, entry in enumerate(document["entries"]):
        if not isinstance(entry, dict):
            errors.append(f"entries[{index}]: malformed baseline entry")
            continue
        approval = entry.get("approval")
        if not isinstance(approval, dict):
            continue
        match = re.match(
            r"^https://github\\.com/([A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)/pull/([1-9][0-9]*)$",
            str(approval.get("approval_ref") or ""),
        )
        if not match:
            errors.append(f"entries[{index}]: approval_ref must identify a GitHub pull request")
            continue
        pr_repo, number_text = match.groups()
        if pr_repo.lower() != repository.lower():
            errors.append(f"entries[{index}]: approval PR belongs to {pr_repo}, not {repository}")
            continue
        source = entry.get("source") if isinstance(entry.get("source"), dict) else {}
        if str(source.get("repository") or "").lower() != repository.lower():
            errors.append(f"entries[{index}]: evidence repository does not match {repository}")
            continue
        number = int(number_text)
        approver = str(approval.get("approved_by") or "")
        reviewed_sha = str(approval.get("reviewed_commit_sha") or "")
        if not _COMMIT_RE.match(reviewed_sha):
            errors.append(f"entries[{index}]: reviewed_commit_sha is invalid")
            continue
        try:
            pkey = (pr_repo, number)
            if pkey not in pull_cache:
                pull = fetch_json(f"{api_root}/repos/{pr_repo}/pulls/{number}")
                reviews = fetch_json(f"{api_root}/repos/{pr_repo}/pulls/{number}/reviews?per_page=100")
                if not isinstance(pull, dict) or not isinstance(reviews, list):
                    raise ValueError("GitHub returned malformed PR or reviews")
                pull_cache[pkey] = (pull, reviews)
            pull, reviews = pull_cache[pkey]
            author = str(((pull.get("user") or {}).get("login")) or "")
            head_sha = str(((pull.get("head") or {}).get("sha")) or "")
            if pull.get("number") != number or not head_sha:
                errors.append(f"entries[{index}]: approval reference did not resolve to the expected pull request")
                continue
            if not approver or approver.lower() == author.lower():
                errors.append(f"entries[{index}]: approver must differ from PR author {author!r}")
                continue
            review = next((
                item for item in reversed(reviews)
                if isinstance(item, dict)
                and str(((item.get("user") or {}).get("login")) or "").lower() == approver.lower()
                and str(item.get("state") or "").upper() == "APPROVED"
                and str(item.get("commit_id") or "").lower() == reviewed_sha.lower()
            ), None)
            if review is None:
                errors.append(f"entries[{index}]: {approver!r} has no APPROVED review on {reviewed_sha}")
                continue
            reviewed_at = _parse_time(str(review.get("submitted_at") or ""))
            approved_at = _parse_time(str(approval.get("approved_at") or ""))
            if reviewed_at is None or approved_at is None or approved_at < reviewed_at:
                errors.append(f"entries[{index}]: approval metadata predates or lacks the actual review timestamp")
                continue
            if approved_at - reviewed_at > timedelta(days=1):
                errors.append(f"entries[{index}]: approval metadata was recorded more than one day after its review")
                continue

            ckey = (pr_repo, reviewed_sha, head_sha)
            if ckey not in compare_cache:
                compare_cache[ckey] = fetch_json(
                    f"{api_root}/repos/{pr_repo}/compare/{reviewed_sha}...{head_sha}"
                )
            comparison = compare_cache[ckey]
            base_sha = str(((comparison.get("merge_base_commit") or {}).get("sha")) or "")
            if comparison.get("status") not in {"ahead", "identical"} or base_sha.lower() != reviewed_sha.lower():
                errors.append(f"entries[{index}]: reviewed commit is not an ancestor of the current PR head")
                continue

            bkey = (pr_repo, reviewed_sha)
            if bkey not in baseline_cache:
                response = fetch_json(
                    f"{api_root}/repos/{pr_repo}/contents/{BASELINE_REPO_PATH}?ref={reviewed_sha}"
                )
                if not isinstance(response, dict) or not isinstance(response.get("content"), str):
                    raise ValueError("reviewed commit does not contain the baseline file")
                content = response["content"]
                if response.get("encoding") == "base64":
                    content = base64.b64decode(content, validate=False).decode("utf-8")
                baseline_cache[bkey] = json.loads(content)
            reviewed_document = baseline_cache[bkey]
            reviewed_entries = [
                item for item in (reviewed_document.get("entries") or [])
                if isinstance(item, dict)
                and item.get("pin_name") == entry.get("pin_name")
                and item.get("ref") == entry.get("ref")
            ] if isinstance(reviewed_document, dict) else []
            if len(reviewed_entries) != 1 or _without_approval(reviewed_entries[0]) != _without_approval(entry):
                errors.append(f"entries[{index}]: baseline entry differs from the exact content reviewed by {approver!r}")
        except (OSError, TimeoutError, ValueError, KeyError, TypeError, json.JSONDecodeError, urllib.error.URLError) as exc:
            errors.append(f"entries[{index}]: GitHub review verification failed: {exc}")
    return errors


def approve_entries(
    document: dict[str, Any],
    *,
    approved_by: str,
    approval_ref: str,
    expires_in_days: int,
    pin_names: Iterable[str] | None = None,
    now: datetime | None = None,
) -> int:
    """Record an owner's approval on pending entries. Run by a human reviewer."""
    clock = now or datetime.now(timezone.utc)
    if not 1 <= expires_in_days <= MAX_BASELINE_TTL.days:
        raise ValueError(f"expires_in_days must be between 1 and {MAX_BASELINE_TTL.days}")
    if not _LOGIN_RE.match(approved_by or ""):
        raise ValueError("approved_by must be a GitHub login")
    if not _APPROVAL_REF_RE.match(approval_ref or ""):
        raise ValueError("approval_ref must be a GitHub pull request or issue URL")
    wanted = set(pin_names or [])
    count = 0
    for entry in document.get("entries") or []:
        if entry.get("approval") is not None or (wanted and entry.get("pin_name") not in wanted):
            continue
        entry["approval"] = {
            "approved_by": approved_by,
            "approval_ref": approval_ref,
            "approved_at": clock.isoformat(),
            "expires_at": (clock + timedelta(days=expires_in_days)).isoformat(),
        }
        count += 1
    return count


def dump_baseline(document: dict[str, Any]) -> str:
    return json.dumps(document, indent=1, sort_keys=True) + "\n"


# ---------------------------------------------------------------------- guard


def pinned_refs_from_source(source: str) -> dict[str, str]:
    """Extract ``{name: ref}`` from the ``PINNED_IMAGES`` literal in images.py source."""
    tree = ast.parse(source)
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(
            isinstance(target, ast.Name) and target.id == "PINNED_IMAGES" for target in node.targets
        ):
            value = ast.literal_eval(node.value)
            return {str(item["name"]): str(item["ref"]) for item in value}
    raise ValueError("PINNED_IMAGES literal not found")


def _entries_by_pin(document: Any) -> dict[str, str]:
    grouped: dict[str, list[Any]] = {}
    if isinstance(document, dict) and isinstance(document.get("entries"), list):
        for entry in document["entries"]:
            name = str(entry.get("pin_name")) if isinstance(entry, dict) else "<invalid>"
            grouped.setdefault(name, []).append(entry)
    return {
        name: json.dumps(sorted(items, key=lambda e: json.dumps(e, sort_keys=True)), sort_keys=True)
        for name, items in grouped.items()
    }


def guard_pin_and_baseline(
    base_pins: dict[str, str],
    head_pins: dict[str, str],
    base_baseline: Any,
    head_baseline: Any,
) -> list[str]:
    """Reject a change set that moves an image pin and edits that pin's baseline together."""
    base_entries = _entries_by_pin(base_baseline)
    head_entries = _entries_by_pin(head_baseline)
    errors = []
    for name in sorted(set(base_pins) | set(head_pins)):
        if base_pins.get(name) == head_pins.get(name):
            continue
        if base_entries.get(name) != head_entries.get(name):
            errors.append(
                f"{name}: the image pin and its baseline entry both change in this change set; "
                "land the baseline update and the pin change in separate reviewed pull requests"
            )
    return errors


def _git_show(ref: str, path: str, cwd: Path) -> str | None:
    completed = subprocess.run(
        ["git", "show", f"{ref}:{path}"], cwd=cwd, capture_output=True, text=True, check=False
    )
    return completed.stdout if completed.returncode == 0 else None


def guard_against_git_ref(base_ref: str, *, root: Path) -> dict[str, Any]:
    base_images = _git_show(base_ref, IMAGES_MODULE_PATH, root)
    if base_images is None:
        return {"ok": False, "errors": [f"cannot read {IMAGES_MODULE_PATH} at {base_ref}"]}
    head_images = (root / IMAGES_MODULE_PATH).read_text(encoding="utf-8")
    base_baseline_text = _git_show(base_ref, BASELINE_REPO_PATH, root)
    head_path = root / BASELINE_REPO_PATH
    try:
        base_baseline = json.loads(base_baseline_text) if base_baseline_text else None
        head_baseline = json.loads(head_path.read_text(encoding="utf-8")) if head_path.is_file() else None
        errors = guard_pin_and_baseline(
            pinned_refs_from_source(base_images), pinned_refs_from_source(head_images), base_baseline, head_baseline
        )
    except (ValueError, SyntaxError, json.JSONDecodeError) as exc:
        return {"ok": False, "errors": [f"guard could not parse pins or baseline: {exc}"]}
    changed = base_baseline_text != (head_path.read_text(encoding="utf-8") if head_path.is_file() else None)
    return {"ok": not errors, "errors": errors, "baseline_changed": changed}
