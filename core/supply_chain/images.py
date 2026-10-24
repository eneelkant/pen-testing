"""Container image pins and an optional Trivy scan.

Digests were resolved from the registry on 2026-10-18. A scan that cannot run
is NOT_VERIFIED. Fixed HIGH and CRITICAL findings are blocking. Unfixed
findings are reported and are not a claim that the image is safe. Empty,
malformed, stale, or identity-mismatched reports are NOT_VERIFIED.

Each ``ref`` digest is a multi-platform OCI image index. ``platform_digest`` is
that index's linux/amd64 child manifest, read from the registry on 2026-10-24
(``docker buildx imagetools inspect --raw <ref>``). Docker Hub's tags API
reports per-platform digests, so candidate monitoring must compare against
``platform_digest``; comparing against the index digest never matches.
Pinned scans force ``--platform linux/amd64`` and verify the scanned platform
and the scanner version recorded in the report itself.
"""

from __future__ import annotations

import json
import re
import shutil
from datetime import datetime, timedelta, timezone
from typing import Any, Callable

PINNED_IMAGES = (
    {
        "name": "python-3.12-probe",
        "ref": "python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258",
        "platform_digest": "sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d",
    },
    {
        "name": "python-3.12-orchestrator",
        "ref": "python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258",
        "platform_digest": "sha256:2ed6491b93cd49272ee6de2b5a38440c3448360322c089fc23e370722d74179d",
    },
    {
        "name": "shannon-worker",
        "ref": "keygraph/shannon:3.4.0@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e",
        "platform_digest": "sha256:9e53649ed684d9e6667740677474fcbe757387c7c71605eedd5f2130d0f8644a",
    },
    {
        "name": "temporal",
        "ref": "temporalio/temporal:1.7.0@sha256:9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4",
        "platform_digest": "sha256:6dc6fda8437b7aca517a5daeff024438f469f0c40a16c28118393d8477965f5f",
    },
    {
        "name": "gitleaks",
        "ref": "zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46",
        "platform_digest": "sha256:e5fa09c73ff086ea57f3731a4e1fb372969fb73314cc932020472eb23a5dfc7e",
    },
    {
        "name": "trivy-scanner",
        "ref": "aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222",
        "platform_digest": "sha256:166061a4a15c64a94a3aab430659e2c166dc0815fbc54a222c6d56d64132f552",
    },
)

TRIVY_IMAGE = PINNED_IMAGES[-1]["ref"]
# Every gate (pinned scans and candidate acceptance) requires this platform and
# the scanner version of the pinned Trivy image.
REQUIRED_PLATFORM = "linux/amd64"
REQUIRED_SCANNER_VERSION = TRIVY_IMAGE.split("@", 1)[0].rsplit(":", 1)[-1] or "0.76.0"
_BLOCKING = {"HIGH", "CRITICAL"}
_KNOWN_SEVERITY = _BLOCKING | {"LOW", "MODERATE", "MEDIUM"}
# Reports older than this, or with a vulnerability DB older than this, are not
# treated as a clean or current result.
_MAX_EVIDENCE_AGE = timedelta(days=7)
_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}")


def parse_image_ref(ref: str) -> dict[str, str]:
    """Split ``name:tag@sha256:...`` into structured identity fields."""
    digest = ""
    name_tag = ref
    if "@" in ref:
        name_tag, digest = ref.rsplit("@", 1)
        digest = digest.strip()
    repository = name_tag
    tag = ""
    if "/" in name_tag:
        # tag is after the final colon that is not part of a registry port
        slash = name_tag.rfind("/")
        colon = name_tag.rfind(":")
        if colon > slash:
            repository, tag = name_tag[:colon], name_tag[colon + 1 :]
    elif ":" in name_tag:
        repository, tag = name_tag.split(":", 1)
    return {"repository": repository, "tag": tag, "digest": digest, "ref": ref}


def _parse_time(value: Any) -> datetime | None:
    if not value or not isinstance(value, str):
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=timezone.utc)
    return parsed.astimezone(timezone.utc)


def _complete_trivy_document(document: dict[str, Any]) -> bool:
    """A usable Trivy report identifies the artifact and includes a Results key.

    ``{}`` and schema-only documents are not clean scans. Trivy emits
    ``Results`` (possibly an empty list) for a completed image scan.
    """
    if "Results" not in document:
        return False
    if "SchemaVersion" not in document and "ArtifactName" not in document:
        return False
    return True


def _report_digests(document: dict[str, Any]) -> set[str]:
    found: set[str] = set()
    for match in _DIGEST_RE.findall(str(document.get("ArtifactName") or "")):
        found.add(match)
    metadata = document.get("Metadata") if isinstance(document.get("Metadata"), dict) else {}
    for key in ("ImageID", "RepoDigests", "DiffIDs"):
        value = metadata.get(key)
        if isinstance(value, str):
            found.update(_DIGEST_RE.findall(value))
        elif isinstance(value, list):
            for item in value:
                found.update(_DIGEST_RE.findall(str(item)))
    return found


def _scanner_version(document: dict[str, Any]) -> str:
    for key in ("Trivy", "trivy"):
        block = document.get(key)
        if isinstance(block, dict) and block.get("Version"):
            return str(block["Version"])
    metadata = document.get("Metadata") if isinstance(document.get("Metadata"), dict) else {}
    for key in ("Trivy", "trivy"):
        block = metadata.get(key)
        if isinstance(block, dict) and block.get("Version"):
            return str(block["Version"])
    return ""


def _database_metadata(document: dict[str, Any]) -> dict[str, str]:
    metadata = document.get("Metadata") if isinstance(document.get("Metadata"), dict) else {}
    trivy = document.get("Trivy") if isinstance(document.get("Trivy"), dict) else {}
    db = metadata.get("VulnerabilityDB") if isinstance(metadata.get("VulnerabilityDB"), dict) else {}
    if not db:
        db = trivy.get("VulnerabilityDB") if isinstance(trivy.get("VulnerabilityDB"), dict) else {}
    if not db:
        db = document.get("VulnerabilityDB") if isinstance(document.get("VulnerabilityDB"), dict) else {}
    return {
        "updated_at": str(db.get("UpdatedAt") or db.get("updated_at") or ""),
        "next_update": str(db.get("NextUpdate") or db.get("next_update") or ""),
        "downloaded_at": str(db.get("DownloadedAt") or db.get("downloaded_at") or ""),
    }


def _merge_database_metadata(document: dict[str, Any], injected: dict[str, str] | None) -> dict[str, str]:
    """Prefer report-embedded DB timestamps; fall back to ``trivy version`` data."""
    embedded = _database_metadata(document)
    if embedded.get("updated_at"):
        return embedded
    if not injected:
        return embedded
    return {
        "updated_at": str(injected.get("updated_at") or ""),
        "next_update": str(injected.get("next_update") or ""),
        "downloaded_at": str(injected.get("downloaded_at") or ""),
    }


def read_trivy_version_document(document: dict[str, Any] | None) -> tuple[str, dict[str, str]]:
    """Parse ``trivy version --format json`` into tool version and DB timestamps."""
    if not isinstance(document, dict):
        return "", {"updated_at": "", "next_update": "", "downloaded_at": ""}
    version = str(document.get("Version") or "")
    db = document.get("VulnerabilityDB") if isinstance(document.get("VulnerabilityDB"), dict) else {}
    return version, {
        "updated_at": str(db.get("UpdatedAt") or db.get("updated_at") or ""),
        "next_update": str(db.get("NextUpdate") or db.get("next_update") or ""),
        "downloaded_at": str(db.get("DownloadedAt") or db.get("downloaded_at") or ""),
    }


def _platform(document: dict[str, Any]) -> str:
    metadata = document.get("Metadata") if isinstance(document.get("Metadata"), dict) else {}
    config = metadata.get("ImageConfig") if isinstance(metadata.get("ImageConfig"), dict) else {}
    architecture = str(config.get("architecture") or metadata.get("Architecture") or "")
    os_name = str(config.get("os") or (metadata.get("OS") or {}).get("Family") or "")
    if isinstance(metadata.get("OS"), dict) and not os_name:
        os_name = str(metadata["OS"].get("Family") or "")
    parts = [part for part in (os_name, architecture) if part]
    return "/".join(parts)


def _not_verified(image: str, error: str, **extra: Any) -> dict[str, Any]:
    identity = parse_image_ref(image)
    payload = {
        "ok": False,
        "status": "NOT_VERIFIED",
        "image": image,
        "name": identity["repository"],
        "tag": identity["tag"],
        "digest": identity["digest"],
        "platform": "",
        "findings": [],
        "finding_row_count": 0,
        "unique_cve_count": 0,
        "blocking_count": 0,
        "unfixed_count": 0,
        "unscored_count": 0,
        "withdrawn_count": 0,
        "error": error,
        "note": "Missing, malformed, stale, or mismatched scan evidence is not a clean result.",
    }
    payload.update(extra)
    return payload


def classify_trivy_document(
    document: dict[str, Any],
    *,
    image: str,
    now: datetime | None = None,
    max_age: timedelta | None = None,
    exit_code: int | None = None,
    database: dict[str, str] | None = None,
) -> dict[str, Any]:
    identity = parse_image_ref(image)
    if not isinstance(document, dict) or not _complete_trivy_document(document):
        return _not_verified(image, "trivy report did not include a vulnerability result", exit_code=exit_code)

    expected = identity["digest"]
    if expected:
        reported = _report_digests(document)
        artifact = str(document.get("ArtifactName") or "")
        # Accept either explicit digest metadata or an ArtifactName that carries
        # the pinned repository/tag (local docker scans often omit RepoDigests).
        digest_ok = any(expected in item or item.endswith(expected.split(":", 1)[-1]) for item in reported)
        name_ok = False
        if artifact:
            pin_name = identity["repository"].split("/")[-1]
            name_ok = identity["repository"] in artifact or (pin_name and pin_name in artifact)
            if identity["tag"] and identity["tag"] in artifact:
                name_ok = True
        if reported and not digest_ok:
            return _not_verified(
                image,
                "trivy report image digest does not match the pinned digest",
                exit_code=exit_code,
                artifact=artifact,
                reported_digests=sorted(reported),
            )
        if not reported and not name_ok and artifact and artifact != image:
            return _not_verified(
                image,
                "trivy report artifact identity does not match the pinned image",
                exit_code=exit_code,
                artifact=artifact,
            )

    clock = now or datetime.now(timezone.utc)
    age_limit = max_age if max_age is not None else _MAX_EVIDENCE_AGE
    created_at = str(document.get("CreatedAt") or "")
    created = _parse_time(created_at)
    if created is not None and clock - created > age_limit:
        return _not_verified(
            image,
            "trivy report CreatedAt is stale",
            exit_code=exit_code,
            created_at=created_at,
        )
    db_meta = _merge_database_metadata(document, database)
    db_updated = _parse_time(db_meta.get("updated_at"))
    if not db_meta.get("updated_at"):
        return _not_verified(
            image,
            "trivy vulnerability database UpdatedAt is missing",
            exit_code=exit_code,
            created_at=created_at,
            database=db_meta,
        )
    if db_updated is not None and clock - db_updated > age_limit:
        return _not_verified(
            image,
            "trivy vulnerability database UpdatedAt is stale",
            exit_code=exit_code,
            created_at=created_at,
            database=db_meta,
        )

    findings: list[dict[str, Any]] = []
    for result in document.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            severity = str(vuln.get("Severity") or "UNKNOWN").upper()
            fixed = str(vuln.get("FixedVersion") or "")
            withdrawn = bool(vuln.get("withdrawn"))
            if withdrawn:
                kind = "withdrawn"
                blocking = False
            elif severity not in _KNOWN_SEVERITY:
                kind = "unscored"
                blocking = True
            elif severity in _BLOCKING and bool(fixed):
                kind = "fixed"
                blocking = True
            elif not fixed:
                kind = "unfixed"
                blocking = False
            else:
                kind = "fixed"
                blocking = False
            findings.append(
                {
                    "id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "installed": vuln.get("InstalledVersion"),
                    "fixed": fixed,
                    "severity": "withdrawn" if withdrawn else severity,
                    "class": kind,
                    "blocking": blocking,
                    "image": image,
                }
            )
    blocking = [item for item in findings if item["blocking"]]
    unique_ids = {str(item["id"]) for item in findings if item.get("id")}
    status = "FAIL" if blocking else "PASS"
    ok = not blocking
    # A nonzero scanner exit is never treated as a clean pass, even when the
    # JSON body happens to contain only non-blocking rows.
    if exit_code not in {0, None} and ok:
        return _not_verified(
            image,
            "trivy exited nonzero",
            exit_code=exit_code,
            created_at=created_at,
            findings=findings,
            finding_row_count=len(findings),
            unique_cve_count=len(unique_ids),
            database=db_meta,
        )
    if exit_code not in {0, None} and not ok:
        # Keep FAIL with findings; still record the exit code.
        pass
    return {
        "ok": ok,
        "status": status,
        "image": image,
        "name": identity["repository"],
        "tag": identity["tag"],
        "digest": identity["digest"],
        "platform": _platform(document),
        "artifact": document.get("ArtifactName") or image,
        "created_at": created_at,
        "scanner_version": _scanner_version(document),
        "database": db_meta,
        "exit_code": exit_code,
        "findings": findings,
        "finding_row_count": len(findings),
        "unique_cve_count": len(unique_ids),
        "blocking_count": len(blocking),
        "unfixed_count": sum(1 for item in findings if item["class"] == "unfixed"),
        "unscored_count": sum(1 for item in findings if item["class"] == "unscored"),
        "withdrawn_count": sum(1 for item in findings if item["class"] == "withdrawn"),
        "note": (
            "Fixed HIGH and CRITICAL findings are blocking. Unscored findings are blocking. "
            "Unfixed findings stay visible and are not a waiver. "
            "A vendor status such as not_affected is not applied as a waiver. "
            "finding_row_count counts package rows; unique_cve_count counts distinct ids."
        ),
    }


def _enforce_scan_identity(
    classified: dict[str, Any],
    *,
    image: str,
    required_platform: str,
    required_scanner_version: str,
) -> dict[str, Any]:
    """Downgrade a PASS/FAIL row to NOT_VERIFIED on platform or scanner mismatch.

    ``scanner_version`` must be present in the report (``Trivy.Version``); a
    missing value is NOT_VERIFIED regardless of what the local probe reports.
    """
    if classified.get("status") == "NOT_VERIFIED":
        return classified
    platform = str(classified.get("platform") or "")
    if platform != required_platform:
        return _not_verified(
            image,
            f"scanned platform {platform!r} does not match required {required_platform!r}"
            if platform
            else "scanned platform is missing from the Trivy report",
            platform=platform,
            scanner_version=classified.get("scanner_version") or "",
            database=classified.get("database") or {},
            created_at=classified.get("created_at") or "",
        )
    scanner = str(classified.get("scanner_version") or "")
    if not scanner:
        return _not_verified(
            image,
            "scanner version is missing from the Trivy report; the local probe is not accepted as a substitute",
            platform=platform,
            scanner_version="",
            database=classified.get("database") or {},
            created_at=classified.get("created_at") or "",
        )
    if scanner != required_scanner_version:
        return _not_verified(
            image,
            f"scanner_version {scanner!r} does not match required {required_scanner_version!r}",
            platform=platform,
            scanner_version=scanner,
            database=classified.get("database") or {},
            created_at=classified.get("created_at") or "",
        )
    return classified


def write_raw_evidence(report: dict[str, Any], raw_dir: Any) -> dict[str, Any]:
    """Move each row's ``raw_document`` into ``raw_dir`` and record its sha256.

    Each file holds canonical JSON (``indent=1``, sorted keys, UTF-8) serialized
    from the parsed Trivy document; it is not a byte-for-byte copy of Trivy's
    original stdout. ``raw_evidence`` records the path, the SHA-256 of the exact
    bytes written to disk, and their length. Rows without a raw document get
    ``raw_evidence: None`` so a missing file is visible rather than silently absent.
    """
    import hashlib
    from pathlib import Path

    directory = Path(raw_dir)
    directory.mkdir(parents=True, exist_ok=True)
    for index, row in enumerate(report.get("images") or []):
        raw = row.pop("raw_document", None)
        if not isinstance(raw, dict) or not raw:
            row["raw_evidence"] = None
            continue
        label = re.sub(r"[^A-Za-z0-9_.-]", "_", str(row.get("pin_name") or row.get("name") or index))
        path = directory / f"{index:02d}-{label}.trivy.json"
        payload = json.dumps(raw, indent=1, sort_keys=True).encode("utf-8")
        path.write_bytes(payload)
        row["raw_evidence"] = {
            "path": str(path),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "bytes": len(payload),
        }
    return report


def _trivy_invoke_prefix(*, use_docker: bool) -> list[str]:
    """Build the argv prefix for host Trivy or the pinned Trivy container.

    Docker runs share a named cache volume so ``trivy version`` and subsequent
    ``trivy image`` calls see the same vulnerability database download.
    """
    if not use_docker:
        return ["trivy"]
    return [
        "docker",
        "run",
        "--rm",
        "-v",
        "pen-testing-trivy-cache:/root/.cache/",
        TRIVY_IMAGE,
    ]


def scan_pinned_images(
    *,
    runner: Callable[..., Any] | None = None,
    images: tuple[dict[str, str], ...] | None = None,
    now: datetime | None = None,
    include_raw: bool = False,
    required_platform: str = REQUIRED_PLATFORM,
    required_scanner_version: str = REQUIRED_SCANNER_VERSION,
) -> dict[str, Any]:
    """Scan pinned images with a local trivy binary or a pinned trivy container.

    ``runner`` is a test hook. It receives the argument list and returns an
    object with ``returncode`` and ``stdout``. Image JSON from Trivy does not
    embed vulnerability-DB timestamps; this function probes
    ``trivy version --format json`` and injects that metadata before
    classification so missing DB freshness cannot be treated as a clean pass.

    ``include_raw`` attaches the parsed Trivy document (a ``dict``, not the
    original stdout bytes) to each image row as ``raw_document`` so callers (the
    candidate monitor) can independently re-classify raw findings instead of
    trusting this summary.

    Pinned refs are multi-platform indexes, so Trivy is told which platform to
    scan. A report whose image config is not ``required_platform``, or whose own
    ``Trivy.Version`` is missing or differs from ``required_scanner_version``, is
    NOT_VERIFIED, never PASS/FAIL. The ``trivy version`` probe result is recorded
    as ``probe_scanner_version`` for diagnostics and never fills a missing version.
    """
    selected = images if images is not None else PINNED_IMAGES
    tool_version = "0.76.0"
    database_meta = {"updated_at": "", "next_update": "", "downloaded_at": ""}
    scan_timestamp = (now or datetime.now(timezone.utc)).isoformat()
    if runner is None:
        if shutil.which("trivy"):
            def runner(args, timeout=600):  # type: ignore[no-redef]
                import subprocess

                completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
                return completed
            invoke = runner
            prefix = _trivy_invoke_prefix(use_docker=False)
        elif shutil.which("docker"):
            def runner(args, timeout=600):  # type: ignore[no-redef]
                import subprocess

                completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
                return completed
            invoke = runner
            prefix = _trivy_invoke_prefix(use_docker=True)
        else:
            return {
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "trivy and docker are unavailable",
                "images": [],
                "blocking_count": 0,
                "finding_row_count": 0,
                "unique_cve_count": 0,
                "tool": "trivy",
                "tool_version": "",
                "database": database_meta,
                "scan_timestamp": scan_timestamp,
            }
    else:
        invoke = runner
        prefix = ["trivy"]

    def _invoke(args: list[str], *, timeout: int = 600) -> Any:
        try:
            return invoke(args, timeout=timeout)
        except TypeError:
            # Test runners may accept only the argv list.
            return invoke(args)

    # Image JSON omits VulnerabilityDB. Download the DB first so ``trivy version``
    # can report UpdatedAt on a cold cache (CI docker volume or empty host cache).
    try:
        download_completed = _invoke([*prefix, "image", "--download-db-only"], timeout=300)
    except (OSError, TimeoutError) as exc:
        return {
            "ok": False,
            "status": "NOT_VERIFIED",
            "error": f"trivy vulnerability database download failed: {exc}",
            "images": [],
            "blocking_count": 0,
            "finding_row_count": 0,
            "unique_cve_count": 0,
            "tool": "trivy",
            "tool_version": tool_version,
            "database": database_meta,
            "scan_timestamp": scan_timestamp,
        }
    download_code = getattr(download_completed, "returncode", None)
    if download_code not in {0, None}:
        return {
            "ok": False,
            "status": "NOT_VERIFIED",
            "error": "trivy vulnerability database download exited nonzero",
            "images": [],
            "blocking_count": 0,
            "finding_row_count": 0,
            "unique_cve_count": 0,
            "tool": "trivy",
            "tool_version": tool_version,
            "database": database_meta,
            "scan_timestamp": scan_timestamp,
            "exit_code": download_code,
        }

    try:
        version_completed = _invoke([*prefix, "version", "--format", "json"], timeout=120)
    except (OSError, TimeoutError) as exc:
        return {
            "ok": False,
            "status": "NOT_VERIFIED",
            "error": f"trivy version probe failed: {exc}",
            "images": [],
            "blocking_count": 0,
            "finding_row_count": 0,
            "unique_cve_count": 0,
            "tool": "trivy",
            "tool_version": "",
            "database": database_meta,
            "scan_timestamp": scan_timestamp,
        }
    version_stdout = getattr(version_completed, "stdout", "") or ""
    try:
        version_document = json.loads(version_stdout) if version_stdout.strip() else {}
    except json.JSONDecodeError:
        version_document = {}
    probed_version, database_meta = read_trivy_version_document(
        version_document if isinstance(version_document, dict) else {}
    )
    if probed_version:
        tool_version = probed_version
    if not database_meta.get("updated_at"):
        return {
            "ok": False,
            "status": "NOT_VERIFIED",
            "error": "trivy vulnerability database UpdatedAt is missing after download",
            "images": [],
            "blocking_count": 0,
            "finding_row_count": 0,
            "unique_cve_count": 0,
            "tool": "trivy",
            "tool_version": tool_version,
            "database": database_meta,
            "scan_timestamp": scan_timestamp,
        }

    reports = []
    blocking_count = 0
    finding_row_count = 0
    unique_cves: set[str] = set()
    for image in selected:
        # Do not pre-filter severities: UNKNOWN/unscored rows must remain visible
        # so the classifier can fail closed on them.
        args = [
            *prefix,
            "image",
            "--format",
            "json",
            "--quiet",
            "--platform",
            required_platform,
            image["ref"],
        ]
        try:
            completed = _invoke(args, timeout=600)
        except (OSError, TimeoutError) as exc:
            return {
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": str(exc),
                "images": reports,
                "blocking_count": blocking_count,
                "finding_row_count": finding_row_count,
                "unique_cve_count": len(unique_cves),
                "tool": "trivy",
                "tool_version": tool_version,
                "database": database_meta,
                "scan_timestamp": scan_timestamp,
            }
        exit_code = getattr(completed, "returncode", None)
        stdout = getattr(completed, "stdout", "") or ""
        try:
            document = json.loads(stdout) if stdout.strip() else {}
        except json.JSONDecodeError:
            return {
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "trivy did not return JSON",
                "images": reports,
                "blocking_count": blocking_count,
                "finding_row_count": finding_row_count,
                "unique_cve_count": len(unique_cves),
                "tool": "trivy",
                "tool_version": tool_version,
                "database": database_meta,
                "scan_timestamp": scan_timestamp,
                "exit_code": exit_code,
            }
        classified = classify_trivy_document(
            document if isinstance(document, dict) else {},
            image=image["ref"],
            now=now,
            exit_code=exit_code if isinstance(exit_code, int) else None,
            database=database_meta,
        )
        # The scanner identity must come from the report itself. The local
        # ``trivy version`` probe is kept as diagnostic metadata only and never
        # substitutes for a missing report version.
        classified["probe_scanner_version"] = tool_version
        classified = _enforce_scan_identity(
            classified,
            image=image["ref"],
            required_platform=required_platform,
            required_scanner_version=required_scanner_version,
        )
        classified["pin_name"] = image.get("name") or ""
        if include_raw:
            classified["raw_document"] = document if isinstance(document, dict) else {}
        reports.append(classified)
        blocking_count += int(classified.get("blocking_count") or 0)
        finding_row_count += int(classified.get("finding_row_count") or 0)
        for item in classified.get("findings") or []:
            if item.get("id"):
                unique_cves.add(str(item["id"]))
        if classified.get("status") == "NOT_VERIFIED":
            return {
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": classified.get("error") or "image scan failed",
                "images": reports,
                "blocking_count": blocking_count,
                "finding_row_count": finding_row_count,
                "unique_cve_count": len(unique_cves),
                "tool": "trivy",
                "tool_version": tool_version,
                "database": database_meta,
                "scan_timestamp": scan_timestamp,
            }
    return {
        "ok": blocking_count == 0,
        "status": "FAIL" if blocking_count else "PASS",
        "error": "",
        "images": reports,
        "blocking_count": blocking_count,
        "finding_row_count": finding_row_count,
        "unique_cve_count": len(unique_cves),
        "tool": "trivy",
        "tool_version": tool_version,
        "database": database_meta,
        "scan_timestamp": scan_timestamp,
        "note": (
            "PASS means no fixed HIGH or CRITICAL finding and no unscored finding "
            "in the scanned images. Empty or mismatched reports are NOT_VERIFIED."
        ),
    }
