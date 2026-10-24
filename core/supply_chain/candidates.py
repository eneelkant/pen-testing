"""Watch official image tags for digests that could replace fail-closed pins.

This module never mutates ``PINNED_IMAGES``. It resolves Hub tags to immutable
digests, reuses fresh prior evidence when the digest is unchanged, scans only
genuinely new digests, and reports ``NO_ACCEPTABLE_CANDIDATE`` when nothing
passes the existing fixed-HIGH/CRITICAL + unscored gate.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Callable

from core.supply_chain.images import (
    PINNED_IMAGES,
    TRIVY_IMAGE,
    _MAX_EVIDENCE_AGE,
    _parse_time,
    classify_trivy_document,
    parse_image_ref,
    read_trivy_version_document,
    scan_pinned_images,
)

# Evidence may be reused only when it was produced by this scanner identity.
REQUIRED_SCANNER_VERSION = parse_image_ref(TRIVY_IMAGE).get("tag") or "0.76.0"
REQUIRED_PLATFORM = "linux/amd64"

# Official tags to watch. Digests are resolved at runtime; pins are not updated.
CANDIDATE_WATCH = (
    {
        "name": "python-3.12-slim-bookworm",
        "hub_repository": "library/python",
        "tag": "3.12-slim-bookworm",
        "image": "python",
    },
    {
        "name": "python-3.13-slim-bookworm",
        "hub_repository": "library/python",
        "tag": "3.13-slim-bookworm",
        "image": "python",
    },
    {
        "name": "shannon-latest",
        "hub_repository": "keygraph/shannon",
        "tag": "latest",
        "image": "keygraph/shannon",
    },
    {
        "name": "temporal-latest",
        "hub_repository": "temporalio/temporal",
        "tag": "latest",
        "image": "temporalio/temporal",
    },
    {
        "name": "gitleaks-latest",
        "hub_repository": "zricethezav/gitleaks",
        "tag": "latest",
        "image": "zricethezav/gitleaks",
    },
    {
        "name": "trivy-latest",
        "hub_repository": "aquasec/trivy",
        "tag": "latest",
        "image": "aquasec/trivy",
    },
)

Fetcher = Callable[[str], dict[str, Any]]
Scanner = Callable[[str], dict[str, Any]]


def _pinned_digests() -> set[str]:
    digests: set[str] = set()
    for item in PINNED_IMAGES:
        digest = parse_image_ref(item["ref"]).get("digest") or ""
        if digest:
            digests.add(digest)
    return digests


def resolve_hub_tag(
    hub_repository: str,
    tag: str,
    *,
    fetcher: Fetcher | None = None,
) -> dict[str, Any]:
    """Resolve a Docker Hub tag to a linux/amd64 digest."""
    url = f"https://hub.docker.com/v2/repositories/{hub_repository}/tags/{tag}"
    if fetcher is None:
        def fetcher(target: str) -> dict[str, Any]:  # type: ignore[no-redef]
            request = urllib.request.Request(target, headers={"User-Agent": "pen-testing-candidate-monitor"})
            with urllib.request.urlopen(request, timeout=30) as response:
                return json.loads(response.read().decode("utf-8"))

    try:
        payload = fetcher(url)
    except (urllib.error.URLError, urllib.error.HTTPError, TimeoutError, json.JSONDecodeError, OSError) as exc:
        return {"ok": False, "error": str(exc), "digest": "", "last_updated": ""}
    if not isinstance(payload, dict):
        return {"ok": False, "error": "hub response was not an object", "digest": "", "last_updated": ""}
    digest = ""
    for image in payload.get("images") or []:
        if not isinstance(image, dict):
            continue
        if image.get("architecture") == "amd64" and image.get("os") == "linux" and not image.get("variant"):
            digest = str(image.get("digest") or "")
            break
    if not digest:
        for image in payload.get("images") or []:
            if isinstance(image, dict) and image.get("architecture") == "amd64" and image.get("os") == "linux":
                digest = str(image.get("digest") or "")
                break
    if not digest:
        return {"ok": False, "error": "linux/amd64 digest not found", "digest": "", "last_updated": ""}
    return {
        "ok": True,
        "digest": digest,
        "last_updated": str(payload.get("last_updated") or ""),
        "error": "",
    }


_DEFAULT_REJECTS = Path(__file__).resolve().parent / "candidate_rejects.json"


def _index_document(index: dict[str, dict[str, Any]], document: dict[str, Any], *, path: str) -> None:
    digests: list[str] = []
    if document.get("digest"):
        digests.append(str(document["digest"]))
    for image in document.get("images") or []:
        if isinstance(image, dict) and image.get("digest"):
            digests.append(str(image["digest"]))
    metadata = document.get("Metadata") if isinstance(document.get("Metadata"), dict) else {}
    for item in metadata.get("RepoDigests") or []:
        text = str(item)
        if "@" in text:
            digests.append(text.rsplit("@", 1)[-1])
    artifact = str(document.get("ArtifactName") or "")
    if "@sha256:" in artifact:
        digests.append(artifact.rsplit("@", 1)[-1])
    for digest in digests:
        if digest.startswith("sha256:") and len(digest) == 71:
            index[digest] = {"path": path, "document": document}


def _evidence_index(evidence_dir: Path | None) -> dict[str, dict[str, Any]]:
    """Index prior Trivy/classified JSON evidence by image digest.

    Always loads the committed reject inventory so unchanged digests are not
    rescanned. Optional ``evidence_dir`` overlays fresher local/CI artifacts.
    """
    index: dict[str, dict[str, Any]] = {}
    if _DEFAULT_REJECTS.is_file():
        try:
            payload = json.loads(_DEFAULT_REJECTS.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            payload = []
        if isinstance(payload, list):
            for document in payload:
                if isinstance(document, dict):
                    _index_document(index, document, path=str(_DEFAULT_REJECTS))
    if evidence_dir is None or not evidence_dir.is_dir():
        return index
    for path in sorted(evidence_dir.rglob("*.json")):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        if isinstance(document, list):
            for item in document:
                if isinstance(item, dict):
                    _index_document(index, item, path=str(path))
            continue
        if isinstance(document, dict):
            _index_document(index, document, path=str(path))
    return index


def _classify_from_evidence(
    document: dict[str, Any],
    *,
    ref: str,
    now: datetime,
    database: dict[str, str] | None,
) -> dict[str, Any]:
    # Already-classified pin/monitor rows.
    if document.get("status") in {"PASS", "FAIL", "NOT_VERIFIED"} and "blocking_count" in document:
        rebound = dict(document)
        identity = parse_image_ref(ref)
        # Keep the watched ref, but never invent a digest that was not recorded.
        rebound["image"] = ref
        rebound["name"] = identity["repository"]
        rebound["tag"] = identity["tag"]
        if identity["digest"]:
            rebound["digest"] = identity["digest"]
        return rebound
    return classify_trivy_document(document, image=ref, now=now, database=database)


def evidence_reusable(
    document: dict[str, Any],
    *,
    digest: str,
    now: datetime,
    max_age: timedelta,
    required_scanner_version: str = REQUIRED_SCANNER_VERSION,
    required_platform: str = REQUIRED_PLATFORM,
    live_database: dict[str, str] | None = None,
) -> tuple[bool, str]:
    """Return whether prior evidence may replace a fresh scan for ``digest``.

    Reuse requires an exact digest match, the required platform and scanner
    version, present CreatedAt / vulnerability-DB UpdatedAt timestamps within
    ``max_age``, and (when a live DB probe is provided) that the evidence DB is
    not older than the live probe's UpdatedAt.
    """
    if not isinstance(document, dict):
        return False, "evidence document is not an object"
    recorded = str(document.get("digest") or "")
    if not recorded:
        return False, "evidence digest is missing"
    if recorded != digest:
        return False, "evidence digest does not match resolved digest"
    platform = str(document.get("platform") or "")
    if not platform:
        return False, "evidence platform is missing"
    if platform != required_platform:
        return False, f"evidence platform {platform!r} does not match {required_platform!r}"
    scanner = str(document.get("scanner_version") or document.get("tool_version") or "")
    if not scanner:
        return False, "evidence scanner_version is missing"
    if scanner != required_scanner_version:
        return False, (
            f"evidence scanner_version {scanner!r} does not match "
            f"required {required_scanner_version!r}"
        )
    if document.get("status") == "NOT_VERIFIED":
        return False, "evidence status is NOT_VERIFIED"
    created_at = str(document.get("created_at") or "")
    created = _parse_time(created_at)
    if not created_at or created is None:
        return False, "evidence CreatedAt is missing"
    if now - created > max_age:
        return False, "evidence CreatedAt is stale"
    db_meta = document.get("database") if isinstance(document.get("database"), dict) else {}
    db_updated_raw = str(db_meta.get("updated_at") or "")
    db_updated = _parse_time(db_updated_raw)
    if not db_updated_raw or db_updated is None:
        return False, "evidence vulnerability database UpdatedAt is missing"
    if now - db_updated > max_age:
        return False, "evidence vulnerability database UpdatedAt is stale"
    if live_database:
        live_raw = str(live_database.get("updated_at") or "")
        live_updated = _parse_time(live_raw)
        if live_raw and live_updated is not None and db_updated < live_updated:
            return False, (
                "evidence vulnerability database UpdatedAt is older than the live "
                "trivy version probe"
            )
    return True, ""


def _default_scanner(ref: str) -> dict[str, Any]:
    scanned = scan_pinned_images(images=({"name": "candidate", "ref": ref},))
    images = scanned.get("images") or []
    if images:
        row = dict(images[0])
        row["tool_version"] = scanned.get("tool_version") or row.get("scanner_version") or ""
        row["database"] = scanned.get("database") or row.get("database") or {}
        row["scan_timestamp"] = scanned.get("scan_timestamp") or ""
        return row
    return {
        "ok": False,
        "status": scanned.get("status") or "NOT_VERIFIED",
        "image": ref,
        "error": scanned.get("error") or "scan produced no image row",
        "blocking_count": 0,
        "database": scanned.get("database") or {},
        "tool_version": scanned.get("tool_version") or "",
    }


def monitor_candidates(
    *,
    watch: tuple[dict[str, str], ...] | None = None,
    fetcher: Fetcher | None = None,
    scanner: Scanner | None = None,
    evidence_dir: Path | None = None,
    now: datetime | None = None,
    max_age: timedelta | None = None,
    database: dict[str, str] | None = None,
    required_scanner_version: str = REQUIRED_SCANNER_VERSION,
    required_platform: str = REQUIRED_PLATFORM,
) -> dict[str, Any]:
    """Resolve watched tags, reuse fresh evidence, scan new digests, never pin.

    Returns a report whose ``status`` is one of:
    ``ACCEPTABLE_CANDIDATE``, ``NO_ACCEPTABLE_CANDIDATE``, or ``NOT_VERIFIED``.
    """
    clock = now or datetime.now(timezone.utc)
    age_limit = max_age if max_age is not None else _MAX_EVIDENCE_AGE
    selected = watch if watch is not None else CANDIDATE_WATCH
    scan = scanner or _default_scanner
    evidence = _evidence_index(evidence_dir)
    pinned = _pinned_digests()
    rows: list[dict[str, Any]] = []
    acceptable: list[dict[str, Any]] = []
    unresolved = False

    for item in selected:
        hub_repository = item["hub_repository"]
        tag = item["tag"]
        image = item["image"]
        name = item["name"]
        resolved = resolve_hub_tag(hub_repository, tag, fetcher=fetcher)
        if not resolved.get("ok"):
            row = {
                "name": name,
                "image": image,
                "tag": tag,
                "ref": "",
                "digest": "",
                "status": "NOT_VERIFIED",
                "error": resolved.get("error") or "digest resolution failed",
                "reused_evidence": False,
                "blocking_count": 0,
                "provenance": f"https://hub.docker.com/r/{hub_repository}/tags",
            }
            rows.append(row)
            unresolved = True
            continue
        digest = str(resolved["digest"])
        ref = f"{image}:{tag}@{digest}"
        provenance = {
            "registry": "https://hub.docker.com",
            "hub_repository": hub_repository,
            "tag": tag,
            "digest": digest,
            "last_updated": resolved.get("last_updated") or "",
            "platform": "linux/amd64",
        }
        if digest in pinned:
            rows.append(
                {
                    "name": name,
                    "image": image,
                    "tag": tag,
                    "ref": ref,
                    "digest": digest,
                    "status": "SKIPPED_PINNED",
                    "error": "",
                    "reused_evidence": False,
                    "blocking_count": 0,
                    "provenance": provenance,
                    "note": "Digest matches a current pin; monitor does not re-evaluate pins here.",
                }
            )
            continue

        classified: dict[str, Any] | None = None
        reused = False
        reuse_error = ""
        prior = evidence.get(digest)
        if prior:
            ok_reuse, reuse_error = evidence_reusable(
                prior["document"],
                digest=digest,
                now=clock,
                max_age=age_limit,
                required_scanner_version=required_scanner_version,
                required_platform=required_platform,
                live_database=database,
            )
            if ok_reuse:
                classified = _classify_from_evidence(
                    prior["document"],
                    ref=ref,
                    now=clock,
                    database=database,
                )
                reused = True

        if classified is None:
            try:
                classified = scan(ref)
            except (OSError, TimeoutError, RuntimeError) as exc:
                classified = {
                    "ok": False,
                    "status": "NOT_VERIFIED",
                    "image": ref,
                    "error": str(exc),
                    "blocking_count": 0,
                }
            # Attach digest identity when the scanner returns a pin-style row.
            if not classified.get("digest"):
                classified["digest"] = digest
            if not classified.get("image"):
                classified["image"] = ref
            if reuse_error and not classified.get("error"):
                classified["reuse_rejected"] = reuse_error

        status = str(classified.get("status") or "NOT_VERIFIED")
        db_meta = classified.get("database") if isinstance(classified.get("database"), dict) else {}
        db_updated = _parse_time(str(db_meta.get("updated_at") or ""))
        if status != "NOT_VERIFIED" and (not db_meta.get("updated_at") or db_updated is None):
            status = "NOT_VERIFIED"
            classified = {
                **classified,
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "trivy vulnerability database UpdatedAt is missing",
            }
        if status != "NOT_VERIFIED" and db_updated is not None and clock - db_updated > age_limit:
            status = "NOT_VERIFIED"
            classified = {
                **classified,
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "trivy vulnerability database UpdatedAt is stale",
            }
        created = _parse_time(str(classified.get("created_at") or ""))
        if status != "NOT_VERIFIED" and (not classified.get("created_at") or created is None):
            status = "NOT_VERIFIED"
            classified = {
                **classified,
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "scan CreatedAt is missing",
            }
        if status != "NOT_VERIFIED" and created is not None and clock - created > age_limit:
            status = "NOT_VERIFIED"
            classified = {
                **classified,
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "scan CreatedAt is stale",
            }
        scanner_version = str(classified.get("scanner_version") or classified.get("tool_version") or "")
        if status != "NOT_VERIFIED" and scanner_version != required_scanner_version:
            status = "NOT_VERIFIED"
            classified = {
                **classified,
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": (
                    f"scanner_version {scanner_version!r} does not match "
                    f"required {required_scanner_version!r}"
                ),
            }
        platform = str(classified.get("platform") or "")
        if status != "NOT_VERIFIED" and platform != required_platform:
            status = "NOT_VERIFIED"
            classified = {
                **classified,
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": (
                    f"platform {platform!r} does not match required {required_platform!r}"
                    if platform
                    else "platform is missing"
                ),
            }

        row = {
            "name": name,
            "image": image,
            "tag": tag,
            "ref": ref,
            "digest": digest,
            "status": status,
            "error": classified.get("error") or "",
            "reused_evidence": reused,
            "reuse_rejected": "" if reused else reuse_error,
            "blocking_count": int(classified.get("blocking_count") or 0),
            "unscored_count": int(classified.get("unscored_count") or 0),
            "finding_row_count": int(classified.get("finding_row_count") or 0),
            "unique_cve_count": int(classified.get("unique_cve_count") or 0),
            "scanner_version": scanner_version,
            "database": db_meta,
            "created_at": classified.get("created_at") or "",
            "platform": platform,
            "provenance": provenance,
            "required_scanner_version": required_scanner_version,
            "required_platform": required_platform,
        }
        rows.append(row)
        if status == "NOT_VERIFIED":
            unresolved = True
        elif status == "PASS" and int(classified.get("blocking_count") or 0) == 0:
            acceptable.append(row)

    if unresolved and not acceptable:
        overall = "NOT_VERIFIED"
        note = "One or more candidates could not be verified; incomplete evidence is not treated as clean."
    elif acceptable:
        overall = "ACCEPTABLE_CANDIDATE"
        note = (
            "At least one watched digest passed the fixed HIGH/CRITICAL and unscored gate. "
            "Pins are not changed automatically; run compatibility tests before adopting."
        )
    else:
        overall = "NO_ACCEPTABLE_CANDIDATE"
        note = "No watched official digest passed the fail-closed image gate."

    return {
        "ok": overall == "ACCEPTABLE_CANDIDATE",
        "status": overall,
        "candidates": rows,
        "acceptable": acceptable,
        "pinned_digests": sorted(pinned),
        "tool": "trivy",
        "tool_version": required_scanner_version,
        "database": database or {},
        "required_scanner_version": required_scanner_version,
        "required_platform": required_platform,
        "scan_timestamp": clock.isoformat(),
        "note": note,
        "policy": (
            "PASS requires zero fixed HIGH/CRITICAL and zero unscored findings with valid "
            "fresh scan metadata. Reused evidence must match digest, platform, scanner "
            "version, and DB freshness (including live trivy version probe when provided). "
            "This monitor never updates PINNED_IMAGES or merges PRs."
        ),
    }


def load_version_database(document: dict[str, Any] | None) -> dict[str, str]:
    """Helper for CLI/workflow: parse ``trivy version --format json`` DB fields."""
    _, database = read_trivy_version_document(document)
    return database
