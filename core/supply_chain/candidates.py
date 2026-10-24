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
    _MAX_EVIDENCE_AGE,
    _parse_time,
    classify_trivy_document,
    parse_image_ref,
    read_trivy_version_document,
    scan_pinned_images,
)

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
        if document.get("image") and document.get("image") != ref:
            # Re-bind identity to the watched ref when the digest matches.
            rebound = dict(document)
            rebound["image"] = ref
            identity = parse_image_ref(ref)
            rebound["name"] = identity["repository"]
            rebound["tag"] = identity["tag"]
            rebound["digest"] = identity["digest"]
            return rebound
        return document
    return classify_trivy_document(document, image=ref, now=now, database=database)


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
        prior = evidence.get(digest)
        if prior:
            candidate = _classify_from_evidence(
                prior["document"],
                ref=ref,
                now=clock,
                database=database,
            )
            db_meta = candidate.get("database") if isinstance(candidate.get("database"), dict) else {}
            db_updated = _parse_time(str(db_meta.get("updated_at") or ""))
            created = _parse_time(str(candidate.get("created_at") or ""))
            platform = str(candidate.get("platform") or "")
            scanner = str(candidate.get("scanner_version") or candidate.get("tool_version") or "")
            fresh = True
            if candidate.get("status") == "NOT_VERIFIED":
                fresh = False
            if not db_meta.get("updated_at"):
                fresh = False
            if db_updated is not None and clock - db_updated > age_limit:
                fresh = False
            if created is not None and clock - created > age_limit:
                fresh = False
            # Bound reused evidence to platform + scanner identity. Missing or
            # mismatched fields are not treated as a reusable pass/fail row.
            if platform and platform != "linux/amd64":
                fresh = False
            if not platform or not scanner:
                fresh = False
            if database and database.get("updated_at") and db_meta.get("updated_at"):
                # Live probe wins: stale inventory relative to the probe is not fresh.
                live = _parse_time(str(database.get("updated_at")))
                if live is not None and db_updated is not None and db_updated < live:
                    fresh = False
            if fresh:
                classified = candidate
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

        status = str(classified.get("status") or "NOT_VERIFIED")
        db_meta = classified.get("database") if isinstance(classified.get("database"), dict) else {}
        db_updated = _parse_time(str(db_meta.get("updated_at") or ""))
        if status != "NOT_VERIFIED" and db_updated is not None and clock - db_updated > age_limit:
            status = "NOT_VERIFIED"
            classified = {
                **classified,
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "trivy vulnerability database UpdatedAt is stale",
            }
        created = _parse_time(str(classified.get("created_at") or ""))
        if status != "NOT_VERIFIED" and created is not None and clock - created > age_limit:
            status = "NOT_VERIFIED"
            classified = {
                **classified,
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "scan CreatedAt is stale",
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
            "blocking_count": int(classified.get("blocking_count") or 0),
            "unscored_count": int(classified.get("unscored_count") or 0),
            "finding_row_count": int(classified.get("finding_row_count") or 0),
            "unique_cve_count": int(classified.get("unique_cve_count") or 0),
            "scanner_version": classified.get("scanner_version") or classified.get("tool_version") or "",
            "database": db_meta,
            "created_at": classified.get("created_at") or "",
            "platform": classified.get("platform") or "linux/amd64",
            "provenance": provenance,
        }
        rows.append(row)
        if status == "NOT_VERIFIED":
            unresolved = True
        elif (
            status == "PASS"
            and int(classified.get("blocking_count") or 0) == 0
            and int(classified.get("unscored_count") or 0) == 0
        ):
            acceptable.append(row)
        elif status == "PASS" and int(classified.get("unscored_count") or 0) > 0:
            # Defensive: a PASS body that still reports unscored rows is not acceptable.
            row["status"] = "FAIL"
            row["error"] = "PASS row reported unscored findings; treated as FAIL"
            rows[-1] = row

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
        "database": database or {},
        "scan_timestamp": clock.isoformat(),
        "note": note,
        "policy": (
            "PASS requires zero fixed HIGH/CRITICAL and zero unscored findings with valid "
            "fresh scan metadata. This monitor never updates PINNED_IMAGES or merges PRs."
        ),
    }


def load_version_database(document: dict[str, Any] | None) -> dict[str, str]:
    """Helper for CLI/workflow: parse ``trivy version --format json`` DB fields."""
    _, database = read_trivy_version_document(document)
    return database
