"""Watch official image tags for digests that could replace fail-closed pins.

This module never mutates ``PINNED_IMAGES``. It resolves Hub tags to immutable
digests, may reuse prior ``FAIL`` evidence to *reject* a digest without
rescanning, scans every other digest, and reports ``NO_ACCEPTABLE_CANDIDATE``
when nothing passes the existing fixed-HIGH/CRITICAL + unscored gate.

Acceptance rules (all must hold, otherwise the candidate fails closed):

* A successful live ``trivy version`` probe whose DB ``UpdatedAt`` parses, is
  not in the future, and is within the evidence age limit.
* A fresh scan in this run (never reused evidence) that carries the raw Trivy
  JSON document. Scanner-supplied ``status`` / ``blocking_count`` summaries are
  ignored; the raw findings are re-classified with ``classify_trivy_document``.
* The raw report names the exact resolved digest (``ArtifactName`` or
  ``Metadata.RepoDigests``), reports ``linux/amd64``, was produced by scanner
  ``0.76.0``, has a present and fresh ``CreatedAt``, and its vulnerability DB is
  fresh and not older than the live probe.
* Zero fixed HIGH/CRITICAL findings and zero unscored findings.
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
    REQUIRED_PLATFORM,
    REQUIRED_SCANNER_VERSION,
    _DIGEST_RE,
    _MAX_EVIDENCE_AGE,
    _not_verified,
    _parse_time,
    _scanner_version,
    classify_trivy_document,
    parse_image_ref,
    read_trivy_version_document,
    scan_pinned_images,
)

# REQUIRED_SCANNER_VERSION / REQUIRED_PLATFORM are defined once in images.py and
# re-exported here so pinned scans and candidate acceptance cannot drift apart.
# Tolerated clock skew before a live DB timestamp is treated as "in the future".
_CLOCK_SKEW = timedelta(minutes=5)

# Official tags to watch. Digests are resolved at runtime; pins are not updated.
CANDIDATE_WATCH = (
    {
        "name": "python-3.12-slim-bookworm",
        "hub_repository": "library/python",
        "tag": "3.12-slim-bookworm",
        "image": "python",
    },
    {
        "name": "python-3.12-alpine3.24",
        "hub_repository": "library/python",
        "tag": "3.12-alpine3.24",
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

_POLICY = (
    "PASS requires zero fixed HIGH/CRITICAL and zero unscored findings, re-classified "
    "from raw Trivy JSON produced by a fresh scan in this run with exact digest, "
    "linux/amd64, scanner 0.76.0, fresh CreatedAt, and a vulnerability DB that is fresh "
    "and not older than a successful live trivy version probe. Stored or reused PASS "
    "summaries never authorize acceptance; reused FAIL evidence may only reject. "
    "This monitor never updates PINNED_IMAGES or merges PRs."
)


def _pinned_digests() -> set[str]:
    """Index digests of every pin plus each pin's linux/amd64 child digest.

    Hub tags resolve to per-platform digests, so the child digest is what
    identifies "this candidate is already the pinned image".
    """
    digests: set[str] = set()
    for item in PINNED_IMAGES:
        digest = parse_image_ref(item["ref"]).get("digest") or ""
        if digest:
            digests.add(digest)
        platform_digest = str(item.get("platform_digest") or "")
        if platform_digest:
            digests.add(platform_digest)
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

    Always loads the committed reject inventory so unchanged rejected digests
    are not rescanned. Optional ``evidence_dir`` overlays fresher artifacts.
    Indexed evidence can only ever reject a candidate, never accept one.
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


def validate_live_database(
    database: dict[str, str] | None,
    *,
    now: datetime,
    max_age: timedelta,
) -> tuple[datetime | None, str]:
    """Validate the live ``trivy version`` probe. Returns (UpdatedAt, error).

    A missing, unparseable, stale, or future-dated UpdatedAt is a failed probe.
    """
    if not isinstance(database, dict):
        return None, "live vulnerability database probe failed or UpdatedAt is missing"
    raw = str(database.get("updated_at") or "")
    if not raw:
        return None, "live vulnerability database probe failed or UpdatedAt is missing"
    updated = _parse_time(raw)
    if updated is None:
        return None, f"live vulnerability database UpdatedAt {raw!r} is not a valid timestamp"
    if updated - now > _CLOCK_SKEW:
        return None, "live vulnerability database UpdatedAt is in the future"
    if now - updated > max_age:
        return None, "live vulnerability database UpdatedAt is stale"
    return updated, ""


def evidence_reusable(
    document: dict[str, Any],
    *,
    digest: str,
    now: datetime,
    max_age: timedelta,
    required_scanner_version: str = REQUIRED_SCANNER_VERSION,
    required_platform: str = REQUIRED_PLATFORM,
    live_database: dict[str, str] | None = None,
    require_live_database: bool = True,
) -> tuple[bool, str]:
    """Return whether prior evidence may be used to *reject* ``digest``.

    Reuse requires an exact digest match, the required platform and scanner
    version, present CreatedAt / vulnerability-DB UpdatedAt timestamps within
    ``max_age``, and (by default) a valid live DB probe whose UpdatedAt is not
    newer than the evidence DB. Stored PASS is never reusable.
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
    if document.get("status") == "PASS":
        return False, "PASS evidence cannot be reused; require a fresh scan"
    created_at = str(document.get("created_at") or document.get("CreatedAt") or "")
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
    if require_live_database or live_database:
        live_updated, live_error = validate_live_database(live_database, now=now, max_age=max_age)
        if live_updated is None:
            if require_live_database:
                return False, f"live probe required for evidence reuse: {live_error}"
        elif db_updated < live_updated:
            return False, (
                "evidence vulnerability database UpdatedAt is older than the live "
                "trivy version probe"
            )
    return True, ""


def _classify_reused_evidence(
    document: dict[str, Any],
    *,
    ref: str,
    now: datetime,
    database: dict[str, str] | None,
) -> dict[str, Any]:
    """Materialize stored evidence for rejection only.

    Raw Trivy documents (``Results`` present) are re-classified. A stored
    summary is honoured only when it says FAIL. Anything else becomes
    NOT_VERIFIED so the caller rescans instead of trusting it.
    """
    identity = parse_image_ref(ref)
    if "Results" in document:
        classified = classify_trivy_document(document, image=ref, now=now, database=database)
        if not classified.get("scanner_version"):
            classified["scanner_version"] = str(
                document.get("scanner_version") or document.get("tool_version") or ""
            )
        if not classified.get("platform"):
            classified["platform"] = str(document.get("platform") or "")
        return classified

    if str(document.get("status") or "") == "FAIL" and "blocking_count" in document:
        rebound = dict(document)
        rebound["image"] = ref
        rebound["name"] = identity["repository"]
        rebound["tag"] = identity["tag"]
        if identity["digest"]:
            rebound["digest"] = identity["digest"]
        if rebound.get("platform") is None:
            rebound["platform"] = ""
        return rebound

    return _not_verified(ref, "stored evidence is not a FAIL summary or raw Trivy report; rescan required")


def _manifest_digests(document: dict[str, Any]) -> set[str]:
    """Digests that identify the scanned manifest (not layers or config)."""
    found: set[str] = set(_DIGEST_RE.findall(str(document.get("ArtifactName") or "")))
    metadata = document.get("Metadata") if isinstance(document.get("Metadata"), dict) else {}
    repo_digests = metadata.get("RepoDigests")
    if isinstance(repo_digests, str):
        found.update(_DIGEST_RE.findall(repo_digests))
    elif isinstance(repo_digests, list):
        for item in repo_digests:
            found.update(_DIGEST_RE.findall(str(item)))
    return found


def _raw_findings_error(document: dict[str, Any]) -> str:
    """Return an error if raw Trivy findings are absent or malformed."""
    results = document.get("Results")
    if not isinstance(results, list):
        return "raw Trivy Results is missing or not a list"
    for result in results:
        if not isinstance(result, dict):
            return "raw Trivy Results contains a non-object entry"
        vulns = result.get("Vulnerabilities")
        if vulns is None:
            continue
        if not isinstance(vulns, list):
            return "raw Trivy Vulnerabilities is not a list"
        for vuln in vulns:
            if not isinstance(vuln, dict) or not str(vuln.get("VulnerabilityID") or ""):
                return "raw Trivy finding is malformed or missing VulnerabilityID"
    return ""


def verify_fresh_scan(
    result: Any,
    *,
    ref: str,
    digest: str,
    now: datetime,
    max_age: timedelta,
    live_updated: datetime,
    required_scanner_version: str = REQUIRED_SCANNER_VERSION,
    required_platform: str = REQUIRED_PLATFORM,
) -> dict[str, Any]:
    """Independently classify a fresh scan from its raw Trivy document.

    The scanner's own ``status``, counts, ``platform`` and ``findings`` are
    ignored. Only ``raw_document``, the scanner-probed ``database`` metadata,
    ``tool_version`` / ``scanner_version`` (diagnostics; never a substitute for
    missing ``Trivy.Version`` in the raw report) and ``exit_code`` are read from
    ``result``.
    """
    if not isinstance(result, dict):
        return _not_verified(ref, "scanner returned a non-object result")
    if result.get("status") == "NOT_VERIFIED":
        return _not_verified(ref, str(result.get("error") or "scan was not verified"))
    raw = result.get("raw_document")
    if not isinstance(raw, dict) or not raw:
        return _not_verified(
            ref, "raw Trivy findings are missing; scanner summaries are not trusted for acceptance"
        )
    malformed = _raw_findings_error(raw)
    if malformed:
        return _not_verified(ref, malformed)
    if digest not in _manifest_digests(raw):
        return _not_verified(
            ref,
            "raw Trivy report does not name the exact resolved digest",
            reported_digests=sorted(_manifest_digests(raw)),
        )

    scan_db = result.get("database") if isinstance(result.get("database"), dict) else {}
    exit_code = result.get("exit_code")
    classified = classify_trivy_document(
        raw,
        image=ref,
        now=now,
        max_age=max_age,
        exit_code=exit_code if isinstance(exit_code, int) else None,
        database=scan_db,
    )
    if classified.get("status") == "NOT_VERIFIED":
        return classified
    # A scanner summary that disagrees with the raw reclassification means the
    # evidence is internally inconsistent; fail closed rather than pick one.
    for key in ("blocking_count", "unscored_count"):
        if key in result:
            try:
                claimed = int(result.get(key) or 0)
            except (TypeError, ValueError):
                return _not_verified(ref, f"scanner summary {key} is not an integer")
            if claimed != int(classified.get(key) or 0):
                return _not_verified(
                    ref,
                    f"scanner summary {key}={claimed} disagrees with raw reclassification "
                    f"{key}={int(classified.get(key) or 0)}",
                )

    created = _parse_time(str(classified.get("created_at") or ""))
    if created is None:
        return _not_verified(ref, "raw Trivy report CreatedAt is missing or invalid")
    if created - now > _CLOCK_SKEW:
        return _not_verified(ref, "raw Trivy report CreatedAt is in the future")

    raw_version = _scanner_version(raw)
    if not raw_version:
        return _not_verified(
            ref,
            "scanner version is missing from the Trivy report; the local probe is not accepted as a substitute",
            scanner_version="",
        )
    probed_version = str(result.get("tool_version") or result.get("scanner_version") or "")
    if probed_version and raw_version != probed_version:
        return _not_verified(
            ref, f"raw report scanner {raw_version!r} disagrees with probed scanner {probed_version!r}"
        )
    if raw_version != required_scanner_version:
        return _not_verified(
            ref,
            f"scanner_version {raw_version!r} does not match required {required_scanner_version!r}",
            scanner_version=raw_version,
        )
    classified["scanner_version"] = raw_version

    platform = str(classified.get("platform") or "")
    if platform != required_platform:
        return _not_verified(
            ref,
            f"platform {platform!r} does not match required {required_platform!r}"
            if platform
            else "platform is missing from raw Trivy report",
            platform=platform,
        )

    db_meta = classified.get("database") if isinstance(classified.get("database"), dict) else {}
    db_updated = _parse_time(str(db_meta.get("updated_at") or ""))
    if db_updated is None:
        return _not_verified(ref, "scan vulnerability database UpdatedAt is missing or invalid")
    if db_updated < live_updated:
        return _not_verified(
            ref, "scan vulnerability database UpdatedAt is older than the live trivy version probe"
        )
    return classified


def _default_scanner(ref: str) -> dict[str, Any]:
    scanned = scan_pinned_images(images=({"name": "candidate", "ref": ref},), include_raw=True)
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
        "platform": "",
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
    require_live_database: bool = True,
) -> dict[str, Any]:
    """Resolve watched tags, reject via fresh FAIL evidence, scan the rest, never pin.

    Returns a report whose ``status`` is one of:
    ``ACCEPTABLE_CANDIDATE``, ``NO_ACCEPTABLE_CANDIDATE``, or ``NOT_VERIFIED``.

    A validated live DB probe is always required for acceptance.
    ``require_live_database`` additionally governs whether FAIL evidence may be
    reused without one; setting it to False can never make a candidate acceptable.
    """
    clock = now or datetime.now(timezone.utc)
    age_limit = max_age if max_age is not None else _MAX_EVIDENCE_AGE
    selected = watch if watch is not None else CANDIDATE_WATCH
    scan = scanner or _default_scanner
    pinned = _pinned_digests()
    live_updated, live_error = validate_live_database(database, now=clock, max_age=age_limit)

    base = {
        "pinned_digests": sorted(pinned),
        "tool": "trivy",
        "tool_version": required_scanner_version,
        "database": database or {},
        "required_scanner_version": required_scanner_version,
        "required_platform": required_platform,
        "scan_timestamp": clock.isoformat(),
        "policy": _POLICY,
    }
    if require_live_database and live_updated is None:
        return {
            "ok": False,
            "status": "NOT_VERIFIED",
            "candidates": [],
            "acceptable": [],
            **base,
            "error": live_error,
            "note": "Incomplete live DB metadata is not treated as clean; candidates were not accepted.",
        }

    evidence = _evidence_index(evidence_dir)
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
            rows.append(
                {
                    "name": name,
                    "image": image,
                    "tag": tag,
                    "ref": "",
                    "digest": "",
                    "status": "NOT_VERIFIED",
                    "error": resolved.get("error") or "digest resolution failed",
                    "reused_evidence": False,
                    "reuse_rejected": "",
                    "blocking_count": 0,
                    "platform": "",
                    "provenance": f"https://hub.docker.com/r/{hub_repository}/tags",
                }
            )
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
            "platform": required_platform,
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
                    "reuse_rejected": "",
                    "blocking_count": 0,
                    "platform": "",
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
                require_live_database=require_live_database,
            )
            if ok_reuse:
                candidate = _classify_reused_evidence(
                    prior["document"], ref=ref, now=clock, database=database
                )
                # Reuse may only reject. Anything other than FAIL forces a rescan.
                if candidate.get("status") == "FAIL":
                    classified = candidate
                    reused = True
                elif candidate.get("status") == "PASS":
                    reuse_error = "reused evidence classified PASS; reuse never accepts, rescanning"
                else:
                    reuse_error = str(candidate.get("error") or "reused evidence not verified")

        if classified is None:
            try:
                result = scan(ref)
            except Exception as exc:  # scanner is an untrusted boundary: fail closed
                result = _not_verified(ref, f"scanner error: {type(exc).__name__}: {exc}")
            if live_updated is None:
                classified = _not_verified(
                    ref, f"live probe required before accepting a candidate: {live_error}"
                )
            else:
                classified = verify_fresh_scan(
                    result,
                    ref=ref,
                    digest=digest,
                    now=clock,
                    max_age=age_limit,
                    live_updated=live_updated,
                    required_scanner_version=required_scanner_version,
                    required_platform=required_platform,
                )

        status = str(classified.get("status") or "NOT_VERIFIED")
        blocking_count = int(classified.get("blocking_count") or 0)
        unscored_count = int(classified.get("unscored_count") or 0)
        if status == "PASS" and (blocking_count or unscored_count):
            # Defensive: the canonical classifier never emits this combination.
            status = "FAIL"
        db_meta = classified.get("database") if isinstance(classified.get("database"), dict) else {}

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
            "blocking_count": blocking_count,
            "unscored_count": unscored_count,
            "finding_row_count": int(classified.get("finding_row_count") or 0),
            "unique_cve_count": int(classified.get("unique_cve_count") or 0),
            "scanner_version": str(classified.get("scanner_version") or classified.get("tool_version") or ""),
            "database": db_meta,
            "created_at": classified.get("created_at") or "",
            "platform": str(classified.get("platform") or ""),
            "provenance": provenance,
            "required_scanner_version": required_scanner_version,
            "required_platform": required_platform,
        }
        rows.append(row)
        if status == "NOT_VERIFIED":
            unresolved = True
        elif status == "PASS" and not reused and live_updated is not None:
            acceptable.append(row)

    if unresolved and not acceptable:
        overall = "NOT_VERIFIED"
        note = "One or more candidates could not be verified; incomplete evidence is not treated as clean."
    elif acceptable:
        overall = "ACCEPTABLE_CANDIDATE"
        note = (
            "At least one watched digest passed the fixed HIGH/CRITICAL and unscored gate on a "
            "fresh raw scan. Pins are not changed automatically; run compatibility tests before adopting."
        )
    else:
        overall = "NO_ACCEPTABLE_CANDIDATE"
        note = "No watched official digest passed the fail-closed image gate."

    return {
        "ok": overall == "ACCEPTABLE_CANDIDATE",
        "status": overall,
        "candidates": rows,
        "acceptable": acceptable,
        **base,
        "note": note,
    }


def load_version_database(document: dict[str, Any] | None) -> dict[str, str]:
    """Helper for CLI/workflow: parse ``trivy version --format json`` DB fields."""
    _, database = read_trivy_version_document(document)
    return database
