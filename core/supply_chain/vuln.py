"""Query the OSV database for pinned Python packages.

This is separate from the metadata audit. A successful audit does not mean
there are no known vulnerabilities. If the database cannot be reached, the
result is NOT_VERIFIED rather than clean.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any
from urllib.error import URLError
from urllib.request import Request, urlopen

OSV_BATCH_URL = "https://api.osv.dev/v1/querybatch"
_BLOCKING_LABELS = {"HIGH", "CRITICAL"}
_NON_BLOCKING_LABELS = {"LOW", "MODERATE", "MEDIUM"}
_FRESHNESS = (
    "OSV querybatch does not return a database snapshot time. "
    "generated_at is the client clock when the query finished."
)


def classify_vulnerability(vuln: dict[str, Any]) -> dict[str, Any]:
    """Classify one OSV vulnerability record.

    Unscored affected vulnerabilities are blocking so an unknown severity is
    not treated as safe. Withdrawn records are ignored.
    """
    if vuln.get("withdrawn"):
        return {
            "id": vuln.get("id"),
            "blocking": False,
            "withdrawn": True,
            "severity": "withdrawn",
        }
    labels: list[str] = []
    specific = vuln.get("database_specific") or {}
    if isinstance(specific, dict) and specific.get("severity"):
        labels.append(str(specific["severity"]).upper())
    for item in vuln.get("severity") or []:
        if isinstance(item, dict) and item.get("score") and not str(item["score"]).startswith("CVSS:"):
            labels.append(str(item["score"]).upper())
    blocking = True
    severity = "unscored"
    if any(label in _BLOCKING_LABELS for label in labels):
        severity = next(label for label in labels if label in _BLOCKING_LABELS)
        blocking = True
    elif labels and all(label in _NON_BLOCKING_LABELS for label in labels):
        severity = labels[0]
        blocking = False
    elif labels:
        severity = labels[0]
        blocking = True
    return {
        "id": vuln.get("id"),
        "summary": vuln.get("summary") or "",
        "blocking": blocking,
        "withdrawn": False,
        "severity": severity,
    }


def scan_components(components: list[dict[str, Any]], *, opener=None, timeout: float = 30) -> dict[str, Any]:
    """Query OSV for components that have an exact version."""
    fetch = opener or urlopen
    queried: list[dict[str, str]] = []
    skipped: list[str] = []
    for component in components:
        name = str(component.get("name") or "")
        version = component.get("version")
        if not name or not version:
            if name:
                skipped.append(name)
            continue
        queried.append({"name": name, "version": str(version)})
    generated = datetime.now(timezone.utc).isoformat()
    if not queried:
        return {
            "ok": False,
            "status": "NOT_VERIFIED",
            "error": "No exact-version components to query",
            "queried": [],
            "skipped_unpinned": skipped,
            "findings": [],
            "blocking_count": 0,
            "database": OSV_BATCH_URL,
            "generated_at": generated,
            "database_freshness": _FRESHNESS,
        }
    body = json.dumps(
        {
            "queries": [
                {"package": {"name": item["name"], "ecosystem": "PyPI"}, "version": item["version"]}
                for item in queried
            ]
        }
    ).encode("utf-8")
    request = Request(
        OSV_BATCH_URL,
        data=body,
        headers={"Content-Type": "application/json", "User-Agent": "pen-testing-platform-sbom"},
        method="POST",
    )
    try:
        with fetch(request, timeout=timeout) as response:
            payload = json.loads(response.read().decode("utf-8"))
    except (URLError, TimeoutError, OSError, json.JSONDecodeError) as exc:
        return {
            "ok": False,
            "status": "NOT_VERIFIED",
            "error": str(exc),
            "queried": queried,
            "skipped_unpinned": skipped,
            "findings": [],
            "blocking_count": 0,
            "database": OSV_BATCH_URL,
            "generated_at": generated,
            "database_freshness": _FRESHNESS,
        }
    results = payload.get("results") if isinstance(payload, dict) else None
    if not isinstance(results, list):
        return {
            "ok": False,
            "status": "NOT_VERIFIED",
            "error": "OSV response did not include a results list",
            "queried": queried,
            "skipped_unpinned": skipped,
            "findings": [],
            "blocking_count": 0,
            "database": OSV_BATCH_URL,
            "generated_at": generated,
            "database_freshness": _FRESHNESS,
        }
    findings: list[dict[str, Any]] = []
    for item, result in zip(queried, results):
        vulns = result.get("vulns") if isinstance(result, dict) else None
        for vuln in vulns or []:
            if not isinstance(vuln, dict):
                continue
            classified = classify_vulnerability(vuln)
            if classified.get("withdrawn"):
                continue
            classified["package"] = item["name"]
            classified["version"] = item["version"]
            findings.append(classified)
    blocking = [item for item in findings if item["blocking"]]
    return {
        "ok": not blocking,
        "status": "FAIL" if blocking else "PASS",
        "error": "",
        "queried": queried,
        "skipped_unpinned": skipped,
        "findings": findings,
        "blocking_count": len(blocking),
        "database": OSV_BATCH_URL,
        "generated_at": generated,
        "database_freshness": _FRESHNESS,
        "note": "PASS means no blocking OSV findings for the queried exact versions. It is not a claim about unpinned packages or unscanned images.",
    }
