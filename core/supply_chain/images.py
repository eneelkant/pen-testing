"""Container image pins and an optional Trivy scan.

Digests were resolved from the registry on 2026-10-18. A scan that cannot run
is NOT_VERIFIED. Fixed HIGH and CRITICAL findings are blocking. Unfixed
findings are reported and are not a claim that the image is safe.
"""

from __future__ import annotations

import json
import shutil
from typing import Any, Callable

PINNED_IMAGES = (
    {
        "name": "python-3.12-probe",
        "ref": "python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258",
    },
    {
        "name": "python-3.12-orchestrator",
        "ref": "python:3.12-slim-bookworm@sha256:34386ef0cb081344d7ec1c103ba398e6e9f64e9ab3a1509accc92a4e24a07258",
    },
    {
        "name": "shannon-worker",
        "ref": "keygraph/shannon:3.4.0@sha256:4e726ed8f3a0b10e2a1dbb41185a526f20ea6fccc98740ca553e3c00c2a6bd0e",
    },
    {
        "name": "temporal",
        "ref": "temporalio/temporal:1.7.0@sha256:9c5b386d86bca59ba08f32ddc4c51287351c8c616b6a8359f03e96a585e137f4",
    },
    {
        "name": "gitleaks",
        "ref": "zricethezav/gitleaks:v8.21.2@sha256:0e99e8821643ea5b235718642b93bb32486af9c8162c8b8731f7cbdc951a7f46",
    },
    {
        "name": "trivy-scanner",
        "ref": "aquasec/trivy:0.76.0@sha256:2416d1f74045b57274df1a340eee6b510cacd73c66a6ccb8da092b117eb7d222",
    },
)

TRIVY_IMAGE = PINNED_IMAGES[-1]["ref"]
_BLOCKING = {"HIGH", "CRITICAL"}


def classify_trivy_document(document: dict[str, Any], *, image: str) -> dict[str, Any]:
    findings: list[dict[str, Any]] = []
    for result in document.get("Results") or []:
        if not isinstance(result, dict):
            continue
        for vuln in result.get("Vulnerabilities") or []:
            if not isinstance(vuln, dict):
                continue
            severity = str(vuln.get("Severity") or "UNKNOWN").upper()
            fixed = str(vuln.get("FixedVersion") or "")
            findings.append(
                {
                    "id": vuln.get("VulnerabilityID"),
                    "package": vuln.get("PkgName"),
                    "installed": vuln.get("InstalledVersion"),
                    "fixed": fixed,
                    "severity": severity,
                    "blocking": severity in _BLOCKING and bool(fixed),
                    "image": image,
                }
            )
    blocking = [item for item in findings if item["blocking"]]
    return {
        "ok": not blocking,
        "status": "FAIL" if blocking else "PASS",
        "image": image,
        "findings": findings,
        "blocking_count": len(blocking),
        "unfixed_count": sum(1 for item in findings if not item["fixed"]),
        "note": "Unfixed findings are visible and are not blocking. They are not a waiver.",
    }


def scan_pinned_images(
    *,
    runner: Callable[..., Any] | None = None,
    images: tuple[dict[str, str], ...] | None = None,
) -> dict[str, Any]:
    """Scan pinned images with a local trivy binary or a pinned trivy container.

    ``runner`` is a test hook. It receives the argument list and returns an
    object with ``returncode`` and ``stdout``.
    """
    selected = images if images is not None else PINNED_IMAGES
    if runner is None:
        if shutil.which("trivy"):
            def runner(args, timeout=600):  # type: ignore[no-redef]
                import subprocess

                completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
                return completed
            invoke = runner
            prefix: list[str] = ["trivy"]
        elif shutil.which("docker"):
            def runner(args, timeout=600):  # type: ignore[no-redef]
                import subprocess

                completed = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
                return completed
            invoke = runner
            prefix = ["docker", "run", "--rm", TRIVY_IMAGE]
        else:
            return {
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": "trivy and docker are unavailable",
                "images": [],
                "blocking_count": 0,
                "tool": "trivy",
                "tool_version": "",
            }
    else:
        invoke = runner
        prefix = ["trivy"]

    reports = []
    blocking_count = 0
    for image in selected:
        args = [
            *prefix,
            "image",
            "--severity",
            "HIGH,CRITICAL",
            "--format",
            "json",
            "--quiet",
            image["ref"],
        ]
        try:
            completed = invoke(args)
        except (OSError, TimeoutError) as exc:
            return {
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": str(exc),
                "images": reports,
                "blocking_count": blocking_count,
                "tool": "trivy",
                "tool_version": "0.76.0",
            }
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
                "tool": "trivy",
                "tool_version": "0.76.0",
            }
        classified = classify_trivy_document(document if isinstance(document, dict) else {}, image=image["ref"])
        if getattr(completed, "returncode", 0) not in {0, None} and not classified["findings"]:
            classified = {
                "ok": False,
                "status": "NOT_VERIFIED",
                "image": image["ref"],
                "findings": [],
                "blocking_count": 0,
                "error": (getattr(completed, "stderr", "") or "")[:500],
            }
        reports.append(classified)
        blocking_count += int(classified.get("blocking_count") or 0)
        if classified.get("status") == "NOT_VERIFIED":
            return {
                "ok": False,
                "status": "NOT_VERIFIED",
                "error": classified.get("error") or "image scan failed",
                "images": reports,
                "blocking_count": blocking_count,
                "tool": "trivy",
                "tool_version": "0.76.0",
            }
    return {
        "ok": blocking_count == 0,
        "status": "FAIL" if blocking_count else "PASS",
        "error": "",
        "images": reports,
        "blocking_count": blocking_count,
        "tool": "trivy",
        "tool_version": "0.76.0",
        "note": "PASS means no fixed HIGH or CRITICAL finding in the scanned images.",
    }
