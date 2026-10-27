"""Report export: JSON, Markdown, and best-effort SARIF."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core.findings import Finding, redact_secrets
from core.findings.redaction import allowlist_finding_fields
from core.paths import safe_write_text


def export_json(findings: Iterable[Finding], path: str | Path, *, metadata: dict[str, Any] | None = None) -> Path:
    path = Path(path)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": redact_secrets(metadata or {}),
        "findings": [allowlist_finding_fields(redact_secrets(f.to_dict())) for f in findings],
    }
    return safe_write_text(path, json.dumps(payload, indent=2))


def export_markdown(
    findings: Iterable[Finding],
    path: str | Path,
    *,
    title: str = "Security Assessment Report (Draft)",
    metadata: dict[str, Any] | None = None,
) -> Path:
    path = Path(path)
    findings = list(findings)
    meta = redact_secrets(metadata or {})
    lines = [
        f"# {title}",
        "",
        f"_Generated: {datetime.now(timezone.utc).isoformat()}_",
        "",
        "**Human review required. Do not submit automatically.**",
        "",
    ]
    if meta:
        lines.extend(["## Run metadata", "", "```json", json.dumps(meta, indent=2), "```", ""])
    lines.extend([f"## Findings ({len(findings)})", ""])
    if not findings:
        lines.append("No findings in this draft.")
    for idx, finding in enumerate(findings, 1):
        data = redact_secrets(finding.to_dict())
        lines.extend(
            [
                f"### {idx}. {data.get('title')}",
                "",
                f"- **ID:** `{data.get('finding_id')}`",
                f"- **Tool:** {data.get('source_tool')} ({data.get('source_tool_version')})",
                f"- **Asset:** {data.get('asset')}",
                f"- **Severity:** {data.get('severity')}",
                f"- **Verification:** {data.get('verification_state')}",
                f"- **Lifecycle:** {data.get('lifecycle')}",
                f"- **Category:** {data.get('category')}",
                "",
                "#### Impact",
                "",
                data.get("impact") or "_Not provided_",
                "",
                "#### Observed behavior",
                "",
                data.get("observed_behavior") or "_Not provided_",
                "",
                "#### Remediation",
                "",
            ]
        )
        rem = data.get("remediation") or []
        if rem:
            lines.extend([f"- {item}" for item in rem])
        else:
            lines.append("_Not provided_")
        lines.append("")
    return safe_write_text(path, "\n".join(lines) + "\n")


_SEVERITY_TO_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def export_sarif(findings: Iterable[Finding], path: str | Path, *, tool_name: str = "pen-testing-platform") -> Path:
    path = Path(path)
    results = []
    rules = {}
    for finding in findings:
        data = redact_secrets(finding.to_dict())
        rule_id = f"{data.get('source_tool')}:{data.get('category')}"
        rules[rule_id] = {
            "id": rule_id,
            "name": data.get("category") or rule_id,
            "shortDescription": {"text": data.get("title") or rule_id},
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": _SEVERITY_TO_LEVEL.get(str(data.get("severity", "info")).lower(), "note"),
                "message": {"text": data.get("title") or rule_id},
                "properties": {
                    "verification_state": data.get("verification_state"),
                    "lifecycle": data.get("lifecycle"),
                    "asset": data.get("asset"),
                    "finding_id": data.get("finding_id"),
                },
            }
        )
    sarif = {
        "version": "2.1.0",
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": tool_name,
                        "informationUri": "https://github.com/eneelkant/pen-testing",
                        "rules": list(rules.values()),
                    }
                },
                "results": results,
            }
        ],
    }
    return safe_write_text(path, json.dumps(sarif, indent=2))
