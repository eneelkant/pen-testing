"""Report export: JSON, Markdown, and best-effort SARIF."""

from __future__ import annotations

import html
import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable

from core.findings import Finding, ValidationStatus, redact_secrets
from core.paths import safe_write_text

_MD_SPECIAL = re.compile(r"([\\`*_{}\[\]()#+\-.!|>])")


def escape_markdown(value: Any) -> str:
    """Neutralize Markdown/HTML injection in untrusted finding fields."""
    text = "" if value is None else str(value)
    text = html.escape(text, quote=True)
    return _MD_SPECIAL.sub(r"\\\1", text)


def filter_reportable_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Drop blocked/out-of-scope findings from human-facing draft exports."""
    out: list[Finding] = []
    for finding in findings:
        status = (finding.validation_status or "").lower()
        if status == ValidationStatus.BLOCKED.value:
            continue
        out.append(finding)
    return out


def export_json(findings: Iterable[Finding], path: str | Path, *, metadata: dict[str, Any] | None = None) -> Path:
    path = Path(path)
    reportable = filter_reportable_findings(findings)
    payload = {
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "metadata": redact_secrets(metadata or {}),
        "findings": [redact_secrets(f.to_dict()) for f in reportable],
        "human_review_required": True,
        "auto_submit": False,
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
    findings = filter_reportable_findings(findings)
    meta = redact_secrets(metadata or {})
    lines = [
        f"# {escape_markdown(title)}",
        "",
        f"_Generated: {datetime.now(timezone.utc).isoformat()}_",
        "",
        "**Human review required. Do not submit automatically to any bug-bounty program.**",
        "",
        "Scanner severity alone does not confirm a vulnerability. "
        "Only findings with validation_status=`validated` after human review should be considered for submission.",
        "",
    ]
    if meta:
        lines.extend(
            [
                "## Assessment context",
                "",
                f"- **Assessment ID:** `{escape_markdown(meta.get('assessment_id', ''))}`",
                f"- **Authorized scope / profile:** {escape_markdown(meta.get('profile_id') or meta.get('scope') or 'see registry')}",
                f"- **Tool:** {escape_markdown(meta.get('tool', ''))} {escape_markdown(meta.get('tool_version', ''))}",
                f"- **Limitations:** {escape_markdown(meta.get('limitations', 'See untested areas below'))}",
                "",
                "```json",
                json.dumps(meta, indent=2),
                "```",
                "",
            ]
        )
    lines.extend([f"## Findings ({len(findings)})", ""])
    if not findings:
        lines.append("No findings in this draft.")
    for idx, finding in enumerate(findings, 1):
        data = redact_secrets(finding.to_dict())
        lines.extend(
            [
                f"### {idx}. {escape_markdown(data.get('title'))}",
                "",
                f"- **ID:** `{escape_markdown(data.get('finding_id'))}`",
                f"- **Tool:** {escape_markdown(data.get('source_tool'))} ({escape_markdown(data.get('source_tool_version'))})",
                f"- **Asset:** {escape_markdown(data.get('asset'))}",
                f"- **Severity (proposed):** {escape_markdown(data.get('severity'))}",
                f"- **Validation status:** {escape_markdown(data.get('validation_status'))}",
                f"- **Verification:** {escape_markdown(data.get('verification_state'))}",
                f"- **Confidence:** {escape_markdown(data.get('confidence'))}",
                f"- **Lifecycle:** {escape_markdown(data.get('lifecycle'))}",
                f"- **Category:** {escape_markdown(data.get('category'))}",
                "",
                "#### Safe reproduction steps",
                "",
            ]
        )
        steps = data.get("reproduction_steps") or []
        if steps:
            lines.extend([f"{i}. {escape_markdown(step)}" for i, step in enumerate(steps, 1)])
        else:
            lines.append("_Not provided_")
        lines.extend(
            [
                "",
                "#### Expected behavior",
                "",
                escape_markdown(data.get("expected_behavior") or "_Not provided_"),
                "",
                "#### Observed behavior",
                "",
                escape_markdown(data.get("observed_behavior") or "_Not provided_"),
                "",
                "#### Impact",
                "",
                escape_markdown(data.get("impact") or "_Not provided_"),
                "",
                "#### Evidence references (redacted)",
                "",
                "```json",
                json.dumps(data.get("evidence_sanitized") or {}, indent=2),
                "```",
                "",
                "#### Remediation",
                "",
            ]
        )
        rem = data.get("remediation") or []
        if rem:
            lines.extend([f"- {escape_markdown(item)}" for item in rem])
        else:
            lines.append("_Not provided_")
        lines.append("")
    lines.extend(
        [
            "## Untested areas / limitations",
            "",
            escape_markdown(
                meta.get("untested_areas")
                or "Areas not covered by this assessment profile remain untested. "
                "Do not infer absence of vulnerabilities from missing findings."
            ),
            "",
        ]
    )
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
    findings = filter_reportable_findings(findings)
    results = []
    rules = {}
    for finding in findings:
        data = redact_secrets(finding.to_dict())
        rule_id = f"{data.get('source_tool')}:{data.get('category')}"
        rules[rule_id] = {
            "id": rule_id,
            "name": data.get("category") or rule_id,
            "shortDescription": {"text": str(data.get("title") or rule_id)[:256]},
        }
        results.append(
            {
                "ruleId": rule_id,
                "level": _SEVERITY_TO_LEVEL.get(str(data.get("severity", "info")).lower(), "note"),
                "message": {"text": str(data.get("title") or rule_id)[:1024]},
                "properties": {
                    "verification_state": data.get("verification_state"),
                    "validation_status": data.get("validation_status"),
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
