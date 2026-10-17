"""Daily research report generator (local-first, redacted)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from core.findings import redact_secrets
from core.paths import safe_write_text


def generate_daily_report(
    *,
    output_path: str | Path,
    authorizations_checked: list[dict[str, Any]] | None = None,
    tool_runs: list[dict[str, Any]] | None = None,
    findings_summary: dict[str, Any] | None = None,
    repo_defects: list[str] | None = None,
    fixes: list[str] | None = None,
    upstream_notes: list[str] | None = None,
    open_prs: list[str] | None = None,
    next_actions: list[str] | None = None,
    include_private_details: bool = False,
) -> Path:
    output_path = Path(output_path)
    payload = {
        "report_type": "daily_research",
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "authorizations_checked": authorizations_checked or [],
        "tool_runs": tool_runs or [],
        "findings_summary": findings_summary
        or {
            "candidates": 0,
            "reproduced": 0,
            "human_verified": 0,
            "false_positives": 0,
            "unresolved_hypotheses": 0,
        },
        "repo_defects": repo_defects or [],
        "fixes": fixes or [],
        "upstream_notes": upstream_notes or [],
        "open_prs": open_prs or [],
        "next_actions": next_actions or [],
        "publication": "local-only unless human-approved",
    }
    if not include_private_details:
        payload = redact_secrets(payload)

    md_lines = [
        "# Daily Bug Bounty / Security Research Report",
        "",
        f"_Generated: {payload['generated_at']}_",
        "",
        "Local report only. Do not publish private target details without authorization.",
        "",
        "## Authorizations and scope checks",
        "",
    ]
    if payload["authorizations_checked"]:
        for item in payload["authorizations_checked"]:
            md_lines.append(f"- {json.dumps(item)}")
    else:
        md_lines.append("- None recorded")

    md_lines.extend(["", "## Tools executed", ""])
    if payload["tool_runs"]:
        for run in payload["tool_runs"]:
            md_lines.append(
                f"- {run.get('tool', 'unknown')} {run.get('version', '')}: {run.get('status', 'unknown')}"
            )
    else:
        md_lines.append("- None recorded")

    summary = payload["findings_summary"]
    md_lines.extend(
        [
            "",
            "## Findings summary",
            "",
            f"- Candidates: {summary.get('candidates', 0)}",
            f"- Reproduced: {summary.get('reproduced', 0)}",
            f"- Human verified: {summary.get('human_verified', 0)}",
            f"- False positives: {summary.get('false_positives', 0)}",
            f"- Unresolved hypotheses: {summary.get('unresolved_hypotheses', 0)}",
            "",
            "## Repository defects",
            "",
        ]
    )
    md_lines.extend([f"- {d}" for d in payload["repo_defects"]] or ["- None"])
    md_lines.extend(["", "## Fixes and regressions", ""])
    md_lines.extend([f"- {d}" for d in payload["fixes"]] or ["- None"])
    md_lines.extend(["", "## Upstream notes", ""])
    md_lines.extend([f"- {d}" for d in payload["upstream_notes"]] or ["- None"])
    md_lines.extend(["", "## Open PRs", ""])
    md_lines.extend([f"- {d}" for d in payload["open_prs"]] or ["- None"])
    md_lines.extend(["", "## Next actions", ""])
    md_lines.extend([f"- {d}" for d in payload["next_actions"]] or ["- None"])
    md_lines.append("")

    safe_write_text(output_path, "\n".join(md_lines))
    json_path = output_path.with_suffix(".json")
    safe_write_text(json_path, json.dumps(payload, indent=2))
    return output_path
