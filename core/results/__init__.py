"""Execution result containers."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from typing import Any

from core.findings import Finding
from core.findings.redaction import redact_secrets, redact_text


@dataclass
class ExecutionResult:
    tool: str
    execution_id: str
    status: str  # succeeded | failed | blocked | timed_out | skipped
    findings: list[Finding] = field(default_factory=list)
    artifacts: dict[str, str] = field(default_factory=dict)
    logs: list[str] = field(default_factory=list)
    error: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["findings"] = [f.to_dict() if hasattr(f, "to_dict") else f for f in self.findings]
        if isinstance(data.get("error"), str):
            data["error"] = redact_text(data["error"])
        data["logs"] = [redact_text(item) if isinstance(item, str) else item for item in data.get("logs") or []]
        data["artifacts"] = redact_secrets(data.get("artifacts") or {})
        data["metadata"] = redact_secrets(data.get("metadata") or {})
        return data
