"""Secret and PII redaction helpers for findings and reports."""

from __future__ import annotations

import re
from typing import Any

from core.net import redact_url_userinfo

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("authorization_header", re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?\S+")),
    ("api_key_assign", re.compile(r"(?i)((?:api[_-]?key|access[_-]?token|refresh[_-]?token|token|secret|password|otp|passcode)\s*[:=]\s*)([^\s,\"']+)")),
    ("cookie_header", re.compile(r"(?i)((?:set-)?cookie\s*[:=]\s*)([^\r\n]+)")),
    ("session_assign", re.compile(r"(?i)((?:session[_-]?id|sess(?:ion)?)\s*[:=]\s*)([^\s,\"']+)")),
    ("bearer_inline", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._\-+=/]{8,}")),
    ("otp_code", re.compile(r"(?i)\b(otp|one[-\s]?time\s*(?:password|code)|2fa\s*code)\b([^\n\r]{0,20})(\b\d{4,8}\b)")),
    ("query_secret", re.compile(r"(?i)([?&](?:access_token|refresh_token|token|otp|session|auth|key|password)=)([^&\s#]+)")),
    ("jwt", re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/\S+")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
]

_SENSITIVE_KEY_FRAGMENTS = (
    "password",
    "secret",
    "token",
    "api_key",
    "apikey",
    "authorization",
    "credential",
    "private_key",
    "otp",
    "passcode",
    "cookie",
    "session",
    "refresh",
    "client_secret",
    "access_token",
    "refresh_token",
)


def redact_text(value: str, replacement: str = "[REDACTED]") -> str:
    redacted = redact_url_userinfo(value)
    for name, pattern in _SECRET_PATTERNS:
        if name == "otp_code":
            redacted = pattern.sub(
                lambda m: f"{m.group(1)}{m.group(2)}{replacement}",
                redacted,
            )
            continue
        if name in {"bearer_inline"}:
            redacted = pattern.sub(replacement, redacted)
            continue
        redacted = pattern.sub(
            lambda m: (m.group(1) + replacement) if m.lastindex and m.lastindex >= 1 else replacement,
            redacted,
        )
    return redacted


def redact_secrets(obj: Any, replacement: str = "[REDACTED]") -> Any:
    """Recursively redact secrets from strings in nested structures."""
    if isinstance(obj, str):
        return redact_text(obj, replacement=replacement)
    if isinstance(obj, list):
        return [redact_secrets(item, replacement=replacement) for item in obj]
    if isinstance(obj, dict):
        out: dict[str, Any] = {}
        for key, value in obj.items():
            key_l = str(key).lower()
            if any(s in key_l for s in _SENSITIVE_KEY_FRAGMENTS):
                out[key] = replacement
            else:
                out[key] = redact_secrets(value, replacement=replacement)
        return out
    return obj


# Conservative allowlist used when exporting operator-facing report summaries.
REPORT_FIELD_ALLOWLIST = frozenset(
    {
        "finding_id",
        "title",
        "category",
        "source_tool",
        "source_tool_version",
        "program",
        "asset",
        "verification_state",
        "confidence",
        "lifecycle",
        "preconditions",
        "reproduction_steps",
        "evidence_sanitized",
        "expected_behavior",
        "observed_behavior",
        "impact",
        "severity",
        "severity_rationale",
        "remediation",
        "references",
        "timestamp",
        "execution_id",
        "validation_status",
        "redaction_status",
    }
)


def allowlist_finding_fields(data: dict[str, Any]) -> dict[str, Any]:
    """Drop non-allowlisted finding keys before persistent export."""
    return {k: redact_secrets(v) for k, v in data.items() if k in REPORT_FIELD_ALLOWLIST}
