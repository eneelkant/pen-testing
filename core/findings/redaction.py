"""Secret and PII redaction helpers for findings and reports."""

from __future__ import annotations

import re
from typing import Any

from core.net import redact_url_userinfo

_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("authorization_header", re.compile(r"(?i)(authorization\s*[:=]\s*)(bearer\s+)?\S+")),
    ("api_key_assign", re.compile(r"(?i)((?:api[_-]?key|token|secret|password)\s*[:=]\s*)([^\s,\"']+)")),
    ("jwt", re.compile(r"\beyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+\b")),
    ("aws_access_key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("github_token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{20,}\b")),
    ("github_pat", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}\b")),
    ("slack_token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b")),
    ("slack_webhook", re.compile(r"https://hooks\.slack\.com/services/\S+")),
    ("openai_style_key", re.compile(r"\bsk-[A-Za-z0-9]{20,}\b")),
    ("private_key_block", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
]


def redact_text(value: str, replacement: str = "[REDACTED]") -> str:
    redacted = redact_url_userinfo(value)
    for _, pattern in _SECRET_PATTERNS:
        redacted = pattern.sub(lambda m: (m.group(1) + replacement) if m.lastindex else replacement, redacted)
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
            if any(
                s in key_l
                for s in (
                    "password",
                    "secret",
                    "token",
                    "api_key",
                    "apikey",
                    "authorization",
                    "credential",
                    "private_key",
                    "cookie",
                    "set-cookie",
                    "session",
                )
            ):
                out[key] = replacement
            else:
                out[key] = redact_secrets(value, replacement=replacement)
        return out
    return obj
