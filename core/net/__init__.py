"""Network safety helpers for platform-owned HTTP clients."""

from .ssrf import (
    is_loopback_hostname,
    is_non_public_ip,
    redact_url_userinfo,
    require_http_url,
    validate_resolved_target,
)

__all__ = [
    "is_loopback_hostname",
    "is_non_public_ip",
    "redact_url_userinfo",
    "require_http_url",
    "validate_resolved_target",
]
