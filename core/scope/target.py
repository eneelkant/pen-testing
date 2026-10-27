"""Conservative target / redirect validation helpers."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

_ALLOWED_SCHEMES = {"http", "https"}


def normalize_origin(url: str) -> tuple[str, str, int | None]:
    """Return (scheme, hostname.lower(), port) for an absolute URL."""
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Target must be an absolute URL with host: {url!r}")
    scheme = parsed.scheme.lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise ValueError(f"Unsupported URL scheme for target validation: {scheme!r}")
    try:
        port = parsed.port
    except ValueError as exc:
        raise ValueError(f"Invalid port in URL: {url!r}") from exc
    return scheme, parsed.hostname.lower(), port


def validate_absolute_http_url(url: str) -> tuple[bool, str]:
    """Fail closed for malformed URLs, bad schemes, or invalid ports."""
    try:
        scheme, host, port = normalize_origin(url)
    except ValueError as exc:
        return False, str(exc)
    if not host:
        return False, "URL is missing a hostname"
    if port is not None and (port < 1 or port > 65535):
        return False, "URL port out of range"
    return True, "ok"


def same_origin(left: str, right: str) -> bool:
    try:
        ls, lh, lp = normalize_origin(left)
        rs, rh, rp = normalize_origin(right)
    except ValueError:
        return False
    # Default ports equivalence
    def eff(scheme: str, port: int | None) -> int | None:
        if port is not None:
            return port
        if scheme == "http":
            return 80
        if scheme == "https":
            return 443
        return None

    return ls == rs and lh == rh and eff(ls, lp) == eff(rs, rp)


def resolve_redirect(base_url: str, location: str) -> str:
    return urljoin(base_url, location)


def validate_redirect_stays_in_scope(base_url: str, location: str | None) -> tuple[bool, str]:
    """
    Reject redirects that leave the original origin.

    This does not claim DNS/IP pinning or browser containment for upstream engines.
    """
    if not location:
        return True, "No Location header"
    try:
        dest = resolve_redirect(base_url, location)
        normalize_origin(dest)
    except ValueError as exc:
        return False, f"Invalid redirect location: {exc}"
    if not same_origin(base_url, dest):
        return False, f"Redirect leaves authorized origin: {dest}"
    return True, dest
