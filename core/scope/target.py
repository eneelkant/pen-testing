"""Conservative target / redirect validation helpers."""

from __future__ import annotations

from urllib.parse import urljoin, urlparse

from .engine import ScopeEngine, inspect_target_url


def normalize_origin(url: str) -> tuple[str, str, int | None]:
    """Return (scheme, hostname.lower(), port) for an absolute URL."""
    parsed = urlparse(url.strip())
    if not parsed.scheme or not parsed.hostname:
        raise ValueError(f"Target must be an absolute URL with host: {url!r}")
    host = parsed.hostname.lower().rstrip(".")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError(f"Invalid IDN hostname in URL: {url!r}") from exc
    return parsed.scheme.lower(), host, parsed.port


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
        info = inspect_target_url(dest)
        if info is None:
            raise ValueError("Redirect destination is not an absolute http(s) URL")
        if info["username"] is not None or info["password"] is not None:
            return False, "Redirect destination contains URL credentials"
        normalize_origin(dest)
    except ValueError as exc:
        return False, f"Invalid redirect location: {exc}"
    if not same_origin(base_url, dest):
        return False, f"Redirect leaves authorized origin: {dest}"
    return True, dest


def validate_redirect_against_registry(
    base_url: str,
    location: str | None,
    engine: ScopeEngine,
    *,
    test_category: str = "passive",
) -> tuple[bool, str]:
    """Validate redirect destination against both same-origin and authorization registry."""
    ok, detail = validate_redirect_stays_in_scope(base_url, location)
    if not ok:
        return False, detail
    if not location:
        return True, detail
    dest = detail if detail.startswith("http") else resolve_redirect(base_url, location)
    decision = engine.evaluate(dest, test_category=test_category)
    if not decision.allowed:
        return False, f"Redirect destination is out of authorization scope: {decision.reason}"
    return True, dest
