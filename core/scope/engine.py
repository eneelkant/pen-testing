"""Mandatory preflight authorization / scope enforcement."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import yaml

from .models import AuthorizationRecord, ScopeDecision

ACTIVE_CATEGORIES = {"active", "dast", "exploit", "pentest", "dynamic"}


def _parse_dt(value: str | None) -> datetime | None:
    if not value:
        return None
    text = value.strip()
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def _normalize_host(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
        return host.lower()
    return value.split("/")[0].split(":")[0].lower()


def _effective_port(scheme: str, port: int | None) -> int | None:
    if port is not None:
        return port
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def _url_components(value: str) -> tuple[str, str, int | None, str] | None:
    parsed = urlparse(value.strip())
    if not parsed.scheme or not parsed.hostname:
        return None
    try:
        port = parsed.port
    except ValueError:
        return None
    return parsed.scheme.lower(), parsed.hostname.lower(), port, parsed.path or "/"


def _asset_matches(candidate: str, pattern: str) -> bool:
    """Conservative exact/host match. Does not auto-expand to subdomains."""
    cand = candidate.strip()
    pat = pattern.strip()
    if not cand or not pat:
        return False

    # Exact match (URLs, repos, identifiers)
    if cand.rstrip("/") == pat.rstrip("/"):
        return True

    cand_url = _url_components(cand) if "://" in cand else None
    pat_url = _url_components(pat) if "://" in pat else None

    # When both sides are absolute URLs, scheme + host + port must agree.
    # Path may still use exact equality via the check above; prefix matching is
    # intentionally not applied for full URL patterns (exact only).
    if cand_url and pat_url:
        cs, ch, cp, _ = cand_url
        ps, ph, pp, _ = pat_url
        if cs != ps or ch != ph:
            return False
        if _effective_port(cs, cp) != _effective_port(ps, pp):
            return False
        # Same origin URL patterns authorize only the exact URL (already handled)
        # or identical origin with identical path already compared; do not broaden.
        return False

    # Scheme-less patterns that include a path (e.g. staging.example.com/app)
    # must not authorize the entire host — require host + path-prefix match.
    if "://" not in pat and "/" in pat.strip().strip("/"):
        host_part, _, path_part = pat.partition("/")
        host_only, _, port_part = host_part.partition(":")
        pat_host = host_only.lower()
        pat_port = int(port_part) if port_part.isdigit() else None
        pat_path = "/" + path_part
        if cand_url:
            cand_scheme, cand_host, cand_port, cand_path = cand_url
            if cand_host and cand_host == pat_host:
                if pat_port is not None and _effective_port(cand_scheme, cand_port) != pat_port:
                    return False
                prefix = pat_path.rstrip("/") or "/"
                if cand_path == prefix or cand_path.startswith(prefix + "/"):
                    return True
        return False

    # Host-only patterns (no URL scheme and no path component)
    # Patterns with an explicit port (host:8443) require that port on the candidate.
    if "://" not in pat:
        if ":" in pat and "/" not in pat:
            host_only, _, port_part = pat.partition(":")
            pat_host = host_only.lower()
            if not port_part.isdigit():
                return False
            pat_port = int(port_part)
            if cand_url:
                cand_scheme, cand_host, cand_port, _ = cand_url
                return bool(
                    cand_host
                    and cand_host == pat_host
                    and _effective_port(cand_scheme, cand_port) == pat_port
                )
            return False
        cand_host = _normalize_host(cand)
        pat_host = _normalize_host(pat)
        if cand_host and pat_host and cand_host == pat_host:
            return True

    # CIDR for IP literals only
    cand_host = _normalize_host(cand)
    try:
        network = ipaddress.ip_network(pat, strict=False)
        ip = ipaddress.ip_address(cand_host)
        return ip in network
    except ValueError:
        pass

    return False


def load_authorization_registry(path: str | Path) -> list[AuthorizationRecord]:
    path = Path(path)
    if not path.exists():
        raise FileNotFoundError(f"Authorization registry not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        data = yaml.safe_load(text) or {}
    else:
        data = json.loads(text)
    records = data.get("authorizations", data if isinstance(data, list) else [])
    if not isinstance(records, list):
        raise ValueError("Authorization registry must contain a list under 'authorizations'")
    return [AuthorizationRecord.from_dict(item) for item in records]


class ScopeEngine:
    """Evaluate whether an intended target is explicitly authorized."""

    def __init__(self, records: Iterable[AuthorizationRecord] | None = None):
        self.records = list(records or [])

    @classmethod
    def from_file(cls, path: str | Path) -> ScopeEngine:
        return cls(load_authorization_registry(path))

    def evaluate(
        self,
        target: str,
        *,
        test_category: str = "active",
        now: datetime | None = None,
        require_non_production: bool = True,
    ) -> ScopeDecision:
        now = now or datetime.now(timezone.utc)
        category = test_category.lower().strip()
        if not target or not target.strip():
            return ScopeDecision(False, "Target is empty or missing")

        # Explicit scheme validation for URL-like targets (fail closed on junk schemes).
        if "://" in target:
            parsed = urlparse(target.strip())
            if parsed.scheme.lower() not in {"http", "https"}:
                return ScopeDecision(False, "Only http(s) URL targets are accepted for scope evaluation")
            if not parsed.hostname:
                return ScopeDecision(False, "URL target is missing a hostname")
            try:
                _ = parsed.port
            except ValueError:
                return ScopeDecision(False, "URL target has an invalid port")

        matches = [r for r in self.records if any(_asset_matches(target, a) for a in r.allowed_assets)]
        if not matches:
            return ScopeDecision(
                False,
                "No explicit authorization record matches the target. "
                "Public accessibility alone is not authorization.",
            )

        # Prefer the most specific exact URL match when available
        matches.sort(
            key=lambda r: max(
                (1 if target.rstrip("/") == a.rstrip("/") else 0) for a in r.allowed_assets
            ),
            reverse=True,
        )
        record = matches[0]

        for excluded in record.excluded_assets:
            if _asset_matches(target, excluded):
                return ScopeDecision(
                    False,
                    f"Target matches excluded asset '{excluded}'",
                    matched_record=record,
                    policy_reference=record.policy_reference,
                )

        if category not in {c.lower() for c in record.allowed_test_categories}:
            return ScopeDecision(
                False,
                f"Test category '{category}' is not allowed for this authorization",
                matched_record=record,
                policy_reference=record.policy_reference,
            )

        start = _parse_dt(record.authorization_start)
        expiry = _parse_dt(record.authorization_expiry)
        if start and now < start:
            return ScopeDecision(
                False,
                "Authorization has not started yet",
                matched_record=record,
                policy_reference=record.policy_reference,
            )
        if expiry and now > expiry:
            return ScopeDecision(
                False,
                "Authorization has expired",
                matched_record=record,
                policy_reference=record.policy_reference,
            )

        if require_non_production and category in ACTIVE_CATEGORIES:
            env = (record.environment or "").lower()
            if env == "production":
                return ScopeDecision(
                    False,
                    "Active testing against production is refused by default policy",
                    matched_record=record,
                    policy_reference=record.policy_reference,
                )

        if category in ACTIVE_CATEGORIES and any(
            p.lower() in {"dos", "ddos", "destructive", "data_destruction"}
            for p in record.prohibited_actions
        ):
            # Still allow non-destructive active tests; document prohibition.
            pass

        return ScopeDecision(
            True,
            "Target is explicitly authorized for the requested test category",
            matched_record=record,
            policy_reference=record.policy_reference,
        )

    def require(
        self,
        target: str,
        *,
        test_category: str = "active",
        now: datetime | None = None,
        require_non_production: bool = True,
    ) -> ScopeDecision:
        decision = self.evaluate(
            target,
            test_category=test_category,
            now=now,
            require_non_production=require_non_production,
        )
        if not decision.allowed:
            raise PermissionError(f"Scope check failed: {decision.reason}")
        return decision
