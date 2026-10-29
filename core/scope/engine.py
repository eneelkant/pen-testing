"""Mandatory preflight authorization / scope enforcement."""

from __future__ import annotations

import ipaddress
import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Iterable
from urllib.parse import urlparse

import yaml

from .models import SCOPE_POLICY_VERSION, AuthorizationRecord, ScopeDecision

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


def _idna_host(host: str) -> str:
    host = host.strip().lower().rstrip(".")
    if not host:
        return ""
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def _normalize_host(value: str) -> str:
    value = value.strip().lower()
    if "://" in value:
        parsed = urlparse(value)
        host = parsed.hostname or ""
        return _idna_host(host)
    return _idna_host(value.split("/")[0].split(":")[0])


def _effective_port(scheme: str, port: int | None) -> int | None:
    if port is not None:
        return port
    if scheme == "http":
        return 80
    if scheme == "https":
        return 443
    return None


def inspect_target_url(target: str) -> dict[str, object] | None:
    """Return parsed URL attributes or None when the target is not an absolute URL."""
    text = (target or "").strip()
    if "://" not in text:
        return None
    parsed = urlparse(text)
    if not parsed.scheme or not parsed.hostname:
        return None
    return {
        "scheme": parsed.scheme.lower(),
        "hostname": _idna_host(parsed.hostname),
        "port": _effective_port(parsed.scheme.lower(), parsed.port),
        "username": parsed.username,
        "password": parsed.password,
        "path": parsed.path or "/",
    }


def _asset_matches(candidate: str, pattern: str) -> bool:
    """Conservative exact/host match. Does not auto-expand to subdomains."""
    cand = candidate.strip()
    pat = pattern.strip()
    if not cand or not pat:
        return False

    # Exact match (URLs, repos, identifiers) after trailing-slash normalize.
    if cand.rstrip("/") == pat.rstrip("/"):
        return True

    # Reject credentialed lookalikes before any host compare.
    cand_info = inspect_target_url(cand)
    if cand_info and (cand_info["username"] is not None or cand_info["password"] is not None):
        # Still allow exact string matches above; otherwise refuse host-pattern auth.
        if "://" in pat:
            return False

    # Scheme-less patterns that include a path (e.g. staging.example.com/app)
    # must not authorize the entire host — require host + path-prefix match.
    if "://" not in pat and "/" in pat.strip().strip("/"):
        host_part, _, path_part = pat.partition("/")
        pat_host = _idna_host(host_part.split(":")[0])
        pat_path = "/" + path_part
        if "://" in cand:
            parsed = urlparse(cand)
            cand_host = _idna_host(parsed.hostname or "")
            cand_path = parsed.path or "/"
            if cand_host and cand_host == pat_host:
                prefix = pat_path.rstrip("/") or "/"
                if cand_path == prefix or cand_path.startswith(prefix + "/"):
                    return True
        return False

    # Host-only patterns (no URL scheme and no path component)
    cand_host = _normalize_host(cand)
    pat_host = _normalize_host(pat)
    if cand_host and pat_host and cand_host == pat_host and "://" not in pat:
        return True

    # Absolute URL pattern: require same host (exact) when candidate is a URL.
    if "://" in pat and "://" in cand:
        pat_info = inspect_target_url(pat)
        if cand_info and pat_info:
            if cand_info["hostname"] == pat_info["hostname"] and cand.rstrip("/") == pat.rstrip("/"):
                return True

    # CIDR for IP literals only
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
        for_live_execution: bool = False,
    ) -> ScopeDecision:
        now = now or datetime.now(timezone.utc)
        category = test_category.lower().strip()
        if not target or not target.strip():
            return ScopeDecision(
                False,
                "Target is empty or missing",
                target=target or "",
                test_category=category,
            )

        info = inspect_target_url(target)
        if info and (info["username"] is not None or info["password"] is not None):
            return ScopeDecision(
                False,
                "URL userinfo/credentials are not permitted in assessment targets",
                target=target,
                test_category=category,
            )

        matches = [r for r in self.records if any(_asset_matches(target, a) for a in r.allowed_assets)]
        if not matches:
            return ScopeDecision(
                False,
                "No explicit authorization record matches the target. "
                "Public accessibility alone is not authorization.",
                target=target,
                test_category=category,
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
                    target=target,
                    test_category=category,
                    live_execution_allowed=False,
                )

        if category not in {c.lower() for c in record.allowed_test_categories}:
            return ScopeDecision(
                False,
                f"Test category '{category}' is not allowed for this authorization",
                matched_record=record,
                policy_reference=record.policy_reference,
                target=target,
                test_category=category,
                live_execution_allowed=False,
            )

        if info is not None:
            schemes = {s.lower() for s in (record.allowed_schemes or ["http", "https"])}
            if info["scheme"] not in schemes:
                return ScopeDecision(
                    False,
                    f"Scheme '{info['scheme']}' is not permitted for this authorization",
                    matched_record=record,
                    policy_reference=record.policy_reference,
                    target=target,
                    test_category=category,
                )
            if record.allowed_ports is not None:
                port = info["port"]
                if port is None or int(port) not in {int(p) for p in record.allowed_ports}:
                    return ScopeDecision(
                        False,
                        f"Port '{port}' is not permitted for this authorization",
                        matched_record=record,
                        policy_reference=record.policy_reference,
                        target=target,
                        test_category=category,
                    )

        start = _parse_dt(record.authorization_start)
        expiry = _parse_dt(record.authorization_expiry)
        if start and now < start:
            return ScopeDecision(
                False,
                "Authorization has not started yet",
                matched_record=record,
                policy_reference=record.policy_reference,
                target=target,
                test_category=category,
            )
        if expiry and now > expiry:
            return ScopeDecision(
                False,
                "Authorization has expired",
                matched_record=record,
                policy_reference=record.policy_reference,
                target=target,
                test_category=category,
            )

        if require_non_production and category in ACTIVE_CATEGORIES:
            env = (record.environment or "").lower()
            if env == "production":
                return ScopeDecision(
                    False,
                    "Active testing against production is refused by default policy",
                    matched_record=record,
                    policy_reference=record.policy_reference,
                    target=target,
                    test_category=category,
                )

        live_ok = bool(record.live_execution_allowed)
        if for_live_execution and not live_ok:
            return ScopeDecision(
                False,
                "Authorization record does not permit live execution",
                matched_record=record,
                policy_reference=record.policy_reference,
                target=target,
                test_category=category,
                live_execution_allowed=False,
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
            target=target,
            test_category=category,
            live_execution_allowed=live_ok,
            policy_version=SCOPE_POLICY_VERSION,
        )

    def require(
        self,
        target: str,
        *,
        test_category: str = "active",
        now: datetime | None = None,
        require_non_production: bool = True,
        for_live_execution: bool = False,
    ) -> ScopeDecision:
        decision = self.evaluate(
            target,
            test_category=test_category,
            now=now,
            require_non_production=require_non_production,
            for_live_execution=for_live_execution,
        )
        if not decision.allowed:
            raise PermissionError(f"Scope check failed: {decision.reason}")
        return decision
