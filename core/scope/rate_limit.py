"""Process-local authorization rate limits and live-scan concurrency.

This is a single-operator control inside one process. It is not a multi-tenant
quota service and it does not survive a restart.
"""

from __future__ import annotations

import os
import threading
from datetime import datetime, timezone

from core.scope.models import ScopeDecision

_lock = threading.Lock()
_next_allowed: dict[str, float] = {}
_inflight = 0


def reset_rate_limiter() -> None:
    """Test helper. Clears buckets and the in-flight counter."""
    global _inflight
    with _lock:
        _next_allowed.clear()
        _inflight = 0


def skip_scope_rate_limit_rps() -> float:
    """Rate applied to live calls that skipped the authorization registry.

    Skipping scope does not skip this limit. ``off`` is not accepted.
    """
    raw = os.environ.get("PEN_SKIP_SCOPE_RATE_LIMIT_RPS", "1")
    try:
        value = float(str(raw).strip())
    except ValueError as exc:
        raise PermissionError("PEN_SKIP_SCOPE_RATE_LIMIT_RPS must be a positive number") from exc
    if value <= 0:
        raise PermissionError("PEN_SKIP_SCOPE_RATE_LIMIT_RPS must be a positive number")
    return value


def enforce_unscoped_rate_limit(*, now: datetime | None = None) -> None:
    """Consume one token for a live scan that did not match an authorization record."""
    rps = skip_scope_rate_limit_rps()
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    stamp = moment.timestamp()
    interval = 1.0 / rps
    with _lock:
        nxt = _next_allowed.get("__unscoped__", stamp)
        if stamp < nxt:
            raise PermissionError(
                f"Rate limit exceeded for scope-skipped live scans ({rps} requests/second). "
                "Skipping the authorization registry does not disable this limit."
            )
        _next_allowed["__unscoped__"] = max(nxt, stamp) + interval


def enforce_rate_limit(decision: ScopeDecision, *, now: datetime | None = None) -> None:
    """Consume one token for the matched authorization, if it sets a limit."""
    record = decision.matched_record
    if record is None or record.rate_limit_rps is None:
        return
    try:
        rps = float(record.rate_limit_rps)
    except (TypeError, ValueError) as exc:
        raise PermissionError("rate_limit_rps must be a positive number") from exc
    if rps <= 0:
        raise PermissionError("rate_limit_rps must be a positive number")
    moment = now or datetime.now(timezone.utc)
    if moment.tzinfo is None:
        moment = moment.replace(tzinfo=timezone.utc)
    key = record.target_id or record.policy_reference or "authorization"
    stamp = moment.timestamp()
    interval = 1.0 / rps
    with _lock:
        nxt = _next_allowed.get(key, stamp)
        if stamp < nxt:
            raise PermissionError(
                f"Rate limit exceeded for authorization '{key}' ({rps} requests/second). "
                "This limit is process-local and applies to non-dry-run scans."
            )
        _next_allowed[key] = max(nxt, stamp) + interval


def max_inflight_scans() -> int:
    raw = os.environ.get("PEN_MAX_INFLIGHT_SCANS", "4")
    try:
        value = int(str(raw).strip())
    except ValueError as exc:
        raise PermissionError("PEN_MAX_INFLIGHT_SCANS must be an integer from 1 to 64") from exc
    if value < 1 or value > 64:
        raise PermissionError("PEN_MAX_INFLIGHT_SCANS must be an integer from 1 to 64")
    return value


def acquire_scan_slot() -> None:
    global _inflight
    limit = max_inflight_scans()
    with _lock:
        if _inflight >= limit:
            raise PermissionError(
                f"In-flight scan limit reached ({limit}). "
                "Wait for the current scan in this process to finish."
            )
        _inflight += 1


def release_scan_slot() -> None:
    global _inflight
    with _lock:
        if _inflight > 0:
            _inflight -= 1
