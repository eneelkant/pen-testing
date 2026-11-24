"""Small read-only client for HexBrain's documented REST API.

The service is research-only. This module deliberately has no scanner, shell,
filesystem, target-probing, or scope-registry mutation capability.

Configuration:
  HEXBRAIN_API_KEY  Personal API key (never log or persist its value)
  HEXBRAIN_API_URL  Optional API base URL; defaults to https://hexbrainai.com/api/v1
  HEXBRAIN_TIMEOUT_SECONDS  Optional request timeout (default 20)
"""
from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlparse
from urllib.request import HTTPRedirectHandler, Request, build_opener, urlopen

_DEFAULT_BASE_URL = "https://hexbrainai.com/api/v1"
_TOOL_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_ALLOWED_TOOLS = frozenset({
    "list_classes",
    "search_reports",
    "get_report",
    "get_testing_playbook",
    "get_program_history",
    "find_bypasses",
    "find_payloads",
    "plan_tests",
    "find_cves",
    "get_cve",
    "get_attack_surface",
})


class _RejectRedirects(HTTPRedirectHandler):
    """Never forward a bearer credential across an HTTP redirect."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _open_without_redirects(request: Request, *, timeout: float):
    """Use urllib while refusing redirects instead of forwarding credentials."""
    return build_opener(_RejectRedirects()).open(request, timeout=timeout)


class HexBrainError(RuntimeError):
    """Sanitized API error; does not include credentials or response headers."""


@dataclass(frozen=True)
class HexBrainConfig:
    base_url: str
    timeout_seconds: float
    api_key: str


def load_config(environ: dict[str, str] | None = None) -> HexBrainConfig:
    """Load API settings from environment without exposing the key in output."""
    env = os.environ if environ is None else environ
    base_url = (env.get("HEXBRAIN_API_URL") or _DEFAULT_BASE_URL).strip().rstrip("/")
    parsed = urlparse(base_url)
    if parsed.scheme != "https" or not parsed.hostname:
        raise HexBrainError("HEXBRAIN_API_URL must be an absolute HTTPS URL")
    if parsed.username or parsed.password or parsed.query or parsed.fragment:
        raise HexBrainError("HEXBRAIN_API_URL must not contain userinfo, query, or fragment")
    try:
        port = parsed.port
    except ValueError as exc:
        raise HexBrainError("HEXBRAIN_API_URL has an invalid port") from exc
    if port not in (None, 443):
        raise HexBrainError("HEXBRAIN_API_URL must use the standard HTTPS port")
    if parsed.hostname.lower() not in {"hexbrainai.com", "www.hexbrainai.com"}:
        # Explicit host allow-list prevents an environment typo or hostile config
        # from forwarding the secret to an arbitrary server.
        raise HexBrainError("HEXBRAIN_API_URL host must be hexbrainai.com")
    raw_timeout = env.get("HEXBRAIN_TIMEOUT_SECONDS", "20")
    try:
        timeout = float(raw_timeout)
    except (TypeError, ValueError) as exc:
        raise HexBrainError("HEXBRAIN_TIMEOUT_SECONDS must be numeric") from exc
    if not 1 <= timeout <= 60:
        raise HexBrainError("HEXBRAIN_TIMEOUT_SECONDS must be between 1 and 60")
    key = (env.get("HEXBRAIN_API_KEY") or "").strip()
    return HexBrainConfig(base_url=base_url, timeout_seconds=timeout, api_key=key)


def _validate_json_value(value: Any, *, depth: int = 0) -> None:
    """Reject unsupported values and excessively nested request payloads."""
    if depth > 12:
        raise HexBrainError("Request arguments are nested too deeply")
    if value is None or isinstance(value, (str, int, float, bool)):
        return
    if isinstance(value, list):
        if len(value) > 300:
            raise HexBrainError("Request list exceeds 300 items")
        for item in value:
            _validate_json_value(item, depth=depth + 1)
        return
    if isinstance(value, dict):
        if len(value) > 100:
            raise HexBrainError("Request object exceeds 100 fields")
        for key, item in value.items():
            if not isinstance(key, str):
                raise HexBrainError("Request object keys must be strings")
            _validate_json_value(item, depth=depth + 1)
        return
    raise HexBrainError(f"Unsupported JSON argument type: {type(value).__name__}")


def _sanitize_research_text(value: Any, *, max_chars: int = 200_000) -> Any:
    """Bound provider output and label text as untrusted data, not instructions.

    Content is returned as data only. Callers must not execute it, interpret it as
    platform policy, change scope from it, or pass it to a scanner without review.
    """
    if isinstance(value, str):
        return value[:max_chars]
    if isinstance(value, list):
        return [_sanitize_research_text(v, max_chars=max_chars) for v in value[:500]]
    if isinstance(value, dict):
        return {
            str(k)[:200]: _sanitize_research_text(v, max_chars=max_chars)
            for k, v in list(value.items())[:500]
        }
    return value


class HexBrainClient:
    """Read-only HexBrain REST client with bounded responses and no side effects."""

    def __init__(
        self,
        *,
        config: HexBrainConfig | None = None,
        opener: Any = _open_without_redirects,
        max_response_bytes: int = 1_000_000,
    ) -> None:
        self.config = config or load_config()
        self._opener = opener
        self.max_response_bytes = max(1024, min(int(max_response_bytes), 2_000_000))

    @property
    def configured(self) -> bool:
        return bool(self.config.api_key)

    def call(self, tool: str, arguments: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call one documented read-only tool.

        API errors are converted to stable, credential-free messages. HexBrain's
        published report text is untrusted research content and is never executed.
        """
        if tool not in _ALLOWED_TOOLS or not _TOOL_RE.fullmatch(tool):
            raise HexBrainError("Unsupported HexBrain read-only tool")
        if not self.config.api_key:
            raise HexBrainError("HexBrain is not configured; set HEXBRAIN_API_KEY")
        args = arguments or {}
        if not isinstance(args, dict):
            raise HexBrainError("Tool arguments must be a JSON object")
        _validate_json_value(args)
        body = json.dumps(args, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
        if len(body) > 64 * 1024:
            raise HexBrainError("Request body exceeds HexBrain's 64 KB limit")
        request = Request(
            f"{self.config.base_url}/{tool}",
            data=body,
            headers={
                "Authorization": f"Bearer {self.config.api_key}",
                "Content-Type": "application/json",
                "Accept": "application/json",
                "User-Agent": "pen-testing-hexbrain-adapter/0.1",
            },
            method="POST",
        )
        try:
            with self._opener(request, timeout=self.config.timeout_seconds) as response:
                raw = response.read(self.max_response_bytes + 1)
                if len(raw) > self.max_response_bytes:
                    raise HexBrainError("HexBrain response exceeded the configured size limit")
        except HTTPError as exc:
            status = int(exc.code)
            if status == 401:
                raise HexBrainError("HexBrain authentication failed; check or rotate the API key") from None
            if status == 429:
                raise HexBrainError("HexBrain rate limit reached; retry after the service reset interval") from None
            if status == 400:
                raise HexBrainError("HexBrain rejected the request arguments (HTTP 400)") from None
            if status == 404:
                raise HexBrainError("HexBrain tool endpoint was not found (HTTP 404)") from None
            raise HexBrainError(f"HexBrain request failed (HTTP {status})") from None
        except (URLError, TimeoutError, OSError) as exc:
            # Do not expose the full exception string: it can include request URLs.
            raise HexBrainError(f"Unable to reach HexBrain ({type(exc).__name__})") from None
        try:
            payload = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError):
            raise HexBrainError("HexBrain returned an invalid JSON response") from None
        if not isinstance(payload, dict):
            raise HexBrainError("HexBrain returned an unexpected response shape")
        if payload.get("error"):
            # Provider messages are bounded and marked as data for the caller.
            return {
                "ok": False,
                "source": "hexbrain",
                "untrusted_research_data": True,
                "error": str(payload["error"])[:1000],
            }
        return {
            "ok": True,
            "source": "hexbrain",
            "untrusted_research_data": True,
            "data": _sanitize_research_text(payload),
        }
