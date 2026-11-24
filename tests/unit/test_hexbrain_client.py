from __future__ import annotations

import io
import json
from urllib.error import HTTPError, URLError

import pytest

from integrations.hexbrain.client import (
    HexBrainClient,
    HexBrainConfig,
    HexBrainError,
    load_config,
)


class FakeResponse:
    def __init__(self, payload: bytes):
        self.payload = payload

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return False

    def read(self, limit=-1):
        return self.payload[:limit]


def cfg(**kwargs):
    values = {
        "base_url": "https://hexbrainai.com/api/v1",
        "timeout_seconds": 5,
        "api_key": "test-key",
    }
    values.update(kwargs)
    return HexBrainConfig(**values)


def test_client_posts_to_allowlisted_endpoint_with_bearer_key():
    captured = {}

    def opener(request, timeout):
        captured["url"] = request.full_url
        captured["auth"] = request.get_header("Authorization")
        captured["timeout"] = timeout
        captured["method"] = request.method
        captured["body"] = json.loads(request.data)
        return FakeResponse(b'{"reports": []}')

    result = HexBrainClient(config=cfg(), opener=opener).call(
        "search_reports", {"query": "access control", "limit": 3}
    )
    assert captured["url"] == "https://hexbrainai.com/api/v1/search_reports"
    assert captured["auth"] == "Bearer test-key"
    assert captured["timeout"] == 5
    assert captured["method"] == "POST"
    assert captured["body"]["limit"] == 3
    assert result["ok"] is True
    assert result["untrusted_research_data"] is True


def test_client_rejects_unknown_tool_before_network():
    def opener(*args, **kwargs):
        pytest.fail("network must not be called")

    with pytest.raises(HexBrainError, match="Unsupported"):
        HexBrainClient(config=cfg(), opener=opener).call("arbitrary_tool", {})


@pytest.mark.parametrize("url", [
    "http://hexbrainai.com/api/v1",
    "https://attacker.example/api",
    "https://user:pass@hexbrainai.com/api",
    "https://hexbrainai.com/api?forward=1",
])
def test_config_rejects_untrusted_urls(url):
    with pytest.raises(HexBrainError):
        load_config({"HEXBRAIN_API_URL": url, "HEXBRAIN_API_KEY": "not-used"})


def test_config_rejects_invalid_timeout():
    with pytest.raises(HexBrainError, match="between 1 and 60"):
        load_config({"HEXBRAIN_TIMEOUT_SECONDS": "1000"})


def test_client_requires_api_key():
    client = HexBrainClient(config=cfg(api_key=""), opener=lambda *a, **k: None)
    with pytest.raises(HexBrainError, match="HEXBRAIN_API_KEY"):
        client.call("list_classes", {})


def test_401_is_sanitized():
    def opener(*args, **kwargs):
        raise HTTPError("https://hexbrainai.com", 401, "no", {}, io.BytesIO(b"secret"))

    with pytest.raises(HexBrainError, match="authentication failed") as exc:
        HexBrainClient(config=cfg(), opener=opener).call("list_classes", {})
    assert "test-key" not in str(exc.value)
    assert "secret" not in str(exc.value)


def test_429_is_sanitized():
    def opener(*args, **kwargs):
        raise HTTPError("https://hexbrainai.com", 429, "rate", {}, io.BytesIO(b"key"))

    with pytest.raises(HexBrainError, match="Rate limit"):
        HexBrainClient(config=cfg(), opener=opener).call("list_classes", {})


def test_response_size_is_bounded():
    def opener(*args, **kwargs):
        return FakeResponse(b'{"x":"' + b"a" * 4096 + b'"}')

    client = HexBrainClient(config=cfg(), opener=opener, max_response_bytes=1024)
    with pytest.raises(HexBrainError, match="size limit"):
        client.call("list_classes", {})


def test_invalid_json_fails_closed():
    def opener(*args, **kwargs):
        return FakeResponse(b"<html>not json</html>")

    with pytest.raises(HexBrainError, match="invalid JSON"):
        HexBrainClient(config=cfg(), opener=opener).call("list_classes", {})


def test_provider_error_is_returned_as_untrusted_data():
    def opener(*args, **kwargs):
        return FakeResponse(b'{"error":"example report excerpt"}')

    result = HexBrainClient(config=cfg(), opener=opener).call("get_report", {"id": 123})
    assert result["ok"] is False
    assert result["untrusted_research_data"] is True
    assert result["error"] == "example report excerpt"


def test_response_data_is_marked_untrusted_and_capped():
    def opener(*args, **kwargs):
        return FakeResponse(json.dumps({"writeup": "x" * 250_000}).encode())

    result = HexBrainClient(config=cfg(), opener=opener, max_response_bytes=400_000).call("get_report", {"id": 1})
    assert result["untrusted_research_data"] is True
    assert len(result["data"]["writeup"]) == 200_000


def test_network_errors_do_not_leak_request_details():
    def opener(*args, **kwargs):
        raise URLError("https://user:secret@somewhere")

    with pytest.raises(HexBrainError) as exc:
        HexBrainClient(config=cfg(), opener=opener).call("list_classes", {})
    assert "secret" not in str(exc.value)
    assert "somewhere" not in str(exc.value)


def test_non_object_response_fails_closed():
    def opener(*args, **kwargs):
        return FakeResponse(b"[]")

    with pytest.raises(HexBrainError, match="unexpected response shape"):
        HexBrainClient(config=cfg(), opener=opener).call("list_classes", {})
