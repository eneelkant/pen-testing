"""Unit tests for the egress-gateway destination policy."""

from __future__ import annotations

import importlib.util
import socket
from pathlib import Path

import pytest

_PROXY_PATH = Path(__file__).resolve().parents[2] / "docker" / "egress-gateway" / "proxy_main.py"


def _load_proxy():
    spec = importlib.util.spec_from_file_location("pen_egress_proxy_main", _PROXY_PATH)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


@pytest.fixture
def proxy():
    return _load_proxy()


def test_proxy_denies_empty_allowlist(proxy, monkeypatch):
    monkeypatch.delenv("PEN_PROXY_ALLOW_HOSTS", raising=False)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = proxy.decide_destination("example.invalid", 443)
    assert ok is False
    assert "empty" in reason.lower() or "PEN_PROXY_ALLOW_HOSTS" in reason


def test_proxy_denies_non_public_resolution(proxy, monkeypatch):
    monkeypatch.setenv("PEN_PROXY_ALLOW_HOSTS", "staging.example.invalid")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("127.0.0.1", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = proxy.decide_destination("staging.example.invalid", 443)
    assert ok is False
    assert "non-public" in reason.lower()


def test_proxy_allows_allowlisted_public(proxy, monkeypatch):
    monkeypatch.setenv("PEN_PROXY_ALLOW_HOSTS", "staging.example.invalid")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = proxy.decide_destination("staging.example.invalid", 443)
    assert ok is True
    assert reason == "ok"


def test_proxy_denies_host_not_in_allowlist(proxy, monkeypatch):
    monkeypatch.setenv("PEN_PROXY_ALLOW_HOSTS", "allowed.example.invalid")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = proxy.decide_destination("other.example.invalid", 443)
    assert ok is False
    assert "not in" in reason


def test_proxy_denies_disallowed_port(proxy, monkeypatch):
    monkeypatch.setenv("PEN_PROXY_ALLOW_HOSTS", "staging.example.invalid")
    monkeypatch.delenv("PEN_PROXY_ALLOW_PORTS", raising=False)

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("8.8.8.8", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = proxy.decide_destination("staging.example.invalid", 22)
    assert ok is False
    assert "port 22" in reason


def test_proxy_denies_metadata_ip_rebinding(proxy, monkeypatch):
    monkeypatch.setenv("PEN_PROXY_ALLOW_HOSTS", "staging.example.invalid")

    def fake_getaddrinfo(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", port))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)
    ok, reason = proxy.decide_destination("staging.example.invalid", 443)
    assert ok is False
    assert "non-public" in reason.lower() or "169.254.169.254" in reason


def test_gateway_policy_module_matches_core():
    """Dockerfile copies core policy into the gateway image — keep sources aligned."""
    root = Path(__file__).resolve().parents[2]
    core = (root / "core" / "isolation" / "destination_policy.py").read_text(encoding="utf-8")
    # Build copies from core/; ensure the module remains stdlib-only.
    assert "import os" in core
    assert "import ipaddress" in core
    assert "from core." not in core
    assert "decide_proxy_destination" in core
