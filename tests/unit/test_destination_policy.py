"""Unit tests for shared egress destination policy."""

from __future__ import annotations

import ipaddress
import socket

import pytest

from core.isolation.destination_policy import (
    decide_proxy_destination,
    is_prohibited_resolved_ip,
    parse_allow_hosts,
    parse_allow_ports,
)


def test_parse_allow_hosts_normalizes():
    assert parse_allow_hosts(" Example.COM., other.invalid ") == {
        "example.com",
        "other.invalid",
    }


def test_parse_allow_ports_default_and_custom():
    assert parse_allow_ports(None) == {80, 443}
    assert parse_allow_ports("") == {80, 443}
    assert parse_allow_ports("80,8080") == {80, 8080}
    with pytest.raises(ValueError):
        parse_allow_ports("70000")


@pytest.mark.parametrize(
    "ip_s",
    [
        "127.0.0.1",
        "10.0.0.5",
        "169.254.169.254",
        "169.254.170.2",
        "::1",
        "fd00:ec2::254",
        "2001:db8::1",
    ],
)
def test_prohibited_resolved_ips(ip_s: str):
    assert is_prohibited_resolved_ip(ipaddress.ip_address(ip_s)) is True


def test_public_ip_not_prohibited():
    assert is_prohibited_resolved_ip(ipaddress.ip_address("8.8.8.8")) is False


def _gai(ip: str):
    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (ip, port))]

    return fake


def test_decide_denies_empty_allowlist():
    ok, reason = decide_proxy_destination(
        "example.invalid",
        443,
        allow_hosts=set(),
        allow_ports={80, 443},
        resolver=_gai("8.8.8.8"),
    )
    assert ok is False
    assert "empty" in reason.lower()


def test_decide_denies_disallowed_port():
    ok, reason = decide_proxy_destination(
        "example.invalid",
        22,
        allow_hosts={"example.invalid"},
        allow_ports={80, 443},
        resolver=_gai("8.8.8.8"),
    )
    assert ok is False
    assert "port 22" in reason


def test_decide_denies_metadata_rebinding():
    ok, reason = decide_proxy_destination(
        "staging.example.invalid",
        443,
        allow_hosts={"staging.example.invalid"},
        allow_ports={80, 443},
        resolver=_gai("169.254.169.254"),
    )
    assert ok is False
    assert "non-public" in reason.lower() or "169.254.169.254" in reason


def test_decide_denies_ipv6_documentation_range():
    def fake(host, port, *args, **kwargs):
        return [(socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2001:db8::1", port, 0, 0))]

    ok, reason = decide_proxy_destination(
        "staging.example.invalid",
        443,
        allow_hosts={"staging.example.invalid"},
        allow_ports={80, 443},
        resolver=fake,
    )
    assert ok is False
    assert "non-public" in reason.lower()


def test_decide_allows_allowlisted_public():
    ok, reason = decide_proxy_destination(
        "staging.example.invalid",
        443,
        allow_hosts={"staging.example.invalid"},
        allow_ports={80, 443},
        resolver=_gai("8.8.8.8"),
    )
    assert ok is True
    assert reason == "ok"


def test_decide_denies_prohibited_literal():
    ok, reason = decide_proxy_destination(
        "169.254.169.254",
        80,
        allow_hosts={"169.254.169.254"},
        allow_ports={80, 443},
    )
    assert ok is False
    assert "prohibited" in reason.lower()
