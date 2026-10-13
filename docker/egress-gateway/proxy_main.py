#!/usr/bin/env python3
"""Minimal HTTP CONNECT / forward proxy with resolve-time destination policy.

Used by Compose scanner workers that have no direct internet (internal networks).
This is not a transparent proxy: clients must honor HTTP(S)_PROXY.
Browsers that ignore proxy settings remain an upstream residual risk.
"""

from __future__ import annotations

import ipaddress
import os
import select
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse


def _truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes"}


def _allow_hosts() -> set[str]:
    raw = os.environ.get("PEN_PROXY_ALLOW_HOSTS", "") or ""
    return {h.strip().lower().rstrip(".") for h in raw.split(",") if h.strip()}


def _is_non_public(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    if bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    ):
        return True
    for net in ("192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32", "169.254.169.254/32"):
        if ip in ipaddress.ip_network(net):
            return True
    return False


def decide_destination(host: str, port: int) -> tuple[bool, str]:
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return False, "missing host"
    allows = _allow_hosts()
    if allows and host not in allows:
        return False, f"host {host!r} not in PEN_PROXY_ALLOW_HOSTS"
    # Always resolve and block non-public answers (DNS rebinding class).
    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        return False, f"DNS failed: {exc}"
    if not infos:
        return False, "DNS returned no addresses"
    for info in infos:
        ip = ipaddress.ip_address(info[4][0])
        if _is_non_public(ip):
            # Allow connecting to other compose service names only when they resolve
            # to non-public AND host is explicitly allowlisted (fixture/gateway cases
            # should use NO_PROXY and direct connect, not the proxy).
            return False, f"resolved to non-public {ip}"
    if not allows:
        # Empty allowlist = deny-by-default for proxied internet destinations.
        return False, "PEN_PROXY_ALLOW_HOSTS is empty (deny by default)"
    return True, "ok"


class ProxyHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt: str, *args) -> None:  # noqa: A003
        sys.stderr.write("egress-gateway: " + (fmt % args) + "\n")

    def do_CONNECT(self) -> None:  # noqa: N802
        host_port = self.path
        if ":" in host_port:
            host, port_s = host_port.rsplit(":", 1)
            try:
                port = int(port_s)
            except ValueError:
                self.send_error(400, "bad port")
                return
        else:
            host, port = host_port, 443
        ok, reason = decide_destination(host, port)
        if not ok:
            self.send_error(403, reason)
            return
        try:
            upstream = socket.create_connection((host, port), timeout=10)
        except OSError as exc:
            self.send_error(502, str(exc))
            return
        self.send_response(200, "Connection Established")
        self.end_headers()
        self._tunnel(self.connection, upstream)

    def do_GET(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_POST(self) -> None:  # noqa: N802
        self._proxy_http()

    def do_HEAD(self) -> None:  # noqa: N802
        self._proxy_http()

    def _proxy_http(self) -> None:
        parsed = urlparse(self.path)
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            self.send_error(400, "absolute URL required")
            return
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        ok, reason = decide_destination(parsed.hostname, port)
        if not ok:
            self.send_error(403, reason)
            return
        # Minimal forward for http only (tests); CONNECT covers https.
        if parsed.scheme != "http":
            self.send_error(501, "use CONNECT for https")
            return
        try:
            upstream = socket.create_connection((parsed.hostname, port), timeout=10)
        except OSError as exc:
            self.send_error(502, str(exc))
            return
        path = parsed.path or "/"
        if parsed.query:
            path += "?" + parsed.query
        req = f"{self.command} {path} HTTP/1.1\r\nHost: {parsed.hostname}\r\nConnection: close\r\n\r\n"
        upstream.sendall(req.encode())
        while True:
            chunk = upstream.recv(65536)
            if not chunk:
                break
            self.wfile.write(chunk)
        upstream.close()

    @staticmethod
    def _tunnel(client: socket.socket, upstream: socket.socket) -> None:
        sockets = [client, upstream]
        try:
            while True:
                readable, _, errored = select.select(sockets, [], sockets, 60)
                if errored or not readable:
                    break
                for sock in readable:
                    other = upstream if sock is client else client
                    data = sock.recv(65536)
                    if not data:
                        return
                    other.sendall(data)
        finally:
            try:
                upstream.close()
            except OSError:
                pass


def main() -> int:
    host = os.environ.get("PEN_PROXY_BIND", "0.0.0.0")
    port = int(os.environ.get("PEN_PROXY_PORT", "3128"))
    if _truthy("PEN_PROXY_REQUIRE_ALLOWLIST", True) and not _allow_hosts():
        # Still start: deny-by-default until allowlist is configured.
        sys.stderr.write("egress-gateway: PEN_PROXY_ALLOW_HOSTS empty — denying all proxied destinations\n")
    server = ThreadingHTTPServer((host, port), ProxyHandler)
    sys.stderr.write(f"egress-gateway: listening on {host}:{port}\n")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
