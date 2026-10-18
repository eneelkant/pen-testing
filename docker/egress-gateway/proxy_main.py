#!/usr/bin/env python3
"""Minimal HTTP CONNECT / forward proxy with resolve-time destination policy.

Used by Compose scanner workers that have no direct internet (internal networks).
This is not a transparent proxy: clients must honor HTTP(S)_PROXY.
Browsers that ignore proxy settings remain an upstream residual risk — Docker
Internal=true is the connection boundary for those clients.

Destination policy lives in destination_policy.py (copied from
core/isolation/destination_policy.py at image build).
"""

from __future__ import annotations

import os
import select
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse

try:
    # Container image layout: /app/destination_policy.py (copied at build).
    from destination_policy import (  # type: ignore[import-not-found]
        evaluate_destination,
        load_allow_hosts_from_env,
        load_allow_ports_from_env,
    )
except ImportError:  # pragma: no cover - host unit tests
    from core.isolation.destination_policy import (
        evaluate_destination,
        load_allow_hosts_from_env,
        load_allow_ports_from_env,
    )


def _truthy(name: str, default: bool = False) -> bool:
    raw = os.environ.get(name)
    if raw is None or raw == "":
        return default
    return raw.strip().lower() in {"1", "true", "yes"}


def decide_destination(host: str, port: int) -> tuple[bool, str]:
    """Public entry used by unit tests and handlers."""
    allowed, reason, _ips = evaluate_destination(
        host,
        port,
        allow_hosts=load_allow_hosts_from_env(),
        allow_ports=load_allow_ports_from_env(),
    )
    return allowed, reason


def _open_upstream(host: str, port: int) -> socket.socket:
    """Connect to an address approved by this call, not a later DNS lookup."""
    allowed, reason, ips = evaluate_destination(
        host,
        port,
        allow_hosts=load_allow_hosts_from_env(),
        allow_ports=load_allow_ports_from_env(),
    )
    if not allowed or not ips:
        raise PermissionError(reason or "destination denied")
    return socket.create_connection((ips[0], port), timeout=10)


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
        try:
            upstream = _open_upstream(host, port)
        except PermissionError as exc:
            self.send_error(403, str(exc))
            return
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
        if parsed.scheme != "http":
            self.send_error(501, "use CONNECT for https")
            return
        try:
            upstream = _open_upstream(parsed.hostname, port)
        except PermissionError as exc:
            self.send_error(403, str(exc))
            return
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
    allows = load_allow_hosts_from_env()
    ports = load_allow_ports_from_env()
    if _truthy("PEN_PROXY_REQUIRE_ALLOWLIST", True) and not allows:
        # Still start: deny-by-default until allowlist is configured.
        sys.stderr.write(
            "egress-gateway: PEN_PROXY_ALLOW_HOSTS empty — denying all proxied destinations\n"
        )
    sys.stderr.write(
        f"egress-gateway: allow_hosts={sorted(allows) or ['<empty>']} "
        f"allow_ports={sorted(ports)}\n"
    )
    server = ThreadingHTTPServer((host, port), ProxyHandler)
    sys.stderr.write(f"egress-gateway: listening on {host}:{port}\n")
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    thread.join()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
