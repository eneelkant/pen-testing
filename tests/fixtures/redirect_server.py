#!/usr/bin/env python3
"""Local redirect fixture: 302 to a prohibited external destination."""

from __future__ import annotations

import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def do_GET(self) -> None:  # noqa: N802
        # Intentional redirect to a public IP that must remain unreachable
        # from an internal scanner network (network-level block, not proxy).
        target = "http://1.1.1.1/"
        self.send_response(302)
        self.send_header("Location", target)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8081
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"redirect fixture listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
