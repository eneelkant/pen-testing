#!/usr/bin/env python3
"""Minimal OpenAI-compatible mock for controlled Shannon --validate-model E2E.

Local fixture only — no upstream provider calls.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        if self.path.split("?", 1)[0] in {"/v1/models", "/models"}:
            self._json(
                200,
                {
                    "object": "list",
                    "data": [
                        {
                            "id": "gpt-test",
                            "object": "model",
                            "owned_by": "pen-testing-fixture",
                        }
                    ],
                },
            )
            return
        if self.path.split("?", 1)[0] in {"/health", "/"}:
            self._json(200, {"ok": True, "fixture": "shannon-llm-mock"})
            return
        self._json(404, {"error": {"message": f"unknown path {self.path}", "type": "not_found"}})

    def do_POST(self) -> None:  # noqa: N802
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            req = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            req = {}
        path = self.path.split("?", 1)[0]
        if path in {"/v1/chat/completions", "/chat/completions"}:
            model = str(req.get("model") or "gpt-test")
            self._json(
                200,
                {
                    "id": "chatcmpl-fixture",
                    "object": "chat.completion",
                    "model": model,
                    "choices": [
                        {
                            "index": 0,
                            "message": {
                                "role": "assistant",
                                "content": "SHANNON_LLM_MOCK_OK",
                            },
                            "finish_reason": "stop",
                        }
                    ],
                    "usage": {"prompt_tokens": 1, "completion_tokens": 1, "total_tokens": 2},
                },
            )
            return
        if path in {"/v1/completions", "/completions"}:
            self._json(
                200,
                {
                    "id": "cmpl-fixture",
                    "object": "text_completion",
                    "model": str(req.get("model") or "gpt-test"),
                    "choices": [{"text": "SHANNON_LLM_MOCK_OK", "index": 0, "finish_reason": "stop"}],
                },
            )
            return
        self._json(404, {"error": {"message": f"unknown path {path}", "type": "not_found"}})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"llm mock listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
