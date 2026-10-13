#!/usr/bin/env python3
"""Minimal OpenAI-compatible mock for controlled Shannon --validate-model E2E.

Supports non-streaming and SSE streaming chat completions. Local fixture only.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, HTTPServer


def _chat_payload(model: str) -> dict:
    return {
        "id": "chatcmpl-fixture",
        "object": "chat.completion",
        "created": 1,
        "model": model,
        "choices": [
            {
                "index": 0,
                "message": {"role": "assistant", "content": "SHANNON_LLM_MOCK_OK"},
                "finish_reason": "stop",
            }
        ],
        "usage": {"prompt_tokens": 8, "completion_tokens": 4, "total_tokens": 12},
    }


class Handler(BaseHTTPRequestHandler):
    def _json(self, code: int, payload: dict) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json(self) -> dict:
        length = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(length) if length else b"{}"
        try:
            data = json.loads(raw.decode("utf-8") or "{}")
        except json.JSONDecodeError:
            return {}
        return data if isinstance(data, dict) else {}

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in {"/v1/models", "/models"}:
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
        if path in {"/health", "/"}:
            self._json(200, {"ok": True, "fixture": "shannon-llm-mock"})
            return
        self._json(404, {"error": {"message": f"unknown path {path}", "type": "not_found"}})

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        req = self._read_json()
        model = str(req.get("model") or "gpt-test")
        stream = bool(req.get("stream"))

        if path in {"/v1/chat/completions", "/chat/completions"}:
            if stream:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "close")
                self.end_headers()
                chunks = [
                    {
                        "id": "chatcmpl-fixture",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"role": "assistant", "content": "SHANNON_"},
                                "finish_reason": None,
                            }
                        ],
                    },
                    {
                        "id": "chatcmpl-fixture",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": model,
                        "choices": [
                            {
                                "index": 0,
                                "delta": {"content": "LLM_MOCK_OK"},
                                "finish_reason": None,
                            }
                        ],
                    },
                    {
                        "id": "chatcmpl-fixture",
                        "object": "chat.completion.chunk",
                        "created": 1,
                        "model": model,
                        "choices": [
                            {"index": 0, "delta": {}, "finish_reason": "stop"}
                        ],
                    },
                ]
                for chunk in chunks:
                    self.wfile.write(f"data: {json.dumps(chunk)}\n\n".encode("utf-8"))
                self.wfile.write(b"data: [DONE]\n\n")
                return
            self._json(200, _chat_payload(model))
            return

        if path in {"/v1/completions", "/completions"}:
            self._json(
                200,
                {
                    "id": "cmpl-fixture",
                    "object": "text_completion",
                    "model": model,
                    "choices": [
                        {"text": "SHANNON_LLM_MOCK_OK", "index": 0, "finish_reason": "stop"}
                    ],
                },
            )
            return

        # Some stacks probe embeddings; return empty vectors rather than 404 storms.
        if path in {"/v1/embeddings", "/embeddings"}:
            self._json(
                200,
                {
                    "object": "list",
                    "data": [{"object": "embedding", "index": 0, "embedding": [0.0] * 8}],
                    "model": model,
                },
            )
            return

        self._json(404, {"error": {"message": f"unknown path {path}", "type": "not_found"}})

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        sys.stderr.write("llm-mock: " + (format % args) + "\n")


def main() -> int:
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8080
    server = HTTPServer(("0.0.0.0", port), Handler)
    print(f"llm mock listening on 0.0.0.0:{port}", flush=True)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
