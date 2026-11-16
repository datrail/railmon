"""A stand-in for the Messages API, so Claude Code can take a turn and write
a real transcript for the fixtures without a model call (see README.md).

Run inside the fixture container only, on 127.0.0.1. To the agent's first
request with tools it answers with two tool calls, Read of CLAUDE.md and
Bash `echo`; once it sees their results, with plain text. Any other request
(a title, a quota check) gets plain text. Streamed as the API streams.
"""

from __future__ import annotations

import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

TOOL_CALLS = [
    ("toolu_fixture_read", "Read", {"file_path": "/work/CLAUDE.md"}),
    ("toolu_fixture_bash", "Bash", {"command": "echo argument-placeholder", "description": "Echo a placeholder"}),
]


def wants_tools(body: dict) -> bool:
    if not body.get("tools"):
        return False
    last = (body.get("messages") or [{}])[-1]
    content = last.get("content")
    return not (isinstance(content, list) and any(
        isinstance(part, dict) and part.get("type") == "tool_result" for part in content))


def events(body: dict) -> list[tuple[str, dict]]:
    model = body.get("model", "stub")
    out = [("message_start", {"type": "message_start", "message": {
        "id": "msg_fixture", "type": "message", "role": "assistant", "model": model, "content": [],
        "stop_reason": None, "stop_sequence": None, "usage": {"input_tokens": 1, "output_tokens": 0}}})]
    if wants_tools(body):
        for index, (call_id, name, arguments) in enumerate(TOOL_CALLS):
            out += [("content_block_start", {"type": "content_block_start", "index": index, "content_block": {
                        "type": "tool_use", "id": call_id, "name": name, "input": {}}}),
                    ("content_block_delta", {"type": "content_block_delta", "index": index, "delta": {
                        "type": "input_json_delta", "partial_json": json.dumps(arguments)}}),
                    ("content_block_stop", {"type": "content_block_stop", "index": index})]
        stop = "tool_use"
    else:
        out += [("content_block_start", {"type": "content_block_start", "index": 0,
                                         "content_block": {"type": "text", "text": ""}}),
                ("content_block_delta", {"type": "content_block_delta", "index": 0,
                                         "delta": {"type": "text_delta", "text": "Stock lookup checked."}}),
                ("content_block_stop", {"type": "content_block_stop", "index": 0})]
        stop = "end_turn"
    out += [("message_delta", {"type": "message_delta", "delta": {"stop_reason": stop, "stop_sequence": None},
                               "usage": {"output_tokens": 1}}),
            ("message_stop", {"type": "message_stop"})]
    return out


def as_message(body: dict) -> dict:
    content, stop = [], "end_turn"
    for name, data in events(body):
        if name == "content_block_start":
            content.append(dict(data["content_block"]))
        elif name == "content_block_delta":
            delta = data["delta"]
            if delta["type"] == "text_delta":
                content[-1]["text"] += delta["text"]
            else:
                content[-1]["input"] = json.loads(delta["partial_json"])
        elif name == "message_delta":
            stop = data["delta"]["stop_reason"]
    return {"id": "msg_fixture", "type": "message", "role": "assistant", "model": body.get("model", "stub"),
            "content": content, "stop_reason": stop, "stop_sequence": None,
            "usage": {"input_tokens": 1, "output_tokens": 1}}


class Handler(BaseHTTPRequestHandler):
    def do_POST(self) -> None:  # noqa: N802 - http.server's name
        body = json.loads(self.rfile.read(int(self.headers.get("content-length") or 0)) or b"{}")
        if not self.path.startswith("/v1/messages") or self.path.startswith("/v1/messages/count_tokens"):
            reply = json.dumps({"input_tokens": 1} if "count_tokens" in self.path else {}).encode()
            self.send_response(200 if "count_tokens" in self.path else 404)
            self.send_header("content-type", "application/json")
            self.send_header("content-length", str(len(reply)))
            self.end_headers()
            self.wfile.write(reply)
            return
        if body.get("stream"):
            self.send_response(200)
            self.send_header("content-type", "text/event-stream")
            self.end_headers()
            for name, data in events(body):
                self.wfile.write(f"event: {name}\ndata: {json.dumps(data)}\n\n".encode())
                self.wfile.flush()
            return
        reply = json.dumps(as_message(body)).encode()
        self.send_response(200)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(reply)))
        self.end_headers()
        self.wfile.write(reply)

    def do_GET(self) -> None:  # noqa: N802
        self.send_response(404)
        self.send_header("content-length", "0")
        self.end_headers()

    def log_message(self, format: str, *args) -> None:  # noqa: A002
        sys.stderr.write(f"stub: {self.command} {self.path}\n")


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", int(sys.argv[1]) if len(sys.argv) > 1 else 8787), Handler).serve_forever()
