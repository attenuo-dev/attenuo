#!/usr/bin/env python3
"""A fake GitHub MCP server for the Docker quickstart (compose.image.yml).

It speaks just enough MCP Streamable HTTP for the leak demo: `initialize`, `tools/list` and
`tools/call` on `POST /mcp`, answered as plain JSON. It has three tools, `read_file`,
`create_issue` and `delete_repo`, and does nothing with a call except echo it back and print one
line, so the demo can show which calls reached it. It uses only the Python standard library.

The repository's own fake server is the Rust example `fake_mcp` (crates/attenuo-proxy). This
file exists so the quickstart needs no Rust toolchain and no image built from source. Never put
it in front of anything real: it has no authentication.
"""

import argparse
import json
import sys
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

PROTOCOL_VERSION = "2025-06-18"
MAX_BODY = 1 << 20

TOOLS = [
    {
        "name": "read_file",
        "description": "Read a file from a repository (fake: echoes the call).",
        "inputSchema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}, "path": {"type": "string"}},
            "required": ["repo"],
        },
    },
    {
        "name": "create_issue",
        "description": "Open an issue in a repository (fake: echoes the call).",
        "inputSchema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}, "title": {"type": "string"}},
            "required": ["repo", "title"],
        },
    },
    {
        "name": "delete_repo",
        "description": "Delete a repository (fake: echoes the call).",
        "inputSchema": {
            "type": "object",
            "properties": {"repo": {"type": "string"}},
            "required": ["repo"],
        },
    },
]
TOOL_NAMES = {tool["name"] for tool in TOOLS}


def error(msg_id, code, message):
    return {"jsonrpc": "2.0", "id": msg_id, "error": {"code": code, "message": message}}


def answer(message):
    """The JSON-RPC response to one message, or None for a notification."""
    if not isinstance(message, dict) or message.get("jsonrpc") != "2.0":
        return error(None, -32600, "invalid request")
    method = message.get("method")
    if "id" not in message:
        return None
    msg_id = message["id"]
    params = message.get("params") or {}
    if method == "initialize":
        result = {
            "protocolVersion": PROTOCOL_VERSION,
            "capabilities": {"tools": {}},
            "serverInfo": {"name": "fake-github-mcp", "version": "0"},
        }
    elif method == "ping":
        result = {}
    elif method == "tools/list":
        result = {"tools": TOOLS}
    elif method == "tools/call":
        name = params.get("name")
        if name not in TOOL_NAMES:
            return error(msg_id, -32602, f"unknown tool: {name}")
        arguments = params.get("arguments") or {}
        print(f"fake-github-mcp: tools/call {name} {json.dumps(arguments)}", flush=True)
        echo = json.dumps({"name": name, "arguments": arguments}, sort_keys=True)
        result = {"content": [{"type": "text", "text": echo}], "isError": False}
    else:
        return error(msg_id, -32601, f"method not found: {method}")
    return {"jsonrpc": "2.0", "id": msg_id, "result": result}


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def send_json(self, status, body):
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def send_empty(self, status):
        self.send_response(status)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_POST(self):
        if self.path != "/mcp":
            return self.send_empty(404)
        try:
            length = int(self.headers.get("Content-Length", ""))
        except ValueError:
            return self.send_empty(411)
        if length > MAX_BODY:
            return self.send_empty(413)
        try:
            message = json.loads(self.rfile.read(length))
        except ValueError:
            return self.send_json(400, error(None, -32700, "parse error"))
        response = answer(message)
        if response is None:
            return self.send_empty(202)
        self.send_json(200, response)

    def do_GET(self):
        # No server-to-client stream.
        self.send_empty(405 if self.path == "/mcp" else 404)

    def do_DELETE(self):
        self.send_empty(200 if self.path == "/mcp" else 404)

    def log_message(self, fmt, *args):
        pass


def main():
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=3001)
    args = parser.parse_args()
    server = ThreadingHTTPServer((args.host, args.port), Handler)
    print(f"fake-github-mcp: listening on http://{args.host}:{args.port}/mcp", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        sys.exit(0)


if __name__ == "__main__":
    main()
