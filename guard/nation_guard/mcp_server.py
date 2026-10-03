# SPDX-License-Identifier: Apache-2.0
"""A read-only MCP stdio server exposing nation-guard to an agent.

Three tools, all read-only (``readOnlyHint``): ``scan`` a tree (or subpath),
``check_integrity`` against a baseline, and ``blast_radius`` to see what a worm
in one config file could spread to. Every path argument is resolved inside the
``--root`` the server was started with; anything outside is refused.

Transport is newline-delimited JSON-RPC 2.0. JSON-RPC *batch* arrays are
rejected explicitly (a known footgun), and any line over 1 MiB is dropped as a
parse error so a hostile client cannot exhaust memory.
"""
from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Dict, List, Optional

from . import __version__, integrity, state, targets
from .rules import load_rules
from .scanner import scan_root

PROTOCOL_VERSION = "2024-11-05"
MAX_LINE_BYTES = 1024 * 1024

_PARSE_ERROR = -32700
_INVALID_REQUEST = -32600
_METHOD_NOT_FOUND = -32601
_INVALID_PARAMS = -32602
_INTERNAL = -32603


class Server:
    def __init__(self, root: Path):
        self.root = Path(root).resolve()
        self._rules = None

    @property
    def rules(self):
        if self._rules is None:
            self._rules = load_rules()
        return self._rules

    # ---- path safety -----------------------------------------------------
    def _resolve(self, subpath: Optional[str]) -> Path:
        if not subpath:
            return self.root
        candidate = (self.root / subpath).resolve()
        try:
            candidate.relative_to(self.root)
        except ValueError:
            raise ValueError("path %r escapes the server root" % subpath)
        return candidate

    # ---- tools -----------------------------------------------------------
    def tool_scan(self, args: dict) -> dict:
        target = self._resolve(args.get("path"))
        if target.is_file():
            from .scanner import scan_file

            rel = targets.relpath(target, self.root)
            findings = scan_file(target, rel, self.rules)
            scanned = [rel]
        else:
            result = scan_root(target, self.rules)
            findings = result.findings
            scanned = result.files_scanned
        return {
            "root": str(self.root),
            "files_scanned": len(scanned),
            "findings": [f.to_dict() for f in findings],
        }

    def tool_check_integrity(self, args: dict) -> dict:
        base = integrity.load_baseline(self.root)
        if base is None:
            return {"baseline": False, "message": "no baseline recorded for this root"}
        findings = integrity.verify(self.root, self.rules)
        return {
            "baseline": True,
            "created": base.get("created"),
            "drift": [f.to_dict() for f in findings],
        }

    def tool_blast_radius(self, args: dict) -> dict:
        instruction_files: List[str] = []
        mcp_servers: List[Dict[str, str]] = []
        for path in targets.iter_config_files(self.root):
            rel = targets.relpath(path, self.root)
            instruction_files.append(rel)
            key = targets.mcp_key_for(rel)
            if key:
                servers = integrity._mcp_servers(path, rel) or {}
                for name in servers:
                    mcp_servers.append({"file": rel, "server": name})
        focus = args.get("path")
        focus_findings = []
        if focus:
            target = self._resolve(focus)
            if target.is_file():
                from .scanner import scan_file

                rel = targets.relpath(target, self.root)
                focus_findings = [f.to_dict() for f in scan_file(target, rel, self.rules)]
        return {
            "root": str(self.root),
            "reachable_config_files": len(instruction_files),
            "config_files": instruction_files,
            "mcp_servers": mcp_servers,
            "focus": focus,
            "focus_findings": focus_findings,
        }

    def call_tool(self, name: str, args: dict) -> dict:
        if name == "scan":
            return self.tool_scan(args)
        if name == "check_integrity":
            return self.tool_check_integrity(args)
        if name == "blast_radius":
            return self.tool_blast_radius(args)
        raise KeyError(name)

    # ---- JSON-RPC dispatch ----------------------------------------------
    def handle(self, msg: dict) -> Optional[dict]:
        if msg.get("jsonrpc") != "2.0" or "method" not in msg:
            return _error(msg.get("id"), _INVALID_REQUEST, "not a JSON-RPC 2.0 request")
        method = msg["method"]
        mid = msg.get("id")
        is_notification = "id" not in msg

        # Per JSON-RPC, params (when present) must be a structured value. A
        # truthy non-object (e.g. a bare string) would otherwise reach a
        # ``.get`` and raise; coerce it to {} so no message can crash us.
        params = msg.get("params")
        if not isinstance(params, dict):
            params = {}

        if method == "initialize":
            requested = params.get("protocolVersion")
            return _result(mid, {
                "protocolVersion": requested or PROTOCOL_VERSION,
                "capabilities": {"tools": {"listChanged": False}},
                "serverInfo": {"name": "nation-guard", "version": __version__},
            })
        if method in ("notifications/initialized", "initialized"):
            return None
        if method == "ping":
            return _result(mid, {})
        if method == "tools/list":
            return _result(mid, {"tools": _TOOL_DEFS})
        if method == "tools/call":
            name = params.get("name")
            args = params.get("arguments") or {}
            if not isinstance(args, dict):
                return _error(mid, _INVALID_PARAMS, "arguments must be an object")
            try:
                payload = self.call_tool(name, args)
            except KeyError:
                return _error(mid, _METHOD_NOT_FOUND, "unknown tool %r" % name)
            except ValueError as exc:
                return _tool_error(mid, str(exc))
            except Exception as exc:  # keep the server alive on tool bugs
                return _tool_error(mid, "internal error: %s" % exc)
            return _result(mid, {
                "content": [{"type": "text", "text": json.dumps(payload, ensure_ascii=False, indent=2)}],
                "isError": False,
            })
        if is_notification:
            return None
        return _error(mid, _METHOD_NOT_FOUND, "unknown method %r" % method)


_TOOL_DEFS = [
    {
        "name": "scan",
        "description": "Scan agent config files for injected/unsafe instructions. Optional 'path' limits to a subpath or single file within the server root.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
        "annotations": {"title": "Scan agent config", "readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "check_integrity",
        "description": "Compare the tree to its recorded baseline and report drift (changed/new/removed files and MCP server changes).",
        "inputSchema": {"type": "object", "properties": {}},
        "annotations": {"title": "Check integrity", "readOnlyHint": True, "openWorldHint": False},
    },
    {
        "name": "blast_radius",
        "description": "List the config files and MCP servers a worm could reach from this root; with 'path', also scan that file.",
        "inputSchema": {"type": "object", "properties": {"path": {"type": "string"}}},
        "annotations": {"title": "Blast radius", "readOnlyHint": True, "openWorldHint": False},
    },
]


def _result(mid, result) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "result": result}


def _error(mid, code, message) -> dict:
    return {"jsonrpc": "2.0", "id": mid, "error": {"code": code, "message": message}}


def _tool_error(mid, message) -> dict:
    return _result(mid, {"content": [{"type": "text", "text": message}], "isError": True})


def _read_line(stream) -> Optional[bytes]:
    """Read one newline-terminated line, capped at MAX_LINE_BYTES."""
    buf = bytearray()
    while True:
        ch = stream.read(1)
        if not ch:
            return bytes(buf) if buf else None
        if ch == b"\n":
            return bytes(buf)
        buf.extend(ch)
        if len(buf) > MAX_LINE_BYTES:
            # Drain the rest of the oversized line and signal overflow.
            while True:
                ch = stream.read(1)
                if not ch or ch == b"\n":
                    break
            return b"\x00OVERSIZE"


def serve(root: Path, instream=None, outstream=None) -> int:
    server = Server(root)
    instream = instream or sys.stdin.buffer
    outstream = outstream or sys.stdout.buffer

    def send(obj: dict) -> None:
        outstream.write((json.dumps(obj, ensure_ascii=False) + "\n").encode("utf-8"))
        outstream.flush()

    while True:
        try:
            line = _read_line(instream)
        except (OSError, ValueError):
            break
        if line is None:
            break
        if line == b"\x00OVERSIZE":
            send(_error(None, _PARSE_ERROR, "message exceeds 1 MiB line limit"))
            continue
        if not line.strip():
            continue
        try:
            msg = json.loads(line.decode("utf-8"))
        except (ValueError, UnicodeDecodeError):
            send(_error(None, _PARSE_ERROR, "invalid JSON"))
            continue
        if isinstance(msg, list):
            send(_error(None, _INVALID_REQUEST, "JSON-RPC batch arrays are not supported"))
            continue
        if not isinstance(msg, dict):
            send(_error(None, _INVALID_REQUEST, "request must be a JSON object"))
            continue
        try:
            response = server.handle(msg)
        except Exception as exc:  # no single message may terminate the server
            send(_error(msg.get("id") if isinstance(msg, dict) else None,
                        _INTERNAL, "internal error: %s" % exc))
            continue
        if response is not None:
            send(response)
    return 0


def main(argv=None):
    import argparse

    ap = argparse.ArgumentParser(prog="nation-guard-mcp", description="Read-only nation-guard MCP stdio server.")
    ap.add_argument("--root", default=".", help="project root the server is limited to (default: .)")
    args = ap.parse_args(argv)
    return serve(Path(args.root).resolve())


if __name__ == "__main__":
    raise SystemExit(main())
