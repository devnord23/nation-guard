# SPDX-License-Identifier: Apache-2.0
"""Static guarantee that the guard performs no network / side-effecting I/O.

nation-guard's promise is that it is local-first and offline: scanning a hostile
file must never let that file phone home, spawn a process, or open a socket. We
enforce that by parsing every module under ``guard/`` with the ``ast`` module
and rejecting imports of a denylist of capability modules.

Allowed exceptions are narrow and explicit (e.g. the MCP server reads
``sys.stdin``/``sys.stdout``; quarantine uses ``shutil`` for local file moves).
Run directly; exits non-zero with a report if anything forbidden appears.
"""
from __future__ import annotations

import ast
import sys
from pathlib import Path
from typing import List, Tuple

# Modules that grant network, subprocess, dynamic-code or FFI capability.
BANNED = {
    "socket", "ssl", "http", "httplib", "http.client", "http.server",
    "urllib", "urllib.request", "urllib2", "ftplib", "telnetlib", "smtplib",
    "poplib", "imaplib", "asyncio", "subprocess", "multiprocessing", "ctypes",
    "cffi", "requests", "httpx", "aiohttp", "urllib3", "websocket", "websockets",
    "paramiko", "pycurl", "xmlrpc", "xmlrpc.client", "socketserver",
    "pty", "popen2", "commands",
    # importlib would let code re-import any banned module dynamically, routing
    # around the import checks below; guard/ never needs it.
    "importlib",
}

# Dynamic-execution builtins that would let scanned content run as code, or
# re-import a banned module by name.
BANNED_CALLS = {"eval", "exec", "compile", "__import__"}

# Attribute calls that perform a dynamic import (e.g. importlib.import_module).
BANNED_ATTR_CALLS = {"import_module", "reload"}

ROOT = Path(__file__).resolve().parent.parent
GUARD = ROOT / "guard"


def _top(name: str) -> str:
    return name.split(".")[0]


def _check_file(path: Path) -> List[Tuple[int, str]]:
    problems: List[Tuple[int, str]] = []
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except SyntaxError as exc:  # a module that will not parse is itself a problem
        return [(getattr(exc, "lineno", 0) or 0, "syntax error: %s" % exc)]

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                if alias.name in BANNED or _top(alias.name) in BANNED:
                    problems.append((node.lineno, "import %s" % alias.name))
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            if mod in BANNED or _top(mod) in BANNED:
                problems.append((node.lineno, "from %s import ..." % mod))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Name):
            if node.func.id in BANNED_CALLS:
                problems.append((node.lineno, "call to %s()" % node.func.id))
        elif isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute):
            # e.g. importlib.import_module("socket"), importlib.reload(...)
            if node.func.attr in BANNED_ATTR_CALLS:
                problems.append((node.lineno, "dynamic import via .%s()" % node.func.attr))
    return problems


def check() -> int:
    if not GUARD.is_dir():
        sys.stderr.write("guard/ directory not found at %s\n" % GUARD)
        return 2
    failures = 0
    for path in sorted(GUARD.rglob("*.py")):
        for lineno, what in _check_file(path):
            rel = path.relative_to(ROOT).as_posix()
            sys.stderr.write("FORBIDDEN  %s:%d  %s\n" % (rel, lineno, what))
            failures += 1
    if failures:
        sys.stderr.write("\n%d forbidden capability reference(s) found under guard/.\n" % failures)
        return 1
    sys.stdout.write("ok: no network/subprocess/dynamic-exec capability under guard/\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(check())
