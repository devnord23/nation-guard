# SPDX-License-Identifier: Apache-2.0
"""A forgiving JSON loader for editor config files.

VS Code, Cursor and friends write "JSONC": JSON with ``//`` and ``/* */``
comments and trailing commas. ``json`` rejects those, so we strip them first,
carefully skipping anything inside string literals. This is best-effort: if a
file still will not parse we return ``None`` and callers treat it as "no data"
rather than crashing.
"""
from __future__ import annotations

import json
from typing import Any, Optional


def _strip(text: str) -> str:
    out = []
    i, n = 0, len(text)
    in_str = False
    quote = ""
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                in_str = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "/":
            i += 2
            while i < n and text[i] not in "\r\n":
                i += 1
            continue
        if ch == "/" and i + 1 < n and text[i + 1] == "*":
            i += 2
            while i + 1 < n and not (text[i] == "*" and text[i + 1] == "/"):
                i += 1
            i += 2
            continue
        out.append(ch)
        i += 1
    return "".join(out)


_TRAILING = None


def _drop_trailing_commas(text: str) -> str:
    # Remove commas that directly precede a closing } or ] (ignoring whitespace),
    # but only outside strings. We reuse the already-stripped text, so strings
    # are the only quoted regions left.
    out = []
    i, n = 0, len(text)
    in_str = False
    quote = ""
    while i < n:
        ch = text[i]
        if in_str:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == quote:
                in_str = False
            i += 1
            continue
        if ch in ('"', "'"):
            in_str = True
            quote = ch
            out.append(ch)
            i += 1
            continue
        if ch == ",":
            j = i + 1
            while j < n and text[j] in " \t\r\n":
                j += 1
            if j < n and text[j] in "}]":
                i += 1
                continue
        out.append(ch)
        i += 1
    return "".join(out)


def loads(text: str) -> Optional[Any]:
    """Parse JSONC text, or return ``None`` if it cannot be parsed."""
    for candidate in (text, _drop_trailing_commas(_strip(text))):
        try:
            return json.loads(candidate)
        except ValueError:
            continue
    return None
