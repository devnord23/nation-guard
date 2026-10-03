# SPDX-License-Identifier: Apache-2.0
"""A deliberately tiny YAML subset loader for rule files.

Why not PyYAML: the guard is stdlib-only so it can be audited in one sitting.
Rule files only need block mappings, block sequences, inline ``[a, b]`` lists
and scalars, so that is all this accepts. Anything else is a hard error rather
than a silent misparse (fail closed: a broken rule file must not load as
"no rules").

Supported scalars: 'single quoted' (with '' escape), "double quoted" (JSON
escapes), plain text, integers, true/false/null.
"""
from __future__ import annotations

import json
import re
from typing import Any, List, Tuple


class YamlSubsetError(ValueError):
    pass


_INT = re.compile(r"^-?\d+$")


def _strip_comment(line: str) -> str:
    out = []
    quote = None
    i = 0
    while i < len(line):
        ch = line[i]
        if quote:
            out.append(ch)
            if ch == quote:
                if quote == "'" and i + 1 < len(line) and line[i + 1] == "'":
                    out.append("'")
                    i += 1
                elif quote == '"' and line[i - 1] == "\\":
                    pass
                else:
                    quote = None
        else:
            if ch in ("'", '"'):
                quote = ch
            elif ch == "#" and (i == 0 or line[i - 1] in " \t"):
                break
            out.append(ch)
        i += 1
    if quote:
        raise YamlSubsetError("unterminated quoted string: %r" % line)
    return "".join(out).rstrip()


def _scalar(text: str, lineno: int) -> Any:
    text = text.strip()
    if text == "":
        return None
    if text.startswith("'"):
        if not text.endswith("'") or len(text) < 2:
            raise YamlSubsetError("line %d: bad single-quoted scalar" % lineno)
        return text[1:-1].replace("''", "'")
    if text.startswith('"'):
        try:
            return json.loads(text)
        except ValueError as exc:
            raise YamlSubsetError("line %d: bad double-quoted scalar: %s" % (lineno, exc))
    if text.startswith("["):
        if not text.endswith("]"):
            raise YamlSubsetError("line %d: inline list must close on the same line" % lineno)
        inner = text[1:-1].strip()
        if not inner:
            return []
        return [_scalar(part, lineno) for part in _split_inline(inner, lineno)]
    if text.startswith(("{", "&", "*", "!", "|", ">")):
        raise YamlSubsetError("line %d: unsupported YAML construct %r" % (lineno, text[:1]))
    if text in ("true", "false"):
        return text == "true"
    if text in ("null", "~"):
        return None
    if _INT.match(text):
        return int(text)
    return text


def _split_inline(inner: str, lineno: int) -> List[str]:
    parts, buf, quote = [], [], None
    for ch in inner:
        if quote:
            buf.append(ch)
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
            buf.append(ch)
        elif ch == ",":
            parts.append("".join(buf))
            buf = []
        else:
            buf.append(ch)
    if quote:
        raise YamlSubsetError("line %d: unterminated quote in inline list" % lineno)
    parts.append("".join(buf))
    return parts


def _tokenize(text: str) -> List[Tuple[int, int, str]]:
    lines = []
    for n, raw in enumerate(text.splitlines(), 1):
        if "\t" in raw[: len(raw) - len(raw.lstrip())]:
            raise YamlSubsetError("line %d: tabs are not allowed for indentation" % n)
        stripped = _strip_comment(raw)
        if not stripped.strip():
            continue
        indent = len(stripped) - len(stripped.lstrip(" "))
        lines.append((n, indent, stripped.strip()))
    return lines


def _split_key(content: str, lineno: int) -> Tuple[str, str]:
    m = re.match(r"^([A-Za-z_][A-Za-z0-9_\-]*)\s*:(\s+|$)(.*)$", content)
    if not m:
        raise YamlSubsetError("line %d: expected 'key: value', got %r" % (lineno, content))
    return m.group(1), m.group(3)


def _parse_block(lines, pos: int, indent: int):
    n, ind, content = lines[pos]
    if content.startswith("- ") or content == "-":
        return _parse_seq(lines, pos, indent)
    return _parse_map(lines, pos, indent)


def _parse_map(lines, pos: int, indent: int):
    result = {}
    while pos < len(lines):
        n, ind, content = lines[pos]
        if ind < indent:
            break
        if ind > indent:
            raise YamlSubsetError("line %d: unexpected indentation" % n)
        if content.startswith("-"):
            raise YamlSubsetError("line %d: sequence item where mapping key expected" % n)
        key, rest = _split_key(content, n)
        if key in result:
            raise YamlSubsetError("line %d: duplicate key %r" % (n, key))
        pos += 1
        if rest.strip():
            result[key] = _scalar(rest, n)
        elif pos < len(lines) and lines[pos][1] > indent:
            result[key], pos = _parse_block(lines, pos, lines[pos][1])
        elif pos < len(lines) and lines[pos][1] == indent and lines[pos][2].startswith("-"):
            # "key:\n- item" at the same indent is valid YAML.
            result[key], pos = _parse_seq(lines, pos, indent)
        else:
            result[key] = None
    return result, pos


def _parse_seq(lines, pos: int, indent: int):
    result = []
    while pos < len(lines):
        n, ind, content = lines[pos]
        if ind < indent or not (content.startswith("- ") or content == "-"):
            if ind > indent:
                raise YamlSubsetError("line %d: unexpected indentation" % n)
            break
        if ind > indent:
            raise YamlSubsetError("line %d: unexpected indentation" % n)
        item = content[1:].strip()
        if not item:
            pos += 1
            if pos < len(lines) and lines[pos][1] > indent:
                value, pos = _parse_block(lines, pos, lines[pos][1])
            else:
                value = None
            result.append(value)
            continue
        if re.match(r"^[A-Za-z_][A-Za-z0-9_\-]*\s*:(\s|$)", item):
            # "- key: value" starts an inline mapping whose other keys sit at
            # the column of "key".
            child_indent = ind + (len(content) - len(item))
            lines[pos] = (n, child_indent, item)
            value, pos = _parse_map(lines, pos, child_indent)
            result.append(value)
            continue
        result.append(_scalar(item, n))
        pos += 1
    return result, pos


def loads(text: str) -> Any:
    lines = _tokenize(text)
    if not lines:
        return None
    value, pos = _parse_block(lines, 0, lines[0][1])
    if pos != len(lines):
        raise YamlSubsetError("line %d: trailing content" % lines[pos][0])
    return value
