# SPDX-License-Identifier: Apache-2.0
"""Turn text into several "views" so rules see through common disguises.

Rules are matched against every view. Each view undoes one family of
obfuscation: invisible characters, Unicode tag smuggling, HTML entities,
homoglyphs, HTML comments, base64 blobs, leetspeak, spaced-out letters and
markdown emphasis. Views are additive: the original text is always scanned
too, so normalisation can only add findings, never hide one.

Signals are facts about the raw bytes (for example "contains Unicode tag
characters") that are suspicious on their own, independent of any wording.
"""
from __future__ import annotations

import base64
import binascii
import html
import re
import unicodedata
from dataclasses import dataclass, field
from typing import Dict, List, Tuple

# Zero-width and bidi control characters. U+200D (ZWJ) is handled separately
# because emoji sequences use it legitimately.
_INVISIBLE = (
    "­᠎​‌‎‏"
    "‪‫‬‭‮"
    "⁠⁡⁢⁣⁤"
    "⁦⁧⁨⁩﻿"
)
_INVISIBLE_RE = re.compile("[%s]" % _INVISIBLE)
_ZWJ = "‍"
_TAG_RE = re.compile("[\U000e0000-\U000e007f]+")
_HTML_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.S)
_B64_RE = re.compile(r"(?<![A-Za-z0-9+/=_-])([A-Za-z0-9+/]{24,}={0,2}|[A-Za-z0-9_-]{24,}={0,2})(?![A-Za-z0-9+/=_-])")
_SPACED_RE = re.compile(r"\b(?:[A-Za-z][ .\-_|]){3,}[A-Za-z]\b")
_MARKDOWN_RE = re.compile(r"[*_~`]+")

# Small confusables table: Cyrillic and Greek letters that render like Latin.
# NFKC does not fold these, and they are the cheapest homoglyph trick.
_CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "у": "y", "х": "x", "і": "i", "ј": "j", "ѕ": "s",
    "һ": "h", "ԁ": "d", "ԛ": "q", "ԝ": "w",
    "А": "A", "В": "B", "Е": "E", "К": "K", "М": "M",
    "Н": "H", "О": "O", "Р": "P", "С": "C", "Т": "T",
    "Х": "X", "І": "I", "Ј": "J", "Ѕ": "S",
    "ο": "o", "α": "a", "ε": "e", "ι": "i", "κ": "k",
    "ν": "v", "ρ": "p", "τ": "t", "υ": "u", "χ": "x",
    "Ο": "O", "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z",
    "Η": "H", "Ι": "I", "Κ": "K", "Μ": "M", "Ν": "N",
    "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
})
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i", "|": "l"})

MAX_DECODED_BLOBS = 64


@dataclass
class Normalized:
    views: List[Tuple[str, str]] = field(default_factory=list)
    signals: Dict[str, int] = field(default_factory=dict)

    def view(self, name: str) -> str:
        for n, text in self.views:
            if n == name:
                return text
        return ""


def _is_emoji_context(text: str, idx: int) -> bool:
    def emojiish(ch: str) -> bool:
        cp = ord(ch)
        return cp >= 0x1F000 or 0x2600 <= cp <= 0x27BF or cp in (0xFE0F, 0x20E3) or 0x1F3FB <= cp <= 0x1F3FF

    before = text[idx - 1] if idx > 0 else ""
    after = text[idx + 1] if idx + 1 < len(text) else ""
    return bool(before and after and emojiish(before) and emojiish(after))


def _count_suspicious_zwj(text: str) -> int:
    count = 0
    start = 0
    while True:
        idx = text.find(_ZWJ, start)
        if idx < 0:
            return count
        if not _is_emoji_context(text, idx):
            count += 1
        start = idx + 1


def _decode_tags(text: str) -> str:
    runs = []
    for m in _TAG_RE.finditer(text):
        chars = []
        for ch in m.group(0):
            cp = ord(ch) - 0xE0000
            if 0x20 <= cp <= 0x7E:
                chars.append(chr(cp))
            elif cp in (0x0A, 0x0D, 0x09):
                chars.append(" ")
        if chars:
            runs.append("".join(chars))
    return "\n".join(runs)


def _printable_ratio(s: str) -> float:
    if not s:
        return 0.0
    ok = sum(1 for ch in s if ch.isprintable() or ch in "\n\r\t")
    return ok / len(s)


def _decode_b64_blobs(text: str) -> str:
    out = []
    for m in _B64_RE.finditer(text):
        blob = m.group(1)
        if len(out) >= MAX_DECODED_BLOBS:
            break
        if re.fullmatch(r"[0-9a-fA-F]+", blob):
            continue  # hex digests are not base64 payloads
        padded = blob + "=" * (-len(blob) % 4)
        try:
            if "-" in blob or "_" in blob:
                raw = base64.urlsafe_b64decode(padded)
            else:
                raw = base64.b64decode(padded, validate=True)
            decoded = raw.decode("utf-8")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        letters = sum(1 for ch in decoded if ch.isalpha())
        if _printable_ratio(decoded) >= 0.95 and letters >= 8 and letters / max(len(decoded), 1) > 0.5:
            out.append(decoded)
    return "\n".join(out)


def _despace(text: str) -> str:
    return _SPACED_RE.sub(lambda m: re.sub(r"[ .\-_|]", "", m.group(0)), text)


def normalize(text: str) -> Normalized:
    result = Normalized()

    # A single leading BOM is how editors mark UTF-8; it is not an attempt to
    # smuggle an invisible character, so drop one (and only one) before we
    # count. A BOM anywhere else, or a second one, still counts.
    if text.startswith("﻿"):
        text = text[1:]

    # Decode HTML entities FIRST. An attacker can entity-encode an invisible or
    # tag character (e.g. "ig&#x200b;nore") so that stripping would run before
    # the character even exists; unescaping first means the smuggled character
    # is present when we count signals and strip it, closing that bypass.
    text = html.unescape(text)

    invisible = len(_INVISIBLE_RE.findall(text)) + _count_suspicious_zwj(text)
    if invisible:
        result.signals["invisible_chars"] = invisible
    tags = sum(len(m.group(0)) for m in _TAG_RE.finditer(text))
    if tags:
        result.signals["tag_chars"] = tags

    base = _TAG_RE.sub("", text)
    base = _INVISIBLE_RE.sub("", base)
    base = "".join(ch for i, ch in enumerate(base) if ch != _ZWJ or _is_emoji_context(base, i))
    base = unicodedata.normalize("NFKC", base).translate(_CONFUSABLES)

    result.views.append(("text", base))

    tag_text = _decode_tags(text)
    if tag_text:
        result.views.append(("tag_chars", tag_text))

    comments = "\n".join(m.group(1) for m in _HTML_COMMENT_RE.finditer(base))
    if comments.strip():
        result.views.append(("html_comment", comments))

    decoded = _decode_b64_blobs(base)
    if decoded:
        # One level of nesting is enough to catch "base64 of an obfuscated
        # payload" without letting an attacker make us loop.
        inner = normalize_flat(decoded)
        result.views.append(("base64", inner))

    plain = _MARKDOWN_RE.sub("", base)
    if plain != base:
        result.views.append(("plain", plain))
    despaced = _despace(plain)
    if despaced != plain:
        result.views.append(("despaced", despaced))
    leet = base.lower().translate(_LEET)
    if leet != base.lower():
        result.views.append(("leet", leet))
    return result


def normalize_flat(text: str) -> str:
    """Single-string normalisation used for nested (decoded) content."""
    text = html.unescape(text)  # unescape before stripping (see normalize())
    text = _INVISIBLE_RE.sub("", _TAG_RE.sub("", text))
    return unicodedata.normalize("NFKC", text).translate(_CONFUSABLES)
