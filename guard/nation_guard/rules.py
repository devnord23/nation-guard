# SPDX-License-Identifier: Apache-2.0
"""Rule loading and matching.

Rules are data (``rules/*.yaml``), not code, so they can be reviewed, diffed
and extended without touching the engine. Three kinds exist:

* ``pattern``: regexes matched against every normalised view of a file.
  ``any`` needs one match; ``all`` needs every pattern to match, each within
  ``within`` characters of the first one (proximity keeps "never commit .env"
  and "send a PR" in different paragraphs from looking like exfiltration).
* ``signal``: fires when the normaliser reports a raw-byte signal such as
  Unicode tag characters.
* ``integrity``: metadata only; raised by ``verify`` (hash drift) so every ID
  the tool can emit is documented in one place.
"""
from __future__ import annotations

import fnmatch
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Sequence, Tuple

from . import yamlsub
from .normalize import Normalized, normalize

SEVERITIES = ("info", "low", "medium", "high", "critical")
KINDS = ("pattern", "signal", "integrity")
MAX_PATTERN_LEN = 2000
HIDDEN_VIEWS = ("html_comment", "tag_chars", "base64")


class RuleError(ValueError):
    pass


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    severity: str
    kind: str
    message: str
    category: str = ""
    any: Tuple["re.Pattern[str]", ...] = ()
    all: Tuple["re.Pattern[str]", ...] = ()
    within: int = 0
    files: Tuple[str, ...] = ()
    signal: str = ""

    def applies_to(self, rel: str) -> bool:
        if not self.files:
            return True
        rel = rel.lower()
        for pattern in self.files:
            p = pattern.lower()
            if fnmatch.fnmatchcase(rel, p) or (p.startswith("**/") and fnmatch.fnmatchcase(rel, p[3:])):
                return True
        return False


@dataclass
class Finding:
    rule_id: str
    severity: str
    title: str
    message: str
    path: str
    line: Optional[int] = None
    evidence: str = ""
    views: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, object]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "title": self.title,
            "message": self.message,
            "path": self.path,
            "line": self.line,
            "evidence": self.evidence,
            "views": list(self.views),
        }


def severity_rank(sev: str) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else 0


def default_rules_dir() -> Path:
    here = Path(__file__).resolve().parent
    for candidate in (here / "rules", here.parent.parent / "rules"):
        if candidate.is_dir() and any(candidate.glob("*.yaml")):
            return candidate
    raise RuleError("no rules directory found (looked next to the package and at the repo root)")


def _compile(pattern: object, rule_id: str) -> "re.Pattern[str]":
    if not isinstance(pattern, str) or not pattern:
        raise RuleError("%s: patterns must be non-empty strings" % rule_id)
    if len(pattern) > MAX_PATTERN_LEN:
        raise RuleError("%s: pattern too long" % rule_id)
    try:
        return re.compile(pattern, re.IGNORECASE | re.MULTILINE)
    except re.error as exc:
        raise RuleError("%s: bad regex %r: %s" % (rule_id, pattern, exc))


def _rule_from_dict(raw: Dict[str, object], source: str) -> Rule:
    if not isinstance(raw, dict):
        raise RuleError("%s: each rule must be a mapping" % source)
    rid = raw.get("id")
    if not isinstance(rid, str) or not re.fullmatch(r"NG-[A-Z]+-\d{3}", rid):
        raise RuleError("%s: rule id must look like NG-ABC-001, got %r" % (source, rid))
    known = {"id", "title", "severity", "kind", "message", "category", "any", "all", "within", "files", "signal"}
    unknown = set(raw) - known
    if unknown:
        raise RuleError("%s: unknown keys %s" % (rid, sorted(unknown)))
    kind = raw.get("kind", "pattern")
    if kind not in KINDS:
        raise RuleError("%s: kind must be one of %s" % (rid, KINDS))
    sev = raw.get("severity")
    if sev not in SEVERITIES:
        raise RuleError("%s: severity must be one of %s" % (rid, SEVERITIES))
    any_p = tuple(_compile(p, rid) for p in (raw.get("any") or []))
    all_p = tuple(_compile(p, rid) for p in (raw.get("all") or []))
    if kind == "pattern" and not (any_p or all_p):
        raise RuleError("%s: pattern rules need 'any' or 'all'" % rid)
    if kind == "signal" and not raw.get("signal"):
        raise RuleError("%s: signal rules need 'signal'" % rid)
    within = raw.get("within", 0) or 0
    if not isinstance(within, int) or within < 0:
        raise RuleError("%s: within must be a non-negative integer" % rid)
    files = raw.get("files") or []
    if not isinstance(files, list) or not all(isinstance(f, str) for f in files):
        raise RuleError("%s: files must be a list of globs" % rid)
    return Rule(
        id=rid,
        title=str(raw.get("title") or rid),
        severity=sev,
        kind=kind,
        message=str(raw.get("message") or ""),
        category=str(raw.get("category") or ""),
        any=any_p,
        all=all_p,
        within=within,
        files=tuple(files),
        signal=str(raw.get("signal") or ""),
    )


def load_rules(rules_dir: Optional[Path] = None) -> List[Rule]:
    rules_dir = Path(rules_dir) if rules_dir else default_rules_dir()
    files = sorted(rules_dir.glob("*.yaml"))
    if not files:
        raise RuleError("no *.yaml rule files in %s" % rules_dir)
    rules: List[Rule] = []
    seen = set()
    for f in files:
        doc = yamlsub.loads(f.read_text(encoding="utf-8"))
        if not isinstance(doc, dict) or not isinstance(doc.get("rules"), list):
            raise RuleError("%s: top level must be 'rules: [...]'" % f.name)
        for raw in doc["rules"]:
            rule = _rule_from_dict(raw, f.name)
            if rule.id in seen:
                raise RuleError("duplicate rule id %s" % rule.id)
            seen.add(rule.id)
            rules.append(rule)
    return rules


def rule_index(rules: Sequence[Rule]) -> Dict[str, Rule]:
    return {r.id: r for r in rules}


def _all_within(text: str, patterns: Sequence["re.Pattern[str]"], within: int) -> Optional["re.Match[str]"]:
    first = list(patterns[0].finditer(text))
    if not first:
        return None
    others = []
    for p in patterns[1:]:
        # finditer yields matches left-to-right, so these are already sorted.
        found = [m.start() for m in p.finditer(text)]
        if not found:
            return None
        others.append(found)
    for m in first:
        if not within:
            return m
        s = m.start()
        # Binary-search each other pattern's positions for one in [s-within,
        # s+within]. This keeps proximity matching O(n log n); a naive
        # all-pairs scan is quadratic and a 2 MiB file with many far-apart
        # half-matches could otherwise hang the scanner (algorithmic DoS).
        if all(_has_within(positions, s, within) for positions in others):
            return m
    return None


def _has_within(positions: Sequence[int], center: int, within: int) -> bool:
    import bisect

    lo = bisect.bisect_left(positions, center - within)
    return lo < len(positions) and positions[lo] <= center + within


def _match_rule(rule: Rule, text: str) -> Optional["re.Match[str]"]:
    if rule.all:
        m = _all_within(text, rule.all, rule.within)
        if not m:
            return None
        if not rule.any:
            return m
    for p in rule.any:
        m = p.search(text)
        if m:
            return m
    return None


def sanitize(snippet: str, limit: int = 160) -> str:
    """Make evidence safe to print: escape invisibles, collapse whitespace."""
    out = []
    for ch in snippet:
        cp = ord(ch)
        if ch in "\n\r\t":
            out.append(" ")
        elif cp < 0x20 or 0x7F <= cp < 0xA0 or (not ch.isprintable()) or 0xE0000 <= cp <= 0xE007F:
            out.append("\\u%04x" % cp if cp <= 0xFFFF else "\\U%08x" % cp)
        else:
            out.append(ch)
    text = re.sub(r"\s+", " ", "".join(out)).strip()
    return text if len(text) <= limit else text[: limit - 1] + "…"


def scan_text(text: str, rel: str, rules: Sequence[Rule], norm: Optional[Normalized] = None) -> List[Finding]:
    """Scan one document. ``rel`` is used for file-scoped rules and reporting."""
    norm = norm or normalize(text)
    findings: Dict[str, Finding] = {}
    for rule in rules:
        if rule.kind != "pattern" or not rule.applies_to(rel):
            continue
        for view_name, view_text in norm.views:
            m = _match_rule(rule, view_text)
            if not m:
                continue
            existing = findings.get(rule.id)
            if existing:
                if view_name not in existing.views:
                    existing.views.append(view_name)
                continue
            line = view_text.count("\n", 0, m.start()) + 1 if view_name == "text" else None
            start = max(0, m.start() - 20)
            findings[rule.id] = Finding(rule.id, rule.severity, rule.title, rule.message, rel,
                                        line=line, evidence=sanitize(view_text[start:m.end() + 20]),
                                        views=[view_name])

    # Derived signal: a pattern rule fired inside content a human reviewer
    # would not see (an HTML comment, tag characters, a base64 blob).
    signals = dict(norm.signals)
    hidden = sorted({v for f in findings.values() for v in f.views if v in HIDDEN_VIEWS})
    if hidden:
        signals["hidden_instruction"] = len(hidden)
    for rule in rules:
        if rule.kind != "signal" or not rule.applies_to(rel):
            continue
        count = signals.get(rule.signal)
        if count:
            evidence = ("found in: " + ", ".join(hidden)) if rule.signal == "hidden_instruction" else "%d character(s)" % count
            findings[rule.id] = Finding(rule.id, rule.severity, rule.title, rule.message, rel,
                                        evidence=evidence, views=["raw"])
    ordered =sorted(findings.values(), key=lambda f: (-severity_rank(f.severity), f.rule_id))
    return ordered
