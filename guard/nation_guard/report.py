# SPDX-License-Identifier: Apache-2.0
"""Render findings as text, JSON, or SARIF 2.1.0.

SARIF is what GitHub code scanning and most CI dashboards ingest, so the action
emits it. The text format is for humans at a terminal; JSON is the stable
machine format for anyone scripting around the tool.
"""
from __future__ import annotations

import json
from typing import Dict, List, Sequence

from . import __version__
from .rules import Finding, Rule, severity_rank

TOOL_NAME = "nation-guard"
INFO_URI = "https://github.com/devnord23/nation-guard"

# SARIF has four levels; map our five severities onto them.
_SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


def _by_severity(findings: Sequence[Finding]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    return counts


def render_text(findings: Sequence[Finding], *, root: str = "", files_scanned: int = 0,
                use_color: bool = False, truncated: Sequence[str] = ()) -> str:
    lines: List[str] = []
    if root:
        lines.append("nation-guard %s  —  %s" % (__version__, root))
    counts = _by_severity(findings)
    summary = ", ".join("%d %s" % (counts[s], s) for s in ("critical", "high", "medium", "low", "info") if counts.get(s))
    lines.append("Scanned %d file(s); %d finding(s)%s" % (
        files_scanned, len(findings), (": " + summary) if summary else ""))
    if truncated:
        lines.append("WARNING: %d file(s) exceeded the 2 MiB scan limit and were scanned only "
                     "in part (integrity hashing still covers them in full): %s"
                     % (len(truncated), ", ".join(sorted(truncated))))
    lines.append("")
    if not findings:
        lines.append("No findings.")
        return "\n".join(lines)

    ordered = sorted(findings, key=lambda f: (-severity_rank(f.severity), f.path, f.rule_id, f.line or 0))
    for f in ordered:
        loc = f.path + (":%d" % f.line if f.line else "")
        tag = _color(f.severity, use_color)
        lines.append("%s  %s  %s" % (tag, f.rule_id, f.title))
        lines.append("    %s" % loc)
        if f.message:
            lines.append("    %s" % f.message)
        if f.evidence:
            lines.append("    evidence: %s" % f.evidence)
        if f.views and f.views != ["text"]:
            lines.append("    seen in: %s" % ", ".join(f.views))
        lines.append("")
    return "\n".join(lines).rstrip() + "\n"


_ANSI = {"critical": "\033[1;31m", "high": "\033[31m", "medium": "\033[33m", "low": "\033[36m", "info": "\033[2m"}
_RESET = "\033[0m"


def _color(sev: str, use_color: bool) -> str:
    label = "[%s]" % sev.upper()
    if use_color and sev in _ANSI:
        return _ANSI[sev] + label + _RESET
    return label


def render_json(findings: Sequence[Finding], *, root: str = "", files_scanned: int = 0,
                truncated: Sequence[str] = ()) -> str:
    payload = {
        "tool": TOOL_NAME,
        "version": __version__,
        "root": root,
        "files_scanned": files_scanned,
        "truncated": sorted(truncated),
        "summary": _by_severity(findings),
        "findings": [f.to_dict() for f in findings],
    }
    return json.dumps(payload, indent=2, ensure_ascii=True, sort_keys=True)


def render_sarif(findings: Sequence[Finding], rules: Sequence[Rule], *, root: str = "") -> str:
    used = {f.rule_id for f in findings}
    descriptors = []
    index: Dict[str, int] = {}
    for rule in sorted(rules, key=lambda r: r.id):
        if rule.id not in used:
            continue
        index[rule.id] = len(descriptors)
        descriptors.append({
            "id": rule.id,
            "name": "".join(part.capitalize() for part in rule.id.split("-")),
            "shortDescription": {"text": rule.title},
            "fullDescription": {"text": rule.message or rule.title},
            "defaultConfiguration": {"level": _SARIF_LEVEL.get(rule.severity, "warning")},
            "properties": {"severity": rule.severity, "category": rule.category or "security"},
        })

    results = []
    for f in findings:
        region = {}
        if f.line:
            region = {"startLine": max(1, f.line)}
        result = {
            "ruleId": f.rule_id,
            "level": _SARIF_LEVEL.get(f.severity, "warning"),
            "message": {"text": f.message or f.title},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.path.replace("\\", "/")},
                    **({"region": region} if region else {}),
                }
            }],
            "properties": {"severity": f.severity, "evidence": f.evidence, "views": list(f.views)},
        }
        if f.rule_id in index:
            result["ruleIndex"] = index[f.rule_id]
        results.append(result)

    sarif = {
        "version": "2.1.0",
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
        "runs": [{
            "tool": {"driver": {
                "name": TOOL_NAME,
                "informationUri": INFO_URI,
                "version": __version__,
                "rules": descriptors,
            }},
            "results": results,
            **({"originalUriBaseIds": {"SRCROOT": {"uri": _as_file_uri(root)}}} if root else {}),
        }],
    }
    # ensure_ascii escapes any lone surrogate / non-BMP char, so serialising a
    # finding drawn from hostile bytes cannot raise on the final UTF-8 encode.
    return json.dumps(sarif, indent=2, ensure_ascii=True, sort_keys=True)


def _as_file_uri(root: str) -> str:
    p = root.replace("\\", "/")
    if not p.endswith("/"):
        p += "/"
    if not p.startswith("/"):
        p = "/" + p
    return "file://" + p
