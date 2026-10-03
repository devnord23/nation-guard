# SPDX-License-Identifier: Apache-2.0
"""Walk a project and scan every agent config file against the rules.

This is the read-only heart of the tool: it never writes to the project. The
result is a list of :class:`~nation_guard.rules.Finding` plus enough bookkeeping
for reports (which files were looked at, which were skipped and why).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Sequence

from . import targets
from .rules import Finding, Rule, load_rules, scan_text


@dataclass
class ScanResult:
    root: Path
    findings: List[Finding] = field(default_factory=list)
    files_scanned: List[str] = field(default_factory=list)
    skipped: List[str] = field(default_factory=list)
    truncated: List[str] = field(default_factory=list)

    @property
    def count(self) -> int:
        return len(self.findings)


def _rules(rules: Optional[Sequence[Rule]]) -> Sequence[Rule]:
    return rules if rules is not None else load_rules()


def scan_content(text: str, rel: str, rules: Optional[Sequence[Rule]] = None) -> List[Finding]:
    """Scan a single in-memory document (used by hooks on proposed content)."""
    return scan_text(text, rel, _rules(rules))


def scan_file(path: Path, rel: str, rules: Optional[Sequence[Rule]] = None) -> List[Finding]:
    text = targets.read_text(path)
    return scan_text(text, rel, _rules(rules))


def scan_root(root: Path, rules: Optional[Sequence[Rule]] = None) -> ScanResult:
    """Scan every agent config file under ``root``."""
    return scan_under(root, root, rules)


def scan_under(walk_root: Path, rel_root: Path, rules: Optional[Sequence[Rule]] = None) -> ScanResult:
    """Scan config files under ``walk_root``, but classify and report each file
    by its logical path relative to ``rel_root``.

    This lets an MCP ``scan`` of a subpath (e.g. ``.vscode``) keep the full
    logical identity (``.vscode/tasks.json``) so filename-scoped rules still
    apply, while containment is checked against ``rel_root``.
    """
    walk_root = Path(walk_root).resolve()
    rel_root = Path(rel_root).resolve()
    rules = _rules(rules)
    result = ScanResult(root=rel_root)
    for path in targets.iter_config_files(walk_root, classify_root=rel_root):
        rel = targets.lexical_relpath(path, rel_root)
        try:
            text, truncated = targets.read_text_sized(path)
        except OSError:
            result.skipped.append(rel)
            continue
        result.files_scanned.append(rel)
        if truncated:
            result.truncated.append(rel)
        result.findings.extend(scan_text(text, rel, rules))
    result.findings.sort(key=_finding_sort_key)
    return result


def _finding_sort_key(f: Finding):
    from .rules import severity_rank

    return (f.path, -severity_rank(f.severity), f.rule_id, f.line or 0)
