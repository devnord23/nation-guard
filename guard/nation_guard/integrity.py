# SPDX-License-Identifier: Apache-2.0
"""Baselines and drift detection.

``baseline`` records a SHA-256 of every agent config file under a root, plus a
per-server hash of every MCP server declaration. ``verify`` re-reads the tree
and reports what changed, was added or was removed, and which MCP server
entries differ. This catches a worm that edits an existing instruction file
even when its payload is too novel for a content rule to recognise.

One baseline per root, stored under the state home (keyed by the absolute root
path) so it cannot be tampered with from inside the project.
"""
from __future__ import annotations

import hashlib
import time
from pathlib import Path
from typing import Dict, List, Optional, Sequence

from . import jsonc, state, targets
from .rules import Finding, Rule, rule_index

SCHEMA_VERSION = 1

# Integrity rule ids and the drift each represents.
INT_CHANGED = "NG-INT-001"
INT_NEW = "NG-INT-002"
INT_REMOVED = "NG-INT-003"
MCP_CHANGED = "NG-MCP-001"


def _sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def baseline_key(root: Path) -> str:
    return _sha256(str(Path(root).resolve()).encode("utf-8"))[:32]


def baseline_path(root: Path) -> Path:
    return state.baselines_dir() / (baseline_key(root) + ".json")


def _canonical(obj) -> str:
    import json

    return json.dumps(obj, sort_keys=True, ensure_ascii=False, separators=(",", ":"))


def _mcp_servers(path: Path, rel: str) -> Optional[Dict[str, str]]:
    """Return ``{server_name: hash}`` for an MCP source file, or ``None``."""
    key = targets.mcp_key_for(rel)
    if not key:
        return None
    try:
        raw = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return None
    doc = jsonc.loads(raw)
    if not isinstance(doc, dict):
        return {}
    servers = doc.get(key)
    if not isinstance(servers, dict):
        return {}
    return {name: _sha256(_canonical(entry).encode("utf-8")) for name, entry in servers.items()}


def compute(root: Path) -> Dict[str, object]:
    root = Path(root).resolve()
    files: Dict[str, Dict[str, object]] = {}
    mcp: Dict[str, Dict[str, str]] = {}
    for path in targets.iter_config_files(root):
        rel = targets.relpath(path, root)
        try:
            data = path.read_bytes()
        except OSError:
            continue
        if len(data) > targets.MAX_FILE_BYTES:
            data = data[: targets.MAX_FILE_BYTES]
        files[rel] = {"sha256": _sha256(data), "size": len(data)}
        servers = _mcp_servers(path, rel)
        if servers is not None:
            mcp[rel] = servers
    return {
        "schema": SCHEMA_VERSION,
        "root": str(root),
        "created": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": files,
        "mcp": mcp,
    }


def load_baseline(root: Path) -> Optional[Dict[str, object]]:
    return state.read_json(baseline_path(root))


def save_baseline(root: Path, update: bool = False) -> Path:
    """Compute and persist the baseline. Refuse to overwrite unless ``update``."""
    state.ensure_home(root)
    path = baseline_path(root)
    if path.exists() and not update:
        raise state.StateError(
            "a baseline already exists for %s; pass --update to replace it" % Path(root).resolve()
        )
    state.write_json_atomic(path, compute(root))
    return path


def _finding(rules: Sequence[Rule], rule_id: str, rel: str, evidence: str) -> Optional[Finding]:
    rule = rule_index(rules).get(rule_id)
    if rule is None:
        return None
    return Finding(rule.id, rule.severity, rule.title, rule.message, rel, evidence=evidence, views=["baseline"])


def verify(root: Path, rules: Sequence[Rule]) -> List[Finding]:
    """Compare the tree to its baseline. Empty list means "no baseline drift"."""
    base = load_baseline(root)
    if base is None:
        raise state.StateError(
            "no baseline for %s; run `nation-guard baseline` first" % Path(root).resolve()
        )
    current = compute(root)
    findings: List[Finding] = []

    old_files: Dict[str, dict] = base.get("files", {})  # type: ignore[assignment]
    new_files: Dict[str, dict] = current["files"]  # type: ignore[assignment]

    for rel, meta in sorted(new_files.items()):
        if rel not in old_files:
            f = _finding(rules, INT_NEW, rel, "new config file not in baseline")
            if f:
                findings.append(f)
        elif meta.get("sha256") != old_files[rel].get("sha256"):
            f = _finding(rules, INT_CHANGED, rel, "sha256 differs from baseline")
            if f:
                findings.append(f)
    for rel in sorted(old_files):
        if rel not in new_files:
            f = _finding(rules, INT_REMOVED, rel, "config file present in baseline is gone")
            if f:
                findings.append(f)

    old_mcp: Dict[str, dict] = base.get("mcp", {})  # type: ignore[assignment]
    new_mcp: Dict[str, dict] = current["mcp"]  # type: ignore[assignment]
    for rel in sorted(set(old_mcp) | set(new_mcp)):
        before = old_mcp.get(rel, {})
        after = new_mcp.get(rel, {})
        for name in sorted(set(before) | set(after)):
            b, a = before.get(name), after.get(name)
            if b == a:
                continue
            if b is None:
                detail = "MCP server %r added" % name
            elif a is None:
                detail = "MCP server %r removed" % name
            else:
                detail = "MCP server %r definition changed" % name
            f = _finding(rules, MCP_CHANGED, rel, detail)
            if f:
                findings.append(f)
    return findings
