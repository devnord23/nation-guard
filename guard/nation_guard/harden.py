# SPDX-License-Identifier: Apache-2.0
"""Make agent instruction files hard to tamper with, reversibly.

Two moves, both conservative:

* drop the write bit on existing instruction files (``CLAUDE.md`` and kin), so
  an agent that is tricked into editing one fails loudly instead of silently
  persisting a payload;
* pre-create the common instruction files (empty, read-only) at the project
  root, so a worm cannot *introduce* a ``CLAUDE.md`` where none existed.

Settings/MCP JSON files are left alone — tools legitimately rewrite those, and
an immutable one would break them. Every change is logged per-root so ``undo``
reverts exactly what this tool did and nothing else. Default is a dry run;
``apply`` performs the changes.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List

from . import integrity, state, targets

# Instruction files worth freezing. Deliberately excludes settings.json /
# *.mcp.json (managed by tools) — see module docstring.
HARDEN_BASENAMES = {
    "claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md",
    ".cursorrules", ".windsurfrules", ".clinerules",
}


@dataclass
class Action:
    kind: str          # "chmod" | "create"
    path: str          # absolute path
    prev_mode: int = -1  # for chmod: mode before we touched it
    note: str = ""

    def describe(self) -> str:
        if self.kind == "chmod":
            return "freeze   %s" % self.path
        if self.kind == "create":
            return "create   %s (empty, read-only)" % self.path
        return "%s %s" % (self.kind, self.path)


def _existing_targets(root: Path) -> List[Path]:
    out = []
    for path in targets.iter_config_files(root):
        if path.name.lower() in HARDEN_BASENAMES and path.is_file():
            out.append(path)
    return out


def _is_readonly(path: Path) -> bool:
    return not (stat.S_IMODE(path.stat().st_mode) & stat.S_IWUSR)


def plan(root: Path) -> List[Action]:
    """What ``apply`` would do, without doing it."""
    root = Path(root).resolve()
    actions: List[Action] = []
    for path in _existing_targets(root):
        if _is_readonly(path):
            continue
        actions.append(Action("chmod", str(path), prev_mode=stat.S_IMODE(path.stat().st_mode)))
    for path in targets.list_precreate(root):
        if not path.exists():
            actions.append(Action("create", str(path)))
    return actions


def _log_all() -> Dict[str, list]:
    data = state.read_json(state.harden_log_path())
    return data if isinstance(data, dict) else {}


def _save_log(data: Dict[str, list]) -> None:
    state.write_json_atomic(state.harden_log_path(), data)


def apply(root: Path) -> List[Action]:
    """Perform the plan and record it so ``undo`` can reverse it."""
    root = Path(root).resolve()
    state.ensure_home(root)
    key = integrity.baseline_key(root)
    log = _log_all()
    logged = log.get(key, [])
    logged_paths = {(a.get("kind"), a.get("path")) for a in logged if isinstance(a, dict)}

    done: List[Action] = []
    for action in plan(root):
        if action.kind == "chmod":
            prev = state.make_readonly(Path(action.path))
            action.prev_mode = prev
        elif action.kind == "create":
            p = Path(action.path)
            with open(p, "x", encoding="utf-8"):
                pass
            try:
                os.chmod(p, 0o444)
            except (OSError, NotImplementedError):
                pass
        done.append(action)
        if (action.kind, action.path) not in logged_paths:
            logged.append({"kind": action.kind, "path": action.path, "prev_mode": action.prev_mode})
            logged_paths.add((action.kind, action.path))

    if done:
        log[key] = logged
        _save_log(log)
    return done


def undo(root: Path) -> List[Action]:
    """Reverse exactly the changes recorded for ``root``."""
    root = Path(root).resolve()
    key = integrity.baseline_key(root)
    log = _log_all()
    recorded = log.get(key, [])
    reverted: List[Action] = []
    remaining: List[dict] = []
    # Undo in reverse so creates are removed before (hypothetical) parent work.
    for raw in reversed(recorded):
        if not isinstance(raw, dict):
            continue
        kind, path = raw.get("kind"), raw.get("path")
        p = Path(path) if path else None
        if p is None:
            continue
        if kind == "chmod":
            try:
                if p.exists():
                    os.chmod(p, int(raw.get("prev_mode", 0o644)) or 0o644)
                reverted.append(Action("unfreeze", str(p)))
            except OSError:
                remaining.append(raw)
        elif kind == "create":
            try:
                if p.exists() and p.stat().st_size == 0:
                    state.make_writable(p)
                    os.remove(p)
                    reverted.append(Action("remove", str(p)))
                elif p.exists():
                    # User put real content here after we created it; keep it.
                    remaining.append(raw)
                    reverted.append(Action("kept", str(p), note="not empty; left in place"))
            except OSError:
                remaining.append(raw)

    if remaining:
        log[key] = list(reversed(remaining))
    else:
        log.pop(key, None)
    _save_log(log)
    return reverted
