# SPDX-License-Identifier: Apache-2.0
"""Make agent instruction files harder to tamper with, reversibly.

This is **best-effort, advisory** protection. On a cooperative OS the dropped
write bit makes an agent that is tricked into editing a frozen file fail
loudly, and pre-creating the common instruction files (empty, read-only) means
a worm cannot *introduce* one where none existed. It does **not** stop a
determined process that can change file modes, and on Windows it only toggles
the read-only attribute. It is a speed bump and an alarm, not a lock.

Safety properties:

* Only regular files are frozen — never symlinks (so we never chmod an external
  referent), and only files whose real path stays inside the root.
* Settings/MCP JSON files are left alone — tools rewrite those legitimately.
* Every completed change is journaled *immediately* (per-root), so a partial
  failure still leaves a complete rollback record. Chmod records are bound to
  the file's identity (device+inode) so ``undo`` refuses to touch a file that
  was swapped out after ``apply``.
"""
from __future__ import annotations

import os
import stat
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List, Optional

from . import integrity, state, targets

HARDEN_BASENAMES = {
    "claude.md", "claude.local.md", "agents.md", "agent.md", "gemini.md",
    ".cursorrules", ".windsurfrules", ".clinerules",
}


@dataclass
class Action:
    kind: str          # "chmod" | "create" | "unfreeze" | "remove" | "kept"
    path: str
    prev_mode: int = -1
    note: str = ""

    def describe(self) -> str:
        if self.kind == "chmod":
            return "freeze   %s" % self.path
        if self.kind == "create":
            return "create   %s (empty, read-only)" % self.path
        return "%s %s" % (self.kind, self.path)


def _identity(path: Path) -> Optional[list]:
    """A stable identity (device, inode) for undo-time verification, or None
    when the platform does not provide a usable inode."""
    try:
        st = os.stat(str(path), follow_symlinks=False)
    except OSError:
        return None
    if not st.st_ino:  # Windows/older FS may report 0
        return None
    return [st.st_dev, st.st_ino]


def _is_readonly(path: Path) -> bool:
    return not (stat.S_IMODE(path.stat().st_mode) & stat.S_IWUSR)


def _existing_targets(root: Path) -> List[Path]:
    out = []
    for path in targets.iter_config_files(root):
        # iter_config_files already excludes files whose real path escapes root.
        # Additionally never operate on a symlink itself (reject links for
        # mutation) — we freeze regular instruction files only.
        if (path.name.lower() in HARDEN_BASENAMES and path.is_file()
                and not path.is_symlink()):
            out.append(path)
    return out


def plan(root: Path) -> List[Action]:
    root = Path(root).resolve()
    actions: List[Action] = []
    for path in _existing_targets(root):
        if _is_readonly(path):
            continue
        actions.append(Action("chmod", str(path), prev_mode=stat.S_IMODE(path.stat().st_mode)))
    for path in targets.list_precreate(root):
        if not path.exists() and not path.is_symlink():
            actions.append(Action("create", str(path)))
    return actions


def _log_all() -> Dict[str, list]:
    data = state.read_json(state.harden_log_path())
    return data if isinstance(data, dict) else {}


def _save_log(data: Dict[str, list]) -> None:
    state.write_json_atomic(state.harden_log_path(), data)


def _journal(key: str, record: dict) -> None:
    """Append one completed change to the log and flush immediately."""
    log = _log_all()
    entries = log.get(key, [])
    if not any(isinstance(e, dict) and e.get("kind") == record["kind"]
               and e.get("path") == record["path"] for e in entries):
        entries.append(record)
        log[key] = entries
        _save_log(log)


def apply(root: Path) -> List[Action]:
    root = Path(root).resolve()
    state.ensure_home(root)
    key = integrity.baseline_key(root)
    done: List[Action] = []
    for action in plan(root):
        try:
            if action.kind == "chmod":
                p = Path(action.path)
                if p.is_symlink():  # never freeze a link's external target
                    continue
                ident = _identity(p)
                action.prev_mode = state.make_readonly(p)
                _journal(key, {"kind": "chmod", "path": action.path,
                               "prev_mode": action.prev_mode, "ident": ident})
            elif action.kind == "create":
                # O_CREAT|O_EXCL fails if the path exists (including a symlink),
                # so we never follow or clobber a planted link.
                fd = os.open(action.path, os.O_CREAT | os.O_EXCL | os.O_WRONLY, 0o444)
                os.close(fd)
                try:
                    os.chmod(action.path, 0o444)
                except (OSError, NotImplementedError):
                    pass
                _journal(key, {"kind": "create", "path": action.path})
            done.append(action)
        except OSError:
            # Leave already-journaled changes in place for rollback; skip this one.
            continue
    return done


def undo(root: Path) -> List[Action]:
    root = Path(root).resolve()
    key = integrity.baseline_key(root)
    log = _log_all()
    recorded = log.get(key, [])
    reverted: List[Action] = []
    remaining: List[dict] = []
    for raw in reversed(recorded):
        if not isinstance(raw, dict):
            continue
        kind, path = raw.get("kind"), raw.get("path")
        if not path:
            continue
        p = Path(path)
        if kind == "chmod":
            try:
                if p.is_symlink():
                    remaining.append(raw)  # refuse to chmod through a link
                    continue
                ident = raw.get("ident")
                if ident is not None and _identity(p) != ident:
                    remaining.append(raw)  # file was swapped out; do not touch
                    continue
                if p.exists():
                    os.chmod(str(p), int(raw.get("prev_mode", 0o644)) or 0o644)
                reverted.append(Action("unfreeze", str(p)))
            except OSError:
                remaining.append(raw)
        elif kind == "create":
            try:
                if p.is_symlink():
                    remaining.append(raw)
                    continue
                if p.exists() and p.stat().st_size == 0:
                    state.make_writable(p)
                    os.remove(str(p))
                    reverted.append(Action("remove", str(p)))
                elif p.exists():
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
