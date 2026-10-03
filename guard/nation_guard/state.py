# SPDX-License-Identifier: Apache-2.0
"""On-disk state: baselines, quarantine, and the harden log.

State lives outside the scanned project (default ``~/.nation-guard``) so a
compromised repository cannot read or rewrite the guard's own records. The
home is created ``0700`` and every file is written atomically. If the home
would land inside the root being scanned we refuse rather than silently store
tamperable data next to the attacker.
"""
from __future__ import annotations

import json
import os
import stat
import tempfile
from pathlib import Path
from typing import Any, Optional

ENV_HOME = "NATION_GUARD_HOME"
_DEFAULT = "~/.nation-guard"


class StateError(RuntimeError):
    pass


def home() -> Path:
    """The state directory (``$NATION_GUARD_HOME`` or ``~/.nation-guard``)."""
    raw = os.environ.get(ENV_HOME, "").strip()
    base = Path(raw).expanduser() if raw else Path(_DEFAULT).expanduser()
    return base.resolve()


def _is_within(child: Path, parent: Path) -> bool:
    try:
        child.resolve().relative_to(parent.resolve())
        return True
    except ValueError:
        return False


def ensure_home(root: Optional[Path] = None) -> Path:
    """Create the state home (``0700``) and return it.

    If ``root`` is given and the home resolves to somewhere inside ``root``,
    refuse: baselines and quarantine must never be part of a scanned tree.
    """
    h = home()
    if root is not None and _is_within(h, Path(root)):
        raise StateError(
            "state home %s is inside the scanned root %s; set %s to a location "
            "outside the project" % (h, Path(root).resolve(), ENV_HOME)
        )
    secure_mkdir(h)
    for sub in (baselines_dir(), quarantine_dir()):
        secure_mkdir(sub)
    return h


def baselines_dir() -> Path:
    return home() / "baselines"


def quarantine_dir() -> Path:
    return home() / "quarantine"


def harden_log_path() -> Path:
    return home() / "harden-log.json"


def secure_mkdir(path: Path, mode: int = 0o700) -> None:
    """Create ``path`` (and parents) with restrictive permissions.

    ``os.makedirs(mode=...)`` is unreliable across platforms and umasks, so we
    create then ``chmod``. On Windows the POSIX bits are largely cosmetic, but
    the call is harmless there.
    """
    path = Path(path)
    path.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(path, mode)
    except (OSError, NotImplementedError):
        pass


def write_json_atomic(path: Path, obj: Any, mode: int = 0o600) -> None:
    """Serialise ``obj`` to ``path`` atomically (write temp + ``os.replace``)."""
    path = Path(path)
    secure_mkdir(path.parent)
    fd, tmp = tempfile.mkstemp(prefix=".ng-", dir=str(path.parent))
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(obj, fh, ensure_ascii=False, indent=2, sort_keys=True)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        try:
            os.chmod(tmp, mode)
        except (OSError, NotImplementedError):
            pass
        os.replace(tmp, path)
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass


def read_json(path: Path) -> Optional[Any]:
    """Load JSON from ``path`` or return ``None`` if it is missing/unreadable."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except (OSError, ValueError):
        return None


def make_readonly(path: Path) -> int:
    """Drop the write bit on ``path``; return the previous mode."""
    path = Path(path)
    prev = stat.S_IMODE(path.stat().st_mode)
    new = prev & ~(stat.S_IWUSR | stat.S_IWGRP | stat.S_IWOTH)
    os.chmod(path, new)
    return prev


def make_writable(path: Path) -> None:
    """Restore the owner write bit (used before removing read-only files)."""
    path = Path(path)
    cur = stat.S_IMODE(path.stat().st_mode)
    os.chmod(path, cur | stat.S_IWUSR)
