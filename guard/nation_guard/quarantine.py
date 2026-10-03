# SPDX-License-Identifier: Apache-2.0
"""Quarantine: pull a malicious file out of the project, reversibly.

``capture`` moves (or, with ``keep``, copies) a file into the state home under
its own id, records a SHA-256 and the original mode, and leaves the payload
read-only (``0400``). ``restore`` puts it back, but refuses to clobber an
existing file unless forced and refuses outright if the quarantined bytes no
longer match the recorded hash (tamper check).
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from . import state


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    rel: str
    sha256: str
    size: int
    mode: int
    captured: str
    payload_name: str

    @property
    def dir(self) -> Path:
        return state.quarantine_dir() / self.id

    @property
    def payload(self) -> Path:
        return self.dir / self.payload_name


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _make_id(rel: str, content_sha: str) -> str:
    base = hashlib.sha256(rel.encode("utf-8")).hexdigest()[:12] + "-" + content_sha[:8]
    candidate = base
    n = 1
    while (state.quarantine_dir() / candidate).exists():
        n += 1
        candidate = "%s-%d" % (base, n)
    return candidate


def capture(path: Path, root: Path, keep: bool = False) -> QuarantineItem:
    path = Path(path)
    if not path.is_file():
        raise state.StateError("not a file: %s" % path)
    state.ensure_home(root)

    from . import targets

    rel = targets.relpath(path, Path(root))
    content_sha = _sha256_file(path)
    st = path.stat()
    qid = _make_id(rel, content_sha)
    dest_dir = state.quarantine_dir() / qid
    state.secure_mkdir(dest_dir)

    payload_name = path.name or "payload"
    payload = dest_dir / payload_name
    shutil.copy2(str(path), str(payload))

    item = QuarantineItem(
        id=qid,
        original_path=str(path.resolve()),
        rel=rel,
        sha256=content_sha,
        size=st.st_size,
        mode=stat.S_IMODE(st.st_mode),
        captured=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        payload_name=payload_name,
    )
    state.write_json_atomic(dest_dir / "meta.json", _to_meta(item))
    try:
        os.chmod(payload, 0o400)
    except (OSError, NotImplementedError):
        pass

    if not keep:
        _remove(path)
    return item


def _remove(path: Path) -> None:
    try:
        state.make_writable(path)
    except OSError:
        pass
    os.remove(path)


def _to_meta(item: QuarantineItem) -> dict:
    return {
        "id": item.id,
        "original_path": item.original_path,
        "rel": item.rel,
        "sha256": item.sha256,
        "size": item.size,
        "mode": item.mode,
        "captured": item.captured,
        "payload_name": item.payload_name,
    }


def _from_meta(meta: dict) -> Optional[QuarantineItem]:
    try:
        return QuarantineItem(
            id=str(meta["id"]),
            original_path=str(meta["original_path"]),
            rel=str(meta.get("rel", "")),
            sha256=str(meta["sha256"]),
            size=int(meta.get("size", 0)),
            mode=int(meta.get("mode", 0o600)),
            captured=str(meta.get("captured", "")),
            payload_name=str(meta.get("payload_name", "payload")),
        )
    except (KeyError, ValueError, TypeError):
        return None


def load_item(qid: str) -> Optional[QuarantineItem]:
    meta = state.read_json(state.quarantine_dir() / qid / "meta.json")
    if not isinstance(meta, dict):
        return None
    return _from_meta(meta)


def list_items() -> List[QuarantineItem]:
    qdir = state.quarantine_dir()
    if not qdir.is_dir():
        return []
    items = []
    for child in sorted(qdir.iterdir()):
        if not child.is_dir():
            continue
        item = load_item(child.name)
        if item:
            items.append(item)
    return items


def restore(qid: str, force: bool = False) -> Path:
    item = load_item(qid)
    if item is None:
        raise state.StateError("no quarantine item with id %r" % qid)
    if not item.payload.is_file():
        raise state.StateError("quarantine payload missing for %r" % qid)
    if _sha256_file(item.payload) != item.sha256:
        raise state.StateError("quarantine payload for %r fails its hash check; refusing to restore" % qid)

    target = Path(item.original_path)
    if target.exists() and not force:
        raise state.StateError("%s already exists; pass --force to overwrite" % target)
    state.secure_mkdir(target.parent)
    if target.exists():
        _remove(target)
    shutil.copy2(str(item.payload), str(target))
    try:
        os.chmod(target, item.mode)
    except (OSError, NotImplementedError):
        pass
    return target
