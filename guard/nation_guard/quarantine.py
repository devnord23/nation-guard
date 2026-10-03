# SPDX-License-Identifier: Apache-2.0
"""Quarantine: pull a malicious file out of the project, reversibly and safely.

``capture`` copies the file into the state home under a fixed internal name
(``payload``, never the original filename, so a source called ``meta.json``
cannot clobber our metadata), verifies the saved bytes against a SHA-256
*before* removing the original, and records the original mode. ``restore``
refuses to write through a symlink at the destination (or its parent), writes
exclusively via a temp file + atomic replace, will not clobber an existing file
without ``force``, and never changes the permissions of an existing directory.
"""
from __future__ import annotations

import hashlib
import os
import shutil
import stat
import tempfile
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional

from . import state

PAYLOAD_NAME = "payload"   # fixed; independent of the original filename
META_NAME = "meta.json"


@dataclass
class QuarantineItem:
    id: str
    original_path: str
    rel: str
    sha256: str
    size: int
    mode: int
    captured: str
    original_name: str

    @property
    def dir(self) -> Path:
        return state.quarantine_dir() / self.id

    @property
    def payload(self) -> Path:
        return self.dir / PAYLOAD_NAME


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


def _remove(path: Path) -> None:
    """Remove ``path``. If it is a symlink, unlink the link only — never chmod
    or delete its (possibly external) target."""
    p = str(path)
    if os.path.islink(p):
        os.remove(p)
        return
    try:
        state.make_writable(path)
    except OSError:
        pass
    os.remove(p)


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

    payload = dest_dir / PAYLOAD_NAME
    shutil.copy2(str(path), str(payload))

    # Verify the saved bytes BEFORE touching the original, so a failed copy can
    # never lose data.
    if _sha256_file(payload) != content_sha:
        try:
            os.chmod(str(payload), 0o600)
            payload.unlink()
        except OSError:
            pass
        raise state.StateError(
            "quarantine copy of %s failed verification; original left untouched" % rel)

    item = QuarantineItem(
        id=qid,
        original_path=os.path.abspath(str(path)),  # literal location (no symlink follow)
        rel=rel,
        sha256=content_sha,
        size=st.st_size,
        mode=stat.S_IMODE(st.st_mode),
        captured=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        original_name=path.name or PAYLOAD_NAME,
    )
    state.write_json_atomic(dest_dir / META_NAME, _to_meta(item))
    try:
        os.chmod(str(payload), 0o400)
    except (OSError, NotImplementedError):
        pass

    if not keep:
        _remove(path)
    return item


def _to_meta(item: QuarantineItem) -> dict:
    return {
        "id": item.id,
        "original_path": item.original_path,
        "rel": item.rel,
        "sha256": item.sha256,
        "size": item.size,
        "mode": item.mode,
        "captured": item.captured,
        "original_name": item.original_name,
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
            original_name=str(meta.get("original_name", PAYLOAD_NAME)),
        )
    except (KeyError, ValueError, TypeError):
        return None


def load_item(qid: str) -> Optional[QuarantineItem]:
    meta = state.read_json(state.quarantine_dir() / qid / META_NAME)
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
    # Reject unsafe symlink destinations BEFORE touching anything: a planted
    # (possibly dangling) symlink at the destination or its parent would
    # otherwise let a restore write a file outside the intended location.
    if os.path.islink(str(target)):
        raise state.StateError("restore destination %s is a symlink; refusing (unsafe)" % target)
    if target.exists() and not force:
        raise state.StateError("%s already exists; pass --force to overwrite" % target)

    parent = target.parent
    if os.path.islink(str(parent)):
        raise state.StateError("restore destination parent %s is a symlink; refusing" % parent)
    if not parent.exists():
        # Create missing parents only; never change the mode of an existing dir.
        parent.mkdir(parents=True, exist_ok=True)

    # Exclusive write: temp file in the parent, then atomic replace of the NAME
    # (os.replace does not follow a symlink target — and we refused symlinks).
    fd, tmp = tempfile.mkstemp(prefix=".ngrestore-", dir=str(parent))
    try:
        with os.fdopen(fd, "wb") as out, open(item.payload, "rb") as src:
            shutil.copyfileobj(src, out)
        os.replace(tmp, str(target))
    finally:
        try:
            if os.path.exists(tmp):
                os.remove(tmp)
        except OSError:
            pass
    try:
        os.chmod(str(target), item.mode)
    except (OSError, NotImplementedError):
        pass
    return target
