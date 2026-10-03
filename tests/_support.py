# SPDX-License-Identifier: Apache-2.0
"""Shared test helpers: path bootstrap, an isolated state home, corpus access."""
from __future__ import annotations

import contextlib
import io
import os
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "guard"))

CORPUS = REPO / "corpus"
RULES_DIR = REPO / "rules"

from nation_guard.rules import load_rules  # noqa: E402

_RULES = None


def rules():
    global _RULES
    if _RULES is None:
        _RULES = load_rules(RULES_DIR)
    return _RULES


@contextlib.contextmanager
def temp_home():
    """Point NATION_GUARD_HOME at a throwaway directory for the duration."""
    with tempfile.TemporaryDirectory(prefix="ng-home-") as d:
        old = os.environ.get("NATION_GUARD_HOME")
        os.environ["NATION_GUARD_HOME"] = d
        try:
            yield Path(d)
        finally:
            if old is None:
                os.environ.pop("NATION_GUARD_HOME", None)
            else:
                os.environ["NATION_GUARD_HOME"] = old


@contextlib.contextmanager
def temp_project():
    with tempfile.TemporaryDirectory(prefix="ng-proj-") as d:
        yield Path(d)


@contextlib.contextmanager
def capture_io(stdin_text=""):
    """Run a block with stdin fed from text and stdout captured (text)."""
    old_in, old_out = sys.stdin, sys.stdout
    sys.stdin = io.StringIO(stdin_text)
    sys.stdout = io.StringIO()
    try:
        yield sys.stdout
    finally:
        sys.stdin, sys.stdout = old_in, old_out
