# SPDX-License-Identifier: Apache-2.0
"""Which files count as agent instruction / configuration files.

These are the files an agent reads as trusted instructions (or that run code
when a project opens), so they are where an injected payload persists.
"""
from __future__ import annotations

import fnmatch
import os
from pathlib import Path, PurePosixPath
from typing import Iterator, List

# Matched against the path relative to the scan root, in POSIX form. "**/"
# means "at any depth", so nested AGENTS.md files in monorepos are included.
CONFIG_GLOBS = (
    "**/CLAUDE.md",
    "**/CLAUDE.local.md",
    "**/AGENTS.md",
    "**/AGENT.md",
    "**/GEMINI.md",
    "**/.cursorrules",
    "**/.windsurfrules",
    "**/.clinerules",
    "**/.clinerules/**",
    "**/.claude/**",
    "**/.cursor/rules/**",
    "**/.cursor/mcp.json",
    "**/.gemini/**",
    "**/.codex/**",
    "**/.roo/rules/**",
    "**/.amazonq/rules/**",
    "**/.kiro/steering/**",
    "**/.windsurf/rules/**",
    "**/.mcp.json",
    "**/.vscode/tasks.json",
    "**/.vscode/settings.json",
    "**/.vscode/mcp.json",
    "**/.github/copilot-instructions.md",
    "**/.github/instructions/**",
    "**/.github/prompts/**",
)

# Instruction files `harden` may pre-create (empty, read-only) so a worm cannot
# introduce them. Settings files are left alone: an empty read-only settings
# file would break tools that legitimately manage their own settings.
PRECREATE = ("CLAUDE.md", "AGENTS.md", "GEMINI.md", ".cursorrules")

# Files whose JSON may define MCP servers, keyed by the property that holds them.
MCP_SOURCES = {
    ".mcp.json": "mcpServers",
    ".cursor/mcp.json": "mcpServers",
    ".claude/settings.json": "mcpServers",
    ".claude/settings.local.json": "mcpServers",
    ".gemini/settings.json": "mcpServers",
    ".vscode/mcp.json": "servers",
}

SKIP_DIRS = {
    ".git", ".hg", ".svn", "node_modules", ".venv", "venv", "env", "__pycache__",
    ".tox", ".mypy_cache", ".pytest_cache", "dist", "build", "target", ".next",
    ".nuxt", ".turbo", ".cache", "site-packages", ".gradle", ".idea",
}

MAX_FILE_BYTES = 2 * 1024 * 1024
MAX_FILES = 20000
MAX_DEPTH = 16


def real_within(path, root) -> bool:
    """True if ``path``'s real (symlink-resolved) location is inside ``root``.

    Used to enforce containment everywhere we touch a file: a config file that
    is a symlink pointing outside the scanned root must not be read, frozen, or
    written through. ``os.path.realpath`` resolves every symlink component, and
    we compare with ``normcase`` so the check holds on case-insensitive
    filesystems too.
    """
    try:
        rp = os.path.normcase(os.path.realpath(str(path)))
        rr = os.path.normcase(os.path.realpath(str(root)))
    except OSError:
        return False
    return rp == rr or rp.startswith(rr + os.sep)


def _match(rel: str, pattern: str) -> bool:
    # Case-insensitive: Windows and macOS filesystems are, and agents there
    # load "claude.md" as readily as "CLAUDE.md".
    rel, pattern = rel.lower(), pattern.lower()
    if fnmatch.fnmatchcase(rel, pattern):
        return True
    # "**/X" should also match "X" at the root.
    if pattern.startswith("**/") and fnmatch.fnmatchcase(rel, pattern[3:]):
        return True
    return False


def is_config_relpath(rel: str) -> bool:
    rel = rel.replace("\\", "/")
    while rel.startswith("./"):
        rel = rel[2:]
    return any(_match(rel, p) for p in CONFIG_GLOBS)


def is_config_path(path: str) -> bool:
    """True if any suffix of ``path`` looks like an agent config file.

    Used by hooks, which see absolute paths and do not know the project root.
    """
    parts = PurePosixPath(path.replace("\\", "/")).parts
    for i in range(len(parts)):
        if is_config_relpath("/".join(parts[i:])):
            return True
    return False


def iter_config_files(root: Path, classify_root: Optional[Path] = None) -> Iterator[Path]:
    """Yield agent config files found by walking ``root``.

    Config-ness is decided by each file's *logical* path relative to
    ``classify_root`` (default: ``root``) so that scanning a subtree such as
    ``.vscode`` still recognises ``.vscode/tasks.json`` and so a symlink alias
    cannot change a file's logical identity to dodge a filename-scoped rule.
    Containment is enforced separately against the real (symlink-resolved) path.
    """
    root = root.resolve()
    croot = Path(classify_root).resolve() if classify_root is not None else root
    seen = 0
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        rel_dir = Path(dirpath).relative_to(root)
        depth = len(rel_dir.parts)
        dirnames[:] = sorted(
            d for d in dirnames
            if d not in SKIP_DIRS and depth < MAX_DEPTH and not d.startswith(".nation-guard")
        )
        for name in sorted(filenames):
            seen += 1
            if seen > MAX_FILES:
                return
            full = Path(dirpath) / name
            crel = lexical_relpath(full, croot)          # logical identity
            if not is_config_relpath(crel):
                continue
            # Containment: skip a config file whose real path (resolving every
            # symlink component) leaves the classify root, so a planted link
            # cannot make us read/freeze content elsewhere on the machine.
            if not real_within(full, croot):
                continue
            yield full


def lexical_relpath(path, root) -> str:
    """Relative POSIX path computed lexically — WITHOUT resolving symlinks, so a
    file's logical identity (used for filename-scoped rules) is preserved."""
    try:
        return Path(os.path.relpath(str(path), str(root))).as_posix()
    except ValueError:
        return Path(str(path)).as_posix()


def relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return lexical_relpath(path, root)


def read_text_sized(path: Path):
    """Read up to MAX_FILE_BYTES for scanning; return (text, truncated).

    This cap applies to *content scanning* only — integrity hashing reads the
    whole file (see ``integrity.py``) so changes appended past the cap are
    still detected.
    """
    with open(path, "rb") as fh:
        data = fh.read(MAX_FILE_BYTES + 1)
    truncated = len(data) > MAX_FILE_BYTES
    if truncated:
        data = data[:MAX_FILE_BYTES]
    return data.decode("utf-8", errors="replace"), truncated


def read_text(path: Path) -> str:
    """Read up to MAX_FILE_BYTES; undecodable bytes become U+FFFD."""
    return read_text_sized(path)[0]


def mcp_key_for(rel: str) -> str:
    """Return the JSON property that holds MCP servers for ``rel``, or ''."""
    for suffix, key in MCP_SOURCES.items():
        if rel == suffix or rel.endswith("/" + suffix):
            return key
    return ""


def list_precreate(root: Path) -> List[Path]:
    return [root / name for name in PRECREATE]
