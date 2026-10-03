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


def iter_config_files(root: Path) -> Iterator[Path]:
    """Yield agent config files under ``root`` (no symlinked directories)."""
    root = root.resolve()
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
            rel = (rel_dir / name).as_posix()
            if is_config_relpath(rel):
                yield Path(dirpath) / name


def relpath(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def read_text(path: Path) -> str:
    """Read up to MAX_FILE_BYTES; undecodable bytes become U+FFFD."""
    with open(path, "rb") as fh:
        data = fh.read(MAX_FILE_BYTES + 1)
    if len(data) > MAX_FILE_BYTES:
        data = data[:MAX_FILE_BYTES]
    return data.decode("utf-8", errors="replace")


def mcp_key_for(rel: str) -> str:
    """Return the JSON property that holds MCP servers for ``rel``, or ''."""
    for suffix, key in MCP_SOURCES.items():
        if rel == suffix or rel.endswith("/" + suffix):
            return key
    return ""


def list_precreate(root: Path) -> List[Path]:
    return [root / name for name in PRECREATE]
