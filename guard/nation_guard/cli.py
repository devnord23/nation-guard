# SPDX-License-Identifier: Apache-2.0
"""Command-line interface: ``nation-guard <command>``.

Commands: ``scan``, ``baseline``, ``verify``, ``harden``, ``capture``,
``restore``, ``quarantine list``, ``hooks print``, ``rules list`` and ``mcp``
(start the read-only MCP server). ``scan`` and ``verify`` exit 1 when a finding
at or above ``--fail-on`` (default ``high``) is present, so CI can gate on them.
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import List, Optional, Sequence

from . import __version__, harden as harden_mod, integrity, quarantine, report, state
from .rules import Finding, SEVERITIES, load_rules, severity_rank
from .scanner import scan_root

EXIT_OK = 0
EXIT_FINDINGS = 1
EXIT_ERROR = 2


def _add_common(p: argparse.ArgumentParser) -> None:
    p.add_argument("--root", default=".", help="project root to operate on (default: .)")


def _format_args(p: argparse.ArgumentParser) -> None:
    p.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    p.add_argument("--fail-on", choices=SEVERITIES, default="high",
                   help="exit 1 if a finding at or above this severity is present (default: high)")
    p.add_argument("--no-color", action="store_true")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="nation-guard", description="Guard AI agent instruction/config files.")
    parser.add_argument("--version", action="version", version="nation-guard " + __version__)
    sub = parser.add_subparsers(dest="command")

    p_scan = sub.add_parser("scan", help="scan a project for unsafe/injected instructions")
    _add_common(p_scan)
    _format_args(p_scan)

    p_base = sub.add_parser("baseline", help="record a trusted baseline for later `verify`")
    _add_common(p_base)
    p_base.add_argument("--update", action="store_true", help="overwrite an existing baseline")

    p_verify = sub.add_parser("verify", help="report drift from the recorded baseline")
    _add_common(p_verify)
    _format_args(p_verify)

    p_harden = sub.add_parser("harden", help="freeze instruction files (dry-run unless --apply)")
    _add_common(p_harden)
    g = p_harden.add_mutually_exclusive_group()
    g.add_argument("--apply", action="store_true", help="perform the changes")
    g.add_argument("--undo", action="store_true", help="revert changes this tool made")

    p_cap = sub.add_parser("capture", help="quarantine a file out of the project")
    _add_common(p_cap)
    p_cap.add_argument("path", help="file to quarantine")
    p_cap.add_argument("--keep", action="store_true", help="copy instead of move (leave the original)")

    p_res = sub.add_parser("restore", help="restore a quarantined file")
    p_res.add_argument("id", help="quarantine id")
    p_res.add_argument("--force", action="store_true", help="overwrite if the target exists")

    p_q = sub.add_parser("quarantine", help="quarantine operations")
    p_q.add_argument("action", choices=("list",))

    p_hooks = sub.add_parser("hooks", help="hook helpers")
    p_hooks.add_argument("action", choices=("print",))
    p_hooks.add_argument("--block", action="store_true", help="emit a config that denies (not asks) on write")

    p_rules = sub.add_parser("rules", help="rule catalogue")
    p_rules.add_argument("action", choices=("list",))
    p_rules.add_argument("--format", choices=("text", "json"), default="text")

    p_mcp = sub.add_parser("mcp", help="run the read-only MCP stdio server")
    _add_common(p_mcp)

    return parser


def _print_findings(findings: Sequence[Finding], fmt: str, root: str, files_scanned: int,
                    rules, no_color: bool) -> None:
    if fmt == "json":
        sys.stdout.write(report.render_json(findings, root=root, files_scanned=files_scanned) + "\n")
    elif fmt == "sarif":
        sys.stdout.write(report.render_sarif(findings, rules, root=root) + "\n")
    else:
        use_color = (not no_color) and sys.stdout.isatty()
        sys.stdout.write(report.render_text(findings, root=root, files_scanned=files_scanned, use_color=use_color))


def _fail(findings: Sequence[Finding], fail_on: str) -> int:
    threshold = severity_rank(fail_on)
    worst = max((severity_rank(f.severity) for f in findings), default=-1)
    return EXIT_FINDINGS if worst >= threshold else EXIT_OK


def cmd_scan(args) -> int:
    root = Path(args.root).resolve()
    rules = load_rules()
    result = scan_root(root, rules)
    _print_findings(result.findings, args.format, str(root), len(result.files_scanned), rules, args.no_color)
    return _fail(result.findings, args.fail_on)


def cmd_baseline(args) -> int:
    root = Path(args.root).resolve()
    try:
        path = integrity.save_baseline(root, update=args.update)
    except state.StateError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return EXIT_ERROR
    base = integrity.load_baseline(root) or {}
    sys.stdout.write("baseline written: %s\n" % path)
    sys.stdout.write("  %d config file(s) recorded\n" % len(base.get("files", {})))
    return EXIT_OK


def cmd_verify(args) -> int:
    root = Path(args.root).resolve()
    rules = load_rules()
    try:
        findings = integrity.verify(root, rules)
    except state.StateError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return EXIT_ERROR
    _print_findings(findings, args.format, str(root), 0, rules, args.no_color)
    return _fail(findings, args.fail_on)


def cmd_harden(args) -> int:
    root = Path(args.root).resolve()
    if args.undo:
        actions = harden_mod.undo(root)
        if not actions:
            sys.stdout.write("nothing to undo for %s\n" % root)
        for a in actions:
            sys.stdout.write("%s %s%s\n" % (a.kind, a.path, (" (%s)" % a.note) if a.note else ""))
        return EXIT_OK
    if args.apply:
        actions = harden_mod.apply(root)
        if not actions:
            sys.stdout.write("already hardened; nothing to do\n")
        for a in actions:
            sys.stdout.write("%s\n" % a.describe())
        return EXIT_OK
    actions = harden_mod.plan(root)
    if not actions:
        sys.stdout.write("nothing to harden (already frozen, or no instruction files)\n")
        return EXIT_OK
    sys.stdout.write("DRY RUN — would make %d change(s); re-run with --apply:\n" % len(actions))
    for a in actions:
        sys.stdout.write("  %s\n" % a.describe())
    return EXIT_OK


def cmd_capture(args) -> int:
    root = Path(args.root).resolve()
    try:
        item = quarantine.capture(Path(args.path), root, keep=args.keep)
    except state.StateError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return EXIT_ERROR
    verb = "copied" if args.keep else "moved"
    sys.stdout.write("quarantined (%s): %s\n  id: %s\n  stored: %s\n" % (verb, item.rel, item.id, item.dir))
    return EXIT_OK


def cmd_restore(args) -> int:
    try:
        target = quarantine.restore(args.id, force=args.force)
    except state.StateError as exc:
        sys.stderr.write("error: %s\n" % exc)
        return EXIT_ERROR
    sys.stdout.write("restored: %s\n" % target)
    return EXIT_OK


def cmd_quarantine(args) -> int:
    items = quarantine.list_items()
    if not items:
        sys.stdout.write("quarantine is empty\n")
        return EXIT_OK
    for it in items:
        sys.stdout.write("%s  %s  (captured %s)\n    from: %s\n" % (it.id, it.rel, it.captured, it.original_path))
    return EXIT_OK


def cmd_hooks(args) -> int:
    write_cmd = "nation-guard-hook write" + (" --block" if args.block else "")
    fragment = {
        "hooks": {
            "PreToolUse": [
                {"matcher": "Write|Edit|MultiEdit|NotebookEdit|Bash",
                 "hooks": [{"type": "command", "command": write_cmd}]},
                {"matcher": "Task|Agent|SendMessage|mcp__.*",
                 "hooks": [{"type": "command", "command": "nation-guard-hook outbound"}]},
            ],
            "PostToolUse": [
                {"matcher": ".*", "hooks": [{"type": "command", "command": "nation-guard-hook read"}]},
            ],
        }
    }
    sys.stdout.write("# Add to .claude/settings.json (project) or ~/.claude/settings.json (global).\n")
    sys.stdout.write("# nation-guard never edits your config; copy what you want.\n")
    sys.stdout.write(json.dumps(fragment, indent=2) + "\n")
    return EXIT_OK


def cmd_rules(args) -> int:
    rules = sorted(load_rules(), key=lambda r: r.id)
    if args.format == "json":
        payload = [{"id": r.id, "title": r.title, "severity": r.severity, "kind": r.kind,
                    "category": r.category, "message": r.message} for r in rules]
        sys.stdout.write(json.dumps(payload, indent=2, ensure_ascii=False) + "\n")
        return EXIT_OK
    for r in rules:
        sys.stdout.write("%-12s %-9s %-9s %s\n" % (r.id, r.severity, r.kind, r.title))
    return EXIT_OK


def cmd_mcp(args) -> int:
    from . import mcp_server

    root = Path(args.root).resolve()
    return mcp_server.serve(root)


_DISPATCH = {
    "scan": cmd_scan,
    "baseline": cmd_baseline,
    "verify": cmd_verify,
    "harden": cmd_harden,
    "capture": cmd_capture,
    "restore": cmd_restore,
    "quarantine": cmd_quarantine,
    "hooks": cmd_hooks,
    "rules": cmd_rules,
    "mcp": cmd_mcp,
}


def main(argv: Optional[Sequence[str]] = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if not args.command:
        parser.print_help()
        return EXIT_ERROR
    try:
        return _DISPATCH[args.command](args)
    except KeyboardInterrupt:
        return EXIT_ERROR
    except BrokenPipeError:
        return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
