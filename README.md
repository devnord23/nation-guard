<!-- SPDX-License-Identifier: Apache-2.0 -->
# nation-guard

**A local-first, offline guard for AI agent instruction/config files.**

AI coding agents read files like `CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
`.cursorrules`, `.mcp.json` and `.vscode/tasks.json` as *trusted instructions*.
That makes those files a perfect place to hide a prompt-injection payload: one
poisoned `AGENTS.md` can tell every agent that opens the repo to exfiltrate
secrets, disable its own guardrails, or copy the payload into the next project.

nation-guard scans those files for such payloads, records a baseline so you can
detect tampering, and can freeze the files so a worm cannot rewrite them. It is
**stdlib-only Python** with **no runtime dependencies** and makes **no network
or subprocess calls** — you can read the whole thing in one sitting, and a CI
check (`tools/check_no_network.py`) proves it stays that way.

> ⚠️ Pre-1.0. Detection is heuristic: it catches known techniques and common
> obfuscations, not everything. See [`docs/limits.md`](docs/limits.md).

## 60-second quickstart

```bash
# Python 3.9+; no dependencies to install.
pip install nation-guard        # or: pip install .

# 1. Scan the current project for unsafe/injected instructions.
nation-guard scan

# 2. Record a trusted baseline, then later detect drift / tampering.
nation-guard baseline
nation-guard verify

# 3. Freeze instruction files so a worm can't rewrite them (dry-run first).
nation-guard harden            # shows what it would do
nation-guard harden --apply    # drop write bits + pre-create read-only stubs
nation-guard harden --undo     # revert exactly what it changed

# Machine-readable output for CI (exit 1 on a finding at/above --fail-on):
nation-guard scan --format sarif --fail-on high > nation-guard.sarif
```

Pull a malicious file out of the tree (reversibly) and put it back later:

```bash
nation-guard capture ./AGENTS.md     # moves it to ~/.nation-guard/quarantine
nation-guard quarantine list
nation-guard restore <id>
```

## What it detects

| ID            | Severity | What |
|---------------|----------|------|
| NG-WORM-001   | critical | Instruction that copies itself into other agent files/repos |
| NG-OVR-001/002| high/med | Instruction-override attempts; forged `<system>`/`[admin]` markers |
| NG-EXF-001/002| crit/med | A secret store / named secret near a data-sending command |
| NG-CON-001    | high     | Telling the agent to hide its activity from the user |
| NG-AUTO-001/2/3| high/med| `curl \| bash`; `SessionStart` hooks; `tasks.json` `folderOpen` |
| NG-PERM-001/2 | high/med | `Bash(*)`, `bypassPermissions`, yolo mode; auto-enabled MCP servers |
| NG-HID-001/2/3| med/high | Invisible chars, Unicode tag smuggling, rule hits in hidden content |
| NG-INT-001..3, NG-MCP-001 | mixed | Baseline drift (changed/new/removed files, MCP entry changes) |

Payloads are matched through common obfuscations — invisible characters,
Unicode tag smuggling, homoglyphs, HTML comments/entities and base64 — so a
disguised instruction is caught the same as a plain one. Run
`nation-guard rules list` for the full catalogue.

## Use it as a Claude Code hook

nation-guard ships a hook that vets edits to config files, warns on injected
tool output, and blocks worm propagation through sub-agents/outgoing messages:

```bash
nation-guard hooks print          # prints a settings.json fragment to copy
nation-guard hooks print --block  # deny (instead of ask) on config writes
```

It **prints** the fragment; it never edits your config for you.

## Use it as an MCP server

A read-only MCP stdio server exposes `scan`, `check_integrity` and
`blast_radius` to an agent, limited to a `--root`:

```bash
nation-guard-mcp --root .
```

## How it works

- [`guard/nation_guard/targets.py`](guard/nation_guard/targets.py) — which files count as agent config.
- [`guard/nation_guard/normalize.py`](guard/nation_guard/normalize.py) — de-obfuscation "views" + raw-byte signals.
- [`rules/core.yaml`](rules/core.yaml) — the detections, as reviewable data.
- [`guard/nation_guard/integrity.py`](guard/nation_guard/integrity.py) — baselines and drift.
- State lives in `~/.nation-guard` (override with `NATION_GUARD_HOME`), never inside a scanned project.

See [`docs/threat-model.md`](docs/threat-model.md), [`docs/privacy.md`](docs/privacy.md) and [`docs/roadmap.md`](docs/roadmap.md).

## License

Apache-2.0. See [`LICENSE`](LICENSE) and [`NOTICE`](NOTICE).
