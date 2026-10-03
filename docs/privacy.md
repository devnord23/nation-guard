<!-- SPDX-License-Identifier: Apache-2.0 -->
# Privacy

nation-guard is designed to be boring about your data: it stays on your machine.

## No network, ever

The scanning/rules/hook/MCP code performs **no** network I/O. There is no
telemetry, no update check, no "phone home", and no third-party runtime
dependency that could add one. As a guardrail against such code slipping in,
`tools/check_no_network.py` statically scans `guard/` for **known** constructs —
imports of `socket`, `ssl`, `urllib`, `http`, `requests`, `subprocess`,
`asyncio`, `ctypes`, `importlib`, etc., and `eval`/`exec`/`import_module` calls —
and runs in CI on every push. It is a construct check over the known surface,
not a proof that no network behavior is possible (e.g. it does not model
`getattr`-built names or C extensions); treat it as defense-in-depth alongside
reading the code, which is deliberately small.

## What is read

- The **content** of agent config files under the scanned root (to match rules).
- File **metadata** (size, SHA-256) for baselines.

## What is written, and where

- **Nothing** inside your project during a scan/verify (read-only).
- Under the state home only: `~/.nation-guard` by default, or
  `$NATION_GUARD_HOME`. It holds:
  - `baselines/<hash>.json` — relative paths, sizes and SHA-256 hashes of config
    files, plus per-MCP-server hashes. Baselines store hashes, **not** file
    contents.
  - `quarantine/<id>/` — when you explicitly run `capture`, a **copy of the file
    you chose** plus a metadata record (original path, SHA-256, mode). This is
    the one case where file contents are stored, and only on your command.
  - `harden-log.json` — the list of changes `harden --apply` made, so `--undo`
    can reverse them.
- Directories are created `0700` and files `0600`/`0400`; writes are atomic.

## What leaves your machine

Only what *you* export: the report you redirect to a file (`--format
sarif/json`) or pipe elsewhere, and whatever your CI does with it. Reports
contain findings — rule ids, file paths, line numbers and a short, sanitized
evidence snippet (invisible characters are escaped). Review a report before
publishing it the same way you would any scanner output, since paths and
snippets can be sensitive.

## No account, no identifiers

There is no account, license key, or machine identifier. Nothing in the tool
generates or transmits a user id.
