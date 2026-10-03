<!-- SPDX-License-Identifier: Apache-2.0 -->
# Threat model

This document separates what nation-guard **confirms** (properties we can and do
enforce/verify) from what it **assumes** (conditions we rely on but do not
control). Being explicit about the boundary is the point.

## Assets

- **Agent instruction/config files** (`CLAUDE.md`, `AGENTS.md`, `GEMINI.md`,
  `.cursorrules`, `.mcp.json`, `.claude/**`, `.gemini/**`, `.vscode/tasks.json`,
  …). An AI agent treats these as trusted instructions.
- **The developer's secrets and machine** (SSH/cloud keys, `.env`, tokens),
  which a poisoned instruction may try to exfiltrate or misuse.
- **Other repositories/projects** the same agent can reach, which a worm tries
  to spread to.

## Adversary

An attacker who can influence the content of an agent config file — via a pull
request, a dependency/template, a copied snippet, a compromised teammate, or a
document the agent ingests and is tricked into persisting. The attacker does
**not** control the developer's machine or the guard's own state directory.

## What nation-guard confirms

- **Content detection on the files it reads.** For every file it scans, each
  rule is evaluated against the raw text *and* a set of de-obfuscation views
  (invisible-char stripped, Unicode-tag decoded, homoglyph-folded, HTML
  comment/entity, base64). This is deterministic and tested against a corpus.
- **De-obfuscation of the implemented channels.** Case-folding, zero-width
  insertion and homoglyph substitution are defeated for plaintext payloads
  (asserted by `tests/test_fuzz.py`). Tag characters and base64 are decoded into
  their own views.
- **Integrity drift.** Given a recorded baseline, `verify` deterministically
  reports changed/new/removed config files (SHA-256) and added/removed/changed
  MCP server definitions.
- **No outbound capability in the guard.** `tools/check_no_network.py` statically
  proves `guard/` imports no network/subprocess/dynamic-exec module, so scanning
  hostile input cannot trigger I/O.
- **Tamper-evident quarantine.** A restored file is verified against the SHA-256
  recorded at capture time and will not silently overwrite an existing file.
- **State isolation.** The guard refuses to place its state inside the scanned
  root, and writes state `0700`/`0600` with atomic replaces.

## What nation-guard assumes

- **The scan actually runs on trusted bytes.** If an attacker can make the agent
  skip the scan, or edit a file after `verify`, detection does not apply. Hooks
  narrow this window but do not close it.
- **The file set is complete.** Detection only covers the config globs in
  `targets.py`. A tool that reads instructions from a path we do not recognise
  is out of scope until a glob is added.
- **Heuristics approximate intent.** Rules match *forms* of known attacks, not
  intent. Novel phrasings evade (false negatives) and some benign text matches
  (false positives). See [`limits.md`](limits.md).
- **The host and the state directory are not already compromised.** nation-guard
  protects config files from a content-injection adversary; it is not a defense
  against a local root attacker who can rewrite `~/.nation-guard` or the guard
  itself.
- **The agent/runtime honours hook decisions.** The Claude Code hook can answer
  `ask`/`deny`, but enforcement is the runtime's; a runtime that ignores the
  decision is out of scope.

## Explicit non-goals

- Not a sandbox and not a runtime policy engine: it does not stop code from
  executing.
- Not a secret scanner for source code in general (it looks for secret *stores*
  near *send* commands in agent config, not for committed credentials).
- Not a malware/behavioural analyzer: it never runs the content.
