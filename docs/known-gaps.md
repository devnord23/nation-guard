<!-- SPDX-License-Identifier: Apache-2.0 -->
# Known gaps

A frank ledger of what is incomplete or imperfect as of v0.1.0. Detection is
heuristic by design; see also [`limits.md`](limits.md) and
[`threat-model.md`](threat-model.md).

## Detection gaps (false negatives)

- **Novel rephrasing** of an attack that no rule pattern anticipates is not
  caught by content rules. `verify` (baseline drift) is the backstop.
- **Whitespace padding** can push the two halves of an `all`/`within` rule
  (e.g. `NG-EXF-001`) outside the proximity window. The mutation-fuzz table
  quantifies this each run; `whitespace` padding currently evades several rules.
- **Base64 of punctuation-heavy payloads** (e.g. a base64-encoded JSON settings
  file) is not decoded, because the base64 view only unwraps blobs that look
  like text. Only one level of base64 nesting is unwrapped.
- **Payload split across multiple files** is not correlated; each file is
  scanned independently.
- **Unknown config locations.** Only the globs in `targets.py` are scanned. A
  new agent tool with a new instruction path needs a glob added.
- **Homoglyph coverage** is the common Cyrillic/Greek Latin-lookalikes, not the
  full Unicode confusables set.

## False-positive classes (documented, shipped as benign fixtures)

- `NG-EXF-001` can fire on a setup doc that mentions `.env` within 240 chars of
  a genuine `curl -X POST` (`ben_env_post_setup.fixture`). Command substitution
  near a secret only counts when it sits in a curl/wget/fetch call or next to a
  URL, so ordinary `$(…)` no longer trips it.
- `NG-OVR-001` fires on security docs that *quote* an injection phrase as an
  example (`ben_security_doc.fixture`).

Tune with `--fail-on`; the default gate is `high`.

## Scope / architecture

- **Not a sandbox.** nation-guard detects; it does not prevent execution. Hook
  decisions (`ask`/`deny`) are only as strong as the runtime that honours them.
- **Hook Bash-write detection is heuristic** — it flags commands that both name
  a config path and contain a write construct; exotic write forms can slip past.
- **`blast_radius` is coarse**: it reports the set of reachable config files and
  declared MCP servers, not a precise propagation graph.
- **Windows file-freezing** uses the read-only attribute (all `os.chmod` can do
  on Windows); it is advisory against a cooperative process, not a hard lock.
- **No provenance/signatures yet.** Baselines record hashes, not authenticity;
  the `verifier` component in [`roadmap.md`](roadmap.md) is not started.
- **`payguard`** (financial/agentic-payment safety) is roadmap-only.

## Verification / build evidence

Checks actually executed (recorded here as evidence rather than intention):

- **Tests:** the full `unittest` suite and `tools/check_no_network.py` pass on
  the development machine (Windows 11, CPython 3.12.10). See the project reports
  for the exact count.
- **Real wheel + sdist build:** `python -m build` produced
  `nation_guard-0.1.0-py3-none-any.whl` and `.tar.gz` on Windows/3.12. The wheel
  was confirmed to bundle `nation_guard/rules/core.yaml` (and no
  `rules/__init__.py`, so the engine module `nation_guard.rules` is not shadowed
  by the data dir).
- **Clean-environment install:** the wheel was installed into a fresh
  virtualenv (wheel only, no source checkout on the path) and, run from an
  unrelated working directory, loaded its **18** bundled rules from the
  installed package and resolved the `nation-guard`, `nation-guard-hook` and
  `nation-guard-mcp` entry points.
- **Still pending (not yet executed anywhere):** the cross-platform matrix —
  Linux, macOS, and **Python 3.9** specifically. The dev machine is Windows with
  only CPython 3.12, so those combinations are unverified. GitHub Actions runs
  for the private repo currently end in `startup_failure` with **0 jobs**; the
  workflow YAML parses and is registered *active*, so the cause is not the
  workflow file. The root cause is **not yet confirmed** (candidates include
  hosted-runner availability/policy for private repos on the account) and is
  **not** asserted to be billing without evidence.
- **SARIF:** output conforms to 2.1.0 structurally (tool driver, rules,
  results, levels) and is emitted with `ensure_ascii` so hostile bytes cannot
  break serialization; it has not been validated against the full JSON Schema
  or uploaded to a live code-scanning dashboard.

## Resolved during review (for the record)

A first adversarial review raised five issues, all fixed with regression tests:
the `$(…)` over-broad exfil match, curly-apostrophe evasion,
HTML-entity-before-strip ordering, an MCP crash on non-object params, and an
`importlib` gap in the offline check. A self-found `O(n²)` proximity matcher was
replaced with binary search, and `NG-WORM-001` was tightened to require
verb + object + destination.

A second review hardened: symlink containment across traversal / harden /
quarantine / restore (reject links for mutation, no-follow exclusive writes,
real-path containment); quarantine payload/metadata separation with
verify-before-delete; full-file integrity hashing (independent of the 2 MiB
content-scan cap, which is now reported); bounded/forward-only matching for
repeated-token and unclosed-comment inputs; MCP subpath/alias handling and
surrogate-safe serialization; harden journaling + identity-bound undo; explicit
hook schema validation with protective decisions on malformed recognised
events; a genuine raw detection view with source-accurate line numbers; sdist
inclusion of tests/corpus/tools; a Python-3.9-safe generator; and removal of the
CI self-scan's unconditional success.
