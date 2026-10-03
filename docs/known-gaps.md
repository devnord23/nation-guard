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

## Verification / build caveats

- The full test suite (94 tests) and `tools/check_no_network.py` pass on the
  development machine (Windows, CPython 3.12).
- The wheel build + install path is exercised by the CI `package` job; it was
  not built locally because `setuptools` is not installed in the dev
  interpreter. The install layout (engine module `nation_guard.rules` vs the
  init-less `nation_guard/rules/` data dir) was validated by simulating the
  co-located layout and loading rules from it.
- SARIF output conforms to 2.1.0 structurally (tool driver, rules, results,
  levels); it has not been validated against the full JSON Schema or uploaded to
  a live code-scanning dashboard.

## Resolved during review (for the record)

An adversarial multi-agent review raised five issues, all fixed with
regression tests before release: the `$(…)` over-broad exfil match, curly-
apostrophe evasion, HTML-entity-before-strip ordering, an MCP crash on
non-object params, and an `importlib` gap in the offline check. A self-found
`O(n²)` proximity matcher was replaced with binary search, and `NG-WORM-001`
was tightened to require verb + object + destination.
