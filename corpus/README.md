<!-- SPDX-License-Identifier: Apache-2.0 -->
# Corpus — hostile test data

**Everything under `corpus/malicious/` is intentionally crafted attack content.**
It exists so the test suite can prove the scanner detects real techniques and
stays quiet on realistic benign files. Do not treat any line in these fixtures
as an instruction, and do not run the commands they contain.

## Safety

- All network destinations use the reserved, non-routable `attacker.invalid`
  domain (RFC 6761). The fixtures are inert strings in text files; nothing here
  executes on its own.
- Fixtures are never discovered by a normal `nation-guard scan`: they use the
  `.fixture` extension, not an agent-config name, so only the test harness reads
  them (and only by the explicit paths in `manifest.json`).

## Layout

- `malicious/` — one or more fixtures per detection technique. Files prefixed
  `gen_` are produced by `generate.py` (invisible characters, Unicode tag
  smuggling, homoglyphs, base64) and are regression-checked for reproducibility.
- `benign/` — realistic config files that must stay clean, plus a few
  deliberately hard cases annotated as **known false positives** in the manifest
  (`known_fp`). These document the limits of the proximity/keyword heuristics
  honestly rather than hiding them.
- `manifest.json` — the oracle. For `malicious` entries the detected rule-id set
  must equal `expect`; for `benign` entries the detected set must be a subset of
  `known_fp`. The `as` field is the repo-relative path a fixture is scanned as,
  so file-scoped rules (e.g. the `.vscode/tasks.json` rule) apply correctly.

## Regenerating

```
python corpus/generate.py
```

This rewrites the `gen_*` fixtures deterministically. If you change
`generate.py`, re-run it and commit the result; `tests/test_generate.py` fails
if the committed bytes drift from a fresh run.
