<!-- SPDX-License-Identifier: Apache-2.0 -->
# Contributing to nation-guard

Thanks for helping! A few ground rules keep this project auditable.

## Non-negotiables

1. **Stdlib only, no runtime dependencies.** The value of this tool is that you
   can read all of it and trust it offline. `tools/check_no_network.py` fails CI
   if anything under `guard/` imports a network/subprocess/dynamic-exec module
   (`socket`, `urllib`, `subprocess`, `ctypes`, `eval`, …). Do not add
   third-party runtime deps.
2. **No side effects from scanning.** Scanning hostile input must never execute
   it, reach the network, or spawn a process.
3. **SPDX headers everywhere.** Every source file starts with
   `SPDX-License-Identifier: Apache-2.0`.
4. **State stays out of the project.** Baselines/quarantine live under
   `~/.nation-guard`; never write them inside a scanned tree.

## Development

```bash
python -m unittest discover -s tests -v     # run the suite
python tools/check_no_network.py            # offline-capability check
python corpus/generate.py                   # regenerate obfuscated fixtures
```

Requires Python 3.9+. There is nothing to install for development.

## Adding or changing a detection

Rules are **data** in [`rules/core.yaml`](rules/core.yaml), not code. To add one:

1. Add the rule with a `NG-XXX-000` id, a `severity`, a clear `message`, and
   `any`/`all` patterns (use `within` for proximity on `all`). Patterns are
   matched case-insensitively against every normalised view.
2. Add at least one **malicious** fixture that it should catch and, ideally, a
   **benign** fixture that it must not trip, under `corpus/`.
3. Record the expected detections in `corpus/manifest.json`
   (`malicious` = exact id set; `benign` = allowed `known_fp` subset).
4. Run the suite. `tests/test_corpus.py` enforces the manifest and
   `tests/test_fuzz.py` reports evasion.

Favour **precision**: a noisy critical finding erodes trust faster than a missed
medium. If a rule has a known false-positive class, document it with a benign
`known_fp` fixture and a line in [`docs/limits.md`](docs/limits.md) rather than
hiding it.

## Commits & DCO

Keep commits focused and messages descriptive. By contributing you agree your
contribution is licensed under Apache-2.0.
