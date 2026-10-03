<!-- SPDX-License-Identifier: Apache-2.0 -->
# Limits & known false positives

Detection is heuristic. This page is deliberately honest about where it breaks,
so you calibrate trust correctly. The mutation-fuzz test prints a live evasion
table; run `python -m unittest tests.test_fuzz -v` to see it.

## False negatives (evasions we know about)

- **Novel rephrasing.** Rules match known *forms*. An attacker who rewrites an
  instruction in prose the patterns do not anticipate will not be caught by the
  content rules. Integrity (`verify`) is the backstop: the *change* is still
  visible even when its wording is not.
- **Proximity / `within` limits.** `all`-rules such as `NG-EXF-001` require the
  two halves (secret store + data-sending command) within a character window
  (240 for EXF-001). Padding the gap with filler can push them apart. The fuzz
  table shows `whitespace` padding evading several rules for exactly this reason.
- **Base64 gating.** The base64 view only decodes blobs that look like text
  (printable ratio ≥ 0.95, enough letters). A payload encoded so its decoding
  is punctuation-heavy (e.g. base64 of a JSON settings file) may not be decoded;
  the fuzz table shows `base64` wrapping evading the JSON fixtures. Only one
  level of base64 nesting is unwrapped.
- **Homoglyph coverage.** The confusables table covers common Cyrillic/Greek
  Latin lookalikes, not the entire Unicode confusables set. Exotic lookalikes
  fold less reliably.
- **Split across files.** A payload spread across several files so no single
  file trips a rule is not correlated across files.
- **Unknown config locations.** Only files matching `targets.py` globs are
  scanned. New agent tools with new instruction paths need a glob added.

## False positives (known classes)

These are shipped as annotated benign fixtures (`known_fp` in
`corpus/manifest.json`) rather than hidden:

- **`NG-EXF-001` on setup docs.** A doc that mentions `.env` near an unrelated
  `curl -X POST` (e.g. "copy `.env`, then register with `curl -X POST …`")
  trips the proximity heuristic even though nothing is exfiltrated. See
  `corpus/benign/ben_env_post_setup.fixture`.
- **`NG-OVR-001` on security documentation.** A doc that *quotes* an injection
  phrase as an example ("attacks often say 'ignore all previous instructions'")
  matches the override rule. See `corpus/benign/ben_security_doc.fixture`.

When a rule fires on legitimately benign content, prefer tightening the rule and
adding a benign fixture over suppressing globally. Use `--fail-on` to tune CI
strictness; the default gates on `high` and above.

## Operational limits

- Files larger than 2 MiB are truncated before scanning (`targets.MAX_FILE_BYTES`).
- At most 20,000 files / depth 16 are walked; symlinked directories are not
  followed.
- The hook's Bash-write detection is heuristic: it flags commands that both
  reference a config path and contain a write construct; obscure ways to write a
  file may slip past.
