<!-- SPDX-License-Identifier: Apache-2.0 -->
# Roadmap

nation-guard (this repo) is the **guard**: detect, baseline, freeze and
quarantine unsafe agent instruction/config files, offline. Everything below is
planned/aspirational and intentionally kept as separate concerns so the core
stays small and auditable.

## Near-term (guard core)

- Broaden the target set as new agent tools appear (new instruction paths,
  settings schemas). Each addition ships with corpus fixtures.
- More de-obfuscation views (additional confusable ranges; quoted-printable).
- Richer rule proximity (ordered `all`, per-pattern windows) to cut the
  false-positive classes in [`limits.md`](limits.md).
- A `diff`-aware mode: scan only files changed in a PR, for faster CI.

## payguard (separate, planned)

A sibling tool focused on **financial/agentic-payment safety**: detecting
instructions that would move money, approve transfers, or wire funds from an
agent config, and asserting a human-in-the-loop boundary. Kept separate because
it has a different threat model (transactions, not instruction propagation) and
must never execute or simulate a payment. Status: **not started**; design notes
only.

## verifier (separate, planned)

A **provenance/signature** layer: sign a reviewed baseline so `verify` can
attest "these config files match a human-approved revision", and optionally
verify signatures on third-party rule packs. This complements the current
hash-only baseline with authenticity, not just change detection. It will remain
offline (local signing/verification, no key-server calls by default). Status:
**not started**; the current baseline format reserves room for a signature
block.

## Explicit non-goals (still)

- Not a sandbox or runtime policy engine.
- No telemetry, no network, no runtime dependencies — these constraints are
  permanent, not phases.
