<!-- SPDX-License-Identifier: Apache-2.0 -->
# Security policy

## Reporting a vulnerability

Please report security issues privately via GitHub Security Advisories
("Report a vulnerability" on the repository's **Security** tab) rather than in a
public issue. If that is unavailable to you, open a minimal issue asking for a
private contact and we will follow up.

Useful things to include:

- what the issue is (false negative/evasion, false positive, or a flaw in the
  tool itself such as a path-traversal or a crash on hostile input);
- a minimal, **inert** reproducer (use the reserved `attacker.invalid` domain,
  as the test corpus does — never a live exploit);
- the nation-guard version (`nation-guard --version`) and your OS/Python.

We aim to acknowledge reports within a few days.

## Scope and threat model

nation-guard is a **detection aid**, not a sandbox. It reduces the risk that a
poisoned agent config file goes unnoticed; it does not prevent code execution
and can be evaded. Read [`docs/threat-model.md`](docs/threat-model.md) and
[`docs/limits.md`](docs/limits.md) for what is and is not covered.

### Evasion / false-negative reports

Because detection is heuristic, novel evasions are expected and welcome as
reports. The mutation-fuzz test (`tests/test_fuzz.py`) prints an honest evasion
table; a report that extends it is ideal.

### The tool itself

nation-guard reads hostile files, so bugs in *the guard* are in scope:
path traversal when resolving a scan/restore target, a crash or unbounded
resource use on malformed input, a quarantine/restore that writes outside its
intended location, or any network/subprocess/dynamic-exec capability slipping
into `guard/` (which `tools/check_no_network.py` is meant to prevent).

## Handling of untrusted content

Treat everything under `corpus/` as hostile sample data, not instructions. The
tool never executes scanned content and performs no outbound I/O.
