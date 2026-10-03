# SPDX-License-Identifier: Apache-2.0
"""Mutation fuzz: apply evasion transforms to every malicious fixture and report
how many still trip their primary rule. Prints an honest per-mutation table.

The normaliser is *designed* to defeat case-folding, zero-width insertion and
homoglyph substitution, so those must retain full detection (asserted). The
remaining transforms (base64 wrapping, comment wrapping, whitespace padding,
markdown emphasis) are reported without assertion: some legitimately evade
specific rules (e.g. whitespace padding can push an `all`/`within` pair out of
range), and hiding that would be dishonest.
"""
import base64
import json
import re
import unittest

import _support
from nation_guard.scanner import scan_content

ZW = "​"
HOMO = {"a": "а", "e": "е", "o": "о", "p": "р", "c": "с",
        "y": "у", "x": "х", "i": "і", "s": "ѕ"}


def m_identity(t):
    return t


def m_case(t):
    return t.swapcase()


def m_zero_width(t):
    return re.sub(r"([A-Za-z0-9])", lambda m: m.group(1) + ZW, t)


def m_homoglyph(t):
    return "".join(HOMO.get(ch, ch) for ch in t)


def m_base64(t):
    return "payload:\n" + base64.b64encode(t.encode("utf-8")).decode("ascii") + "\n"


def m_comment(t):
    return "<!--\n" + t + "\n-->"


def m_whitespace(t):
    return re.sub(r" ", "   \n  ", t)


def m_markdown(t):
    return re.sub(r"([A-Za-z])", r"\1*", t)


MUTATIONS = [
    ("identity", m_identity),
    ("case", m_case),
    ("zero_width", m_zero_width),
    ("homoglyph", m_homoglyph),
    ("base64", m_base64),
    ("comment", m_comment),
    ("whitespace", m_whitespace),
    ("markdown", m_markdown),
]

# Transforms the normaliser is built to see through when applied to a
# plaintext payload. Some fixtures carry their payload inside an encoding
# (base64, an HTML entity, Unicode tag chars) that a byte-level mutation can
# itself corrupt — e.g. swapcase on a base64 blob, or homoglyph-substituting
# the "x" of "&#x200b;" so it no longer decodes. Re-obfuscating a carrier is
# out of scope for the "plaintext payload is defeated" guarantee, so the
# assertion skips carrier fixtures. Every fixture is still reported in the
# printed table.
ASSERTED_FULL = {"identity", "case", "zero_width", "homoglyph"}
CARRIER_PREFIXES = ("gen_",)
CARRIER_FIXTURES = {"mal_entity_invisible.fixture"}


def _is_carrier(name):
    return name.startswith(CARRIER_PREFIXES) or name in CARRIER_FIXTURES


class MutationFuzzTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        manifest = json.loads((_support.CORPUS / "manifest.json").read_text(encoding="utf-8"))
        cls.cases = []
        for e in manifest["malicious"]:
            text = (_support.CORPUS / e["file"]).read_text(encoding="utf-8")
            primary = e["expect"][0]
            cls.cases.append((e["file"], e["as"], text, primary))

    def test_evasion_table(self):
        rules = _support.rules()
        total = len(self.cases)
        table = {}
        for name, fn in MUTATIONS:
            detected = 0
            evaded = []
            for fpath, as_rel, text, primary in self.cases:
                ids = {f.rule_id for f in scan_content(fn(text), as_rel, rules)}
                if primary in ids:
                    detected += 1
                else:
                    evaded.append(fpath.split("/")[-1])
            table[name] = (detected, total, evaded)

        print("\n  mutation-fuzz evasion table (detected / %d fixtures)" % total)
        print("  " + "-" * 52)
        for name, _ in MUTATIONS:
            det, tot, evaded = table[name]
            rate = 100.0 * det / tot
            note = "" if not evaded else "  evaded: " + ", ".join(sorted(evaded))
            print("  %-12s %3d/%-3d  %5.1f%%%s" % (name, det, tot, rate, note))
        print("  " + "-" * 52)

        for name in ASSERTED_FULL:
            _, _, evaded = table[name]
            core_evaded = [e for e in evaded if not _is_carrier(e)]
            self.assertEqual(core_evaded, [],
                             "mutation %r must be defeated on plaintext fixtures; evaded: %s" % (name, core_evaded))


if __name__ == "__main__":
    unittest.main()
