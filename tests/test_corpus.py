# SPDX-License-Identifier: Apache-2.0
import json
import unittest

import _support
from nation_guard.scanner import scan_content


def _ids(path_rel, as_rel):
    text = (_support.CORPUS / path_rel).read_text(encoding="utf-8")
    return {f.rule_id for f in scan_content(text, as_rel, _support.rules())}


class CorpusRegressionTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.manifest = json.loads((_support.CORPUS / "manifest.json").read_text(encoding="utf-8"))

    def test_malicious_exact_match(self):
        for entry in self.manifest["malicious"]:
            got = _ids(entry["file"], entry["as"])
            self.assertEqual(
                got, set(entry["expect"]),
                msg="%s: got %s expected %s" % (entry["file"], sorted(got), sorted(entry["expect"])),
            )

    def test_benign_within_known_fp(self):
        for entry in self.manifest["benign"]:
            got = _ids(entry["file"], entry["as"])
            allowed = set(entry.get("known_fp", []))
            self.assertTrue(
                got <= allowed,
                msg="%s: unexpected findings %s (allowed %s)" % (entry["file"], sorted(got - allowed), sorted(allowed)),
            )

    def test_every_fixture_is_in_manifest(self):
        listed = {e["file"] for e in self.manifest["malicious"] + self.manifest["benign"]}
        on_disk = set()
        for group in ("malicious", "benign"):
            for p in (_support.CORPUS / group).glob("*.fixture"):
                on_disk.add("%s/%s" % (group, p.name))
        self.assertEqual(on_disk, listed, "corpus files and manifest are out of sync")


if __name__ == "__main__":
    unittest.main()
