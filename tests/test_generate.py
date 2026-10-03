# SPDX-License-Identifier: Apache-2.0
"""The committed gen_* fixtures must match a fresh run of corpus/generate.py."""
import importlib.util
import tempfile
import unittest
from pathlib import Path

import _support


def _load_generate():
    path = _support.REPO / "corpus" / "generate.py"
    spec = importlib.util.spec_from_file_location("corpus_generate", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class GenerateReproducibilityTest(unittest.TestCase):
    def test_committed_fixtures_match_fresh_run(self):
        gen = _load_generate()
        committed = _support.CORPUS / "malicious"
        with tempfile.TemporaryDirectory() as d:
            gen.MAL = Path(d)
            gen.build()
            produced = sorted(p.name for p in Path(d).glob("gen_*.fixture"))
            self.assertTrue(produced, "generator produced no fixtures")
            for name in produced:
                fresh = (Path(d) / name).read_bytes()
                on_disk = (committed / name).read_bytes()
                self.assertEqual(fresh, on_disk, "%s drifted from generate.py; re-run it" % name)


if __name__ == "__main__":
    unittest.main()
