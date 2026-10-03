# SPDX-License-Identifier: Apache-2.0
import importlib.util
import unittest

import _support


def _load():
    path = _support.REPO / "tools" / "check_no_network.py"
    spec = importlib.util.spec_from_file_location("check_no_network", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class NoNetworkTest(unittest.TestCase):
    def test_guard_has_no_forbidden_capability(self):
        mod = _load()
        self.assertEqual(mod.check(), 0, "guard/ must not import network/subprocess/exec modules")

    def test_detects_a_planted_violation(self):
        import ast
        mod = _load()
        tree = ast.parse("import socket\nx = eval('1')\n")
        found = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                for a in node.names:
                    if a.name in mod.BANNED:
                        found.add("import")
            if isinstance(node, ast.Call) and isinstance(node.func, ast.Name) and node.func.id in mod.BANNED_CALLS:
                found.add("call")
        self.assertEqual(found, {"import", "call"})

    def test_importlib_is_banned(self):
        # Review finding #5: importlib would route around the import denylist.
        self.assertIn("importlib", _load().BANNED)

    def test_detects_dynamic_import_via_importlib(self, ):
        import tempfile
        from pathlib import Path
        mod = _load()
        with tempfile.TemporaryDirectory() as d:
            p = Path(d) / "evil.py"
            p.write_text(
                "import importlib\n"
                "s = importlib.import_module('socket')\n",
                encoding="utf-8",
            )
            problems = mod._check_file(p)
        self.assertTrue(problems, "importlib + import_module() must be flagged")
        joined = " ".join(w for _, w in problems)
        self.assertIn("importlib", joined)
        self.assertIn("import_module", joined)


if __name__ == "__main__":
    unittest.main()
