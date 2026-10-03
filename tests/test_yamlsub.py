# SPDX-License-Identifier: Apache-2.0
import unittest

import _support  # noqa: F401  (path bootstrap)
from nation_guard import yamlsub


class YamlSubsetTest(unittest.TestCase):
    def test_mapping_and_scalars(self):
        doc = yamlsub.loads("a: 1\nb: true\nc: null\nd: hello world\n")
        self.assertEqual(doc, {"a": 1, "b": True, "c": None, "d": "hello world"})

    def test_quoted_scalars(self):
        doc = yamlsub.loads("a: 'it''s fine'\nb: \"line\\nbreak\"\n")
        self.assertEqual(doc["a"], "it's fine")
        self.assertEqual(doc["b"], "line\nbreak")

    def test_block_sequence(self):
        doc = yamlsub.loads("items:\n  - one\n  - two\n  - 3\n")
        self.assertEqual(doc, {"items": ["one", "two", 3]})

    def test_inline_list(self):
        doc = yamlsub.loads("files: [a, 'b c', d]\n")
        self.assertEqual(doc, {"files": ["a", "b c", "d"]})

    def test_list_of_maps_inline_key(self):
        doc = yamlsub.loads("rules:\n  - id: X\n    n: 2\n  - id: Y\n    n: 3\n")
        self.assertEqual(doc, {"rules": [{"id": "X", "n": 2}, {"id": "Y", "n": 3}]})

    def test_comments_and_blank_lines(self):
        doc = yamlsub.loads("# a comment\na: 1  # trailing\n\nb: 2\n")
        self.assertEqual(doc, {"a": 1, "b": 2})

    def test_hash_inside_quotes_is_not_a_comment(self):
        doc = yamlsub.loads("a: 'x # y'\n")
        self.assertEqual(doc["a"], "x # y")

    def test_reject_tabs(self):
        with self.assertRaises(yamlsub.YamlSubsetError):
            yamlsub.loads("a:\n\t- x\n")

    def test_reject_block_scalar(self):
        for marker in (">", "|", ">-"):
            with self.assertRaises(yamlsub.YamlSubsetError):
                yamlsub.loads("a: %s\n  text\n" % marker)

    def test_reject_flow_mapping_and_anchors(self):
        for bad in ("a: {x: 1}\n", "a: &anchor 1\n", "a: *ref\n", "a: !tag v\n"):
            with self.assertRaises(yamlsub.YamlSubsetError):
                yamlsub.loads(bad)

    def test_reject_duplicate_keys(self):
        with self.assertRaises(yamlsub.YamlSubsetError):
            yamlsub.loads("a: 1\na: 2\n")

    def test_reject_unterminated_quote(self):
        with self.assertRaises(yamlsub.YamlSubsetError):
            yamlsub.loads("a: 'oops\n")

    def test_core_rules_file_parses(self):
        doc = yamlsub.loads((_support.RULES_DIR / "core.yaml").read_text(encoding="utf-8"))
        self.assertIsInstance(doc, dict)
        self.assertIsInstance(doc.get("rules"), list)
        self.assertTrue(all(isinstance(r, dict) and "id" in r for r in doc["rules"]))


if __name__ == "__main__":
    unittest.main()
