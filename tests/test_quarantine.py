# SPDX-License-Identifier: Apache-2.0
import unittest
from pathlib import Path

import _support
from nation_guard import quarantine, state


class QuarantineTest(unittest.TestCase):
    def test_capture_moves_and_restore_roundtrip(self):
        with _support.temp_home(), _support.temp_project() as d:
            target = d / "AGENTS.md"
            target.write_text("malicious content\n", encoding="utf-8")
            item = quarantine.capture(target, d)
            self.assertFalse(target.exists(), "original moved away")
            self.assertTrue(item.payload.is_file())

            listed = quarantine.list_items()
            self.assertEqual([i.id for i in listed], [item.id])

            restored = quarantine.restore(item.id)
            self.assertTrue(restored.exists())
            self.assertEqual(restored.read_text(encoding="utf-8"), "malicious content\n")

    def test_keep_copies_leaving_original(self):
        with _support.temp_home(), _support.temp_project() as d:
            target = d / "CLAUDE.md"
            target.write_text("x\n", encoding="utf-8")
            item = quarantine.capture(target, d, keep=True)
            self.assertTrue(target.exists(), "original kept with --keep")
            self.assertTrue(item.payload.is_file())

    def test_restore_refuses_overwrite_without_force(self):
        with _support.temp_home(), _support.temp_project() as d:
            target = d / "AGENTS.md"
            target.write_text("content\n", encoding="utf-8")
            item = quarantine.capture(target, d, keep=True)
            with self.assertRaises(state.StateError):
                quarantine.restore(item.id)  # target still exists
            quarantine.restore(item.id, force=True)  # ok

    def test_restore_detects_tamper(self):
        with _support.temp_home(), _support.temp_project() as d:
            target = d / "AGENTS.md"
            target.write_text("content\n", encoding="utf-8")
            item = quarantine.capture(target, d)
            # tamper with the stored payload
            import os
            os.chmod(item.payload, 0o600)
            item.payload.write_text("tampered\n", encoding="utf-8")
            with self.assertRaises(state.StateError):
                quarantine.restore(item.id)

    def test_capture_records_hash_and_mode(self):
        with _support.temp_home(), _support.temp_project() as d:
            target = d / "AGENTS.md"
            target.write_text("abc\n", encoding="utf-8")
            item = quarantine.capture(target, d)
            meta = state.read_json(item.dir / "meta.json")
            self.assertEqual(meta["sha256"], item.sha256)
            self.assertEqual(meta["rel"], "AGENTS.md")


if __name__ == "__main__":
    unittest.main()
