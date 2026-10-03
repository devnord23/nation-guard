# SPDX-License-Identifier: Apache-2.0
import stat
import unittest
from pathlib import Path

import _support
from nation_guard import harden


def _writable(p: Path) -> bool:
    return bool(stat.S_IMODE(p.stat().st_mode) & stat.S_IWUSR)


class HardenTest(unittest.TestCase):
    def test_plan_lists_freeze_and_create(self):
        with _support.temp_home(), _support.temp_project() as d:
            (d / "CLAUDE.md").write_text("# existing\n", encoding="utf-8")
            kinds = sorted((a.kind, Path(a.path).name) for a in harden.plan(d))
            self.assertIn(("chmod", "CLAUDE.md"), kinds)
            self.assertIn(("create", "AGENTS.md"), kinds)
            self.assertIn(("create", "GEMINI.md"), kinds)
            self.assertIn(("create", ".cursorrules"), kinds)

    def test_apply_freezes_and_creates_then_undo(self):
        with _support.temp_home(), _support.temp_project() as d:
            claude = d / "CLAUDE.md"
            claude.write_text("# existing\n", encoding="utf-8")
            harden.apply(d)
            self.assertFalse(_writable(claude), "CLAUDE.md should be read-only after apply")
            created = d / "AGENTS.md"
            self.assertTrue(created.exists())
            self.assertFalse(_writable(created))
            self.assertEqual(created.read_text(encoding="utf-8"), "")

            harden.undo(d)
            self.assertTrue(_writable(claude), "CLAUDE.md writable again after undo")
            self.assertFalse(created.exists(), "empty created file removed on undo")

    def test_undo_keeps_created_file_with_content(self):
        with _support.temp_home(), _support.temp_project() as d:
            (d / "CLAUDE.md").write_text("# existing\n", encoding="utf-8")
            harden.apply(d)
            agents = d / "AGENTS.md"
            # user later adds real content (make writable first since it is 0444)
            import os
            os.chmod(agents, 0o644)
            agents.write_text("real content\n", encoding="utf-8")
            harden.undo(d)
            self.assertTrue(agents.exists(), "non-empty created file must be kept")
            self.assertEqual(agents.read_text(encoding="utf-8"), "real content\n")

    def test_apply_is_idempotent(self):
        with _support.temp_home(), _support.temp_project() as d:
            (d / "CLAUDE.md").write_text("# x\n", encoding="utf-8")
            harden.apply(d)
            second = harden.apply(d)
            self.assertEqual(second, [], "nothing left to do on a second apply")


if __name__ == "__main__":
    unittest.main()
