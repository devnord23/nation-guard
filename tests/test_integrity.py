# SPDX-License-Identifier: Apache-2.0
import json
import unittest
from pathlib import Path

import _support
from nation_guard import integrity, state


def _write(p: Path, text: str):
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(text, encoding="utf-8")


class IntegrityTest(unittest.TestCase):
    def _project(self, d: Path):
        _write(d / "CLAUDE.md", "# clean\nbuild with make\n")
        _write(d / "AGENTS.md", "# agents\nrun tests\n")
        _write(d / ".mcp.json", json.dumps({"mcpServers": {"docs": {"command": "npx"}}}))

    def test_baseline_then_verify_clean(self):
        with _support.temp_home(), _support.temp_project() as d:
            self._project(d)
            integrity.save_baseline(d)
            self.assertEqual(integrity.verify(d, _support.rules()), [])

    def test_detects_changed_new_removed(self):
        with _support.temp_home(), _support.temp_project() as d:
            self._project(d)
            integrity.save_baseline(d)
            (d / "CLAUDE.md").write_text("# changed\n", encoding="utf-8")
            _write(d / "sub" / "AGENTS.md", "# new file\n")
            (d / ".mcp.json").unlink()
            ids = {f.rule_id for f in integrity.verify(d, _support.rules())}
            self.assertIn("NG-INT-001", ids)  # CLAUDE.md changed
            self.assertIn("NG-INT-002", ids)  # sub/AGENTS.md new
            self.assertIn("NG-INT-003", ids)  # .mcp.json removed

    def test_detects_mcp_server_change(self):
        with _support.temp_home(), _support.temp_project() as d:
            self._project(d)
            integrity.save_baseline(d)
            (d / ".mcp.json").write_text(
                json.dumps({"mcpServers": {"docs": {"command": "evil"}}}), encoding="utf-8")
            ids = {f.rule_id for f in integrity.verify(d, _support.rules())}
            self.assertIn("NG-MCP-001", ids)

    def test_refuse_overwrite_without_update(self):
        with _support.temp_home(), _support.temp_project() as d:
            self._project(d)
            integrity.save_baseline(d)
            with self.assertRaises(state.StateError):
                integrity.save_baseline(d)
            integrity.save_baseline(d, update=True)  # ok

    def test_verify_without_baseline_errors(self):
        with _support.temp_home(), _support.temp_project() as d:
            self._project(d)
            with self.assertRaises(state.StateError):
                integrity.verify(d, _support.rules())

    def test_refuse_home_inside_root(self):
        with _support.temp_project() as d:
            import os
            inside = d / ".nation-guard-home"
            os.environ["NATION_GUARD_HOME"] = str(inside)
            try:
                with self.assertRaises(state.StateError):
                    integrity.save_baseline(d)
            finally:
                os.environ.pop("NATION_GUARD_HOME", None)


if __name__ == "__main__":
    unittest.main()
