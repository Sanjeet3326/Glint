"""Tests for the desktop app: the display model everywhere, the window itself when a display exists."""

from __future__ import annotations

import contextlib
import io
import os
import unittest
from pathlib import Path
from unittest import mock

from glint import gui
from glint.cli import main
from glint.gui_model import FILTER_ALL, details, filter_rows, finding_file, reveal_marks, rows, summarise
from glint.reveal import reveal_text
from glint.scanner import scan

ROOT = Path(__file__).resolve().parent.parent
VULNERABLE = ROOT / "demo" / "vulnerable-agent"
CLEAN = ROOT / "demo" / "clean-agent"


class GuiModelTest(unittest.TestCase):
    def test_rows_and_summary(self) -> None:
        result = scan(VULNERABLE)
        table = rows(result)
        self.assertEqual(len(table), len(result.findings))
        self.assertEqual(table[0].severity, "Critical")
        summary = summarise(result)
        self.assertEqual(summary.score, 100)
        self.assertTrue(summary.trifecta)
        self.assertEqual(sum(summary.counts.values()), len(result.findings))
        clean = summarise(scan(CLEAN))
        self.assertFalse(clean.trifecta)
        self.assertIn("No problems found", clean.headline)

    def test_filter_and_search(self) -> None:
        table = rows(scan(VULNERABLE))
        self.assertEqual(filter_rows(table), table)
        critical = filter_rows(table, "Critical")
        self.assertTrue(critical and all(r.severity == "Critical" for r in critical))
        self.assertEqual({r.rule_id for r in filter_rows(table, FILTER_ALL, "trifecta")}, {"GL-011"})
        self.assertEqual(filter_rows(table, "Low"), [])
        self.assertTrue(filter_rows(table, query="CLAUDE.MD"))

    def test_details_and_paths(self) -> None:
        result = scan(VULNERABLE)
        finding = result.findings[0]
        parts = details(finding, "# GL-000 Title\n\n**What it is:** x\n\n```text\ncode\n```\n")
        text = "".join(t for t, _ in parts)
        self.assertIn(finding.rule_id, text)
        self.assertIn("How to fix", text)
        self.assertNotIn("```", text)
        self.assertNotIn("**", text)
        self.assertTrue(finding_file(result.root, finding).is_file())

    def test_reveal_marks_cover_hidden_parts(self) -> None:
        result = reveal_text("a <!-- hidden --> b\u202ec")
        marked = [result.agent[s:e] for s, e in reveal_marks(result)]
        self.assertEqual(len(marked), 2)
        self.assertTrue(all(m.startswith("\u27e6") for m in marked))


class GuiCommandTest(unittest.TestCase):
    def test_missing_tkinter_gives_help_not_a_crash(self) -> None:
        err = io.StringIO()
        with mock.patch.object(gui, "tk", None), contextlib.redirect_stderr(err):
            code = main(["gui"])
        self.assertEqual(code, 2)
        self.assertIn("python3-tk", err.getvalue())


def _tk_root() -> object | None:
    """A Tk root window, or None when tkinter or a display is unavailable.

    With GLINT_REQUIRE_GUI=1 (set in CI) a missing GUI is an error, not a skip.
    """
    required = os.environ.get("GLINT_REQUIRE_GUI") == "1"
    if gui.tk is None:
        if required:
            raise RuntimeError("GLINT_REQUIRE_GUI=1 but tkinter is not available")
        return None
    try:
        root = gui.tk.Tk()
    except gui.tk.TclError:
        if required:
            raise
        return None
    root.withdraw()
    window: object = root
    return window


class GuiWindowTest(unittest.TestCase):
    """Drives the real window. Skipped without a display (CI runs it under xvfb on Linux)."""

    def setUp(self) -> None:
        self.app: gui.GlintApp | None = None
        self.root = _tk_root()
        if self.root is None:
            self.skipTest("tkinter or a display is not available")

    def tearDown(self) -> None:
        if self.app is not None:
            self.app.close()
        elif self.root is not None:
            self.root.destroy()  # type: ignore[attr-defined]

    def make_app(self) -> gui.GlintApp:
        self.app = gui.GlintApp(self.root)
        return self.app

    def test_scan_filter_select_and_reveal(self) -> None:
        app = self.make_app()
        app.show_result(scan(VULNERABLE))
        self.assertEqual(len(app.table.get_children()), len(app.all_rows))
        self.assertEqual(app.score_label.cget("text"), "100")
        self.assertIn("Lethal trifecta", app.trifecta_label.cget("text"))

        app.filter_var.set("Medium")
        self.assertTrue(all(r.severity == "Medium" for r in app.visible.values()))
        app.filter_var.set(FILTER_ALL)
        app.search_var.set("GL-003")
        key = next(iter(app.visible))
        app.table.selection_set(key)
        app.root.update()
        app.show_selected()
        self.assertIn("GL-003", app.detail.get("1.0", "end"))

        before = len(app.root.winfo_children())
        app.reveal_selected()
        self.assertEqual(len(app.root.winfo_children()), before + 1)

    def test_clean_project(self) -> None:
        app = self.make_app()
        app.show_result(scan(CLEAN))
        self.assertEqual(app.table.get_children(), ())
        self.assertEqual(app.score_label.cget("text"), "0")
        self.assertIn("not present", app.trifecta_label.cget("text"))


if __name__ == "__main__":
    unittest.main()
