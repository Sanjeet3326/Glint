"""End-to-end tests: CLI exit codes, reporters and reveal."""

from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from glint.cli import main
from glint.reveal import reveal_text

ROOT = Path(__file__).resolve().parent.parent
VULNERABLE = ROOT / "demo" / "vulnerable-agent"
CLEAN = ROOT / "demo" / "clean-agent"
ALL_RULES = {f"GL-{i:03d}" for i in range(1, 11)}


def run_cli(*args: str) -> tuple[int, str, str]:
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        code = main(list(args))
    return code, out.getvalue(), err.getvalue()


class ScanCommandTest(unittest.TestCase):
    def test_vulnerable_demo_triggers_every_rule(self) -> None:
        code, out, _ = run_cli("scan", str(VULNERABLE), "--format", "json")
        report = json.loads(out)
        self.assertEqual(code, 1)
        self.assertEqual({f["rule_id"] for f in report["findings"]}, ALL_RULES)
        self.assertEqual(report["risk_score"], 100)

    def test_clean_demo_has_no_findings(self) -> None:
        code, out, _ = run_cli("scan", str(CLEAN), "--format", "json", "--fail-on", "low")
        report = json.loads(out)
        self.assertEqual(code, 0)
        self.assertEqual(report["findings"], [])
        self.assertGreater(len(report["scanned_files"]), 0)

    def test_fail_on_threshold(self) -> None:
        code, _, _ = run_cli("scan", str(VULNERABLE), "--rules", "GL-007", "--fail-on", "high")
        self.assertEqual(code, 0)
        code, _, _ = run_cli("scan", str(VULNERABLE), "--rules", "GL-007", "--fail-on", "medium")
        self.assertEqual(code, 1)

    def test_usage_errors_exit_2(self) -> None:
        self.assertEqual(run_cli("scan", "/no/such/path")[0], 2)
        self.assertEqual(run_cli("scan", str(CLEAN), "--rules", "GL-999")[0], 2)
        self.assertEqual(run_cli()[0], 2)

    def test_terminal_output_has_no_colour_when_piped(self) -> None:
        _, out, _ = run_cli("scan", str(VULNERABLE))
        self.assertNotIn("\x1b[", out)
        self.assertIn("Risk score: 100/100", out)

    def test_secrets_never_printed_in_full(self) -> None:
        for fmt in ("terminal", "json", "sarif"):
            _, out, _ = run_cli("scan", str(VULNERABLE), "--format", fmt)
            with self.subTest(fmt=fmt):
                self.assertNotRegex(out, r"ghp_[A-Za-z0-9]{36}")

    def test_sarif_structure(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "out.sarif"
            run_cli("scan", str(VULNERABLE), "--format", "sarif", "--output", str(target))
            sarif = json.loads(target.read_text())
        self.assertEqual(sarif["version"], "2.1.0")
        run = sarif["runs"][0]
        rule_ids = [r["id"] for r in run["tool"]["driver"]["rules"]]
        self.assertEqual(set(rule_ids), ALL_RULES)
        for result in run["results"]:
            self.assertIn(result["level"], {"error", "warning", "note"})
            self.assertEqual(rule_ids[result["ruleIndex"]], result["ruleId"])
            region = result["locations"][0]["physicalLocation"]["region"]
            self.assertGreaterEqual(region["startLine"], 1)

    def test_rules_and_version_commands(self) -> None:
        code, out, _ = run_cli("rules")
        self.assertEqual(code, 0)
        self.assertIn("GL-010", out)
        self.assertEqual(run_cli("version")[0], 0)


class RevealTest(unittest.TestCase):
    def test_hidden_parts_shown_to_agent_only(self) -> None:
        tag = "".join(chr(0xE0000 + ord(c)) for c in "hi")
        result = reveal_text(f"visible\n<!-- secret note -->\nrtl‮ here{tag}\n")
        self.assertNotIn("secret note", result.human)
        self.assertIn("HTML comment: secret note", result.agent)
        self.assertIn("RIGHT-TO-LEFT OVERRIDE", result.agent)
        self.assertIn("hidden tag text: hi", result.agent)
        self.assertEqual(result.hidden_parts, 3)
        self.assertEqual(result.human.count("\n"), result.agent.count("\n"))

    def test_clean_file_has_nothing_hidden(self) -> None:
        self.assertEqual(reveal_text("just text\n").hidden_chars, 0)

    def test_reveal_command(self) -> None:
        code, out, _ = run_cli("reveal", str(VULNERABLE / "CLAUDE.md"))
        self.assertEqual(code, 0)
        self.assertIn("invisible to a human reader", out)


if __name__ == "__main__":
    unittest.main()
