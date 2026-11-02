"""Command-line interface: ``glint scan``, ``glint reveal``, ``glint rules``."""

from __future__ import annotations

import argparse
import os
import shutil
import sys
from collections.abc import Sequence
from pathlib import Path

from glint import __version__
from glint.config import ConfigError, load_config
from glint.models import Confidence, Severity
from glint.registry import load_rules
from glint.reporters import json_report, sarif, terminal
from glint.reveal import render_side_by_side, reveal_text
from glint.scanner import ScanOptions, scan

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2
DEFAULT_FAIL_ON = Severity.HIGH


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="glint",
        description="Offline security scanner for AI agent configs, prompts and MCP servers.",
    )
    parser.add_argument("--version", action="version", version=f"glint {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p_scan = sub.add_parser("scan", help="scan a folder or file for agent security risks")
    p_scan.add_argument("path", nargs="?", default=".", help="folder or file to scan (default: .)")
    p_scan.add_argument("--format", choices=["terminal", "json", "sarif"], default="terminal")
    p_scan.add_argument("--output", "-o", help="write the report to this file")
    p_scan.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        help="exit 1 when a finding is at or above this severity (default: high)",
    )
    p_scan.add_argument("--rules", help="comma-separated rule ids to run, e.g. GL-001,GL-005")
    p_scan.add_argument("--strict", action="store_true", help="also flag matches inside code blocks and quotes")
    p_scan.add_argument(
        "--min-confidence",
        choices=[c.label for c in Confidence],
        default="low",
        help="hide findings below this confidence (default: low)",
    )
    p_scan.add_argument("--no-color", action="store_true", help="disable coloured output")

    p_reveal = sub.add_parser("reveal", help="show what a human sees vs. what the agent reads")
    p_reveal.add_argument("file", help="file to reveal")

    sub.add_parser("rules", help="list every rule")
    sub.add_parser("version", help="print the version")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Entry point; returns the process exit code."""
    for stream in (sys.stdout, sys.stderr):
        # Never crash on a console that cannot print some characters.
        reconfigure = getattr(stream, "reconfigure", None)
        if reconfigure is not None:
            reconfigure(errors="replace")
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        if args.command == "scan":
            return _cmd_scan(args)
        if args.command == "reveal":
            return _cmd_reveal(args)
        if args.command == "rules":
            return _cmd_rules()
        if args.command == "version":
            print(f"glint {__version__}")
            return EXIT_OK
    except (ConfigError, ValueError) as exc:
        print(f"glint: error: {exc}", file=sys.stderr)
        return EXIT_USAGE
    parser.print_help()
    return EXIT_USAGE


def _use_colour(no_color: bool, to_file: bool) -> bool:
    if no_color or to_file or os.environ.get("NO_COLOR"):
        return False
    return sys.stdout.isatty()


def _cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.path)
    if not target.exists():
        print(f"glint: error: path not found: {args.path}", file=sys.stderr)
        return EXIT_USAGE
    config = load_config(target.resolve())
    options = ScanOptions(
        rules=args.rules.split(",") if args.rules else None,
        strict=args.strict,
        min_confidence=Confidence.parse(args.min_confidence),
    )
    result = scan(target, options, config)
    if args.format == "json":
        report = json_report.render(result)
    elif args.format == "sarif":
        report = sarif.render(result)
    else:
        report = terminal.render(result, _use_colour(args.no_color, bool(args.output)))
    if args.output:
        Path(args.output).write_text(report + "\n", encoding="utf-8")
    else:
        print(report)
    fail_on = Severity.parse(args.fail_on) if args.fail_on else (config.fail_on or DEFAULT_FAIL_ON)
    return EXIT_FINDINGS if any(f.severity >= fail_on for f in result.findings) else EXIT_OK


def _cmd_reveal(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        print(f"glint: error: file not found: {args.file}", file=sys.stderr)
        return EXIT_USAGE
    text = path.read_bytes().decode("utf-8", errors="replace")
    width = shutil.get_terminal_size((120, 24)).columns
    print(render_side_by_side(reveal_text(text), width))
    return EXIT_OK


def _cmd_rules() -> int:
    for rule in load_rules():
        print(f"{rule.id}  {rule.default_severity.label:<8}  {rule.title}")
        print(f"        {rule.description}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
