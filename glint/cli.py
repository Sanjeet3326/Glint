"""Command-line interface for Glint."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from collections.abc import Sequence
from pathlib import Path, PurePosixPath

from glint import __version__
from glint.baseline import load_baseline, write_baseline
from glint.config import ConfigError, load_config
from glint.explain import card
from glint.fixer import apply_fix, plan_fixes, render_diff
from glint.inventory import build_inventory, inventory_dict, render_graph_dot, render_graph_text, render_inventory
from glint.lockfile import LOCK_FILE, build_lock, render_lock
from glint.models import Confidence, Project, Severity
from glint.registry import load_rules
from glint.reporters import html, json_report, sarif, terminal
from glint.reveal import render_side_by_side, reveal_text
from glint.scanner import ScanOptions, load_project, scan
from glint.selftest import render_selftest, run_selftest

EXIT_OK, EXIT_FINDINGS, EXIT_USAGE = 0, 1, 2
DEFAULT_FAIL_ON = Severity.HIGH
FORMATS = ("terminal", "json", "sarif", "html")


class UsageError(Exception):
    """A problem with how Glint was called."""


def build_parser() -> argparse.ArgumentParser:
    """Create the argument parser."""
    parser = argparse.ArgumentParser(
        prog="glint",
        description="Offline security scanner for AI agent configs, prompts and MCP servers.",
        epilog="Run 'glint COMMAND --help' for details on a command.",
    )
    parser.add_argument("--version", action="version", version=f"glint {__version__}")
    sub = parser.add_subparsers(dest="command", metavar="COMMAND")

    p = sub.add_parser("scan", help="scan a folder or file for agent security risks")
    p.add_argument("path", nargs="?", default=".", help="folder or file to scan (default: .)")
    p.add_argument("--format", choices=FORMATS, default="terminal", help="report format (default: terminal)")
    p.add_argument("--output", "-o", help="write the report to this file")
    p.add_argument(
        "--fail-on",
        choices=[s.label for s in Severity],
        help="exit 1 when a finding is at or above this severity (default: high)",
    )
    p.add_argument("--rules", help="comma-separated rule ids to run, e.g. GL-001,GL-005")
    p.add_argument("--strict", action="store_true", help="also flag matches inside code blocks and quotes")
    p.add_argument(
        "--min-confidence",
        choices=[c.label for c in Confidence],
        default="low",
        help="hide findings below this confidence (default: low)",
    )
    p.add_argument("--baseline", metavar="FILE", help="report only findings not in this baseline file")
    p.add_argument("--write-baseline", metavar="FILE", help="save current findings as a baseline and exit 0")
    p.add_argument("--diff", metavar="GIT_REF", help="report only findings in files changed since GIT_REF")
    p.add_argument("--no-color", action="store_true", help="disable coloured output")

    p = sub.add_parser("reveal", help="show what a human sees next to what the agent reads")
    p.add_argument("file", help="file to reveal")

    p = sub.add_parser("inventory", help="list every agent file, MCP server, tool, permission and hook")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--format", choices=("terminal", "json"), default="terminal")

    p = sub.add_parser("graph", help="show what each server, tool and permission lets the agent do")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--format", choices=("terminal", "dot", "json"), default="terminal")

    p = sub.add_parser("lock", help=f"record approved MCP servers and tool descriptions in {LOCK_FILE}")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--check", action="store_true", help=f"exit 1 if {LOCK_FILE} is missing or out of date")

    p = sub.add_parser("fix", help="remove invisible and bidirectional characters (shows a diff first)")
    p.add_argument("path", nargs="?", default=".")
    p.add_argument("--write", action="store_true", help="apply the changes (default: only show the diff)")

    p = sub.add_parser("explain", help="show the attack story and fix for a rule")
    p.add_argument("rule", nargs="?", help="rule id, e.g. GL-011 (omit to list rules)")

    p = sub.add_parser("selftest", help="measure detection and false-positive rates on built-in samples")
    p.add_argument("--markdown", action="store_true", help="print a Markdown table")

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
    commands = {
        "scan": _cmd_scan,
        "reveal": _cmd_reveal,
        "inventory": _cmd_inventory,
        "graph": _cmd_graph,
        "lock": _cmd_lock,
        "fix": _cmd_fix,
        "explain": _cmd_explain,
        "selftest": _cmd_selftest,
        "rules": _cmd_rules,
        "version": _cmd_version,
    }
    handler = commands.get(args.command or "")
    if handler is None:
        parser.print_help()
        return EXIT_USAGE
    try:
        return handler(args)
    except (ConfigError, UsageError, ValueError) as exc:
        print(f"glint: error: {exc}", file=sys.stderr)
        return EXIT_USAGE


def _existing(path: str) -> Path:
    target = Path(path)
    if not target.exists():
        raise UsageError(f"path not found: {path}")
    return target


def _use_colour(no_color: bool = False, to_file: bool = False) -> bool:
    if no_color or to_file or os.environ.get("NO_COLOR"):
        return False
    if os.environ.get("FORCE_COLOR"):
        return True
    return sys.stdout.isatty()


def _emit(text: str, output: str | None) -> None:
    if output:
        Path(output).write_text(text if text.endswith("\n") else text + "\n", encoding="utf-8")
    else:
        print(text)


def changed_files(target: Path, ref: str) -> set[str]:
    """Agent-relevant paths (relative to ``target``) changed since ``ref``, including untracked files."""
    base = target.resolve() if target.is_dir() else target.resolve().parent

    def git(*args: str) -> str:
        try:
            done = subprocess.run(["git", *args], cwd=base, capture_output=True, text=True, check=True, timeout=60)
        except FileNotFoundError as exc:
            raise UsageError("--diff needs git on PATH") from exc
        except subprocess.CalledProcessError as exc:
            raise UsageError(f"git failed: {exc.stderr.strip() or exc}") from exc
        return done.stdout

    top = Path(git("rev-parse", "--show-toplevel").strip()).resolve()
    names = git("diff", "--name-only", "--diff-filter=ACMRT", ref, "--").splitlines()
    names += git("ls-files", "--others", "--exclude-standard").splitlines()
    out: set[str] = set()
    for name in names:
        absolute = (top / name).resolve()
        try:
            out.add(PurePosixPath(absolute.relative_to(base).as_posix()).as_posix())
        except ValueError:
            continue
        # Untracked names from ls-files are relative to the working directory, which is base.
        if (base / name).exists():
            out.add(PurePosixPath(name).as_posix())
    return out


def _cmd_scan(args: argparse.Namespace) -> int:
    target = _existing(args.path)
    config = load_config(target.resolve())
    options = ScanOptions(
        rules=args.rules.split(",") if args.rules else None,
        strict=args.strict,
        min_confidence=Confidence.parse(args.min_confidence),
        baseline=load_baseline(Path(args.baseline)) if args.baseline else None,
        changed_files=changed_files(target, args.diff) if args.diff else None,
    )
    result = scan(target, options, config)
    if args.write_baseline:
        count = write_baseline(Path(args.write_baseline), result.findings)
        print(f"Wrote {count} finding(s) to {args.write_baseline}. Use --baseline to report only new ones.")
        return EXIT_OK
    if args.format == "json":
        report = json_report.render(result)
    elif args.format == "sarif":
        report = sarif.render(result)
    elif args.format == "html":
        report = html.render(result)
    else:
        report = terminal.render(result, _use_colour(args.no_color, bool(args.output)))
    _emit(report, args.output)
    if args.output and args.format != "terminal":
        print(f"Wrote {args.format} report to {args.output} ({len(result.findings)} finding(s)).", file=sys.stderr)
    fail_on = Severity.parse(args.fail_on) if args.fail_on else (config.fail_on or DEFAULT_FAIL_ON)
    return EXIT_FINDINGS if any(f.severity >= fail_on for f in result.findings) else EXIT_OK


def _cmd_reveal(args: argparse.Namespace) -> int:
    path = Path(args.file)
    if not path.is_file():
        raise UsageError(f"file not found: {args.file}")
    text = path.read_bytes().decode("utf-8", errors="replace")
    width = shutil.get_terminal_size((120, 24)).columns
    print(render_side_by_side(reveal_text(text), width, colour=_use_colour()))
    return EXIT_OK


def _project(path: str) -> Project:
    target = _existing(path)
    return load_project(target, load_config(target.resolve()))


def _cmd_inventory(args: argparse.Namespace) -> int:
    inv = build_inventory(_project(args.path))
    if args.format == "json":
        print(json.dumps(inventory_dict(inv), indent=2))
    else:
        print(render_inventory(inv))
    return EXIT_OK


def _cmd_graph(args: argparse.Namespace) -> int:
    inv = build_inventory(_project(args.path))
    if args.format == "dot":
        print(render_graph_dot(inv.providers), end="")
    elif args.format == "json":
        data = {
            "providers": [
                {"label": p.label, "kind": p.kind, "file": p.path, "line": p.line, "capabilities": sorted(p.caps)}
                for p in inv.providers
            ],
            "trifecta": inventory_dict(inv)["trifecta"],
        }
        print(json.dumps(data, indent=2))
    else:
        print(render_graph_text(inv.providers))
    return EXIT_OK


def _cmd_lock(args: argparse.Namespace) -> int:
    target = _existing(args.path)
    if not target.is_dir():
        raise UsageError("glint lock needs a folder")
    content = render_lock(build_lock(load_project(target, load_config(target.resolve()))))
    lock_path = target / LOCK_FILE
    if args.check:
        current = lock_path.read_text(encoding="utf-8") if lock_path.is_file() else None
        if current == content:
            print(f"{LOCK_FILE} is up to date.")
            return EXIT_OK
        print(f"{LOCK_FILE} is {'missing' if current is None else 'out of date'}. Run 'glint lock' after review.")
        return EXIT_FINDINGS
    lock_path.write_text(content, encoding="utf-8", newline="\n")
    data = json.loads(content)
    print(f"Wrote {lock_path} ({len(data['servers'])} server(s), {len(data['tools'])} tool(s)). Commit it.")
    return EXIT_OK


def _cmd_fix(args: argparse.Namespace) -> int:
    fixes = plan_fixes(_existing(args.path))
    if not fixes:
        print("Nothing to fix: no invisible or bidirectional characters found.")
        return EXIT_OK
    for fix in fixes:
        print(render_diff(fix), end="")
    total = sum(f.removed for f in fixes)
    if args.write:
        for fix in fixes:
            apply_fix(fix)
        print(f"\nRemoved {total} hidden character(s) from {len(fixes)} file(s).")
        return EXIT_OK
    print(f"\n{total} hidden character(s) in {len(fixes)} file(s). Run again with --write to apply.")
    return EXIT_FINDINGS


def _cmd_explain(args: argparse.Namespace) -> int:
    if not args.rule:
        print("Usage: glint explain RULE   (for example: glint explain GL-011)\n")
        return _cmd_rules(args)
    text = card(args.rule)
    if text is None:
        raise UsageError(f"no card for rule {args.rule!r}; run 'glint rules' for the list")
    print(text.rstrip())
    return EXIT_OK


def _cmd_selftest(args: argparse.Namespace) -> int:
    result = run_selftest()
    print(render_selftest(result, markdown=args.markdown))
    return EXIT_OK


def _cmd_rules(args: argparse.Namespace) -> int:
    for rule in load_rules():
        print(f"{rule.id}  {rule.default_severity.label:<8}  {rule.title}")
        print(f"        {rule.description}")
    return EXIT_OK


def _cmd_version(args: argparse.Namespace) -> int:
    print(f"glint {__version__}")
    return EXIT_OK


if __name__ == "__main__":
    raise SystemExit(main())
