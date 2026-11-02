"""Human-readable terminal report."""

from __future__ import annotations

import shutil
import textwrap
from collections.abc import Callable

from glint.models import Finding, Severity
from glint.scanner import ScanResult
from glint.textutil import safe

_COLOURS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_BOLD, _DIM, _GREEN, _RESET = "\033[1m", "\033[2m", "\033[32m", "\033[0m"

Paint = Callable[[str, str], str]


def terminal_width() -> int:
    """Current terminal width, clamped to a readable range."""
    return max(60, min(shutil.get_terminal_size((100, 24)).columns, 140))


def wrap(text: str, width: int, indent: int, hang: int = 2) -> list[str]:
    """Wrap ``text`` to ``width`` with a hanging indent for continuation lines."""
    return textwrap.wrap(
        text,
        width=width,
        initial_indent=" " * indent,
        subsequent_indent=" " * (indent + hang),
        break_long_words=True,
        break_on_hyphens=False,
    ) or [" " * indent]


def render(result: ScanResult, colour: bool, width: int | None = None) -> str:
    """Render the scan result as text, grouped by severity and wrapped to ``width``."""
    width = width or terminal_width()

    def paint(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if colour else text

    out: list[str] = [paint(_BOLD, line) for line in wrap(f"Glint scan of {safe(result.root, 500)}", width, 0, 2)]
    out.extend(wrap(f"Scanned {len(result.scanned_files)} agent file(s) with {len(result.rules)} rule(s).", width, 0))
    for warning in result.warnings:
        out.extend(paint(_DIM, line) for line in wrap(f"note: {safe(warning, 500)}", width, 0, 6))
    out.append("")
    if not result.scanned_files:
        hint = (
            "No agent files found. Glint looks for files such as AGENTS.md, CLAUDE.md, .cursorrules, "
            ".claude/settings.json, .mcp.json and SKILL.md."
        )
        out.extend(paint(_DIM, line) for line in wrap(hint, width, 0, 0))
    if not result.findings:
        out.append(paint(_GREEN, "No findings."))
    for severity in sorted(Severity, reverse=True):
        group = [f for f in result.findings if f.severity is severity]
        if not group:
            continue
        out.append(paint(_COLOURS[severity], f"{severity.name} ({len(group)})"))
        for finding in group:
            out.extend(_finding(finding, paint, width))
        out.append("")
    if result.suppressed:
        out.append(paint(_DIM, f"{len(result.suppressed)} finding(s) suppressed by ignore rules."))
    if result.baselined:
        out.append(paint(_DIM, f"{len(result.baselined)} finding(s) accepted in the baseline (not counted)."))
    out.append(paint(_BOLD, f"Risk score: {result.score}/100 ({result.band})"))
    return "\n".join(out)


def _finding(finding: Finding, paint: Paint, width: int) -> list[str]:
    title = f"  {finding.rule_id} {finding.title}"
    where = f"{safe(str(finding.path))}:{finding.line}"
    if len(title) + 2 + len(where) <= width:
        lines = [paint(_BOLD, f"{title}  {where}")]
    else:
        lines = [paint(_BOLD, title), *wrap(where, width, 4)]
    lines.extend(wrap(safe(finding.message, 600), width, 4))
    if finding.evidence:
        lines.extend(paint(_DIM, line) for line in wrap(f"evidence: {finding.evidence}", width, 4, 10))
    lines.extend(wrap(f"fix: {finding.fix}", width, 4, 5))
    return lines
