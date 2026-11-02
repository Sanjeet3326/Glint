"""Display logic for the desktop app, kept free of tkinter so it can be tested anywhere."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from glint.capabilities import analyse_trifecta, project_providers
from glint.models import Finding, Severity
from glint.reveal import RevealResult
from glint.scanner import ScanResult

SEVERITY_COLOURS = {
    Severity.CRITICAL: "#a40e26",
    Severity.HIGH: "#d1242f",
    Severity.MEDIUM: "#9a6700",
    Severity.LOW: "#0969da",
}
BAND_COLOURS = {
    "clean": "#1a7f37",
    "low": "#0969da",
    "medium": "#9a6700",
    "high": "#d1242f",
    "critical": "#a40e26",
}
FILTER_ALL = "All severities"
FILTER_CHOICES = (FILTER_ALL, "Critical", "High", "Medium", "Low")

_MARK_RE = re.compile("\u27e6[^\u27e7]*\u27e7?")


@dataclass(frozen=True)
class Row:
    """One line in the findings table."""

    key: str
    severity: str
    rule_id: str
    title: str
    location: str
    finding: Finding


@dataclass(frozen=True)
class Summary:
    """The numbers shown in the banner above the table."""

    score: int
    band: str
    colour: str
    counts: dict[str, int]
    files: int
    trifecta: bool
    headline: str


def rows(result: ScanResult) -> list[Row]:
    """Table rows for every finding, most severe first."""
    return [
        Row(
            key=str(index),
            severity=f.severity.label.capitalize(),
            rule_id=f.rule_id,
            title=f.title,
            location=f"{f.path}:{f.line}",
            finding=f,
        )
        for index, f in enumerate(result.findings)
    ]


def filter_rows(all_rows: list[Row], severity: str = FILTER_ALL, query: str = "") -> list[Row]:
    """Rows matching a severity choice and a free-text search (case-insensitive)."""
    wanted = severity.lower() if severity != FILTER_ALL else None
    needle = query.strip().lower()
    out: list[Row] = []
    for row in all_rows:
        if wanted and row.severity.lower() != wanted:
            continue
        if needle:
            haystack = " ".join(
                [row.rule_id, row.title, row.location, row.finding.message, row.finding.evidence]
            ).lower()
            if needle not in haystack:
                continue
        out.append(row)
    return out


def summarise(result: ScanResult) -> Summary:
    """Build the banner: score, band, counts and the lethal-trifecta status."""
    counts = {s.label: sum(1 for f in result.findings if f.severity is s) for s in sorted(Severity, reverse=True)}
    trifecta = bool(result.project and analyse_trifecta(project_providers(result.project)).complete)
    files = len(result.scanned_files)
    if not files:
        headline = "No agent files found in this folder."
    elif not result.findings:
        headline = f"No problems found in {files} agent file(s)."
    else:
        headline = f"{len(result.findings)} finding(s) in {files} agent file(s)."
    return Summary(
        score=result.score,
        band=result.band,
        colour=BAND_COLOURS[result.band],
        counts=counts,
        files=files,
        trifecta=trifecta,
        headline=headline,
    )


def details(finding: Finding, card_text: str | None) -> list[tuple[str, str]]:
    """The details pane as (text, style) pairs; styles are 'title', 'label', 'body', 'code'."""
    parts: list[tuple[str, str]] = [
        (f"{finding.rule_id}  {finding.title}\n", "title"),
        (f"{finding.severity.label.upper()}  \u00b7  {finding.path}:{finding.line}", "label"),
    ]
    if finding.owasp:
        parts.append((f"  \u00b7  {finding.owasp}", "label"))
    parts += [
        ("\n\n", "body"),
        (finding.message + "\n\n", "body"),
        ("Evidence\n", "label"),
        ((finding.evidence or "(none)") + "\n\n", "code"),
        ("How to fix\n", "label"),
        (finding.fix + "\n", "body"),
    ]
    if card_text:
        parts += [("\nHow this attack works\n", "label"), (_plain_card(card_text), "body")]
    return parts


def _plain_card(card_text: str) -> str:
    """Drop the card's own title and Markdown fences for display in a text box."""
    lines = card_text.splitlines()
    if lines and lines[0].startswith("# "):
        lines = lines[1:]
    keep = [line for line in lines if not line.startswith("```")]
    text = "\n".join(line.removeprefix("## ").replace("**", "") for line in keep)
    return text.strip() + "\n"


def reveal_marks(result: RevealResult) -> list[tuple[int, int]]:
    """Character ranges in the agent view that are hidden from humans."""
    return [(m.start(), m.end()) for m in _MARK_RE.finditer(result.agent)]


def finding_file(root: str, finding: Finding) -> Path:
    """Absolute path of the file a finding points at."""
    base = Path(root).resolve()
    if base.is_file():
        base = base.parent
    return base / Path(str(finding.path))
