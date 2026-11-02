"""Human-readable terminal report."""

from __future__ import annotations

from glint.models import Finding, Severity
from glint.scanner import ScanResult
from glint.textutil import safe

_COLOURS = {
    Severity.CRITICAL: "\033[1;31m",
    Severity.HIGH: "\033[31m",
    Severity.MEDIUM: "\033[33m",
    Severity.LOW: "\033[36m",
}
_BOLD, _DIM, _RESET = "\033[1m", "\033[2m", "\033[0m"


def render(result: ScanResult, colour: bool) -> str:
    """Render the scan result as text, grouped by severity."""

    def paint(code: str, text: str) -> str:
        return f"{code}{text}{_RESET}" if colour else text

    out: list[str] = []
    out.append(paint(_BOLD, f"Glint scan of {safe(result.root)}"))
    out.append(f"Scanned {len(result.scanned_files)} agent file(s) with {len(result.rules)} rule(s).")
    for warning in result.warnings:
        out.append(paint(_DIM, f"note: {safe(warning)}"))
    out.append("")
    if not result.findings:
        out.append(paint("\033[32m", "No findings."))
    for severity in sorted(Severity, reverse=True):
        group = [f for f in result.findings if f.severity is severity]
        if not group:
            continue
        out.append(paint(_COLOURS[severity], f"{severity.name} ({len(group)})"))
        for finding in group:
            out.extend(_finding(finding, paint))
        out.append("")
    if result.suppressed:
        out.append(paint(_DIM, f"{len(result.suppressed)} finding(s) suppressed by ignore rules."))
    out.append(paint(_BOLD, f"Risk score: {result.score}/100 ({result.band})"))
    return "\n".join(out)


def _finding(finding: Finding, paint: object) -> list[str]:
    assert callable(paint)
    head = f"  {finding.rule_id} {finding.title}  {safe(str(finding.path))}:{finding.line}"
    lines = [paint(_BOLD, head)]
    lines.append(f"    {safe(finding.message, 300)}")
    if finding.evidence:
        lines.append(paint(_DIM, f"    evidence: {finding.evidence}"))
    lines.append(f"    fix: {finding.fix}")
    return lines
