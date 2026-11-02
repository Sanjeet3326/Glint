"""GL-006: instructions that send data off the user's machine."""

from __future__ import annotations

from glint.models import KIND_MCP, KIND_TOOLS, TEXT_KINDS, Document, Finding, Rule, Severity
from glint.rules._helpers import exfil_hits
from glint.textutil import safe


class ExfiltrationPatterns(Rule):
    """Instructions that send data to outside addresses."""

    id = "GL-006"
    title = "Exfiltration patterns"
    default_severity = Severity.HIGH
    applies_to = TEXT_KINDS | {KIND_MCP, KIND_TOOLS}
    respects_context = True
    owasp = "LLM02: Sensitive Information Disclosure"
    description = (
        "Flags instructions to send data to a URL, web addresses built from private data, "
        "Markdown images that leak data when rendered, and requests to read credential files."
    )
    fix = (
        "Remove the instruction. Agents should not send data to addresses named in prompt "
        "files or read credential files."
    )

    def check(self, doc: Document) -> list[Finding]:
        """Scan each line, and pairs of lines, for exfiltration patterns."""
        findings: list[Finding] = []
        hit_lines: set[int] = set()
        lines = doc.lines
        for idx, line in enumerate(lines):
            hits = exfil_hits(line)
            if hits:
                hit_lines.add(idx + 1)
                findings.append(self.finding(doc, idx + 1, f"Line {hits[0]}.", safe(line)))
        for idx in range(len(lines) - 1):
            if idx + 1 in hit_lines or idx + 2 in hit_lines or not lines[idx + 1].strip():
                continue
            if doc.context(idx + 1) != doc.context(idx + 2):
                continue
            joined = f"{lines[idx]} {lines[idx + 1]}"
            hits = exfil_hits(joined)
            if hits:
                hit_lines.update({idx + 1, idx + 2})
                findings.append(
                    self.finding(doc, idx + 1, f"Text split across lines {idx + 1}-{idx + 2} {hits[0]}.", safe(joined))
                )
        return findings
