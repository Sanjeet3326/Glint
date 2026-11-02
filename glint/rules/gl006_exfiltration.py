"""GL-006: instructions that send data off the user's machine."""

from __future__ import annotations

from glint.models import KIND_MCP, KIND_TOOLS, TEXT_KINDS, Document, Finding, Rule, Severity
from glint.rules._helpers import exfil_hits, text_lines
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
        """Scan each line for exfiltration patterns."""
        findings: list[Finding] = []
        for line_no, line in text_lines(doc):
            hits = exfil_hits(line)
            if hits:
                findings.append(self.finding(doc, line_no, f"Line {hits[0]}.", safe(line)))
        return findings
