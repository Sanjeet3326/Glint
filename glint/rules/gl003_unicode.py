"""GL-003: invisible and bidirectional Unicode characters."""

from __future__ import annotations

from glint.models import ALL_KINDS, Document, Finding, Rule, Severity
from glint.rules._helpers import injection_hits, text_lines
from glint.textutil import BIDI, ZERO_WIDTH, decode_tags, describe, is_tag, safe


class InvisibleUnicode(Rule):
    """Characters that hide or reorder text."""

    id = "GL-003"
    title = "Invisible Unicode"
    default_severity = Severity.MEDIUM
    applies_to = ALL_KINDS
    owasp = "LLM01: Prompt Injection"
    description = (
        "Flags zero-width characters, bidirectional controls and Unicode tag characters, "
        "which can hide instructions or make text read differently to humans and agents."
    )
    fix = "Remove the characters. Run `glint reveal FILE` to see exactly where they are."

    def check(self, doc: Document) -> list[Finding]:
        """Report each line that contains hidden characters."""
        findings: list[Finding] = []
        for line_no, line in text_lines(doc):
            found: dict[int, None] = {}
            severity = Severity.MEDIUM
            for col, ch in enumerate(line):
                cp = ord(ch)
                if cp == 0xFEFF and line_no == 1 and col == 0:
                    continue  # UTF-8 byte order mark at file start is harmless
                if cp in ZERO_WIDTH:
                    found.setdefault(cp)
                elif cp in BIDI or is_tag(cp):
                    found.setdefault(cp)
                    severity = Severity.HIGH
            if not found:
                continue
            labels = ["<Unicode tag characters>" if is_tag(cp) else describe(cp) for cp in found]
            names = ", ".join(dict.fromkeys(labels))
            message = f"Line contains invisible characters: {names}."
            hidden = decode_tags(line)
            if hidden:
                message += f' Hidden tag text reads: "{safe(hidden, 120)}".'
                if injection_hits(hidden):
                    severity = Severity.CRITICAL
            findings.append(self.finding(doc, line_no, message, safe(line), severity=severity))
        return findings
