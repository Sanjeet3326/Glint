"""GL-001: prompt-injection phrases."""

from __future__ import annotations

from glint.models import (
    KIND_MCP,
    KIND_TOOLS,
    TEXT_KINDS,
    Confidence,
    Document,
    Finding,
    Rule,
    Severity,
)
from glint.rules._helpers import SAFETY_OFF_PATTERNS, encoded_hits, injection_hits
from glint.textutil import normalise, safe


class InjectionPhrases(Rule):
    """Text that tries to override the agent's rules."""

    id = "GL-001"
    title = "Injection phrases"
    default_severity = Severity.HIGH
    applies_to = TEXT_KINDS | {KIND_MCP, KIND_TOOLS}
    respects_context = True
    owasp = "LLM01: Prompt Injection"
    description = (
        "Flags phrases that try to override the agent's instructions, hide actions from the user, or "
        "switch off approval prompts. Resists common evasion: look-alike letters, leetspeak, invisible "
        "characters, phrases split across lines and base64 or hex encoding."
    )
    fix = (
        "Remove the instruction. Agent files should not contain text that overrides other instructions "
        "or hides actions from the user."
    )

    def check(self, doc: Document) -> list[Finding]:
        """Scan every line (and each pair of lines) for injection phrases."""
        findings: list[Finding] = []
        lines = doc.lines
        hit_lines: set[int] = set()
        for idx, line in enumerate(lines):
            line_no = idx + 1
            hits = injection_hits(line)
            if hits:
                hit_lines.add(line_no)
                findings.append(self.finding(doc, line_no, f"Line {hits[0]}.", safe(line)))
                continue
            encoded = encoded_hits(line)
            if encoded:
                hit_lines.add(line_no)
                findings.append(
                    self.finding(
                        doc,
                        line_no,
                        f"Encoded text (base64 or hex) decodes to text that {encoded[0]}.",
                        safe(line),
                        severity=Severity.CRITICAL,
                    )
                )
                continue
            norm = normalise(line)
            if any(rx.search(norm) for rx in SAFETY_OFF_PATTERNS):
                hit_lines.add(line_no)
                findings.append(
                    self.finding(
                        doc,
                        line_no,
                        "Line tells the agent to act without asking the user for approval.",
                        safe(line),
                        severity=Severity.MEDIUM,
                        confidence=Confidence.MEDIUM,
                        fix=(
                            "Remove the instruction, or limit it to read-only actions. "
                            "Approval prompts are the last check before a harmful action."
                        ),
                    )
                )
        # A phrase split over two lines only matches when the lines are joined.
        for idx in range(len(lines) - 1):
            line_no = idx + 1
            if line_no in hit_lines or line_no + 1 in hit_lines or not lines[idx + 1].strip():
                continue
            if doc.context(line_no) != doc.context(line_no + 1):
                continue
            joined = f"{lines[idx]} {lines[idx + 1]}"
            hits = injection_hits(joined)
            if hits:
                hit_lines.update({line_no, line_no + 1})
                findings.append(
                    self.finding(
                        doc,
                        line_no,
                        f"Text split across lines {line_no}-{line_no + 1} {hits[0]}.",
                        safe(joined),
                    )
                )
        return findings
