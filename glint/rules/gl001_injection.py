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
from glint.rules._helpers import SAFETY_OFF_PATTERNS, injection_hits, text_lines
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
        "Flags phrases that try to override the agent's instructions, hide actions "
        "from the user, or switch off approval prompts."
    )
    fix = (
        "Remove the instruction. Agent files should not contain text that overrides "
        "other instructions or hides actions from the user."
    )

    def check(self, doc: Document) -> list[Finding]:
        """Scan every line for injection and safety-off phrases."""
        findings: list[Finding] = []
        for line_no, line in text_lines(doc):
            hits = injection_hits(line)
            if hits:
                findings.append(self.finding(doc, line_no, f"Line {hits[0]}.", safe(line)))
                continue
            norm = normalise(line)
            if any(rx.search(norm) for rx in SAFETY_OFF_PATTERNS):
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
        return findings
