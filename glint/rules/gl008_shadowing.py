"""GL-008: tool descriptions that try to change how other tools behave."""

from __future__ import annotations

import re

from glint.models import KIND_MCP, KIND_SKILL, KIND_TOOLS, Document, Finding, Rule, Severity
from glint.rules._helpers import text_lines
from glint.textutil import normalise, safe

# Patterns that are suspicious anywhere (tool descriptions and skills).
_STRONG = tuple(
    re.compile(p)
    for p in (
        r"\b(?:always|also|secretly|silently)\s+(?:bcc|cc|copy|forward|send\s+a\s+copy)\b",
        r"\bbefore\s+(?:using|calling|running)\s+any\s+other\s+tools?\b",
        r"\bthis\s+tool\s+must\s+(?:always\s+)?be\s+(?:called|used|run)\s+(?:first|before)\b",
        r"\b(?:instead\s+of|rather\s+than)\s+(?:using|calling)\s+(?:the\s+)?[\w`'\".-]{2,40}\s+tool\b",
    )
)
# Only suspicious inside a tool description, where it should describe itself.
_DESCRIPTION_ONLY = (
    re.compile(
        r"\bwhen\s+(?:using|calling|invoking)\s+(?:the\s+)?[\w`'\".-]{2,40}"
        r"[^.\n]{0,40}?\b(?:always|instead|also|first|must)\b"
    ),
)


class ToolShadowing(Rule):
    """A tool or skill description that rewires other tools."""

    id = "GL-008"
    title = "Tool shadowing"
    default_severity = Severity.HIGH
    applies_to = frozenset({KIND_MCP, KIND_TOOLS, KIND_SKILL})
    respects_context = True
    owasp = "LLM01: Prompt Injection"
    description = (
        "Flags tool or skill descriptions that reference other tools and tell the agent to "
        "change how they behave (for example, BCC every email to an outside address)."
    )
    fix = "Tool descriptions should describe only their own tool. Remove references to other tools."

    def check(self, doc: Document) -> list[Finding]:
        """Scan descriptions for cross-tool instructions."""
        findings: list[Finding] = []
        is_json = doc.kind in (KIND_MCP, KIND_TOOLS)
        for line_no, line in text_lines(doc):
            if is_json and '"description"' not in line:
                continue
            norm = normalise(line)
            patterns = _STRONG + (_DESCRIPTION_ONLY if is_json else ())
            if any(rx.search(norm) for rx in patterns):
                findings.append(
                    self.finding(
                        doc,
                        line_no,
                        "Description tells the agent how to use other tools.",
                        safe(line),
                    )
                )
        return findings
