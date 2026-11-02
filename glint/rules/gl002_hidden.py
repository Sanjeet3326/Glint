"""GL-002: instructions hidden from human readers in rendered Markdown."""

from __future__ import annotations

import re

from glint.models import TEXT_KINDS, Document, Finding, Rule, Severity
from glint.rules._helpers import exfil_hits, injection_hits
from glint.textutil import line_of, safe

_COMMENT_RE = re.compile(r"<!--(.*?)-->", re.DOTALL)
_HIDDEN_ELEMENT_RE = re.compile(
    r"<(\w+)\b[^>]{0,300}?(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0"
    r"|\shidden(?:\s|>|=))[^>]{0,300}>(.{1,2000}?)</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_LONG_ALT_RE = re.compile(r"!\[([^\]\n]{80,})\]")
_LONG_TITLE_RE = re.compile(r"\[[^\]\n]*\]\(\S+\s+\"([^\"\n]{80,})\"\)")
_ADDRESSES_AGENT_RE = re.compile(
    r"\b(?:assistant|agent|ai|model|llm|claude|copilot|gpt|you\s+must|you\s+should|always|never)\b",
    re.IGNORECASE,
)
_SHORT_COMMENT = 80


class HiddenContent(Rule):
    """Instructions the human reader cannot see in rendered Markdown."""

    id = "GL-002"
    title = "Hidden content"
    default_severity = Severity.HIGH
    applies_to = TEXT_KINDS
    owasp = "LLM01: Prompt Injection"
    description = (
        "Flags HTML comments, hidden HTML elements and over-long image alt text or link "
        "titles that carry instructions a human reader never sees."
    )
    fix = "Move the content into visible text or delete it."

    def check(self, doc: Document) -> list[Finding]:
        """Find hidden blocks and grade them by what they contain."""
        findings: list[Finding] = []
        for match in _COMMENT_RE.finditer(doc.text):
            body = match.group(1).strip()
            if not body:
                continue
            line = line_of(doc.text, match.start())
            finding = self._grade(doc, line, "HTML comment", body)
            if finding:
                findings.append(finding)
        for match in _HIDDEN_ELEMENT_RE.finditer(doc.text):
            line = line_of(doc.text, match.start())
            body = re.sub(r"<[^>]+>", " ", match.group(2)).strip()
            if body:
                findings.append(
                    self._grade(doc, line, "hidden HTML element", body, always=True)
                    or self.finding(doc, line, "Hidden HTML element.", safe(body))
                )
        for regex, label in ((_LONG_ALT_RE, "image alt text"), (_LONG_TITLE_RE, "link title")):
            for match in regex.finditer(doc.text):
                line = line_of(doc.text, match.start())
                finding = self._grade(doc, line, label, match.group(1), always=True)
                if finding:
                    findings.append(finding)
        return findings

    def _grade(self, doc: Document, line: int, where: str, body: str, *, always: bool = False) -> Finding | None:
        hits = injection_hits(body) + exfil_hits(body)
        if hits:
            return self.finding(
                doc,
                line,
                f"Instructions hidden in an {where}: {hits[0]}.",
                safe(body),
                severity=Severity.CRITICAL,
            )
        if always or len(body) > _SHORT_COMMENT or _ADDRESSES_AGENT_RE.search(body):
            return self.finding(
                doc,
                line,
                f"Text hidden in an {where} is read by the agent but not shown to humans.",
                safe(body),
            )
        return None
