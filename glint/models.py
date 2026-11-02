"""Core data types shared by every part of Glint."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import IntEnum
from pathlib import Path, PurePosixPath
from typing import Any


class Severity(IntEnum):
    """How bad a finding is if it is real."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3
    CRITICAL = 4

    @classmethod
    def parse(cls, value: str) -> Severity:
        """Return the severity named by ``value`` (case-insensitive)."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(s.name.lower() for s in cls)
            raise ValueError(f"unknown severity {value!r} (choose from {choices})") from exc

    def bump(self) -> Severity:
        """Return the next higher severity, capped at CRITICAL."""
        return Severity(min(self + 1, Severity.CRITICAL))

    @property
    def label(self) -> str:
        """Lower-case name used in reports."""
        return self.name.lower()


class Confidence(IntEnum):
    """How sure Glint is that a finding is real."""

    LOW = 1
    MEDIUM = 2
    HIGH = 3

    @classmethod
    def parse(cls, value: str) -> Confidence:
        """Return the confidence named by ``value`` (case-insensitive)."""
        try:
            return cls[value.strip().upper()]
        except KeyError as exc:
            choices = ", ".join(c.name.lower() for c in cls)
            raise ValueError(f"unknown confidence {value!r} (choose from {choices})") from exc

    @property
    def label(self) -> str:
        """Lower-case name used in reports."""
        return self.name.lower()


# Kinds of agent files the collector can produce.
KIND_INSTRUCTIONS = "instructions"
KIND_PROMPT = "prompt"
KIND_SKILL = "skill"
KIND_MCP = "mcp-config"
KIND_SETTINGS = "agent-settings"
KIND_TOOLS = "tool-listing"

TEXT_KINDS = frozenset({KIND_INSTRUCTIONS, KIND_PROMPT, KIND_SKILL})
JSON_KINDS = frozenset({KIND_MCP, KIND_SETTINGS, KIND_TOOLS})
ALL_KINDS = TEXT_KINDS | JSON_KINDS

# Line contexts assigned by the parser.
CTX_TEXT = "text"
CTX_HEADING = "heading"
CTX_FENCED = "fenced-code"
CTX_QUOTE = "blockquote"
CTX_COMMENT = "html-comment"
CTX_FRONT_MATTER = "front-matter"


@dataclass(frozen=True)
class Document:
    """One agent-related file, loaded and ready for rules to inspect."""

    path: PurePosixPath
    kind: str
    text: str
    data: Any = None
    parse_error: str | None = None
    contexts: tuple[str, ...] = ()
    lines: tuple[str, ...] = field(default=(), repr=False)

    def context(self, line_no: int) -> str:
        """Return the context of 1-based line ``line_no``."""
        if 1 <= line_no <= len(self.contexts):
            return self.contexts[line_no - 1]
        return CTX_TEXT


@dataclass(frozen=True)
class Finding:
    """A single problem found in a document."""

    rule_id: str
    title: str
    severity: Severity
    confidence: Confidence
    path: PurePosixPath
    line: int
    message: str
    evidence: str
    fix: str
    owasp: str = ""
    suppressed: bool = False

    def sort_key(self) -> tuple[int, str, int, str]:
        """Order: most severe first, then by file, line and rule."""
        return (-int(self.severity), str(self.path), self.line, self.rule_id)


class Rule(ABC):
    """Base class for every Glint rule.

    Subclasses set the class attributes and implement :meth:`check`.
    The registry discovers subclasses automatically.
    """

    id: str = ""
    title: str = ""
    default_severity: Severity = Severity.MEDIUM
    applies_to: frozenset[str] = ALL_KINDS
    fix: str = ""
    owasp: str = ""
    description: str = ""
    # When True, matches inside fenced code and blockquotes are dropped
    # unless the scan runs with --strict.
    respects_context: bool = False

    @abstractmethod
    def check(self, doc: Document) -> list[Finding]:
        """Return every finding for ``doc``."""

    def finding(
        self,
        doc: Document,
        line: int,
        message: str,
        evidence: str,
        *,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.HIGH,
        fix: str | None = None,
    ) -> Finding:
        """Build a :class:`Finding` for this rule with sensible defaults."""
        return self.finding_at(doc.path, line, message, evidence, severity=severity, confidence=confidence, fix=fix)

    def finding_at(
        self,
        path: PurePosixPath,
        line: int,
        message: str,
        evidence: str,
        *,
        severity: Severity | None = None,
        confidence: Confidence = Confidence.HIGH,
        fix: str | None = None,
    ) -> Finding:
        """Build a :class:`Finding` for an explicit file path."""
        return Finding(
            rule_id=self.id,
            title=self.title,
            severity=severity or self.default_severity,
            confidence=confidence,
            path=path,
            line=max(line, 1),
            message=message,
            evidence=evidence,
            fix=fix or self.fix,
            owasp=self.owasp,
        )


@dataclass
class Project:
    """Every document of one scan, for rules that reason across files."""

    root: Path
    docs: list[Document]
    capability_overrides: dict[str, list[str]] = field(default_factory=dict)
    lock: dict[str, Any] | None = None
    lock_path: PurePosixPath | None = None

    def of_kind(self, *kinds: str) -> list[Document]:
        """Documents whose kind is one of ``kinds``."""
        return [d for d in self.docs if d.kind in kinds]


class ProjectRule(Rule):
    """A rule that looks at the whole project at once (for example, tool combinations)."""

    def check(self, doc: Document) -> list[Finding]:
        """Project rules do not run per document."""
        return []

    @abstractmethod
    def check_project(self, project: Project) -> list[Finding]:
        """Return every finding for the project."""
