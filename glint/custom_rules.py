"""Team-defined pattern rules from ``.glint.toml``.

Example::

    [[rules]]
    id = "ORG-001"
    title = "Internal hostnames in prompts"
    severity = "medium"
    applies_to = ["instructions", "prompt"]
    pattern = '\\b[a-z0-9-]+\\.corp\\.example\\.com\\b'
    fix = "Do not put internal hostnames in agent files."

Custom rules can only add findings. They go through the same context
filtering, ignores and reporting as built-in rules.
"""

from __future__ import annotations

import re
import time
from typing import Any

from glint.models import ALL_KINDS, TEXT_KINDS, Document, Finding, Rule, Severity
from glint.textutil import safe

ID_RE = re.compile(r"^[A-Z][A-Z0-9]{1,9}-\d{3}$")
# Nested quantifiers such as (a+)+ or (\w*)* can take exponential time.
_NESTED_QUANTIFIER = re.compile(r"\((?:[^()\\]|\\.)*[+*](?:[^()\\]|\\.)*\)\s*(?:[+*]|\{\d*,?\d*\})")
_PROBES = ("a" * 22 + "!", "aaaaaaaaaaaaaaaaaaaa\n!", " " * 22 + "x", "ab" * 11 + "!")


class CustomRuleError(ValueError):
    """Raised for an invalid custom rule definition."""


class PatternRule(Rule):
    """A regex rule defined in configuration."""

    respects_context = True

    def __init__(self, spec: dict[str, Any]) -> None:
        """Validate ``spec`` and build the rule."""
        rule_id = str(spec.get("id", "")).upper()
        if not ID_RE.match(rule_id) or rule_id.startswith("GL-"):
            raise CustomRuleError(f"custom rule id {rule_id!r} must look like ORG-001 and not start with GL-")
        self.id = rule_id
        self.title = str(spec.get("title") or rule_id)
        try:
            self.default_severity = Severity.parse(str(spec.get("severity", "medium")))
        except ValueError as exc:
            raise CustomRuleError(f"{rule_id}: {exc}") from exc
        kinds = spec.get("applies_to", sorted(TEXT_KINDS))
        if not isinstance(kinds, list) or not set(kinds) <= ALL_KINDS:
            raise CustomRuleError(f"{rule_id}: applies_to must be a list of: {', '.join(sorted(ALL_KINDS))}")
        self.applies_to = frozenset(str(k) for k in kinds)
        self.fix = str(spec.get("fix") or "Review and remove this content.")
        self.description = str(spec.get("description") or self.title)
        self.owasp = str(spec.get("owasp", ""))
        self.message = str(spec.get("message") or f"Matches custom rule: {self.title}.")
        pattern = str(spec.get("pattern", ""))
        if not pattern:
            raise CustomRuleError(f"{rule_id}: pattern is required")
        self.pattern = compile_safe(pattern, rule_id, bool(spec.get("ignore_case", True)))

    def check(self, doc: Document) -> list[Finding]:
        """Report every line matching the pattern."""
        return [
            self.finding(doc, line_no, self.message, safe(line))
            for line_no, line in enumerate(doc.lines, start=1)
            if self.pattern.search(line)
        ]


def compile_safe(pattern: str, rule_id: str, ignore_case: bool = True) -> re.Pattern[str]:
    """Compile a user regex, rejecting patterns likely to hang the scanner."""
    if _NESTED_QUANTIFIER.search(pattern):
        raise CustomRuleError(f"{rule_id}: pattern has a nested quantifier such as (a+)+, which can hang the scan")
    try:
        regex = re.compile(pattern, re.IGNORECASE if ignore_case else 0)
    except re.error as exc:
        raise CustomRuleError(f"{rule_id}: invalid pattern: {exc}") from exc
    for probe in _PROBES:
        start = time.perf_counter()
        regex.search(probe)
        if time.perf_counter() - start > 0.05:
            raise CustomRuleError(f"{rule_id}: pattern is too slow on simple input; simplify it")
    return regex


def build_custom_rules(specs: Any) -> list[Rule]:
    """Build rules from the ``[[rules]]`` array of ``.glint.toml``."""
    if specs is None:
        return []
    if not isinstance(specs, list):
        raise CustomRuleError("[[rules]] must be an array of tables")
    rules: list[Rule] = []
    seen: set[str] = set()
    for spec in specs:
        if not isinstance(spec, dict):
            raise CustomRuleError("each [[rules]] entry must be a table")
        rule = PatternRule(spec)
        if rule.id in seen:
            raise CustomRuleError(f"duplicate custom rule id {rule.id}")
        seen.add(rule.id)
        rules.append(rule)
    return rules
