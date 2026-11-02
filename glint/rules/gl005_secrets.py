"""GL-005: credentials stored in agent files and MCP configs."""

from __future__ import annotations

import re

from glint.models import ALL_KINDS, Confidence, Document, Finding, Rule, Severity
from glint.rules._helpers import text_lines
from glint.textutil import mask, safe, shannon_entropy

_KNOWN: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p), name)
    for p, name in (
        (r"\bgh[pousr]_[A-Za-z0-9]{36}\b", "GitHub token"),
        (r"\bgithub_pat_[A-Za-z0-9_]{60,100}\b", "GitHub fine-grained token"),
        (r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b", "AWS access key"),
        (r"\bsk-ant-[A-Za-z0-9_-]{20,}", "Anthropic API key"),
        (r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{32,}", "OpenAI-style API key"),
        (r"\bxox[abprs]-[A-Za-z0-9-]{10,}", "Slack token"),
        (r"\bAIza[0-9A-Za-z_-]{35}\b", "Google API key"),
        (r"\bglpat-[A-Za-z0-9_-]{20,}", "GitLab token"),
        (r"\b(?:sk|rk)_live_[A-Za-z0-9]{20,}", "Stripe live key"),
        (r"-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY(?: BLOCK)?-----", "private key"),
    )
)

_KEYED_RE = re.compile(
    r"""["']?([A-Za-z0-9_.-]{0,40}(?:token|secret|password|passwd|api[_-]?key|apikey|access[_-]?key"""
    r"""|private[_-]?key|auth)[A-Za-z0-9_.-]{0,40})["']?\s*[:=]\s*["']([^"'\s]{20,200})["']""",
    re.IGNORECASE,
)
_PLACEHOLDER_RE = re.compile(
    r"^\$\{?[A-Za-z_]|^<.*>$|^\{\{.*\}\}$|your[-_]|example|placeholder|changeme|redacted"
    r"|^x{6,}|^\*{4,}|replace[-_]?me|dummy|^%[A-Z_]+%$",
    re.IGNORECASE,
)
_ENTROPY_MIN = 4.0


class LeakedSecrets(Rule):
    """Credentials written directly into agent files."""

    id = "GL-005"
    title = "Leaked secrets"
    default_severity = Severity.CRITICAL
    applies_to = ALL_KINDS
    owasp = "LLM02: Sensitive Information Disclosure"
    description = (
        "Flags known token formats (GitHub, AWS, Anthropic, OpenAI, Slack, Google, GitLab, "
        "Stripe, private keys) and high-entropy values under secret-like keys."
    )
    fix = (
        "Move the secret to an environment variable or secret manager "
        '(e.g. "${GITHUB_TOKEN}") and rotate the exposed key now.'
    )

    def check(self, doc: Document) -> list[Finding]:
        """Scan each line; never print a full secret."""
        findings: list[Finding] = []
        for line_no, line in text_lines(doc):
            hit = self._known(line) or self._keyed(line)
            if hit is None:
                continue
            name, secret, confidence = hit
            redacted = line.replace(secret, mask(secret))
            findings.append(
                self.finding(
                    doc,
                    line_no,
                    f"{name} stored in plain text.",
                    safe(redacted),
                    confidence=confidence,
                )
            )
        return findings

    @staticmethod
    def _known(line: str) -> tuple[str, str, Confidence] | None:
        for regex, name in _KNOWN:
            match = regex.search(line)
            if match:
                return name, match.group(0), Confidence.HIGH
        return None

    @staticmethod
    def _keyed(line: str) -> tuple[str, str, Confidence] | None:
        for match in _KEYED_RE.finditer(line):
            key, value = match.group(1), match.group(2)
            if _PLACEHOLDER_RE.search(value):
                continue
            if shannon_entropy(value) >= _ENTROPY_MIN:
                return f"Secret-like value for '{key}'", value, Confidence.MEDIUM
        return None
