"""GL-010: permission allowlists that grant far more than a project needs."""

from __future__ import annotations

import re

from glint.models import KIND_SETTINGS, Document, Finding, Rule, Severity
from glint.textutil import find_line, safe

_BROAD_BASH = re.compile(r"^Bash(?:\(\s*\*?\s*(?::\s*\*)?\s*\))?$")
_RISKY_COMMANDS = (
    "curl",
    "wget",
    "rm",
    "sudo",
    "ssh",
    "scp",
    "nc",
    "ncat",
    "bash",
    "sh",
    "zsh",
    "eval",
    "python",
    "python3",
    "node",
    "perl",
    "ruby",
    "chmod",
    "chown",
    "dd",
    "git push",
)
_RISKY_BASH = re.compile(
    r"^Bash\(\s*(?:" + "|".join(re.escape(c) for c in _RISKY_COMMANDS) + r")\s*(?::\s*\*|\s+\*|\*)\s*\)$"
)
_BROAD_FILE = re.compile(r"^(?:Read|Write|Edit|MultiEdit)\(\s*(?:/|~/?|//)\*\*?\s*\)$|^(?:Write|Edit|MultiEdit)$")
_SENSITIVE_DENY = re.compile(r"\.env|\.ssh|secret|credential", re.IGNORECASE)


class WildcardPermissions(Rule):
    """Over-broad entries in an agent's permission allowlist."""

    id = "GL-010"
    title = "Wildcard or over-broad permissions"
    default_severity = Severity.HIGH
    applies_to = frozenset({KIND_SETTINGS})
    owasp = "LLM06: Excessive Agency"
    description = (
        "Flags allowlist entries such as Bash(*), Bash(curl:*), unrestricted WebFetch or "
        "Write(/**) that let the agent run almost anything without asking."
    )
    fix = (
        "List the exact commands the agent needs (e.g. Bash(npm run test:*)) and add deny "
        "entries for secrets and network tools."
    )

    def check(self, doc: Document) -> list[Finding]:
        """Inspect permissions.allow entries."""
        data = doc.data if isinstance(doc.data, dict) else {}
        perms = data.get("permissions")
        if not isinstance(perms, dict):
            return []
        allow = perms.get("allow")
        deny = perms.get("deny") if isinstance(perms.get("deny"), list) else []
        if not isinstance(allow, list):
            return []
        protects_secrets = any(_SENSITIVE_DENY.search(str(d)) for d in deny)
        findings: list[Finding] = []
        for entry in allow:
            text = str(entry).strip()
            reason = self._reason(text)
            if not reason:
                continue
            severity = Severity.HIGH
            if text.startswith("Read") and protects_secrets:
                severity = Severity.MEDIUM
            findings.append(
                self.finding(
                    doc,
                    find_line(doc.text, f'"{text}"'),
                    f"Allowlist entry '{text}' {reason}.",
                    safe(f'"{text}"'),
                    severity=severity,
                )
            )
        return findings

    @staticmethod
    def _reason(text: str) -> str | None:
        if _BROAD_BASH.match(text):
            return "lets the agent run any shell command without asking"
        if _RISKY_BASH.match(text):
            return "lets the agent run a powerful command with any arguments"
        if text == "WebFetch":
            return "lets the agent fetch any web address"
        if _BROAD_FILE.match(text):
            return "gives file access to the whole disk or home folder"
        return None
