"""GL-013: agent hooks that run downloaded or hidden code automatically."""

from __future__ import annotations

import re
from collections.abc import Iterator
from typing import Any

from glint.models import KIND_SETTINGS, Document, Finding, Rule, Severity
from glint.textutil import find_line, safe

_PIPE_TO_SHELL = re.compile(
    r"\b(?:curl|wget|iwr|invoke-webrequest|irm|invoke-restmethod)\b[^|;&\n]{0,300}\|\s*(?:sudo\s+)?"
    r"(?:ba|z|da)?sh\b|\b(?:iwr|irm|invoke-webrequest|invoke-restmethod)\b[^\n]{0,300}\|\s*iex\b|\biex\s*\(",
    re.IGNORECASE,
)
_EVAL_DOWNLOAD = re.compile(r"(?:eval|source|\.)\s+[\"']?\$\(\s*(?:curl|wget)\b|<\(\s*(?:curl|wget)\b", re.IGNORECASE)
_DECODE_TO_SHELL = re.compile(
    r"base64\s+(?:-d|--decode|-D)\b[^\n]{0,200}\|\s*(?:ba|z)?sh\b|frombase64string", re.IGNORECASE
)
_URL = re.compile(r"https?://[^\s'\"|;)]+", re.IGNORECASE)
_OUTSIDE_SCRIPT = re.compile(
    r"(?:^|[\s;&|])(?:/tmp/|/var/tmp/|/dev/shm/|~/|\$HOME/|%TEMP%|%APPDATA%)\S+", re.IGNORECASE
)
_LOCALHOST = re.compile(r"https?://(?:localhost|127\.0\.0\.1|\[::1\])", re.IGNORECASE)


def iter_hook_commands(data: Any) -> Iterator[tuple[str, str]]:
    """Yield (event name, command) for every command hook in Claude Code settings."""
    hooks = data.get("hooks") if isinstance(data, dict) else None
    if not isinstance(hooks, dict):
        return
    for event, entries in hooks.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            inner = entry.get("hooks", [entry]) if isinstance(entry, dict) else []
            for hook in inner if isinstance(inner, list) else []:
                if isinstance(hook, dict) and isinstance(hook.get("command"), str):
                    yield str(event), hook["command"]


class RiskyHooks(Rule):
    """Hooks that download and run code, or run scripts from outside the repo."""

    id = "GL-013"
    title = "Risky hooks"
    default_severity = Severity.HIGH
    applies_to = frozenset({KIND_SETTINGS})
    owasp = "LLM03: Supply Chain"
    description = (
        "Flags agent hooks (which run automatically on events such as session start or every tool "
        "call) that pipe downloads into a shell, decode and run hidden code, call remote URLs or run "
        "scripts from temporary or home folders."
    )
    fix = "Keep hook scripts in the repository, reviewed and versioned. Never pipe network content into a shell."

    def check(self, doc: Document) -> list[Finding]:
        """Inspect every hook command."""
        findings: list[Finding] = []
        for event, command in iter_hook_commands(doc.data):
            line = find_line(doc.text, command[:40].replace("\\", "\\\\").replace('"', '\\"'))
            if _PIPE_TO_SHELL.search(command) or _EVAL_DOWNLOAD.search(command):
                reason, severity = "downloads code and runs it", Severity.CRITICAL
            elif _DECODE_TO_SHELL.search(command):
                reason, severity = "decodes hidden code and runs it", Severity.CRITICAL
            elif _URL.search(command) and not _LOCALHOST.search(command):
                reason, severity = "contacts a remote URL", Severity.HIGH
            elif _OUTSIDE_SCRIPT.search(command):
                reason, severity = "runs a script from outside the repository", Severity.MEDIUM
            else:
                continue
            findings.append(
                self.finding(
                    doc,
                    line,
                    f"{event} hook {reason} automatically.",
                    safe(command),
                    severity=severity,
                )
            )
        return findings
