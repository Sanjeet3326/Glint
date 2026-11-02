"""GL-009: settings that let tools run with no human approval."""

from __future__ import annotations

import json
import re

from glint.models import (
    KIND_MCP,
    KIND_SETTINGS,
    TEXT_KINDS,
    Document,
    Finding,
    Rule,
    Severity,
)
from glint.rules._helpers import iter_servers, server_line, text_lines
from glint.textutil import find_line, safe

_APPROVE_KEYS = ("autoApprove", "alwaysAllow", "auto_approve", "always_allow")
_RISKY_TOOL_RE = re.compile(
    r"\*|exec|shell|command|run|terminal|write|delete|remove|send|post|email|fetch|http|push|deploy",
    re.IGNORECASE,
)
_SKIP_FLAG_RE = re.compile(r"--dangerously-skip-permissions|--yolo\b|--auto-approve-all|--no-confirm")


class AutoApprove(Rule):
    """Tools allowed to run without asking the user."""

    id = "GL-009"
    title = "Auto-approve and skip-permission flags"
    default_severity = Severity.HIGH
    applies_to = frozenset({KIND_MCP, KIND_SETTINGS}) | TEXT_KINDS
    respects_context = True
    owasp = "LLM06: Excessive Agency"
    description = (
        "Flags MCP auto-approve lists, settings that trust every project MCP server or "
        "bypass permission prompts, and skip-permission command-line flags."
    )
    fix = "Remove auto-approval for tools that write, execute or send data. Auto-approve read-only tools only."

    def check(self, doc: Document) -> list[Finding]:
        """Look for auto-approval in configs and skip flags in text."""
        findings: list[Finding] = []
        if doc.kind == KIND_MCP:
            findings.extend(self._mcp(doc))
        elif doc.kind == KIND_SETTINGS:
            findings.extend(self._settings(doc))
        for line_no, line in text_lines(doc):
            if _SKIP_FLAG_RE.search(line):
                findings.append(
                    self.finding(
                        doc,
                        line_no,
                        "Line uses a flag that skips every permission prompt.",
                        safe(line),
                    )
                )
        return findings

    def _mcp(self, doc: Document) -> list[Finding]:
        out: list[Finding] = []
        for server in iter_servers(doc):
            for key in _APPROVE_KEYS:
                value = server.raw.get(key)
                if not value:
                    continue
                tools = value if isinstance(value, list) else ["*"]
                risky = [str(t) for t in tools if _RISKY_TOOL_RE.search(str(t))]
                out.append(
                    self.finding(
                        doc,
                        server_line(doc, server, f'"{key}"'),
                        f"Server '{server.name}' auto-approves "
                        + (f"risky tools: {', '.join(risky)}." if risky else f"{len(tools)} tool(s)."),
                        safe(f'"{key}": {json.dumps(value)}'),
                        severity=Severity.CRITICAL if risky else Severity.HIGH,
                    )
                )
        return out

    def _settings(self, doc: Document) -> list[Finding]:
        out: list[Finding] = []
        data = doc.data if isinstance(doc.data, dict) else {}
        if data.get("enableAllProjectMcpServers") is True:
            out.append(
                self.finding(
                    doc,
                    find_line(doc.text, "enableAllProjectMcpServers"),
                    "Every MCP server defined in the project is trusted automatically.",
                    '"enableAllProjectMcpServers": true',
                    fix="List approved servers in enabledMcpjsonServers instead.",
                )
            )
        perms = data.get("permissions")
        if isinstance(perms, dict) and perms.get("defaultMode") == "bypassPermissions":
            out.append(
                self.finding(
                    doc,
                    find_line(doc.text, "defaultMode"),
                    "Permission prompts are bypassed for every tool.",
                    '"defaultMode": "bypassPermissions"',
                    severity=Severity.CRITICAL,
                    fix="Use the default mode and allow specific commands instead.",
                )
            )
        return out
