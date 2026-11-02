"""GL-004: MCP servers with shell, full-disk or unrestricted access."""

from __future__ import annotations

import re

from glint.models import KIND_MCP, Document, Finding, Rule, Severity
from glint.rules._helpers import Server, iter_servers, server_line
from glint.textutil import safe

_SHELLS = frozenset({"bash", "sh", "zsh", "dash", "fish", "cmd", "powershell", "pwsh"})
_SHELL_FLAGS = frozenset({"-c", "/c", "/k", "-command", "-encodedcommand", "-e"})
_EXEC_SERVER_RE = re.compile(
    r"(?:shell|terminal|command|exec|cmd)[-_]?(?:server|mcp)\b|\bmcp[-_]?(?:shell|terminal|exec)"
    r"|desktop[-_]commander|server[-_](?:shell|terminal|exec)",
    re.IGNORECASE,
)
_FILESYSTEM_RE = re.compile(r"filesystem", re.IGNORECASE)
_BROAD_PATHS = frozenset({"/", "~", "~/", "$HOME", "${HOME}", "%USERPROFILE%", "C:\\", "C:/", "C:", "/Users", "/home"})


class DangerousMcpTools(Rule):
    """MCP servers that can run commands or reach the whole disk."""

    id = "GL-004"
    title = "Dangerous MCP tools"
    default_severity = Severity.CRITICAL
    applies_to = frozenset({KIND_MCP})
    owasp = "LLM06: Excessive Agency"
    description = (
        "Flags MCP servers that run raw shell commands, offer command execution as a tool, "
        "or give file access to the whole disk or home folder."
    )
    fix = "Limit the path or command list, or require user approval for this server's tools."

    def check(self, doc: Document) -> list[Finding]:
        """Inspect each server's command and arguments."""
        findings: list[Finding] = []
        for server in iter_servers(doc):
            findings.extend(self._check_server(doc, server))
        return findings

    def _check_server(self, doc: Document, server: Server) -> list[Finding]:
        out: list[Finding] = []
        lowered = [a.lower() for a in server.args]
        cmdline = " ".join([server.command, *server.args])
        if server.command_name in _SHELLS and any(a in _SHELL_FLAGS for a in lowered):
            out.append(
                self.finding(
                    doc,
                    server_line(doc, server, '"command"'),
                    f"Server '{server.name}' runs a raw shell command line.",
                    safe(cmdline),
                )
            )
        elif _EXEC_SERVER_RE.search(cmdline):
            out.append(
                self.finding(
                    doc,
                    server.line,
                    f"Server '{server.name}' gives the agent a tool that runs shell commands.",
                    safe(cmdline),
                )
            )
        if _FILESYSTEM_RE.search(cmdline):
            for arg in server.args:
                if arg.rstrip("/\\") in {p.rstrip("/\\") for p in _BROAD_PATHS} or arg in _BROAD_PATHS:
                    out.append(
                        self.finding(
                            doc,
                            server_line(doc, server, f'"{arg}"'.replace("\\", "\\\\")),
                            f"Filesystem server '{server.name}' can reach '{arg}' (the whole disk or home folder).",
                            safe(cmdline),
                            fix="Point the filesystem server at the project folder only, e.g. './docs'.",
                        )
                    )
                    break
        return out
