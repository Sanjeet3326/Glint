"""GL-007: MCP servers that download whatever version is latest."""

from __future__ import annotations

from glint.mcp import iter_servers, server_package
from glint.models import KIND_MCP, Document, Finding, Rule, Severity
from glint.rules._helpers import server_line
from glint.textutil import safe

_WHAT = {"npm": "npm package", "pypi": "Python package", "container": "container image"}


class UnpinnedMcpServers(Rule):
    """Servers launched from a package with no exact version."""

    id = "GL-007"
    title = "Unpinned MCP servers"
    default_severity = Severity.MEDIUM
    applies_to = frozenset({KIND_MCP})
    owasp = "LLM03: Supply Chain"
    description = (
        "Flags MCP servers started through npx, bunx, pnpm dlx, uvx, pipx or docker without "
        "an exact version, so a new (possibly compromised) release runs automatically."
    )
    fix = "Pin an exact version (e.g. some-mcp-server@1.4.2) and update it deliberately."

    def check(self, doc: Document) -> list[Finding]:
        """Check every package-runner server for a pinned version."""
        findings: list[Finding] = []
        for server in iter_servers(doc):
            package = server_package(server)
            if package is None or package.pinned:
                continue
            shown = package.name + (f"@{package.version}" if package.version else "")
            how = "a fixed tag or digest" if package.ecosystem == "container" else "an exact version"
            findings.append(
                self.finding(
                    doc,
                    server_line(doc, server, '"args"'),
                    f"Server '{server.name}' runs {_WHAT[package.ecosystem]} '{shown}' without {how}.",
                    safe(server.cmdline),
                )
            )
        return findings
