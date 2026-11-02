"""GL-015: MCP packages whose names look like a well-known package."""

from __future__ import annotations

from glint.known_packages import KNOWN_PACKAGES, closest_known
from glint.mcp import iter_servers, server_package
from glint.models import KIND_MCP, Document, Finding, Rule, Severity
from glint.rules._helpers import server_line
from glint.textutil import safe


class LookalikePackage(Rule):
    """Possible typosquats of popular MCP server packages."""

    id = "GL-015"
    title = "Look-alike package name"
    default_severity = Severity.HIGH
    applies_to = frozenset({KIND_MCP})
    owasp = "LLM03: Supply Chain"
    description = (
        "Compares MCP server packages with a built-in list of popular packages and flags names that "
        "are one or two characters away, or use look-alike characters (for example a capital I for l)."
    )
    fix = "Check the package name against the official source before running it, and pin the real package."

    def check(self, doc: Document) -> list[Finding]:
        """Flag packages close to, but not equal to, a known package."""
        findings: list[Finding] = []
        for server in iter_servers(doc):
            package = server_package(server)
            if package is None or package.ecosystem == "container" or package.name in KNOWN_PACKAGES:
                continue
            near = closest_known(package.name, package.ecosystem)
            if near:
                findings.append(
                    self.finding(
                        doc,
                        server_line(doc, server, '"args"'),
                        f"Server '{server.name}' runs '{package.name}', which looks like the well-known "
                        f"package '{near}'. It may be a typosquat.",
                        safe(server.cmdline),
                    )
                )
        return findings
