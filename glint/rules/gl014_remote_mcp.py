"""GL-014: remote MCP servers reached insecurely."""

from __future__ import annotations

import re
from urllib.parse import parse_qsl, urlsplit

from glint.mcp import iter_servers
from glint.models import KIND_MCP, Document, Finding, Rule, Severity
from glint.rules._helpers import server_line
from glint.textutil import mask, safe

_LOCAL_HOSTS = re.compile(r"^(?:localhost|127(?:\.\d{1,3}){3}|\[?::1\]?|0\.0\.0\.0|host\.docker\.internal)$")
_SECRET_PARAM = re.compile(r"key|token|secret|password|passwd|auth|sig|signature|credential", re.IGNORECASE)
_PLACEHOLDER = re.compile(r"^\$\{?\w+\}?$|^\{\{.*\}\}$|^<.*>$|^%\w+%$")
_BEARER = re.compile(r"^(?:bearer|basic|token)\s+(\S{8,})$", re.IGNORECASE)


class InsecureRemoteMcp(Rule):
    """Remote servers over plain HTTP or with credentials in the URL or headers."""

    id = "GL-014"
    title = "Insecure remote MCP server"
    default_severity = Severity.HIGH
    applies_to = frozenset({KIND_MCP})
    owasp = "LLM02: Sensitive Information Disclosure"
    description = (
        "Flags remote MCP servers reached over plain HTTP (anything on the network can read or change "
        "the traffic) and credentials written into the server URL or headers."
    )
    fix = 'Use HTTPS and pass credentials through environment variables (e.g. "Bearer ${API_TOKEN}").'

    def check(self, doc: Document) -> list[Finding]:
        """Inspect each remote server's URL and headers."""
        findings: list[Finding] = []
        for server in iter_servers(doc):
            if not server.url:
                continue
            line = server_line(doc, server, '"url"')
            try:
                parts = urlsplit(server.url)
            except ValueError:
                continue
            host = (parts.hostname or "").lower()
            if parts.scheme == "http" and host and not _LOCAL_HOSTS.match(host):
                findings.append(
                    self.finding(doc, line, f"Server '{server.name}' uses plain HTTP to {host}.", safe(server.url))
                )
            for key, value in parse_qsl(parts.query, keep_blank_values=True):
                if _SECRET_PARAM.search(key) and value and not _PLACEHOLDER.match(value):
                    shown = server.url.replace(value, mask(value))
                    findings.append(
                        self.finding(
                            doc,
                            line,
                            f"Server '{server.name}' has a credential in its URL ('{key}'); URLs end up in logs.",
                            safe(shown),
                            severity=Severity.CRITICAL,
                        )
                    )
                    break
            for key, value in server.headers.items():
                match = _BEARER.match(str(value).strip())
                if match and not _PLACEHOLDER.match(match.group(1)):
                    findings.append(
                        self.finding(
                            doc,
                            server_line(doc, server, f'"{key}"'),
                            f"Server '{server.name}' has a literal credential in its '{key}' header.",
                            safe(f'"{key}": "{str(value).split()[0]} {mask(match.group(1))}"'),
                            severity=Severity.CRITICAL,
                        )
                    )
        return findings
