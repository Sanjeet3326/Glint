"""Tag MCP servers, tools and agent permissions with what they let an agent do.

The tags feed the lethal-trifecta check (GL-011), ``glint graph`` and
``glint inventory``. A tag is a guess from names, commands and
descriptions; teams can override it per server in ``.glint.toml``::

    [capabilities]
    "internal-wiki" = ["reads-private"]
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from glint.mcp import Server, iter_servers, iter_tools
from glint.models import KIND_SETTINGS, Project
from glint.textutil import find_line

READS_PRIVATE = "reads-private"
INGESTS_UNTRUSTED = "ingests-untrusted"
CAN_EXFILTRATE = "can-exfiltrate"
EXECUTES = "executes"
WRITES = "writes"

ALL_CAPS = (READS_PRIVATE, INGESTS_UNTRUSTED, CAN_EXFILTRATE, EXECUTES, WRITES)
TRIFECTA = (READS_PRIVATE, INGESTS_UNTRUSTED, CAN_EXFILTRATE)

CAP_HELP = {
    READS_PRIVATE: "reads private data (files, databases, email, secrets)",
    INGESTS_UNTRUSTED: "brings in untrusted content (web pages, issues, inbox)",
    CAN_EXFILTRATE: "can send data out (HTTP, email, messages, git push)",
    EXECUTES: "runs commands",
    WRITES: "changes files or records",
}

# Matched against "name command args url" of a server, lower-cased.
_SERVER_TAGS: tuple[tuple[re.Pattern[str], frozenset[str]], ...] = tuple(
    (re.compile(p), frozenset(caps))
    for p, caps in (
        (r"filesystem|file-system|server-files\b", (READS_PRIVATE, WRITES)),
        (
            r"postgres|mysql|mariadb|sqlite|mongo|redis|supabase|bigquery|snowflake|"
            r"\bneon\b|database|\bdb\b|clickhouse|duckdb",
            (READS_PRIVATE, WRITES),
        ),
        (r"gmail|\bemail\b|\bmail\b|outlook|imap|smtp", (READS_PRIVATE, INGESTS_UNTRUSTED, CAN_EXFILTRATE)),
        (
            r"slack|discord|\bteams\b|telegram|whatsapp|\bsms\b|twilio",
            (READS_PRIVATE, INGESTS_UNTRUSTED, CAN_EXFILTRATE),
        ),
        (r"notion|gdrive|google-drive|\bdrive\b|confluence|obsidian|calendar|dropbox|box-", (READS_PRIVATE,)),
        (r"jira|linear|asana|trello|zendesk|intercom|hubspot|salesforce", (READS_PRIVATE, INGESTS_UNTRUSTED)),
        (r"1password|\bvault\b|keychain|bitwarden|secrets?-manager|\bsecrets?\b", (READS_PRIVATE,)),
        (r"github|gitlab|bitbucket|gitea", (INGESTS_UNTRUSTED, CAN_EXFILTRATE)),
        (r"server-git\b|mcp-server-git\b|\bgit-mcp\b", (READS_PRIVATE, WRITES)),
        (
            r"\bfetch\b|server-fetch|browser|puppeteer|playwright|firecrawl|brave|tavily|\bexa\b|"
            r"search|scrap|crawl|\bweb\b|perplexity|context7",
            (INGESTS_UNTRUSTED, CAN_EXFILTRATE),
        ),
        (r"\bhttp\b|request|webhook|\bcurl\b|zapier|\bn8n\b|make\.com", (INGESTS_UNTRUSTED, CAN_EXFILTRATE)),
        (
            r"shell|terminal|\bexec\b|command|desktop-commander|\bbash\b|powershell|\bssh\b",
            (EXECUTES, READS_PRIVATE, CAN_EXFILTRATE),
        ),
        (
            r"\bs3\b|\bgcs\b|blob-storage|\baws\b|\bazure\b|\bgcp\b|cloudflare|vercel|kubernetes|\bk8s\b",
            (READS_PRIVATE, WRITES),
        ),
    )
)

# Matched against a tool name, lower-cased (e.g. "send_email").
_TOOL_TAGS: tuple[tuple[re.Pattern[str], frozenset[str]], ...] = tuple(
    (re.compile(p), frozenset(caps))
    for p, caps in (
        (
            r"\b(?:read|get|list|query|search)_?(?:file|files|secret|secrets|email|emails|messages|records|rows|table)\b"
            r"|\bread_file\b|\bsql\b|\bquery\b",
            (READS_PRIVATE,),
        ),
        (
            r"\b(?:fetch|browse|scrape|crawl|open)_?(?:url|page|web|website)?\b|\bweb_search\b|\bread_issue\b"
            r"|\bget_issue\b|\binbox\b",
            (INGESTS_UNTRUSTED,),
        ),
        (
            r"\b(?:send|post|create|publish|upload|forward)_?(?:email|mail|message|issue|comment|pull_request|pr|"
            r"webhook|request)\b|\bhttp_(?:request|post)\b|\bpush\b",
            (CAN_EXFILTRATE,),
        ),
        (r"\b(?:run|exec|execute)_?(?:command|shell|script|code)?\b|\bterminal\b", (EXECUTES,)),
        (r"\b(?:write|edit|delete|remove|update)_?(?:file|files|record|row)s?\b", (WRITES,)),
    )
)

_BROAD_BASH_RE = re.compile(r"^Bash(?:\(\s*\*?\s*(?::\s*\*)?\s*\))?$")
_NET_BASH_RE = re.compile(r"^Bash\(\s*(?:curl|wget|nc|ncat|ssh|scp|git push)\b")
_BROAD_READ_RE = re.compile(r"^Read(?:\(\s*(?:/|~/?|//)\*\*?\s*\))?$")


@dataclass(frozen=True)
class Provider:
    """Something that gives the agent capabilities: a server, a tool or a permission."""

    label: str
    kind: str  # "mcp-server", "tool" or "permission"
    path: str
    line: int
    caps: frozenset[str]
    overridden: bool = False


def server_caps(server: Server) -> frozenset[str]:
    """Guess the capabilities of an MCP server from its name and command."""
    url = re.sub(r"^[a-z]+://", "", server.url.lower())
    haystack = " ".join([server.name, server.command, *server.args, url]).lower()
    caps: set[str] = set()
    for regex, tags in _SERVER_TAGS:
        if regex.search(haystack):
            caps |= tags
    return frozenset(caps)


def tool_caps(name: str, description: str = "") -> frozenset[str]:
    """Guess the capabilities of a single tool from its name.

    Descriptions are free text and too noisy to tag reliably, so only the
    tool name (e.g. ``send_email``, ``read_file``) is used.
    """
    haystack = name.lower().replace("-", "_")
    caps: set[str] = set()
    for regex, tags in _TOOL_TAGS:
        if regex.search(haystack):
            caps |= tags
    return frozenset(caps)


def permission_caps(entry: str) -> frozenset[str]:
    """Capabilities granted by one Claude Code ``permissions.allow`` entry."""
    entry = entry.strip()
    if _BROAD_BASH_RE.match(entry):
        return frozenset({EXECUTES, READS_PRIVATE, CAN_EXFILTRATE, WRITES})
    if _NET_BASH_RE.match(entry):
        return frozenset({CAN_EXFILTRATE, INGESTS_UNTRUSTED})
    if entry == "WebFetch":
        return frozenset({INGESTS_UNTRUSTED, CAN_EXFILTRATE})
    if entry.startswith(("WebFetch(", "WebSearch")):
        return frozenset({INGESTS_UNTRUSTED})
    if _BROAD_READ_RE.match(entry):
        return frozenset({READS_PRIVATE})
    return frozenset()


def project_providers(project: Project) -> list[Provider]:
    """Every capability provider in the project, with overrides applied."""
    overrides = {k: frozenset(v) for k, v in project.capability_overrides.items()}
    providers: list[Provider] = []
    tools_by_server: dict[str, set[str]] = {}
    for doc in project.docs:
        for tool in iter_tools(doc):
            caps = tool_caps(tool.name, tool.description)
            tools_by_server.setdefault(tool.server, set()).update(caps)
            if caps:
                providers.append(Provider(f"tool '{tool.server}/{tool.name}'", "tool", tool.path, tool.line, caps))
    for doc in project.docs:
        for server in iter_servers(doc):
            if server.name in overrides:
                caps, overridden = overrides[server.name], True
            else:
                caps, overridden = server_caps(server) | tools_by_server.get(server.name, set()), False
            providers.append(
                Provider(f"server '{server.name}'", "mcp-server", server.path, server.line, frozenset(caps), overridden)
            )
    for doc in project.of_kind(KIND_SETTINGS):
        data = doc.data if isinstance(doc.data, dict) else {}
        perms = data.get("permissions")
        allow = perms.get("allow") if isinstance(perms, dict) else None
        if not isinstance(allow, list):
            continue
        for entry in allow:
            caps = permission_caps(str(entry))
            if caps:
                line = find_line(doc.text, f'"{entry}"')
                providers.append(Provider(f"permission '{entry}'", "permission", str(doc.path), line, caps))
    return [p for p in providers if p.caps]


@dataclass(frozen=True)
class Trifecta:
    """Result of the lethal-trifecta analysis."""

    by_cap: dict[str, list[Provider]]
    complete: bool
    breaker: Provider | None

    def chain(self) -> list[tuple[str, list[Provider]]]:
        """Each trifecta capability with its providers."""
        return [(cap, self.by_cap.get(cap, [])) for cap in TRIFECTA]


def analyse_trifecta(providers: list[Provider]) -> Trifecta:
    """Check whether all three trifecta capabilities are reachable together.

    When they are, find a single provider whose removal breaks the chain,
    preferring permissions (easiest to change), then tools, then servers.
    """
    by_cap: dict[str, list[Provider]] = {cap: [p for p in providers if cap in p.caps] for cap in ALL_CAPS}
    complete = all(by_cap[cap] for cap in TRIFECTA)
    breaker = None
    if complete:
        order = {"permission": 0, "tool": 1, "mcp-server": 2}
        for candidate in sorted(providers, key=lambda p: (order.get(p.kind, 3), p.label)):
            rest = [p for p in providers if p is not candidate]
            if not all(any(cap in p.caps for p in rest) for cap in TRIFECTA):
                breaker = candidate
                break
    return Trifecta(by_cap, complete, breaker)
