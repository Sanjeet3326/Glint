"""Popular MCP server packages, used to spot look-alike names (GL-015).

This list is intentionally conservative: only widely used packages from
their official publishers. Contributions are welcome.
"""

from __future__ import annotations

NPM_PACKAGES = frozenset(
    {
        "@modelcontextprotocol/server-filesystem",
        "@modelcontextprotocol/server-memory",
        "@modelcontextprotocol/server-everything",
        "@modelcontextprotocol/server-sequential-thinking",
        "@modelcontextprotocol/server-github",
        "@modelcontextprotocol/server-gitlab",
        "@modelcontextprotocol/server-postgres",
        "@modelcontextprotocol/server-puppeteer",
        "@modelcontextprotocol/server-brave-search",
        "@modelcontextprotocol/server-google-maps",
        "@modelcontextprotocol/server-slack",
        "@modelcontextprotocol/server-gdrive",
        "@modelcontextprotocol/server-redis",
        "@modelcontextprotocol/inspector",
        "@playwright/mcp",
        "@upstash/context7-mcp",
        "@notionhq/notion-mcp-server",
        "@stripe/mcp",
        "@supabase/mcp-server-supabase",
        "@sentry/mcp-server",
        "@browsermcp/mcp",
        "@wonderwhy-er/desktop-commander",
        "@cloudflare/mcp-server-cloudflare",
        "@azure/mcp",
        "@heroku/mcp-server",
        "figma-developer-mcp",
        "firecrawl-mcp",
        "mcp-remote",
    }
)

PYPI_PACKAGES = frozenset(
    {
        "mcp-server-fetch",
        "mcp-server-git",
        "mcp-server-time",
        "mcp-server-sqlite",
        "mcp-server-sentry",
    }
)

KNOWN_PACKAGES = NPM_PACKAGES | PYPI_PACKAGES

# Characters that look alike in most fonts, folded to one form.
_CONFUSABLES = (("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("i", "l"), ("5", "s"), ("_", "-"), (".", "-"))


def skeleton(name: str) -> str:
    """Fold look-alike characters so 'modelcontextprotocoI' matches 'modelcontextprotocol'."""
    out = name.lower()
    for a, b in _CONFUSABLES:
        out = out.replace(a, b)
    return out


def distance(a: str, b: str) -> int:
    """Damerau-Levenshtein distance (adjacent swaps count as one edit)."""
    rows = [list(range(len(b) + 1))]
    for i in range(1, len(a) + 1):
        row = [i] + [0] * len(b)
        for j in range(1, len(b) + 1):
            cost = 0 if a[i - 1] == b[j - 1] else 1
            row[j] = min(row[j - 1] + 1, rows[i - 1][j] + 1, rows[i - 1][j - 1] + cost)
            if i > 1 and j > 1 and a[i - 1] == b[j - 2] and a[i - 2] == b[j - 1]:
                row[j] = min(row[j], rows[i - 2][j - 2] + 1)
        rows.append(row)
    return rows[-1][-1]


def _split_scope(name: str) -> tuple[str, str]:
    if name.startswith("@") and "/" in name:
        scope, rest = name.split("/", 1)
        return scope, rest
    return "", name


def closest_known(name: str, ecosystem: str) -> str | None:
    """Return the known package that ``name`` imitates, or None."""
    pool = NPM_PACKAGES if ecosystem == "npm" else PYPI_PACKAGES
    if name in pool:
        return None
    folded = skeleton(name)
    limit = 1 if len(name) < 20 else 2
    scope, rest = _split_scope(name.lower())
    for known in sorted(pool):
        if folded == skeleton(known) or distance(name.lower(), known) <= limit:
            return known
        known_scope, known_rest = _split_scope(known)
        scope_limit = 3 if len(known_scope) >= 10 else 1
        if scope and known_scope and rest == known_rest and 0 < distance(scope, known_scope) <= scope_limit:
            return known
    return None
