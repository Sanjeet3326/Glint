"""``glint inventory`` and ``glint graph``: what agents can touch in a repository."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from glint.capabilities import ALL_CAPS, CAP_HELP, TRIFECTA, Provider, analyse_trifecta, project_providers
from glint.mcp import iter_servers, iter_tools, server_package
from glint.models import KIND_SETTINGS, Project
from glint.reporters.terminal import terminal_width
from glint.rules.gl013_hooks import iter_hook_commands
from glint.textutil import safe


@dataclass
class Inventory:
    """Everything an agent setup is made of."""

    files: dict[str, list[str]] = field(default_factory=dict)
    servers: list[dict[str, Any]] = field(default_factory=list)
    tools: list[dict[str, Any]] = field(default_factory=list)
    permissions: list[dict[str, Any]] = field(default_factory=list)
    hooks: list[dict[str, Any]] = field(default_factory=list)
    providers: list[Provider] = field(default_factory=list)


def build_inventory(project: Project) -> Inventory:
    """Collect files, servers, tools, permissions and hooks from a project."""
    inv = Inventory()
    providers = project_providers(project)
    inv.providers = providers
    caps_by_label = {p.label: p.caps for p in providers}
    for doc in project.docs:
        inv.files.setdefault(doc.kind, []).append(str(doc.path))
        for server in iter_servers(doc):
            package = server_package(server)
            launch = server.url or server.cmdline
            inv.servers.append(
                {
                    "name": server.name,
                    "file": server.path,
                    "line": server.line,
                    "transport": "remote" if server.url else "local",
                    "launch": launch,
                    "package": package.name if package else None,
                    "version": package.version if package else None,
                    "pinned": package.pinned if package else None,
                    "capabilities": sorted(caps_by_label.get(f"server '{server.name}'", frozenset())),
                }
            )
        for tool in iter_tools(doc):
            inv.tools.append(
                {
                    "server": tool.server,
                    "name": tool.name,
                    "file": tool.path,
                    "description": tool.description,
                    "capabilities": sorted(caps_by_label.get(f"tool '{tool.server}/{tool.name}'", frozenset())),
                }
            )
        if doc.kind == KIND_SETTINGS and isinstance(doc.data, dict):
            perms = doc.data.get("permissions", {})
            if isinstance(perms, dict):
                for mode in ("allow", "ask", "deny"):
                    for entry in perms.get(mode, []) if isinstance(perms.get(mode), list) else []:
                        inv.permissions.append({"file": str(doc.path), "mode": mode, "entry": str(entry)})
            for event, command in iter_hook_commands(doc.data):
                inv.hooks.append({"file": str(doc.path), "event": event, "command": command})
    return inv


def inventory_dict(inv: Inventory) -> dict[str, Any]:
    """Plain JSON form of an inventory."""
    trifecta = analyse_trifecta(inv.providers)
    return {
        "files": inv.files,
        "servers": inv.servers,
        "tools": inv.tools,
        "permissions": inv.permissions,
        "hooks": inv.hooks,
        "trifecta": {
            "complete": trifecta.complete,
            "legs": {cap: [p.label for p in provs] for cap, provs in trifecta.chain()},
            "smallest_fix": trifecta.breaker.label if trifecta.breaker else None,
        },
    }


def _table(headers: list[str], rows: list[list[str]]) -> list[str]:
    widths = [len(h) for h in headers]
    for row in rows:
        for i, cell in enumerate(row):
            widths[i] = min(max(widths[i], len(cell)), 60)

    def fmt(cells: list[str]) -> str:
        return "  ".join((c if len(c) <= 60 else c[:57] + "...").ljust(widths[i]) for i, c in enumerate(cells)).rstrip()

    return [fmt(headers), fmt(["-" * w for w in widths]), *(fmt(r) for r in rows)]


def render_inventory(inv: Inventory) -> str:
    """Human-readable inventory."""
    out: list[str] = ["Agent files"]
    if not inv.files:
        out.append("  none found")
    for kind, paths in sorted(inv.files.items()):
        out.append(f"  {kind} ({len(paths)}): {', '.join(safe(p, 80) for p in paths)}")
    out += ["", f"MCP servers ({len(inv.servers)})"]
    if inv.servers:
        rows = [
            [
                safe(s["name"], 30),
                s["transport"],
                safe(s["launch"], 60),
                {True: "yes", False: "NO", None: "-"}[s["pinned"]],
                ", ".join(s["capabilities"]) or "-",
            ]
            for s in inv.servers
        ]
        out += ["  " + line for line in _table(["name", "type", "launch", "pinned", "capabilities"], rows)]
    out += ["", f"Tools from saved listings ({len(inv.tools)})"]
    for t in inv.tools:
        caps = ", ".join(t["capabilities"]) or "-"
        out.append(f"  {safe(t['server'], 30)}/{safe(t['name'], 40)}  [{caps}]")
    out += ["", f"Permissions ({len(inv.permissions)})"]
    for p in inv.permissions:
        out.append(f"  {p['mode']:<5}  {safe(p['entry'], 80)}  ({safe(p['file'], 60)})")
    out += ["", f"Hooks ({len(inv.hooks)})"]
    for h in inv.hooks:
        out.append(f"  {h['event']}: {safe(h['command'], 100)}")
    out += ["", render_trifecta_summary(inv.providers, terminal_width())]
    return "\n".join(out)


def render_trifecta_summary(providers: list[Provider], width: int = 100) -> str:
    """One paragraph on the lethal trifecta, wrapped to ``width``."""
    import textwrap

    result = analyse_trifecta(providers)
    lines = ["Lethal trifecta: " + ("PRESENT" if result.complete else "not present")]
    for cap, provs in result.chain():
        names = ", ".join(p.label for p in provs) or "none"
        mark = "x" if provs else " "
        lines += textwrap.wrap(
            f"[{mark}] {CAP_HELP[cap]}: {safe(names, 400)}", width, initial_indent="  ", subsequent_indent="      "
        )
    if result.breaker:
        lines.append(f"  Smallest fix: remove or require approval for {result.breaker.label}.")
    return "\n".join(lines)


def render_graph_text(providers: list[Provider]) -> str:
    """Capability matrix: one row per provider, one column per capability."""
    short = {
        "reads-private": "private",
        "ingests-untrusted": "untrusted",
        "can-exfiltrate": "send-out",
        "executes": "exec",
        "writes": "write",
    }
    if not providers:
        return "No servers, tools or permissions with known capabilities.\n\n" + render_trifecta_summary(
            providers, terminal_width()
        )
    headers = ["provider", *(short[c] for c in ALL_CAPS)]
    rows = [[safe(p.label, 50), *("x" if c in p.caps else "." for c in ALL_CAPS)] for p in providers]
    lines = _table(headers, rows)
    return "\n".join([*lines, "", render_trifecta_summary(providers, terminal_width())])


def render_graph_dot(providers: list[Provider]) -> str:
    """Graphviz DOT: providers on the left, capabilities on the right."""

    def q(text: str) -> str:
        return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'

    result = analyse_trifecta(providers)
    lines = ["digraph glint {", "  rankdir=LR;", '  node [fontname="Helvetica"];']
    for cap in ALL_CAPS:
        colour = "#d1242f" if result.complete and cap in TRIFECTA else "#57606a"
        lines.append(f"  {q(cap)} [shape=box, style=rounded, color={q(colour)}];")
    for p in providers:
        lines.append(f"  {q(p.label)} [shape=ellipse];")
        for cap in sorted(p.caps):
            lines.append(f"  {q(p.label)} -> {q(cap)};")
    lines.append("}")
    return "\n".join(lines) + "\n"
