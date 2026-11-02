"""``glint.lock``: a record of approved MCP servers and tool descriptions.

Commit the lockfile. Later scans compare against it (rule GL-012), so a
server whose command, version or tool descriptions change after review
(a "rug pull") shows up as a reviewable finding.
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from glint.mcp import Server, iter_servers, iter_tools
from glint.models import Project

LOCK_FILE = "glint.lock"
LOCK_VERSION = 1


def _digest(value: Any) -> str:
    raw = json.dumps(value, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def server_record(server: Server) -> dict[str, Any]:
    """What is locked for one server. Secret values are never stored, only env key names."""
    definition = {
        "command": server.command,
        "args": server.args,
        "url": server.url,
        "env_keys": sorted(str(k) for k in server.env),
        "header_keys": sorted(str(k) for k in server.headers),
    }
    return {**definition, "hash": _digest(definition)}


def build_lock(project: Project) -> dict[str, Any]:
    """Build the lockfile content for the current project."""
    servers: dict[str, Any] = {}
    tools: dict[str, Any] = {}
    for doc in project.docs:
        for server in iter_servers(doc):
            servers[f"{server.path}::{server.name}"] = server_record(server)
        for tool in iter_tools(doc):
            body = {"name": tool.name, "description": tool.description, "inputSchema": tool.schema}
            tools[f"{tool.server}::{tool.name}"] = {
                "file": tool.path,
                "description": tool.description,
                "hash": _digest(body),
            }
    return {
        "glint_lock_version": LOCK_VERSION,
        "servers": dict(sorted(servers.items())),
        "tools": dict(sorted(tools.items())),
    }


def render_lock(lock: dict[str, Any]) -> str:
    """Serialise a lock with stable formatting for clean diffs."""
    return json.dumps(lock, indent=2, sort_keys=False, ensure_ascii=False) + "\n"


def load_lock(path: Path) -> dict[str, Any] | None:
    """Read a lockfile; return None when absent. Raises ValueError when invalid."""
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"{LOCK_FILE} is not valid JSON: {exc}") from exc
    if not isinstance(data, dict) or data.get("glint_lock_version") != LOCK_VERSION:
        raise ValueError(f"{LOCK_FILE} has an unsupported format; run `glint lock` to recreate it")
    return data
