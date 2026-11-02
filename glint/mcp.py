"""Read MCP server definitions and saved tool listings."""

from __future__ import annotations

import re
from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

from glint.models import KIND_MCP, KIND_TOOLS, Document
from glint.textutil import find_line

_EXACT_SEMVER = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?"
_NPM_SPEC_RE = re.compile(r"^(?P<name>(?:@[^/@\s]+/)?[^@\s/]+)(?:@(?P<version>[^\s]+))?$")
_PY_SPEC_RE = re.compile(r"^(?P<name>[A-Za-z0-9_.\-]+)(?:\[[^\]]*\])?(?:(?:==|@)(?P<version>[^\s,;]+))?")
_EXACT_RE = re.compile(rf"^{_EXACT_SEMVER}$")
_DOCKER_DIGEST_RE = re.compile(r"@sha256:[0-9a-f]{64}$")

NODE_RUNNERS: dict[str, list[str]] = {"npx": [], "bunx": [], "pnpx": [], "pnpm": ["dlx"], "yarn": ["dlx"]}
PY_RUNNERS: dict[str, list[str]] = {"uvx": [], "pipx": ["run"], "uv": ["tool", "run"]}
CONTAINER_RUNNERS = frozenset({"docker", "podman"})

# Options that take a value, so the value is not the package name.
_VALUE_FLAGS = frozenset({"--python", "-p", "--with", "--index-url", "--index", "--registry", "--cache", "--spec"})
_DOCKER_VALUE_FLAGS = frozenset(
    {
        "-e",
        "--env",
        "-v",
        "--volume",
        "--name",
        "-p",
        "--publish",
        "--network",
        "-w",
        "--workdir",
        "--env-file",
        "--mount",
        "-u",
        "--user",
        "--entrypoint",
        "--label",
        "-l",
        "--platform",
    }
)


@dataclass
class Server:
    """One MCP server entry from a config file."""

    name: str
    command: str
    args: list[str]
    env: dict[str, Any]
    url: str
    raw: dict[str, Any] = field(repr=False)
    path: str = ""
    line: int = 1

    @property
    def command_name(self) -> str:
        """Base name of the command, lower-cased, without .exe/.cmd/.bat."""
        base = re.split(r"[\\/]", self.command)[-1].lower()
        return re.sub(r"\.(?:exe|cmd|bat)$", "", base)

    @property
    def cmdline(self) -> str:
        """Command and arguments as one string (or the URL for remote servers)."""
        return " ".join([self.command, *self.args]).strip() or self.url

    @property
    def headers(self) -> dict[str, Any]:
        """HTTP headers for a remote server, if any."""
        headers = self.raw.get("headers", {})
        return headers if isinstance(headers, dict) else {}


@dataclass(frozen=True)
class Package:
    """The package a server is launched from."""

    ecosystem: str  # "npm", "pypi" or "container"
    name: str
    version: str | None
    pinned: bool


@dataclass
class Tool:
    """One tool from a saved MCP ``tools/list`` response."""

    server: str
    name: str
    description: str
    schema: Any
    path: str
    line: int


def iter_servers(doc: Document) -> Iterator[Server]:
    """Yield every MCP server defined in a config document."""
    data = doc.data
    if doc.kind != KIND_MCP or not isinstance(data, dict):
        return
    tables: list[Any] = [data.get("mcpServers"), data.get("servers")]
    nested = data.get("mcp")
    if isinstance(nested, dict):
        tables.append(nested.get("servers"))
    seen_line = 1
    for table in tables:
        if not isinstance(table, dict):
            continue
        for name, raw in table.items():
            if not isinstance(raw, dict):
                continue
            line = find_line(doc.text, f'"{name}"', seen_line)
            seen_line = line
            args = raw.get("args", [])
            env = raw.get("env", {})
            yield Server(
                name=str(name),
                command=str(raw.get("command", "")),
                args=[str(a) for a in args] if isinstance(args, list) else [],
                env=env if isinstance(env, dict) else {},
                url=str(raw.get("url", "") or raw.get("serverUrl", "") or raw.get("httpUrl", "")),
                raw=raw,
                path=str(doc.path),
                line=line,
            )


def iter_tools(doc: Document) -> Iterator[Tool]:
    """Yield every tool in a saved tool listing.

    Accepts a raw ``tools/list`` result (``{"tools": [...]}``), a JSON-RPC
    response (``{"result": {"tools": [...]}}``) or a bare list. The server
    name comes from a top-level ``"server"`` key or the file name
    (``github.tools.json`` belongs to server ``github``).
    """
    if doc.kind != KIND_TOOLS:
        return
    data = doc.data
    server = doc.path.name.removesuffix(".tools.json")
    tools: Any = data
    if isinstance(data, dict):
        server = str(data.get("server", server))
        tools = data.get("tools")
        if tools is None and isinstance(data.get("result"), dict):
            tools = data["result"].get("tools")
    if not isinstance(tools, list):
        return
    seen_line = 1
    for item in tools:
        if not isinstance(item, dict) or "name" not in item:
            continue
        name = str(item["name"])
        line = find_line(doc.text, f'"{name}"', seen_line)
        seen_line = line
        yield Tool(
            server=server,
            name=name,
            description=str(item.get("description", "")),
            schema=item.get("inputSchema", item.get("input_schema")),
            path=str(doc.path),
            line=line,
        )


def _first_positional(args: list[str], prefix: list[str], value_flags: frozenset[str]) -> tuple[str | None, str | None]:
    """Return (first positional argument, explicit --from/--package value) after ``prefix``."""
    rest = list(args)
    for word in prefix:
        if rest and rest[0] == word:
            rest.pop(0)
        else:
            return None, None
    explicit = None
    skip = False
    for idx, arg in enumerate(rest):
        if skip:
            skip = False
            continue
        if arg in ("--from", "--package") and idx + 1 < len(rest):
            explicit = rest[idx + 1]
            skip = True
            continue
        if arg.startswith(("--from=", "--package=")):
            explicit = arg.split("=", 1)[1]
            continue
        if arg in value_flags:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        return arg, explicit
    return None, explicit


def is_local(spec: str) -> bool:
    """True for local paths and URLs, which are not registry packages."""
    return spec.startswith((".", "/", "~", "file:", "git+", "http://", "https://")) or "\\" in spec


def server_package(server: Server) -> Package | None:
    """Work out which package a server runs, and whether it is pinned."""
    cmd = server.command_name
    if cmd in NODE_RUNNERS:
        pkg, explicit = _first_positional(server.args, NODE_RUNNERS[cmd], _VALUE_FLAGS)
        spec = explicit or pkg
        if not spec or is_local(spec):
            return None
        match = _NPM_SPEC_RE.match(spec)
        if not match:
            return None
        version = match.group("version")
        return Package("npm", match.group("name"), version, bool(version and _EXACT_RE.match(version)))
    if cmd in PY_RUNNERS:
        pkg, explicit = _first_positional(server.args, PY_RUNNERS[cmd], _VALUE_FLAGS)
        spec = explicit or pkg
        if not spec or is_local(spec):
            return None
        match = _PY_SPEC_RE.match(spec)
        if not match:
            return None
        version = match.group("version")
        return Package("pypi", match.group("name"), version, bool(version and _EXACT_RE.match(version)))
    if cmd in CONTAINER_RUNNERS and server.args[:1] == ["run"]:
        image, _ = _first_positional(server.args[1:], [], _DOCKER_VALUE_FLAGS)
        if not image:
            return None
        if _DOCKER_DIGEST_RE.search(image):
            return Package("container", image.split("@", 1)[0], image.split("@", 1)[1], True)
        last = image.rsplit("/", 1)[-1]
        if ":" in last:
            name, tag = image.rsplit(":", 1)
            return Package("container", name, tag, tag != "latest")
        return Package("container", image, None, False)
    return None
