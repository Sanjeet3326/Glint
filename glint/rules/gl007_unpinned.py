"""GL-007: MCP servers that download whatever version is latest."""

from __future__ import annotations

import re

from glint.models import KIND_MCP, Document, Finding, Rule, Severity
from glint.rules._helpers import Server, iter_servers, server_line
from glint.textutil import safe

_EXACT_SEMVER = r"\d+\.\d+\.\d+(?:[-+][0-9A-Za-z.-]+)?"
_NPM_PINNED_RE = re.compile(rf"^(?:@[^/@\s]+/)?[^@\s/]+@{_EXACT_SEMVER}$")
_PY_PINNED_RE = re.compile(rf"^[A-Za-z0-9_.\-\[\],]+(?:==|@){_EXACT_SEMVER}$")
_DOCKER_PINNED_RE = re.compile(r"@sha256:[0-9a-f]{64}$|:(?!latest$)[\w][\w.-]{0,127}$")

_NODE_RUNNERS = {"npx": [], "bunx": [], "pnpm": ["dlx"], "yarn": ["dlx"], "pnpx": []}
_PY_RUNNERS = {"uvx": [], "pipx": ["run"], "uv": ["tool", "run"]}
# Flags that take a value, so the value is not the package name.
_VALUE_FLAGS = frozenset({"--python", "-p", "--with", "--index-url", "--index", "--registry", "--cache", "--spec"})


def _package_arg(args: list[str], prefix: list[str]) -> tuple[str | None, str | None]:
    """Return (package, explicit --from/--package value) after the runner prefix."""
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
        if arg in _VALUE_FLAGS:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        return arg, explicit
    return None, explicit


def _is_local(pkg: str) -> bool:
    return pkg.startswith((".", "/", "~", "file:", "git+", "http://", "https://")) or "\\" in pkg


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
            problem = self._problem(server)
            if problem:
                findings.append(
                    self.finding(
                        doc,
                        server_line(doc, server, '"args"'),
                        f"Server '{server.name}' {problem}.",
                        safe(" ".join([server.command, *server.args])),
                    )
                )
        return findings

    @staticmethod
    def _problem(server: Server) -> str | None:
        cmd = server.command_name
        if cmd in _NODE_RUNNERS:
            pkg, explicit = _package_arg(server.args, _NODE_RUNNERS[cmd])
            target = explicit or pkg
            if target and not _is_local(target) and not _NPM_PINNED_RE.match(target):
                return f"runs npm package '{target}' without an exact version"
        elif cmd in _PY_RUNNERS:
            pkg, explicit = _package_arg(server.args, _PY_RUNNERS[cmd])
            target = explicit or pkg
            if target and not _is_local(target) and not _PY_PINNED_RE.match(target):
                return f"runs Python package '{target}' without an exact version"
        elif cmd in ("docker", "podman") and server.args[:1] == ["run"]:
            pkg, _ = _package_arg(server.args[1:], [])
            image = _docker_image(server.args[1:]) or pkg
            if image and not _DOCKER_PINNED_RE.search(image.split("/")[-1] if "@" not in image else image):
                return f"runs container image '{image}' without a fixed tag or digest"
        return None


def _docker_image(args: list[str]) -> str | None:
    """Find the image argument of `docker run`, skipping options and their values."""
    takes_value = {
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
    }
    skip = False
    for arg in args:
        if skip:
            skip = False
            continue
        if arg in takes_value:
            skip = True
            continue
        if arg.startswith("-"):
            continue
        return arg
    return None
