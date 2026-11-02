"""Find agent-related files in a folder."""

from __future__ import annotations

import os
import re
from collections.abc import Iterable, Iterator
from dataclasses import dataclass
from pathlib import Path

from glint.models import (
    KIND_INSTRUCTIONS,
    KIND_MCP,
    KIND_PROMPT,
    KIND_SETTINGS,
    KIND_SKILL,
    KIND_TOOLS,
)

MAX_FILE_BYTES = 2 * 1024 * 1024

SKIP_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        "node_modules",
        ".venv",
        "venv",
        "__pycache__",
        ".tox",
        ".mypy_cache",
        ".ruff_cache",
        "dist",
        "build",
    }
)

# One table of file patterns. A pattern without "/" matches a file name
# at any depth; a pattern with "/" matches the end of the relative path.
# "**" crosses folders, "*" does not. First match wins.
PATTERNS: tuple[tuple[str, str], ...] = (
    # MCP configs
    ("mcp.json", KIND_MCP),
    (".mcp.json", KIND_MCP),
    ("claude_desktop_config.json", KIND_MCP),
    ("cline_mcp_settings.json", KIND_MCP),
    ("mcp_settings.json", KIND_MCP),
    # Agent settings
    (".claude/settings.json", KIND_SETTINGS),
    (".claude/settings.local.json", KIND_SETTINGS),
    # Saved MCP tool listings
    ("*.tools.json", KIND_TOOLS),
    # Skills, subagents and slash commands
    ("SKILL.md", KIND_SKILL),
    (".claude/agents/**/*.md", KIND_SKILL),
    (".claude/commands/**/*.md", KIND_SKILL),
    # Agent instructions
    ("AGENTS.md", KIND_INSTRUCTIONS),
    ("CLAUDE.md", KIND_INSTRUCTIONS),
    ("CLAUDE.local.md", KIND_INSTRUCTIONS),
    ("GEMINI.md", KIND_INSTRUCTIONS),
    (".cursorrules", KIND_INSTRUCTIONS),
    (".windsurfrules", KIND_INSTRUCTIONS),
    (".clinerules", KIND_INSTRUCTIONS),
    (".cursor/rules/**/*", KIND_INSTRUCTIONS),
    (".windsurf/rules/**/*", KIND_INSTRUCTIONS),
    (".clinerules/**/*", KIND_INSTRUCTIONS),
    (".roo/rules/**/*", KIND_INSTRUCTIONS),
    (".continue/rules/**/*", KIND_INSTRUCTIONS),
    (".github/copilot-instructions.md", KIND_INSTRUCTIONS),
    (".github/instructions/**/*.instructions.md", KIND_INSTRUCTIONS),
    # Prompt files
    (".github/prompts/**/*.prompt.md", KIND_PROMPT),
    ("*.prompt.md", KIND_PROMPT),
    ("*.prompt", KIND_PROMPT),
    ("system_prompt*.txt", KIND_PROMPT),
    ("system_prompt*.md", KIND_PROMPT),
    ("prompts/**/*.md", KIND_PROMPT),
    ("prompts/**/*.txt", KIND_PROMPT),
)


def glob_to_regex(pattern: str) -> re.Pattern[str]:
    """Compile a collector glob into a regex over a POSIX relative path."""
    parts: list[str] = []
    i = 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            parts.append("(?:.*/)?")
            i += 3
        elif pattern.startswith("**", i):
            parts.append(".*")
            i += 2
        elif pattern[i] == "*":
            parts.append("[^/]*")
            i += 1
        elif pattern[i] == "?":
            parts.append("[^/]")
            i += 1
        else:
            parts.append(re.escape(pattern[i]))
            i += 1
    return re.compile(r"(?:^|.*/)" + "".join(parts) + r"$")


_COMPILED = tuple((glob_to_regex(p), kind) for p, kind in PATTERNS)


def classify(rel_posix: str) -> str | None:
    """Return the document kind for a relative path, or None if not an agent file."""
    for regex, kind in _COMPILED:
        if regex.match(rel_posix):
            return kind
    return None


def is_binary(path: Path) -> bool:
    """True when the first 8 KB of a file contain a NUL byte."""
    with path.open("rb") as handle:
        return b"\x00" in handle.read(8192)


@dataclass(frozen=True)
class Collected:
    """A file chosen for scanning and its document kind."""

    path: Path
    kind: str


@dataclass(frozen=True)
class Skipped:
    """A matching file that was not scanned, and why."""

    path: Path
    reason: str


def collect(root: Path, exclude: Iterable[str] = ()) -> Iterator[Collected | Skipped]:
    """Walk ``root`` and yield agent files to scan (and ones skipped).

    Symlinked folders are never followed, and symlinked files are only
    read when they point inside ``root``.
    """
    root = root.resolve()
    excludes = [glob_to_regex(p.rstrip("/") + ("/**" if p.endswith("/") else "")) for p in exclude]
    if root.is_file():
        kind = classify(root.name)
        if kind:
            yield Collected(root, kind)
        return
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        current = Path(dirpath)
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not _excluded(current / d, root, excludes))
        for name in sorted(filenames):
            path = current / name
            rel = path.relative_to(root).as_posix()
            kind = classify(rel)
            if kind is None or _excluded(path, root, excludes):
                continue
            reason = _skip_reason(path, root)
            if reason:
                yield Skipped(path, reason)
            else:
                yield Collected(path, kind)


def _excluded(path: Path, root: Path, excludes: list[re.Pattern[str]]) -> bool:
    rel = path.relative_to(root).as_posix()
    return any(rx.match(rel) for rx in excludes)


def _skip_reason(path: Path, root: Path) -> str | None:
    try:
        if path.is_symlink():
            target = path.resolve()
            if not target.is_relative_to(root):
                return "symlink points outside the scan folder"
        if not path.is_file():
            return "not a regular file"
        if path.stat().st_size > MAX_FILE_BYTES:
            return "larger than 2 MB"
        if is_binary(path):
            return "binary file"
    except OSError as exc:
        return f"cannot read file: {exc.strerror or exc}"
    return None
