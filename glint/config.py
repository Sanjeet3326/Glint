"""Read ``.glint.toml``, ``.glintignore`` and inline ignore comments."""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from glint.capabilities import ALL_CAPS
from glint.collector import glob_to_regex
from glint.custom_rules import CustomRuleError, build_custom_rules
from glint.models import Document, Finding, Rule, Severity

CONFIG_FILE = ".glint.toml"
IGNORE_FILE = ".glintignore"

_ID = r"[A-Za-z][A-Za-z0-9]{1,9}-\d{3}"
_INLINE_RE = re.compile(rf"glint:\s*ignore(?:\s+((?:{_ID}[\s,]*)+))?", re.IGNORECASE)
_RULE_ID_RE = re.compile(_ID)
_COMMENT_MARKERS_RE = re.compile(r"<!--|-->|^#+|^//|^/\*|\*/")


class ConfigError(Exception):
    """Raised when a config or ignore file is invalid."""


@dataclass
class Config:
    """Settings loaded from the scanned project."""

    fail_on: Severity | None = None
    exclude: list[str] = field(default_factory=list)
    disable: list[str] = field(default_factory=list)
    # (path regex, rule ids or empty for all rules)
    ignores: list[tuple[re.Pattern[str], frozenset[str]]] = field(default_factory=list)
    notes: list[str] = field(default_factory=list)
    capabilities: dict[str, list[str]] = field(default_factory=dict)
    custom_rules: list[Rule] = field(default_factory=list)


def load_config(root: Path) -> Config:
    """Load config from ``root`` (a folder, or the folder holding a file)."""
    base = root if root.is_dir() else root.parent
    config = Config()
    toml_path = base / CONFIG_FILE
    if toml_path.is_file():
        try:
            data = tomllib.loads(toml_path.read_text(encoding="utf-8"))
        except (tomllib.TOMLDecodeError, UnicodeDecodeError) as exc:
            raise ConfigError(f"{CONFIG_FILE}: {exc}") from exc
        section = data.get("glint", data)
        if "fail_on" in section:
            try:
                config.fail_on = Severity.parse(str(section["fail_on"]))
            except ValueError as exc:
                raise ConfigError(f"{CONFIG_FILE}: {exc}") from exc
        config.exclude = [str(p) for p in section.get("exclude", [])]
        config.disable = [str(r).upper() for r in section.get("disable", [])]
        if config.disable:
            config.notes.append(f"{CONFIG_FILE} disables rule(s): {', '.join(sorted(config.disable))}")
        caps = section.get("capabilities", {})
        if not isinstance(caps, dict):
            raise ConfigError(f"{CONFIG_FILE}: [capabilities] must be a table")
        for server, values in caps.items():
            if not isinstance(values, list) or not set(map(str, values)) <= set(ALL_CAPS):
                raise ConfigError(
                    f"{CONFIG_FILE}: capabilities for {server!r} must be a list of: {', '.join(ALL_CAPS)}"
                )
            config.capabilities[str(server)] = [str(v) for v in values]
        try:
            config.custom_rules = build_custom_rules(section.get("rules"))
        except CustomRuleError as exc:
            raise ConfigError(f"{CONFIG_FILE}: {exc}") from exc
        if config.custom_rules:
            config.notes.append(f"{CONFIG_FILE} adds custom rule(s): {', '.join(r.id for r in config.custom_rules)}")
    ignore_path = base / IGNORE_FILE
    if ignore_path.is_file():
        config.ignores = parse_ignore_file(ignore_path.read_text(encoding="utf-8", errors="replace"))
    return config


def parse_ignore_file(text: str) -> list[tuple[re.Pattern[str], frozenset[str]]]:
    """Parse ``.glintignore`` lines: ``path-glob`` or ``GL-005 path-glob``."""
    entries: list[tuple[re.Pattern[str], frozenset[str]]] = []
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        parts = line.split()
        ids = frozenset(p.upper() for p in parts if _RULE_ID_RE.fullmatch(p))
        globs = [p for p in parts if not _RULE_ID_RE.fullmatch(p)]
        for glob in globs or ["**"]:
            glob = glob.rstrip("/") + ("/**" if glob.endswith("/") else "")
            entries.append((glob_to_regex(glob), ids))
    return entries


def inline_ignored(doc: Document, finding: Finding) -> bool:
    """True when the finding's line has a glint ignore comment, or the line
    above holds nothing but one."""
    for line_no in (finding.line, finding.line - 1):
        if 1 <= line_no <= len(doc.lines):
            text = doc.lines[line_no - 1]
            match = _INLINE_RE.search(text)
            if match and line_no != finding.line:
                rest = (text[: match.start()] + text[match.end() :]).strip()
                if _COMMENT_MARKERS_RE.sub("", rest).strip():
                    continue  # the comment belongs to content on its own line
            if match:
                ids = {i.upper() for i in _RULE_ID_RE.findall(match.group(1) or "")}
                if not ids or finding.rule_id in ids:
                    return True
    return False


def file_ignored(config: Config, finding: Finding) -> bool:
    """True when ``.glintignore`` silences this finding."""
    path = str(finding.path)
    return any(rx.match(path) and (not ids or finding.rule_id in ids) for rx, ids in config.ignores)
