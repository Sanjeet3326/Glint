"""``glint fix``: safe automatic fixes.

Only fixes that cannot change meaning are automatic: removing invisible
and bidirectional characters (GL-003). Risky fixes, such as removing
tools or rotating secrets, stay manual.
"""

from __future__ import annotations

import difflib
from dataclasses import dataclass
from pathlib import Path

from glint.config import load_config
from glint.scanner import load_project
from glint.textutil import is_hidden, safe


@dataclass
class FileFix:
    """The fix for one file."""

    path: Path
    rel: str
    before: str
    after: str
    removed: int


def strip_invisible(text: str) -> tuple[str, int]:
    """Remove hidden characters; keep a UTF-8 BOM at the very start."""
    out: list[str] = []
    removed = 0
    for idx, ch in enumerate(text):
        if is_hidden(ord(ch)) and not (idx == 0 and ch == "\ufeff"):
            removed += 1
            continue
        out.append(ch)
    return "".join(out), removed


def plan_fixes(target: Path) -> list[FileFix]:
    """Work out the fixes for every agent file under ``target``."""
    root = target.resolve()
    project = load_project(root, load_config(root))
    fixes: list[FileFix] = []
    for doc in project.docs:
        path = project.root / Path(str(doc.path))
        original = path.read_bytes().decode("utf-8", errors="strict") if _is_utf8(path) else None
        if original is None:
            continue
        fixed, removed = strip_invisible(original)
        if removed:
            fixes.append(FileFix(path, str(doc.path), original, fixed, removed))
    return fixes


def _is_utf8(path: Path) -> bool:
    try:
        path.read_bytes().decode("utf-8")
    except UnicodeDecodeError:
        return False
    return True


def render_diff(fix: FileFix) -> str:
    """Unified diff with hidden characters made visible."""
    before = [safe(line, 10_000) + "\n" for line in fix.before.splitlines()]
    after = [safe(line, 10_000) + "\n" for line in fix.after.splitlines()]
    return "".join(difflib.unified_diff(before, after, f"a/{fix.rel}", f"b/{fix.rel}"))


def apply_fix(fix: FileFix) -> None:
    """Write the fixed content, keeping the file's original line endings."""
    fix.path.write_bytes(fix.after.encode("utf-8"))
