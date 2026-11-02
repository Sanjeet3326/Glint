"""Load files into :class:`Document` objects."""

from __future__ import annotations

import json
import re
from pathlib import Path, PurePosixPath

from glint.models import (
    CTX_COMMENT,
    CTX_FENCED,
    CTX_FRONT_MATTER,
    CTX_HEADING,
    CTX_QUOTE,
    CTX_TEXT,
    JSON_KINDS,
    Document,
)

_FENCE_RE = re.compile(r"^\s{0,3}(`{3,}|~{3,})")


def strip_json_comments(text: str) -> str:
    """Remove ``//`` and ``/* */`` comments and trailing commas from JSONC.

    Newlines are kept so line numbers still match the original file.
    String contents are never touched.
    """
    out: list[str] = []
    i, n = 0, len(text)
    in_string = False
    while i < n:
        ch = text[i]
        if in_string:
            out.append(ch)
            if ch == "\\" and i + 1 < n:
                out.append(text[i + 1])
                i += 2
                continue
            if ch == '"':
                in_string = False
            i += 1
            continue
        if ch == '"':
            in_string = True
            out.append(ch)
            i += 1
        elif text.startswith("//", i):
            end = text.find("\n", i)
            i = n if end == -1 else end
        elif text.startswith("/*", i):
            end = text.find("*/", i + 2)
            chunk = text[i : n if end == -1 else end + 2]
            out.append("\n" * chunk.count("\n"))
            i = n if end == -1 else end + 2
        else:
            out.append(ch)
            i += 1
    return re.sub(r",(\s*[}\]])", r"\1", "".join(out))


def markdown_contexts(lines: list[str]) -> tuple[str, ...]:
    """Tag each line of a Markdown file with where it sits.

    The result lets rules skip examples inside fenced code blocks and
    quotes, and treat HTML comments and front matter as hidden text.
    """
    contexts: list[str] = []
    fence: str | None = None
    in_comment = False
    in_front = bool(lines) and lines[0].strip() == "---"
    for idx, line in enumerate(lines):
        stripped = line.strip()
        if in_front:
            contexts.append(CTX_FRONT_MATTER)
            if idx > 0 and stripped in ("---", "..."):
                in_front = False
            continue
        if fence is not None:
            contexts.append(CTX_FENCED)
            match = _FENCE_RE.match(line)
            if match and match.group(1)[0] == fence[0] and len(match.group(1)) >= len(fence):
                fence = None
            continue
        if in_comment:
            contexts.append(CTX_COMMENT)
            if "-->" in line:
                in_comment = False
            continue
        match = _FENCE_RE.match(line)
        if match:
            fence = match.group(1)
            contexts.append(CTX_FENCED)
        elif stripped.startswith("<!--"):
            contexts.append(CTX_COMMENT)
            in_comment = "-->" not in stripped[4:]
        elif stripped.startswith(">"):
            contexts.append(CTX_QUOTE)
        elif stripped.startswith("#"):
            contexts.append(CTX_HEADING)
        else:
            contexts.append(CTX_TEXT)
    return tuple(contexts)


def decode(raw: bytes) -> tuple[str, bool]:
    """Decode file bytes as UTF-8; return the text and whether it was clean."""
    try:
        return raw.decode("utf-8"), True
    except UnicodeDecodeError:
        return raw.decode("utf-8", errors="replace"), False


def parse_text(rel_path: PurePosixPath, kind: str, text: str) -> Document:
    """Build a :class:`Document` from already-decoded text."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    lines = text.split("\n")
    data = None
    error = None
    if kind in JSON_KINDS:
        contexts = tuple(CTX_TEXT for _ in lines)
        try:
            data = json.loads(strip_json_comments(text)) if text.strip() else {}
        except json.JSONDecodeError as exc:
            error = f"invalid JSON at line {exc.lineno}: {exc.msg}"
    else:
        contexts = markdown_contexts(lines)
    return Document(
        path=rel_path,
        kind=kind,
        text=text,
        data=data,
        parse_error=error,
        contexts=contexts,
        lines=tuple(lines),
    )


def parse_file(path: Path, root: Path, kind: str) -> Document:
    """Read ``path`` from disk and build a :class:`Document`."""
    text, clean = decode(path.read_bytes())
    rel = PurePosixPath(path.relative_to(root).as_posix())
    doc = parse_text(rel, kind, text)
    if not clean and doc.parse_error is None:
        doc = Document(
            path=doc.path,
            kind=doc.kind,
            text=doc.text,
            data=doc.data,
            parse_error="file is not valid UTF-8; unreadable bytes were replaced",
            contexts=doc.contexts,
            lines=doc.lines,
        )
    return doc
