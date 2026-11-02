"""The agent's-eye view: what a human sees versus what the agent reads."""

from __future__ import annotations

import re
import textwrap
from dataclasses import dataclass

from glint.textutil import BIDI, ZERO_WIDTH, decode_tags, describe, is_tag, safe

_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)
_HIDDEN_ELEMENT_RE = re.compile(
    r"<(\w+)\b[^>]{0,300}?(?:display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0"
    r"|\shidden(?:\s|>|=))[^>]{0,300}>.{0,2000}?</\1\s*>",
    re.IGNORECASE | re.DOTALL,
)
_MARK_OPEN, _MARK_CLOSE = "⟦", "⟧"  # ⟦ ⟧


@dataclass
class RevealResult:
    """Both views of a file and how much text is hidden."""

    human: str
    agent: str
    hidden_chars: int
    hidden_parts: int


def _mark(label: str, body: str = "") -> str:
    body = safe(body, 160) if body else ""
    return f"{_MARK_OPEN}{label}{': ' + body if body else ''}{_MARK_CLOSE}"


def reveal_text(text: str) -> RevealResult:
    """Build the human view and the labelled agent view of ``text``."""
    text = text.replace("\r\n", "\n").replace("\r", "\n")
    spans: list[tuple[int, int, str]] = []
    for match in _COMMENT_RE.finditer(text):
        spans.append((match.start(), match.end(), _mark("HTML comment", match.group(0)[4:-3].strip())))
    for match in _HIDDEN_ELEMENT_RE.finditer(text):
        if not any(s <= match.start() < e for s, e, _ in spans):
            inner = re.sub(r"<[^>]+>", " ", match.group(0)).strip()
            spans.append((match.start(), match.end(), _mark("hidden HTML element", inner)))
    spans.sort()

    human: list[str] = []
    agent: list[str] = []
    hidden_chars = 0
    hidden_parts = len(spans)
    pos = 0
    for start, end, label in spans:
        if start < pos:
            continue
        h, a, n, parts = _chars(text[pos:start])
        human.append(h)
        agent.append(a)
        hidden_chars += n + (end - start)
        hidden_parts += parts
        # Keep both views on the same line count so they can be shown side by side.
        newlines = "\n" * text.count("\n", start, end)
        human.append(newlines)
        agent.append(label + newlines)
        pos = end
    h, a, n, parts = _chars(text[pos:])
    human.append(h)
    agent.append(a)
    hidden_chars += n
    hidden_parts += parts
    return RevealResult("".join(human), "".join(agent), hidden_chars, hidden_parts)


def _chars(chunk: str) -> tuple[str, str, int, int]:
    """Split a chunk into human and agent views for invisible characters."""
    human: list[str] = []
    agent: list[str] = []
    hidden = 0
    parts = 0
    i = 0
    while i < len(chunk):
        cp = ord(chunk[i])
        if is_tag(cp):
            j = i
            while j < len(chunk) and is_tag(ord(chunk[j])):
                j += 1
            run = chunk[i:j]
            agent.append(_mark("hidden tag text", decode_tags(run)))
            hidden += len(run)
            parts += 1
            i = j
            continue
        if cp in ZERO_WIDTH or cp in BIDI:
            agent.append(_MARK_OPEN + describe(cp)[1:-1] + _MARK_CLOSE)
            hidden += 1
            parts += 1
        elif chunk[i] == "\n" or chunk[i] == "\t" or (cp >= 0x20 and not (0x7F <= cp <= 0x9F)):
            human.append(chunk[i])
            agent.append(chunk[i])
        else:
            agent.append(f"{_MARK_OPEN}control 0x{cp:02X}{_MARK_CLOSE}")
            hidden += 1
            parts += 1
        i += 1
    return "".join(human), "".join(agent), hidden, parts


def render_side_by_side(result: RevealResult, width: int) -> str:
    """Render both views in two columns (or stacked on narrow terminals)."""
    summary = summary_line(result)
    if width < 90:
        return "\n".join(
            [
                "=== Human sees " + "=" * max(0, width - 15),
                result.human.rstrip("\n"),
                "",
                "=== Agent reads " + "=" * max(0, width - 16),
                result.agent.rstrip("\n"),
                "",
                summary,
            ]
        )
    col = (width - 3) // 2
    lines = [f"{'Human sees':<{col}} | Agent reads", f"{'-' * col}-+-{'-' * col}"]
    human_lines = result.human.rstrip("\n").split("\n")
    agent_lines = result.agent.rstrip("\n").split("\n")
    for idx in range(max(len(human_lines), len(agent_lines))):
        left = _wrap(human_lines[idx] if idx < len(human_lines) else "", col)
        right = _wrap(agent_lines[idx] if idx < len(agent_lines) else "", col)
        for row in range(max(len(left), len(right))):
            lval = left[row] if row < len(left) else ""
            rval = right[row] if row < len(right) else ""
            lines.append(f"{lval:<{col}} | {rval}".rstrip())
    lines.extend(["", summary])
    return "\n".join(lines)


def _wrap(line: str, width: int) -> list[str]:
    return textwrap.wrap(line, width) or [""]


def summary_line(result: RevealResult) -> str:
    """One sentence on how much of the file is invisible to a human."""
    if result.hidden_chars == 0:
        return "Nothing hidden: the agent reads the same text a human sees."
    return (
        f"{result.hidden_chars} characters in {result.hidden_parts} place(s) are read by the "
        "agent but invisible to a human reader."
    )
