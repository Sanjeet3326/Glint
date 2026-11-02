"""Text helpers: invisible characters, safe printing and light normalisation."""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter

ZERO_WIDTH = frozenset({0x200B, 0x200C, 0x200D, 0x2060, 0x180E, 0xFEFF})
BIDI = frozenset({0x202A, 0x202B, 0x202C, 0x202D, 0x202E, 0x2066, 0x2067, 0x2068, 0x2069})
TAG_START, TAG_END = 0xE0000, 0xE007F

EVIDENCE_LIMIT = 200

_FALLBACK_NAMES = {
    0x180E: "MONGOLIAN VOWEL SEPARATOR",
    0xFEFF: "ZERO WIDTH NO-BREAK SPACE",
}


def is_tag(cp: int) -> bool:
    """True for Unicode tag characters (U+E0000 to U+E007F)."""
    return TAG_START <= cp <= TAG_END


def is_hidden(cp: int) -> bool:
    """True for characters a human reader cannot see in rendered text."""
    return cp in ZERO_WIDTH or cp in BIDI or is_tag(cp)


def char_name(cp: int) -> str:
    """Return the Unicode name of a code point, or a fallback."""
    name = unicodedata.name(chr(cp), "") or _FALLBACK_NAMES.get(cp, "")
    if not name and is_tag(cp):
        name = "TAG CHARACTER"
    return name or "UNNAMED CHARACTER"


def describe(cp: int) -> str:
    """Return a visible label such as ``<U+202E RIGHT-TO-LEFT OVERRIDE>``."""
    return f"<U+{cp:04X} {char_name(cp)}>"


def decode_tags(text: str) -> str:
    """Return the ASCII text smuggled inside Unicode tag characters."""
    out = []
    for ch in text:
        cp = ord(ch)
        if 0xE0020 <= cp <= 0xE007E:
            out.append(chr(cp - 0xE0000))
    return "".join(out)


def safe(text: str, limit: int = EVIDENCE_LIMIT) -> str:
    """Make text safe to print in any report.

    Control characters (including ANSI escape sequences) and invisible
    characters are replaced with visible labels, so a scanned file can
    never hide or rewrite part of the report. Output is trimmed to
    ``limit`` characters.
    """
    out: list[str] = []
    i = 0
    while i < len(text):
        ch = text[i]
        cp = ord(ch)
        if is_tag(cp):
            j = i
            while j < len(text) and is_tag(ord(text[j])):
                j += 1
            hidden = decode_tags(text[i:j]).replace('"', "'")
            out.append(f'<hidden tag text: "{safe(hidden, 80)}">')
            i = j
            continue
        i += 1
        if ch == "\t":
            out.append(" ")
        elif cp < 0x20 or 0x7F <= cp <= 0x9F:
            out.append(f"<0x{cp:02X}>")
        elif is_hidden(cp):
            out.append(describe(cp))
        else:
            out.append(ch)
    result = "".join(out).strip()
    if len(result) > limit:
        result = result[: limit - 3].rstrip() + "..."
    return result


_SPACE_RE = re.compile(r"\s+")


def normalise(text: str) -> str:
    """Light normalisation applied before text rules match.

    NFKC folds look-alike forms (full-width letters, ligatures), hidden
    characters are removed so they cannot split a keyword, whitespace is
    collapsed and the result is lower-cased.
    """
    text = unicodedata.normalize("NFKC", text)
    text = "".join(ch for ch in text if not is_hidden(ord(ch)))
    return _SPACE_RE.sub(" ", text).strip().lower()


def shannon_entropy(value: str) -> float:
    """Shannon entropy of ``value`` in bits per character."""
    if not value:
        return 0.0
    counts = Counter(value)
    total = len(value)
    return -sum((n / total) * math.log2(n / total) for n in counts.values())


def mask(secret: str) -> str:
    """Show only the first four characters of a secret."""
    return secret[:4] + "****"


def line_of(text: str, offset: int) -> int:
    """Return the 1-based line number of character ``offset`` in ``text``."""
    return text.count("\n", 0, max(offset, 0)) + 1


def find_line(text: str, needle: str, start_line: int = 1) -> int:
    """Return the first line at or after ``start_line`` containing ``needle``.

    Falls back to ``start_line`` when the needle is not found.
    """
    lines = text.split("\n")
    for idx in range(max(start_line, 1) - 1, len(lines)):
        if needle in lines[idx]:
            return idx + 1
    return max(start_line, 1)
