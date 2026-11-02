"""Text helpers: invisible characters, safe printing and light normalisation."""

from __future__ import annotations

import math
import re
import unicodedata
from collections import Counter
from functools import lru_cache

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

# Cyrillic and Greek letters that look like Latin ones.
_HOMOGLYPHS_SRC: dict[str, str] = {
    "\u0430": "a",
    "\u0435": "e",
    "\u043e": "o",
    "\u0440": "p",
    "\u0441": "c",
    "\u0445": "x",
    "\u0443": "y",
    "\u0456": "i",
    "\u0458": "j",
    "\u0455": "s",
    "\u04bb": "h",
    "\u0501": "d",
    "\u0410": "a",
    "\u0415": "e",
    "\u041e": "o",
    "\u0420": "p",
    "\u0421": "c",
    "\u0425": "x",
    "\u0406": "i",
    "\u0405": "s",
    "\u041d": "h",
    "\u041a": "k",
    "\u041c": "m",
    "\u0422": "t",
    "\u0412": "b",
    "\u03bf": "o",
    "\u03b1": "a",
    "\u03b5": "e",
    "\u03b9": "i",
    "\u03ba": "k",
    "\u03bd": "v",
    "\u03c1": "p",
    "\u03c4": "t",
    "\u03c5": "u",
    "\u039f": "o",
    "\u0391": "a",
}
_LEET = str.maketrans({"0": "o", "1": "i", "3": "e", "4": "a", "5": "s", "7": "t", "@": "a", "$": "s", "!": "i"})
_BASE64_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{24,}={0,2}(?![A-Za-z0-9+/=])")
_HEX_RE = re.compile(r"(?<![0-9A-Fa-f])(?:[0-9A-Fa-f]{2}){16,}(?![0-9A-Fa-f])")


# One table that deletes hidden characters and folds look-alike letters.
_FOLD: dict[int, str | None] = {cp: None for cp in (*ZERO_WIDTH, *BIDI, *range(TAG_START, TAG_END + 1))}
_FOLD.update({ord(k): v for k, v in _HOMOGLYPHS_SRC.items()})


@lru_cache(maxsize=8192)
def normalise(text: str) -> str:
    """Normalisation applied before text rules match.

    NFKC folds full-width letters and ligatures, Cyrillic and Greek
    look-alike letters become Latin, hidden characters are removed so they
    cannot split a keyword, whitespace is collapsed and the result is
    lower-cased. Plain ASCII text takes a fast path, since none of the
    Unicode steps can change it.
    """
    if not text.isascii():
        text = unicodedata.normalize("NFKC", text).translate(_FOLD)
    return _SPACE_RE.sub(" ", text).strip().lower()


def deleet(text: str) -> str:
    """Undo common leetspeak ("ign0re prev1ous" becomes "ignore previous")."""
    return text.translate(_LEET)


def decoded_payloads(text: str) -> list[str]:
    """Decode base64 or hex strings in ``text`` that turn out to be readable text."""
    import base64
    import binascii

    out: list[str] = []
    for match in _BASE64_RE.finditer(text):
        chunk = match.group(0)
        try:
            raw = base64.b64decode(chunk + "=" * (-len(chunk) % 4), validate=True)
        except (binascii.Error, ValueError):
            continue
        decoded = _readable(raw)
        if decoded:
            out.append(decoded)
    for match in _HEX_RE.finditer(text):
        decoded = _readable(bytes.fromhex(match.group(0)))
        if decoded:
            out.append(decoded)
    return out


def _readable(raw: bytes) -> str | None:
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError:
        return None
    printable = sum(1 for ch in text if ch.isprintable() or ch in "\n\t")
    letters = sum(1 for ch in text if ch.isalpha())
    if len(text) >= 12 and printable / len(text) > 0.95 and letters / len(text) > 0.5 and " " in text:
        return text
    return None


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
