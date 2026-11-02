"""Helpers shared by several rules."""

from __future__ import annotations

import re
from collections.abc import Iterator

from glint.mcp import Server, iter_servers
from glint.models import Document
from glint.textutil import decoded_payloads, deleet, find_line, normalise

# Prompt-injection phrases, matched on normalised (lower-case) text.
INJECTION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = tuple(
    (re.compile(p), msg)
    for p, msg in (
        (
            r"\b(?:ignore|skip|bypass)\s+(?:all\s+|any\s+|the\s+|your\s+)?"
            r"(?:previous|prior|above|earlier|preceding|existing|original)\s+"
            r"(?:instructions?|rules|directions|prompts?|guidelines)\b",
            "tries to make the agent ignore its earlier instructions",
        ),
        (
            r"\bdisregard\s+(?:all\s+|any\s+)?(?:your|the|previous|prior|above)\s+"
            r"(?:system\s+)?(?:prompt|instructions?|rules|guidelines)\b",
            "tries to make the agent disregard its instructions",
        ),
        (
            r"\bforget\s+(?:all\s+|everything\s+)?(?:you\s+were\s+told|your\s+instructions"
            r"|(?:all\s+)?previous\s+instructions)\b",
            "tries to wipe the agent's instructions",
        ),
        (
            r"\byou\s+are\s+now\s+(?:in\s+)?(?:dan\b|developer\s+mode|jailbroken|unrestricted"
            r"|an?\s+(?:unfiltered|unrestricted|uncensored))",
            "tries to switch the agent into an unrestricted role",
        ),
        (
            r"\b(?:do\s+not|don't|never)\s+(?:tell|inform|show|alert|notify|mention\s+(?:this\s+|it\s+)?to)"
            r"\s+the\s+user\b",
            "tells the agent to hide what it does from the user",
        ),
        (
            r"\bnew\s+(?:system\s+)?instructions\s*:",
            "introduces replacement instructions",
        ),
        (
            r"\boverride\s+(?:the\s+|your\s+|all\s+)?(?:system\s+prompt|safety|previous\s+instructions"
            r"|security)\b",
            "tries to override the agent's safety rules",
        ),
    )
)

# Phrases that switch off human approval. Not attacks alone, but they make
# every other problem worse.
SAFETY_OFF_PATTERNS: tuple[re.Pattern[str], ...] = tuple(
    re.compile(p)
    for p in (
        r"\bnever\s+ask\s+(?:the\s+user\s+)?(?:for\s+)?(?:confirmation|permission|approval)\b",
        r"\b(?:do\s+not|don't)\s+ask\s+(?:the\s+user\s+)?(?:for\s+)?(?:confirmation|permission|approval)"
        r"\s+before\b",
        r"\brun\s+(?:all\s+|any\s+)?(?:commands|tools)(?:\s+\w+){0,3}\s+without\s+"
        r"(?:asking|approval|confirmation|permission)\b",
    )
)

# Exfiltration phrases, matched on normalised text.
EXFIL_SEND_RE = re.compile(
    r"\b(?:send|post|upload|forward|transmit|exfiltrate|submit|leak)\b[^.\n]{0,80}?"
    r"\bto\b[^.\n]{0,20}?https?://"
)
URL_WITH_QUERY_RE = re.compile(r"https?://[^\s)\"'>]*\?[^\s)\"'>]*")
SENSITIVE_WORDS_RE = re.compile(
    r"\b(?:conversation|chat\s+history|chat\s+log|context\s+window|secrets?|api\s+keys?"
    r"|tokens?|credentials?|passwords?|\.env\b|ssh\s+keys?|private\s+keys?|cookies?)"
)
IMAGE_PLACEHOLDER_RE = re.compile(
    r"!\[[^\]]{0,200}\]\(\s*https?://[^\s)]*[?&][^\s)]*(?:\{[^}\s]{1,40}\}|\$\{?\w{1,40}|<[^>\s]{1,40}>|%s)"
)
SENSITIVE_FILE_RE = re.compile(
    r"\b(?:read|cat|open|print|show|send|upload|include|copy|output|dump|attach)\b[^\n]{0,40}?"
    r"(?:\.env\b|~/\.ssh|\.ssh/|id_rsa|id_ed25519|\.aws/credentials|\.npmrc|\.netrc|\.git-credentials"
    r"|/etc/passwd|/etc/shadow)"
)
NEGATION_RE = re.compile(r"\b(?:never|don't|do\s+not|avoid|must\s+not|should\s+not|shouldn't|no)\b")


def negated(text: str, start: int) -> bool:
    """True when a negation word appears shortly before ``start``."""
    window = text[max(0, start - 40) : start]
    return bool(NEGATION_RE.search(window))


_QUOTED_RE = re.compile("[\"\u201c\u201d'`]([^\"\u201c\u201d'`]{3,200})[\"\u201c\u201d'`]")
_MENTION_CUE_RE = re.compile(
    r"\b(?:such\s+as|like|e\.g\.|for\s+example|phrases?|text|strings?|patterns?|wording|attacks?)\b"
)


def _quoted_mention(norm: str, start: int, end: int) -> bool:
    """True when the match sits inside quotes and the line talks *about* the phrase."""
    for quoted in _QUOTED_RE.finditer(norm):
        if quoted.start() <= start and end <= quoted.end():
            return bool(_MENTION_CUE_RE.search(norm[: quoted.start()]))
    return False


# Every injection pattern needs one of these words; checking for them first keeps scans fast.
_INJECTION_PREFILTER = re.compile(
    r"ignore|skip|bypass|disregard|forget|you\s+are\s+now|tell|inform|show|alert|notify|mention|"
    r"instructions\s*:|override"
)
# Every exfiltration pattern needs a URL, a credential file or a Markdown image.
_EXFIL_PREFILTER = re.compile(r"https?://|\.env|ssh|id_rsa|id_ed25519|credentials|npmrc|netrc|passwd|shadow|!\[")


def injection_hits(text: str) -> list[str]:
    """Return messages for every injection pattern matching ``text``.

    Matches on normalised text and again with leetspeak undone. A phrase
    quoted as an example (attackers write text such as "ignore previous
    instructions") is a mention, not an instruction, and is skipped.
    """
    norm = normalise(text)
    candidates = (norm, deleet(norm)) if any(ch in norm for ch in "013457@$!") else (norm,)
    variants = [v for v in candidates if _INJECTION_PREFILTER.search(v)]
    hits: list[str] = []
    if not variants:
        return hits
    for rx, msg in INJECTION_PATTERNS:
        for variant in variants:
            match = rx.search(variant)
            if match and not _quoted_mention(variant, match.start(), match.end()):
                hits.append(msg)
                break
    return hits


def encoded_hits(text: str) -> list[str]:
    """Injection or exfiltration hidden inside base64 or hex strings."""
    hits: list[str] = []
    for payload in decoded_payloads(text):
        hits.extend(injection_hits(payload) + exfil_hits(payload))
    return hits


def exfil_hits(text: str) -> list[str]:
    """Return messages for every exfiltration pattern matching ``text``.

    Checks the normalised text and, when it contains digits or symbols,
    the same text with leetspeak undone.
    """
    norm = normalise(text)
    hits = _exfil_hits_norm(text, norm) if _EXFIL_PREFILTER.search(norm) else []
    if not hits and any(ch in norm for ch in "013457@$!"):
        leet = deleet(norm)
        if _EXFIL_PREFILTER.search(leet):
            hits = _exfil_hits_norm(text, leet)
    return hits


def _exfil_hits_norm(text: str, norm: str) -> list[str]:
    hits: list[str] = []
    match = EXFIL_SEND_RE.search(norm)
    if match and not negated(norm, match.start()):
        hits.append("tells the agent to send data to a web address")
    if URL_WITH_QUERY_RE.search(norm) and SENSITIVE_WORDS_RE.search(norm):
        query = URL_WITH_QUERY_RE.search(norm)
        if query and not negated(norm, query.start()):
            hits.append("builds a web address that carries private data")
    if IMAGE_PLACEHOLDER_RE.search(text):
        hits.append("has a Markdown image whose address is filled with data (it leaks when rendered)")
    match = SENSITIVE_FILE_RE.search(norm)
    if match and not negated(norm, match.start()):
        hits.append("tells the agent to read or share a credential file")
    return hits


__all__ = ["Server", "iter_servers"]


def server_line(doc: Document, server: Server, needle: str) -> int:
    """Line of ``needle`` inside a server block, or the server's own line."""
    return find_line(doc.text, needle, server.line)


def text_lines(doc: Document) -> Iterator[tuple[int, str]]:
    """Yield (line number, line) pairs for a document."""
    yield from enumerate(doc.lines, start=1)
