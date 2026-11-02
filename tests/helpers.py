"""Shared test helpers."""

from __future__ import annotations

import json
from pathlib import PurePosixPath
from typing import Any

from glint.models import Document, Finding
from glint.parser import parse_text
from glint.registry import load_rules
from glint.scanner import ScanOptions, check_document

RULES = {rule.id: rule for rule in load_rules()}


def doc(text: str, kind: str = "instructions", name: str = "CLAUDE.md") -> Document:
    """Build a document from text."""
    return parse_text(PurePosixPath(name), kind, text)


def json_doc(data: Any, kind: str = "mcp-config", name: str = ".mcp.json") -> Document:
    """Build a JSON document from a Python object."""
    return doc(json.dumps(data, indent=2), kind, name)


def run(rule_id: str, document: Document, strict: bool = False) -> list[Finding]:
    """Run one rule through the scanner pipeline (context filtering included)."""
    return check_document(document, [RULES[rule_id]], ScanOptions(strict=strict))


def mcp(**servers: Any) -> Document:
    """Build an MCP config document with the given servers."""
    return json_doc({"mcpServers": servers})
