"""``glint explain``: attack cards for each rule."""

from __future__ import annotations

from importlib import resources


def card(rule_id: str) -> str | None:
    """Return the Markdown card for a rule, or None if there is none."""
    name = f"{rule_id.upper()}.md"
    path = resources.files("glint").joinpath("cards", name)
    if not path.is_file():
        return None
    return path.read_text(encoding="utf-8")
