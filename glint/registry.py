"""Discover and load every rule class in ``glint.rules``."""

from __future__ import annotations

import importlib
import inspect
import pkgutil

import glint.rules
from glint.models import Rule


def load_rules() -> list[Rule]:
    """Import every module in ``glint.rules`` and return one instance per Rule.

    Adding a rule means adding a module with one Rule subclass; nothing
    else in the code base needs to change.
    """
    rules: dict[str, Rule] = {}
    for info in pkgutil.iter_modules(glint.rules.__path__):
        if info.name.startswith("_"):
            continue
        module = importlib.import_module(f"glint.rules.{info.name}")
        for _, obj in inspect.getmembers(module, inspect.isclass):
            if issubclass(obj, Rule) and obj is not Rule and obj.__module__ == module.__name__:
                rule = obj()
                if not rule.id:
                    raise ValueError(f"rule class {obj.__name__} has no id")
                if rule.id in rules:
                    raise ValueError(f"duplicate rule id {rule.id}")
                rules[rule.id] = rule
    return [rules[k] for k in sorted(rules)]


def select_rules(rules: list[Rule], wanted: list[str] | None) -> list[Rule]:
    """Keep only the rules whose ids are in ``wanted`` (all when None)."""
    if not wanted:
        return rules
    ids = {w.strip().upper() for w in wanted if w.strip()}
    known = {r.id for r in rules}
    unknown = ids - known
    if unknown:
        raise ValueError(f"unknown rule id(s): {', '.join(sorted(unknown))}")
    return [r for r in rules if r.id in ids]
