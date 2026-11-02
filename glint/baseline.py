"""Baseline files: accept today's findings and report only new ones.

A fingerprint is a hash of the rule id, file path and normalised
evidence. Line numbers are not part of it, so edits above a finding do
not make it look new.
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Iterable
from pathlib import Path

from glint.models import Finding
from glint.textutil import normalise

BASELINE_VERSION = 1


def fingerprint(finding: Finding) -> str:
    """Stable identity of a finding across edits."""
    raw = "\x1f".join([finding.rule_id, str(finding.path), normalise(finding.evidence)])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


def write_baseline(path: Path, findings: Iterable[Finding]) -> int:
    """Write a baseline file; return how many findings it holds."""
    entries = sorted(
        {fingerprint(f): {"rule_id": f.rule_id, "path": str(f.path), "message": f.message} for f in findings}.items()
    )
    data = {"glint_baseline_version": BASELINE_VERSION, "findings": [{"fingerprint": k, **v} for k, v in entries]}
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return len(entries)


def load_baseline(path: Path) -> set[str]:
    """Read fingerprints from a baseline file. Raises ValueError when invalid."""
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError as exc:
        raise ValueError(f"baseline file not found: {path}") from exc
    except (json.JSONDecodeError, UnicodeDecodeError) as exc:
        raise ValueError(f"baseline file is not valid JSON: {path}") from exc
    if not isinstance(data, dict) or data.get("glint_baseline_version") != BASELINE_VERSION:
        raise ValueError(f"unsupported baseline format: {path}")
    return {str(item["fingerprint"]) for item in data.get("findings", []) if isinstance(item, dict)}
