"""Machine-readable JSON report."""

from __future__ import annotations

import json
from typing import Any

from glint import __version__
from glint.models import Finding
from glint.scanner import ScanResult

SCHEMA_VERSION = 1


def finding_dict(finding: Finding) -> dict[str, Any]:
    """Convert a finding into plain JSON types."""
    return {
        "rule_id": finding.rule_id,
        "title": finding.title,
        "severity": finding.severity.label,
        "confidence": finding.confidence.label,
        "path": str(finding.path),
        "line": finding.line,
        "message": finding.message,
        "evidence": finding.evidence,
        "fix": finding.fix,
        "owasp": finding.owasp,
    }


def build(result: ScanResult) -> dict[str, Any]:
    """Build the JSON report object."""
    return {
        "tool": "glint",
        "version": __version__,
        "schema_version": SCHEMA_VERSION,
        "target": result.root,
        "scanned_files": [str(p) for p in result.scanned_files],
        "skipped_files": [{"path": p, "reason": r} for p, r in result.skipped],
        "warnings": result.warnings,
        "risk_score": result.score,
        "risk_band": result.band,
        "summary": {
            sev: sum(1 for f in result.findings if f.severity.label == sev)
            for sev in ("critical", "high", "medium", "low")
        },
        "findings": [finding_dict(f) for f in result.findings],
        "suppressed": [finding_dict(f) for f in result.suppressed],
    }


def render(result: ScanResult) -> str:
    """Render the scan result as indented JSON."""
    return json.dumps(build(result), indent=2, ensure_ascii=True)
