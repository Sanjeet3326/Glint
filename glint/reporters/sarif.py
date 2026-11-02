"""SARIF 2.1.0 report for GitHub code scanning."""

from __future__ import annotations

import json
from typing import Any

from glint import __version__
from glint.models import Confidence, Finding, Severity
from glint.scanner import ScanResult

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
INFO_URI = "https://github.com/Sanjeet3326/glint"

_LEVEL = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
}
_SECURITY_SEVERITY = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "8.0",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.0",
}
_PRECISION = {Confidence.HIGH: "high", Confidence.MEDIUM: "medium", Confidence.LOW: "low"}


def _rule(rule: Any) -> dict[str, Any]:
    tags = ["security", "ai-agents"]
    if rule.owasp:
        tags.append(rule.owasp)
    return {
        "id": rule.id,
        "name": rule.title.title().replace(" ", "").replace("-", ""),
        "shortDescription": {"text": rule.title},
        "fullDescription": {"text": rule.description or rule.title},
        "help": {"text": rule.fix, "markdown": f"**Fix:** {rule.fix}"},
        "helpUri": f"{INFO_URI}/blob/main/docs/rules.md#{rule.id.lower()}",
        "defaultConfiguration": {"level": _LEVEL[rule.default_severity]},
        "properties": {
            "tags": tags,
            "security-severity": _SECURITY_SEVERITY[rule.default_severity],
            "precision": "medium",
        },
    }


def _result(finding: Finding, rule_index: dict[str, int]) -> dict[str, Any]:
    return {
        "ruleId": finding.rule_id,
        "ruleIndex": rule_index.get(finding.rule_id, 0),
        "level": _LEVEL[finding.severity],
        "message": {"text": f"{finding.message} Fix: {finding.fix}"},
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": str(finding.path), "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": finding.line},
                }
            }
        ],
        "partialFingerprints": {"glintFinding/v1": f"{finding.rule_id}:{finding.path}:{finding.evidence[:80]}"},
        "properties": {
            "severity": finding.severity.label,
            "precision": _PRECISION[finding.confidence],
            "security-severity": _SECURITY_SEVERITY[finding.severity],
        },
    }


def build(result: ScanResult) -> dict[str, Any]:
    """Build the SARIF log object."""
    rules = result.rules
    index = {r.id: i for i, r in enumerate(rules)}
    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "Glint",
                        "version": __version__,
                        "informationUri": INFO_URI,
                        "rules": [_rule(r) for r in rules],
                    }
                },
                "results": [_result(f, index) for f in result.findings],
            }
        ],
    }


def render(result: ScanResult) -> str:
    """Render the scan result as SARIF JSON."""
    return json.dumps(build(result), indent=2, ensure_ascii=True)
