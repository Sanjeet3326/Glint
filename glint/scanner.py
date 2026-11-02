"""Run the collect, parse, check and score pipeline."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from glint.collector import Collected, collect
from glint.config import Config, file_ignored, inline_ignored, load_config
from glint.models import (
    CTX_COMMENT,
    CTX_FENCED,
    CTX_QUOTE,
    Confidence,
    Document,
    Finding,
    Rule,
)
from glint.parser import parse_file
from glint.registry import load_rules, select_rules
from glint.scoring import band, risk_score

# Contexts where text rules skip matches unless --strict is set.
# HTML comments are covered by GL-002, which grades them as hidden content.
QUIET_CONTEXTS = frozenset({CTX_FENCED, CTX_QUOTE, CTX_COMMENT})
MAX_FINDINGS_PER_FILE = 50


@dataclass
class ScanOptions:
    """Options that change how a scan runs."""

    rules: list[str] | None = None
    strict: bool = False
    min_confidence: Confidence = Confidence.LOW


@dataclass
class ScanResult:
    """Everything a reporter needs."""

    root: str
    scanned_files: list[PurePosixPath] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)

    @property
    def score(self) -> int:
        """Overall 0 to 100 risk score."""
        return risk_score(self.findings)

    @property
    def band(self) -> str:
        """Name of the score band."""
        return band(self.score)


def check_document(doc: Document, rules: list[Rule], options: ScanOptions) -> list[Finding]:
    """Run every applicable rule on one document and de-duplicate results."""
    found: dict[tuple[str, int], Finding] = {}
    for rule in rules:
        if doc.kind not in rule.applies_to:
            continue
        for finding in rule.check(doc):
            if rule.respects_context and not options.strict and doc.context(finding.line) in QUIET_CONTEXTS:
                continue
            if finding.confidence < options.min_confidence:
                continue
            key = (finding.rule_id, finding.line)
            current = found.get(key)
            if current is None or finding.severity > current.severity:
                found[key] = finding
    return sorted(found.values(), key=Finding.sort_key)


def scan(target: Path, options: ScanOptions | None = None, config: Config | None = None) -> ScanResult:
    """Scan a folder (or one file) and return the result."""
    options = options or ScanOptions()
    root = target.resolve()
    config = config if config is not None else load_config(root)
    rules = select_rules(load_rules(), options.rules)
    rules = [r for r in rules if r.id not in config.disable]
    base = root if root.is_dir() else root.parent
    result = ScanResult(root=str(target), rules=rules)
    result.warnings.extend(config.notes)
    for item in collect(root, config.exclude):
        if not isinstance(item, Collected):
            result.skipped.append((item.path.relative_to(base).as_posix(), item.reason))
            continue
        try:
            doc = parse_file(item.path, base, item.kind)
        except OSError as exc:
            result.skipped.append((item.path.relative_to(base).as_posix(), str(exc)))
            continue
        result.scanned_files.append(doc.path)
        if doc.parse_error:
            result.warnings.append(f"{doc.path}: {doc.parse_error}")
        findings = check_document(doc, rules, options)
        kept = 0
        for finding in findings:
            if inline_ignored(doc, finding) or file_ignored(config, finding):
                result.suppressed.append(dataclasses.replace(finding, suppressed=True))
            elif kept < MAX_FINDINGS_PER_FILE:
                result.findings.append(finding)
                kept += 1
        if kept >= MAX_FINDINGS_PER_FILE and len(findings) > kept:
            result.warnings.append(f"{doc.path}: showing the first {MAX_FINDINGS_PER_FILE} findings only")
    result.findings.sort(key=Finding.sort_key)
    return result
