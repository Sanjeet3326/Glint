"""Run the collect, parse, check and score pipeline."""

from __future__ import annotations

import dataclasses
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath

from glint.baseline import fingerprint
from glint.collector import Collected, collect
from glint.config import Config, file_ignored, inline_ignored, load_config
from glint.lockfile import LOCK_FILE, load_lock
from glint.models import (
    CTX_COMMENT,
    CTX_FENCED,
    CTX_QUOTE,
    Confidence,
    Document,
    Finding,
    Project,
    ProjectRule,
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
    baseline: set[str] | None = None
    # Relative POSIX paths; when set, only findings in these files are reported.
    changed_files: set[str] | None = None


@dataclass
class ScanResult:
    """Everything a reporter needs."""

    root: str
    scanned_files: list[PurePosixPath] = field(default_factory=list)
    skipped: list[tuple[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    suppressed: list[Finding] = field(default_factory=list)
    baselined: list[Finding] = field(default_factory=list)
    rules: list[Rule] = field(default_factory=list)
    project: Project | None = field(default=None, repr=False)

    @property
    def score(self) -> int:
        """Overall 0 to 100 risk score."""
        return risk_score(self.findings)

    @property
    def band(self) -> str:
        """Name of the score band."""
        return band(self.score)


def check_document(doc: Document, rules: list[Rule], options: ScanOptions) -> list[Finding]:
    """Run every applicable per-file rule on one document and de-duplicate results."""
    found: dict[tuple[str, int], Finding] = {}
    for rule in rules:
        if isinstance(rule, ProjectRule) or doc.kind not in rule.applies_to:
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


def load_project(target: Path, config: Config, result: ScanResult | None = None) -> Project:
    """Collect and parse every agent file under ``target``."""
    root = target.resolve()
    base = root if root.is_dir() else root.parent
    docs: list[Document] = []
    for item in collect(root, config.exclude):
        rel = item.path.relative_to(base).as_posix()
        if not isinstance(item, Collected):
            if result is not None:
                result.skipped.append((rel, item.reason))
            continue
        try:
            doc = parse_file(item.path, base, item.kind)
        except OSError as exc:
            if result is not None:
                result.skipped.append((rel, str(exc)))
            continue
        docs.append(doc)
        if result is not None:
            result.scanned_files.append(doc.path)
            if doc.parse_error:
                result.warnings.append(f"{doc.path}: {doc.parse_error}")
    lock = None
    lock_path = None
    if root.is_dir():
        lock = load_lock(root / LOCK_FILE)
        lock_path = PurePosixPath(LOCK_FILE) if lock is not None else None
    return Project(root=base, docs=docs, capability_overrides=dict(config.capabilities), lock=lock, lock_path=lock_path)


def scan(target: Path, options: ScanOptions | None = None, config: Config | None = None) -> ScanResult:
    """Scan a folder (or one file) and return the result."""
    options = options or ScanOptions()
    root = target.resolve()
    config = config if config is not None else load_config(root)
    rules = select_rules(load_rules() + list(config.custom_rules), options.rules)
    rules = [r for r in rules if r.id not in config.disable]
    result = ScanResult(root=str(target), rules=rules)
    result.warnings.extend(config.notes)
    project = load_project(target, config, result)
    result.project = project
    by_path = {str(d.path): d for d in project.docs}

    raw: list[Finding] = []
    for doc in project.docs:
        findings = check_document(doc, rules, options)
        if len(findings) > MAX_FINDINGS_PER_FILE:
            result.warnings.append(f"{doc.path}: showing the first {MAX_FINDINGS_PER_FILE} findings only")
            findings = findings[:MAX_FINDINGS_PER_FILE]
        raw.extend(findings)
    for rule in rules:
        if isinstance(rule, ProjectRule):
            raw.extend(f for f in rule.check_project(project) if f.confidence >= options.min_confidence)

    for finding in raw:
        owner = by_path.get(str(finding.path))
        if options.changed_files is not None and str(finding.path) not in options.changed_files:
            continue
        if (owner is not None and inline_ignored(owner, finding)) or file_ignored(config, finding):
            result.suppressed.append(dataclasses.replace(finding, suppressed=True))
        elif options.baseline is not None and fingerprint(finding) in options.baseline:
            result.baselined.append(dataclasses.replace(finding, suppressed=True))
        else:
            result.findings.append(finding)
    result.findings.sort(key=Finding.sort_key)
    return result
