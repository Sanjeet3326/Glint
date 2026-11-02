"""Turn findings into a 0 to 100 risk score."""

from __future__ import annotations

from collections.abc import Iterable

from glint.models import Finding, Severity

WEIGHTS: dict[Severity, int] = {
    Severity.CRITICAL: 40,
    Severity.HIGH: 15,
    Severity.MEDIUM: 5,
    Severity.LOW: 1,
}
CRITICAL_FLOOR = 70

BANDS: tuple[tuple[int, str], ...] = (
    (0, "clean"),
    (24, "low"),
    (49, "medium"),
    (69, "high"),
    (100, "critical"),
)


def risk_score(findings: Iterable[Finding]) -> int:
    """Sum severity weights (capped at 100); any Critical means at least 70.

    Suppressed findings do not count.
    """
    active = [f for f in findings if not f.suppressed]
    score = min(100, sum(WEIGHTS[f.severity] for f in active))
    if any(f.severity is Severity.CRITICAL for f in active):
        score = max(score, CRITICAL_FLOOR)
    return score


def band(score: int) -> str:
    """Name the band a score falls in."""
    for upper, name in BANDS:
        if score <= upper:
            return name
    return "critical"
