"""GL-011: the lethal trifecta across tools."""

from __future__ import annotations

from pathlib import PurePosixPath

from glint.capabilities import (
    CAN_EXFILTRATE,
    CAP_HELP,
    INGESTS_UNTRUSTED,
    READS_PRIVATE,
    analyse_trifecta,
    project_providers,
)
from glint.models import ALL_KINDS, Finding, Project, ProjectRule, Severity
from glint.textutil import safe


class LethalTrifecta(ProjectRule):
    """Private data, untrusted content and a way out, all reachable by one agent."""

    id = "GL-011"
    title = "Lethal trifecta"
    default_severity = Severity.CRITICAL
    applies_to = ALL_KINDS
    owasp = "LLM06: Excessive Agency"
    description = (
        "Flags projects where the agent can read private data, take in untrusted content and "
        "send data out. Together these let injected text steal data, even if each tool is safe alone."
    )
    fix = "Remove one leg of the chain, or put the tools that send data out behind user approval."

    def check_project(self, project: Project) -> list[Finding]:
        """Combine every server, tool and permission and look for the full chain."""
        result = analyse_trifecta(project_providers(project))
        if not result.complete:
            return []
        verbs = {
            READS_PRIVATE: "read private data through",
            INGESTS_UNTRUSTED: "take in untrusted content through",
            CAN_EXFILTRATE: "send data out through",
        }
        parts = []
        for cap, providers in result.chain():
            names = ", ".join(p.label for p in providers[:3])
            more = f" and {len(providers) - 3} more" if len(providers) > 3 else ""
            parts.append(f"{verbs[cap]} {names}{more}")
        anchor = result.breaker or result.by_cap["can-exfiltrate"][0]
        if result.breaker:
            fix = (
                f"Smallest fix: remove {result.breaker.label} or require approval for it; that alone breaks the chain."
            )
        else:
            fewest = min(result.chain(), key=lambda item: len(item[1]))
            fix = (
                "No single change breaks the chain. Remove or require approval for every source that "
                f"{CAP_HELP[fewest[0]]}: {', '.join(p.label for p in fewest[1])}."
            )
        return [
            self.finding_at(
                project_path(anchor.path),
                anchor.line,
                "The agent can "
                + "; ".join(parts)
                + ". Text injected through the untrusted source could make it leak the private data.",
                safe(
                    " | ".join(
                        f"{cap}: " + ", ".join(p.label.split(" ", 1)[1].strip("'") for p in provs)
                        for cap, provs in result.chain()
                    ),
                    300,
                ),
                fix=fix,
            )
        ]


def project_path(path: str) -> PurePosixPath:
    """Convert a stored path string back to a PurePosixPath."""
    return PurePosixPath(path)
