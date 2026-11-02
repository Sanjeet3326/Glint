"""GL-012: servers or tool descriptions that changed since they were locked."""

from __future__ import annotations

import difflib
import hashlib
import json

from glint.lockfile import LOCK_FILE, server_record
from glint.mcp import iter_servers, iter_tools
from glint.models import ALL_KINDS, Finding, Project, ProjectRule, Severity
from glint.textutil import safe


def _tool_hash(name: str, description: str, schema: object) -> str:
    body = {"name": name, "description": description, "inputSchema": schema}
    raw = json.dumps(body, sort_keys=True, ensure_ascii=True, separators=(",", ":"))
    return "sha256:" + hashlib.sha256(raw.encode("utf-8")).hexdigest()


def _word_diff(old: str, new: str) -> str:
    """Short inline diff: [-removed-] {+added+}."""
    out: list[str] = []
    a, b = old.split(), new.split()
    for op, i1, i2, j1, j2 in difflib.SequenceMatcher(a=a, b=b).get_opcodes():
        if op == "equal":
            words = a[i1:i2]
            out.append(" ".join(words if len(words) <= 6 else [*words[:3], "...", *words[-3:]]))
        if op in ("delete", "replace"):
            out.append("[-" + " ".join(a[i1:i2]) + "-]")
        if op in ("insert", "replace"):
            out.append("{+" + " ".join(b[j1:j2]) + "+}")
    return " ".join(out)


class ToolDrift(ProjectRule):
    """Silent changes to approved MCP servers ("rug pulls")."""

    id = "GL-012"
    title = "Tool drift since lock"
    default_severity = Severity.HIGH
    applies_to = ALL_KINDS
    owasp = "LLM03: Supply Chain"
    description = (
        "Compares MCP servers and saved tool descriptions with glint.lock and flags anything that "
        "changed or was added after it was reviewed."
    )
    fix = "Review the change. If it is expected, run `glint lock` and commit the updated glint.lock."

    def check_project(self, project: Project) -> list[Finding]:
        """Diff the current servers and tools against the lockfile."""
        lock = project.lock
        if lock is None:
            return []
        locked_servers = lock.get("servers", {})
        locked_tools = lock.get("tools", {})
        findings: list[Finding] = []
        for doc in project.docs:
            for server in iter_servers(doc):
                key = f"{server.path}::{server.name}"
                current = server_record(server)
                before = locked_servers.get(key)
                if before is None:
                    findings.append(
                        self.finding_at(
                            doc.path,
                            server.line,
                            f"Server '{server.name}' was added after {LOCK_FILE} was written.",
                            safe(server.cmdline),
                            severity=Severity.MEDIUM,
                        )
                    )
                elif before.get("hash") != current["hash"]:
                    fields = ("command", "args", "url", "env_keys", "header_keys")
                    changed = [k for k in fields if before.get(k) != current[k]]
                    detail = "; ".join(f"{k}: {before.get(k)!r} -> {current[k]!r}" for k in changed)
                    findings.append(
                        self.finding_at(
                            doc.path,
                            server.line,
                            f"Server '{server.name}' changed since it was locked ({', '.join(changed)}).",
                            safe(detail, 300),
                        )
                    )
            for tool in iter_tools(doc):
                key = f"{tool.server}::{tool.name}"
                before = locked_tools.get(key)
                if before is None:
                    findings.append(
                        self.finding_at(
                            doc.path,
                            tool.line,
                            f"Tool '{tool.server}/{tool.name}' was added after {LOCK_FILE} was written.",
                            safe(tool.description),
                            severity=Severity.MEDIUM,
                        )
                    )
                elif before.get("hash") != _tool_hash(tool.name, tool.description, tool.schema):
                    old = str(before.get("description", ""))
                    what = "description" if old != tool.description else "input schema"
                    findings.append(
                        self.finding_at(
                            doc.path,
                            tool.line,
                            f"Tool '{tool.server}/{tool.name}' {what} changed since it was locked.",
                            safe(_word_diff(old, tool.description) if what == "description" else "schema changed", 300),
                        )
                    )
        return findings
