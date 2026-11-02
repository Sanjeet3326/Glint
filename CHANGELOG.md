# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-11-02

### Added

- `glint scan` with ten rules: injection phrases (GL-001), hidden content (GL-002), invisible
  Unicode (GL-003), dangerous MCP tools (GL-004), leaked secrets (GL-005), exfiltration
  patterns (GL-006), unpinned MCP servers (GL-007), tool shadowing (GL-008), auto-approve and
  skip-permission flags (GL-009) and wildcard permissions (GL-010).
- `glint reveal` side-by-side view of what a human sees and what an agent reads.
- Terminal, JSON and SARIF 2.1.0 output; risk score from 0 to 100; exit codes for CI.
- Collector for Claude Code, Cursor, Windsurf, Cline, Roo, Continue and Copilot files and MCP
  configs (including JSON with comments).
- Context-aware matching that skips examples in code blocks and quotes (`--strict` to include).
- `.glint.toml`, `.glintignore` and inline `glint: ignore` comments.
- Output hardening: control characters and ANSI escapes are shown as labels; secrets are masked.
