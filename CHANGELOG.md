# Changelog

All notable changes to this project are documented here.
This project follows [Semantic Versioning](https://semver.org/).

## [0.2.1] - 2026-11-02

### Changed

- Releases are now published to PyPI automatically: `pip install glintscan`.
- CI uses `actions/checkout` v7.0.1 and `actions/setup-python` v7.1.0.

## [0.2.0] - 2026-11-02

### Added

- GL-011 lethal trifecta: tags every MCP server, saved tool and permission with capabilities and
  flags agents that can read private data, take in untrusted content and send data out, with the
  smallest fix that breaks the chain. Capability overrides in `.glint.toml`.
- GL-012 tool drift: `glint lock` writes `glint.lock`; scans report servers and tool descriptions that
  changed or were added since, with a word-level diff. `glint lock --check` for CI.
- GL-013 risky hooks, GL-014 insecure remote MCP servers, GL-015 look-alike package names.
- Evasion-resistant matching: look-alike Cyrillic and Greek letters, leetspeak, invisible characters
  inside words, phrases split across lines, and base64 or hex encoded payloads.
- `glint inventory`, `glint graph` (terminal, DOT, JSON), `glint fix`, `glint explain` (attack cards for
  every rule) and `glint selftest` (published detection and false-positive rates).
- `scan --format html`: self-contained report with no scripts and a strict Content-Security-Policy.
- `scan --baseline` / `--write-baseline`, `scan --diff GIT_REF`, and custom regex rules in `.glint.toml`
  with protection against slow patterns.
- GitHub Action (`action.yml`), pre-commit hook, published JSON report schema, `FORCE_COLOR` support.
- Release workflow with build provenance attestations and optional PyPI trusted publishing.

### Changed

- Terminal output wraps to the terminal width; `reveal` highlights hidden parts in colour.
- Quoted example phrases in security notes are treated as mentions, not instructions.
- Strict type checking (`mypy --strict`) and coverage of at least 90% are enforced in CI.

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
