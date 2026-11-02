<h1 align="center">Glint</h1>

<p align="center"><b>See what your AI agents are really told and allowed to do.</b></p>

<p align="center">
<a href="https://github.com/Sanjeet3326/Glint/actions/workflows/ci.yml"><img alt="CI" src="https://github.com/Sanjeet3326/Glint/actions/workflows/ci.yml/badge.svg"></a>
<a href="https://pypi.org/project/glintscan/"><img alt="PyPI" src="https://img.shields.io/pypi/v/glintscan"></a>
<img alt="Python 3.11+" src="https://img.shields.io/badge/python-3.11%2B-3776ab">
<img alt="Dependencies: none" src="https://img.shields.io/badge/dependencies-none-2ea44f">
<img alt="Typed: mypy strict" src="https://img.shields.io/badge/types-mypy%20strict-2a6db2">
<a href="LICENSE"><img alt="License: MIT" src="https://img.shields.io/badge/license-MIT-blue"></a>
</p>

Glint is an offline security scanner for the files that steer AI coding agents: `AGENTS.md`,
`CLAUDE.md`, Cursor, Windsurf, Cline and Copilot rules, Claude Code settings and hooks, skills,
saved tool listings and MCP server configs.

A single poisoned instruction, leaked token, over-powered tool or quietly changed MCP server can turn
an agent against the person using it. Glint finds these problems before you commit, explains each one
with evidence and an attack story, and tells you how to fix it.

<p align="center"><img src="docs/images/scan.svg" alt="glint scan output showing a lethal trifecta, a leaked token, hidden instructions, a look-alike package and tool drift" width="880"></p>

## Why Glint

- **Reasons across tools, not just files.** The lethal-trifecta check (GL-011) finds agents that can
  read private data, take in untrusted content *and* send data out, and names the single change that
  breaks the chain.
- **Catches rug pulls.** `glint lock` records approved MCP servers and tool descriptions; later scans
  show exactly what changed (GL-012).
- **Shows what humans miss.** `glint reveal` puts the rendered view next to what the agent actually
  reads: HTML comments, bidirectional overrides and invisible Unicode "tag" text.
- **Hard to dodge.** Look-alike letters, leetspeak, zero-width characters, line breaks and base64 do
  not hide an injection. The `selftest` command measures this and publishes the numbers.
- **Built for teams.** SARIF for GitHub code scanning, a ready-made GitHub Action, a pre-commit hook,
  baselines for existing repos, diff mode for pull requests, custom rules and an HTML report.
- **Safe to run on hostile input.** Offline, read-only, no dependencies, strict types. Escape codes in
  scanned files cannot rewrite the report, and secrets are always masked.

## Install

```bash
pip install glintscan
```

Requires Python 3.11 or newer. The command is `glint`. Or run it from a clone with `python -m glint`.

## Quick start

```bash
glint scan .                 # scan the current repository
glint reveal CLAUDE.md       # see hidden content in one file
glint graph .                # what each server, tool and permission lets the agent do
glint explain GL-011         # the attack story behind a rule
```

Try it on the demo project, where every rule fires:

```bash
git clone https://github.com/Sanjeet3326/Glint && cd Glint
python -m glint scan demo/vulnerable-agent
```

## What it checks

| Rule | Catches | Severity |
| --- | --- | --- |
| GL-001 | Prompt-injection phrases, including evasion tricks and encoded payloads | High |
| GL-002 | Instructions hidden in HTML comments, hidden elements or long alt text | High / Critical |
| GL-003 | Invisible, bidirectional and Unicode tag characters (hidden text is decoded) | Medium / High |
| GL-004 | MCP servers with shell access or access to the whole disk | Critical |
| GL-005 | Secrets in agent files and MCP configs (always masked in output) | Critical |
| GL-006 | Instructions to send data to URLs, leaky Markdown images, credential-file reads | High |
| GL-007 | MCP packages without an exact version (npx, uvx, pipx, docker) | Medium |
| GL-008 | Tool descriptions that change how other tools behave | High |
| GL-009 | Auto-approve lists, bypassed permission prompts, skip-permission flags | High / Critical |
| GL-010 | Over-broad permissions such as `Bash(*)`, `Bash(curl:*)`, unrestricted `WebFetch` | High |
| GL-011 | **Lethal trifecta:** private data + untrusted content + a way out, in one agent | Critical |
| GL-012 | **Tool drift:** servers or tool descriptions changed since `glint.lock` | High |
| GL-013 | Hooks that download and run code, or contact remote URLs | High / Critical |
| GL-014 | Remote MCP servers over plain HTTP or with credentials in the URL or headers | High / Critical |
| GL-015 | Look-alike (typosquatted) MCP package names | High |

Every rule maps to the OWASP Top 10 for LLM Applications 2025. Details, with examples of what each rule
does and does not flag: [docs/rules.md](docs/rules.md).

## See what the agent sees

<p align="center"><img src="docs/images/reveal.svg" alt="glint reveal: human view next to agent view with hidden parts highlighted" width="880"></p>

## Find dangerous combinations

Each tool can be reasonable on its own and still be dangerous in combination. `glint graph` tags every
MCP server, saved tool and permission with what it lets the agent do, and checks for the lethal trifecta.

<p align="center"><img src="docs/images/graph.svg" alt="glint graph capability matrix and lethal trifecta summary" width="880"></p>

`glint graph --format dot | dot -Tsvg > agents.svg` draws it with Graphviz. Tags are inferred from names
and commands; correct them for your own servers in `.glint.toml`:

```toml
[capabilities]
"internal-wiki" = ["reads-private"]
```

## Lock approved tools

```bash
glint lock            # write glint.lock after reviewing your MCP setup; commit it
glint lock --check    # in CI: fail if the lockfile is missing or out of date
```

The lockfile stores hashes of server commands, arguments and URLs, env and header *key names* (never
secret values) and the name, description and schema of every tool in saved listings (`*.tools.json`, the
JSON a server returns for `tools/list`). Any later change becomes a GL-012 finding with a word-level diff.

## All commands

| Command | What it does |
| --- | --- |
| `glint scan [PATH]` | Scan for risks. Formats: `terminal`, `json`, `sarif`, `html` |
| `glint reveal FILE` | Human view next to agent view, with hidden parts highlighted |
| `glint inventory [PATH]` | Every agent file, MCP server, tool, permission and hook (`--format json`) |
| `glint graph [PATH]` | Capability matrix and lethal-trifecta check (`--format dot` or `json`) |
| `glint lock [PATH]` | Record approved servers and tools in `glint.lock` (`--check` for CI) |
| `glint fix [PATH]` | Remove invisible and bidirectional characters; shows a diff, `--write` applies |
| `glint explain RULE` | Attack story, before and after examples, and references for a rule |
| `glint selftest` | Measure detection and false-positive rates on built-in samples |
| `glint rules` | List every rule |

Useful `scan` options:

```text
--fail-on low|medium|high|critical   exit 1 at or above this severity (default: high)
--format terminal|json|sarif|html    report format; --output FILE to write it
--baseline FILE / --write-baseline FILE   accept today's findings, report only new ones
--diff GIT_REF                       report only findings in files changed since GIT_REF
--rules GL-001,GL-005                run selected rules
--strict                             also check examples inside code blocks and quotes
--min-confidence low|medium|high     hide less certain findings
```

Exit codes: `0` nothing at or above `--fail-on`, `1` findings found, `2` usage or configuration error.
The JSON report follows [schema/report.schema.json](schema/report.schema.json).

## Use it in CI

### GitHub Action

```yaml
name: Glint
on: [push, pull_request]
permissions:
  contents: read
  security-events: write
jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v6
      - uses: Sanjeet3326/Glint@v0.2.1
        id: glint
        with:
          fail-on: high
      - uses: github/codeql-action/upload-sarif@v4
        if: always()
        with:
          sarif_file: ${{ steps.glint.outputs.sarif-file }}
```

Findings then appear in the Security tab and as annotations on pull requests. The action also writes a
summary to the job page. Inputs: `path`, `fail-on`, `sarif-file`, `args` (for example
`--baseline .glint-baseline.json`).

### pre-commit

```yaml
repos:
  - repo: https://github.com/Sanjeet3326/Glint
    rev: v0.2.1
    hooks:
      - id: glint
```

### Adopting Glint in an existing repository

```bash
glint scan . --write-baseline .glint-baseline.json   # accept what is there today
glint scan . --baseline .glint-baseline.json         # from now on, fail only on new findings
```

Baseline fingerprints use the rule, file and normalised evidence, not the line number, so editing a file
does not make old findings look new.

## Configuration

Optional `.glint.toml` in the scanned folder:

```toml
fail_on = "medium"
exclude = ["vendor/", "examples/**"]
disable = ["GL-007"]

[capabilities]
"internal-wiki" = ["reads-private"]

[[rules]]
id = "ORG-001"
title = "Internal hostnames in prompts"
severity = "medium"
applies_to = ["instructions", "prompt"]
pattern = '\b[a-z0-9-]+\.corp\.example\.com\b'
fix = "Do not put internal hostnames in agent files."
```

Custom rules are checked before use: patterns with nested quantifiers such as `(a+)+`, or that are slow
on simple input, are rejected so a config file cannot hang the scanner.

Silence findings with `.glintignore` (`path-glob` or `GL-005 path-glob` per line) or inline with
`<!-- glint: ignore GL-002 -->` on the same line or on its own line just above. Suppressed findings do not
count toward the score but are still listed in JSON output.

## Files it reads

| Tool | Files |
| --- | --- |
| Any agent | `AGENTS.md`, `CLAUDE.md`, `GEMINI.md` at any depth |
| Claude Code | `.claude/settings.json`, `.claude/settings.local.json` (permissions and hooks), `.claude/agents/`, `.claude/commands/`, `SKILL.md` |
| Cursor | `.cursorrules`, `.cursor/rules/`, `.cursor/mcp.json` |
| Windsurf | `.windsurfrules`, `.windsurf/rules/` |
| Cline and Roo | `.clinerules`, `.roo/rules/`, `cline_mcp_settings.json` |
| Continue | `.continue/rules/` |
| GitHub Copilot | `.github/copilot-instructions.md`, `.github/instructions/`, `.github/prompts/` |
| MCP | `mcp.json`, `.mcp.json`, `.vscode/mcp.json`, `claude_desktop_config.json` (JSON with comments is fine) |
| Prompts | `prompts/**`, `*.prompt`, `*.prompt.md`, `system_prompt*` |
| Tool listings | `*.tools.json` |

Glint skips `.git`, `node_modules`, virtual environments, binary files, files over 2 MB and symlinks that
point outside the scanned folder.

## Results

Measured on v0.2.0 (reproduce with the commands shown):

- `glint scan demo/vulnerable-agent`: all 15 rules fire (26 findings).
- `glint scan demo/clean-agent`: 0 findings.
- 1,000 agent files scanned in 1.4 seconds on a 4-core Linux container.
- `glint selftest`: 138/138 generated attack variants detected, 0/40 benign samples flagged.

<details>
<summary>Self-test detail by rule and evasion style</summary>

| Rule | Evasion style | Detected |
| --- | --- | --- |
| GL-001 | plain | 8/8 |
| GL-001 | upper case | 8/8 |
| GL-001 | extra spaces | 8/8 |
| GL-001 | zero-width chars | 8/8 |
| GL-001 | look-alike letters | 8/8 |
| GL-001 | full-width letters | 8/8 |
| GL-001 | leetspeak | 8/8 |
| GL-001 | split across lines | 8/8 |
| GL-001 | base64 encoded | 8/8 |
| GL-006 | plain | 5/5 |
| GL-006 | upper case | 5/5 |
| GL-006 | extra spaces | 5/5 |
| GL-006 | zero-width chars | 5/5 |
| GL-006 | look-alike letters | 5/5 |
| GL-006 | full-width letters | 5/5 |
| GL-006 | leetspeak | 5/5 |
| GL-006 | split across lines | 5/5 |
| GL-006 | base64 encoded | 5/5 |
| GL-002 | HTML comment | 13/13 |
| GL-003 | Unicode tag characters | 8/8 |

**Overall: 138/138 attack samples detected (100%), 0/40 benign samples flagged.**

</details>

The self-test samples are generated by Glint's own test suite, so a perfect score is a regression
guarantee, not a claim about attacks in the wild. Real attackers will find phrasings that no pattern list
covers.

## Threat model and limits

Glint is static analysis. It catches known patterns, hidden content and risky configuration, and it
reasons about tool combinations, but it cannot catch a novel, well-disguised injection and it does not
run or sandbox agents. Capability tags are inferred from names and can be wrong; override them in
`.glint.toml`. Treat a clean scan as a good sign, not a guarantee.

## How it works

```text
collect -> parse -> per-file rules -> project rules -> ignores and baseline -> score -> report
```

Each rule is one class in `glint/rules/`; the registry discovers it, so adding a rule never touches the
core. Project rules (the trifecta and drift checks) see every parsed file at once.

## Related tools

mcp-scan focuses on MCP servers and their live tool descriptions; gitleaks and TruffleHog find secrets in
general. Glint focuses on the agent files a repository ships, works fully offline, and covers permissions,
hooks and tool combinations as well as prompts and MCP configs.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Report a detection bypass privately through
[SECURITY.md](SECURITY.md).

## License

MIT © 2026 Sanjeet Kumar
