# Contributing

Thanks for helping make agent setups safer.

## Set up

```bash
git clone https://github.com/Sanjeet3326/glint
cd glint
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
python -m unittest discover -s tests -t .
```

## Add a rule

A new rule is one module and some tests. Nothing else in the code base changes; the registry
finds the rule automatically.

1. Create `glint/rules/glNNN_<topic>.py` with exactly one `Rule` subclass. Set `id`, `title`,
   `default_severity`, `applies_to`, `description`, `fix` and `owasp`, and implement
   `check(doc) -> list[Finding]`. Use `self.finding(...)` to build results.
2. Compile regexes once at module level. Prefer bounded repeats such as `.{0,80}` over `.*`,
   and avoid nested quantifiers like `(a+)+`, so a crafted file cannot hang the scanner.
3. Pass all evidence through `glint.textutil.safe()` and never print a full secret.
4. Add tests to `tests/test_rules.py`: at least three cases the rule must flag and three it must
   leave alone, including one tricky clean case. Check line numbers and severity.
5. Make the rule fire in `demo/vulnerable-agent` and stay silent in `demo/clean-agent`.
6. Add a section to `docs/rules.md` and a line to the README table.

## Conventions

- Python 3.11+, standard library only at runtime.
- Type hints on every function and a docstring on every public class and function.
- No `print` outside `glint/cli.py` and `glint/reporters/`.
- `ruff check .` and `ruff format .` before committing.
- Commit messages like `feat(rules): add GL-011 risky hooks` or `fix(collector): skip symlink loops`.
- Never put real secrets in tests or demos; build fake ones that match the format.

## False positives

A scanner that cries wolf gets uninstalled. If Glint flags something harmless, please open an
issue with the text (redacted if needed) and what you expected.
