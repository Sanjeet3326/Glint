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

A new rule is one module and some tests. Nothing else in the core changes; the registry finds the
rule automatically.

1. Create `glint/rules/glNNN_<topic>.py` with exactly one rule class. Set `id`, `title`,
   `default_severity`, `applies_to`, `description`, `fix` and `owasp`.
   - A per-file rule subclasses `Rule` and implements `check(doc) -> list[Finding]`.
   - A rule that needs every file at once (like GL-011) subclasses `ProjectRule` and implements
     `check_project(project) -> list[Finding]`.
2. Compile regexes once at module level. Prefer bounded repeats such as `.{0,80}` over `.*`, and
   avoid nested quantifiers like `(a+)+`, so a crafted file cannot hang the scanner.
3. Pass all evidence through `glint.textutil.safe()` and never print a full secret.
4. Add tests with at least three cases the rule must flag and three it must leave alone, including
   one tricky clean case. Check line numbers and severity.
5. Add an attack card at `glint/cards/GL-NNN.md` (the tests check every rule has one).
6. Make the rule fire in the vulnerable demo and stay silent in the clean demo by editing
   `scripts/make_demos.py`, then run `python scripts/make_demos.py`.
7. Add a section to `docs/rules.md`, a row to the README table and a CHANGELOG entry.

## Checks to run

```bash
python -m unittest discover -s tests -t .
ruff check . && ruff format --check .
mypy glint tests
glint selftest            # must stay at 100% detected, 0 benign flagged
```

After changing terminal output, regenerate the README images with `python scripts/render_svg.py`.

## Conventions

- Python 3.11+, standard library only at runtime.
- Type hints on every function and a docstring on every public class and function.
- No `print` outside `glint/cli.py` and `glint/reporters/`.
- Write invisible characters as `\u` escapes in source files, never as raw characters.
- Commit messages like `feat(rules): add GL-011 risky hooks` or `fix(collector): skip symlink loops`.
- Never put real secrets in tests or demos; build fake ones that match the format.

## False positives

A scanner that cries wolf gets uninstalled. If Glint flags something harmless, please open an
issue with the text (redacted if needed) and what you expected.
