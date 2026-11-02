# Security policy

## Reporting a bypass or vulnerability

Please report privately through GitHub's **Report a vulnerability** button on the Security tab
of this repository. Do not open a public issue for:

- a way to hide an attack from Glint (a detection bypass),
- a crafted file that crashes, hangs or tricks Glint's own output,
- anything that makes Glint read outside the folder it was asked to scan.

You can expect an acknowledgement within 7 days. Bypasses are fixed with a new test case and
credited in the changelog unless you prefer otherwise.

## Scope and limits

Glint is a static, pattern-based scanner. Missing a novel, well-disguised prompt injection is a
known limit rather than a vulnerability, but reports of realistic misses are still very welcome.
