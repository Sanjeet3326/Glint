"""Self-contained HTML report (no external assets, no scripts)."""

from __future__ import annotations

from collections import defaultdict
from html import escape

from glint import __version__
from glint.explain import card
from glint.models import Finding, Severity
from glint.scanner import ScanResult

_CSS = """
:root{--bg:#ffffff;--fg:#1f2328;--muted:#59636e;--line:#d1d9e0;--card:#f6f8fa;
--critical:#a40e26;--high:#d1242f;--medium:#9a6700;--low:#0969da;--ok:#1a7f37}
@media (prefers-color-scheme:dark){:root{--bg:#0d1117;--fg:#e6edf3;--muted:#9198a1;--line:#3d444d;
--card:#151b23;--critical:#ff7b72;--high:#f85149;--medium:#d29922;--low:#4493f8;--ok:#3fb950}}
*{box-sizing:border-box}body{margin:0;background:var(--bg);color:var(--fg);
font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",Helvetica,Arial,sans-serif}
main{max-width:980px;margin:0 auto;padding:32px 16px}h1{font-size:24px;margin:0 0 4px}
h2{font-size:18px;margin:32px 0 12px;border-bottom:1px solid var(--line);padding-bottom:6px}
.muted{color:var(--muted)}.top{display:flex;gap:24px;align-items:center;flex-wrap:wrap}
.gauge{width:120px;height:120px;border-radius:50%;display:grid;place-items:center;
background:conic-gradient(var(--sev) calc(var(--score)*1%),var(--line) 0)}
.gauge div{width:92px;height:92px;border-radius:50%;background:var(--bg);display:grid;place-items:center;text-align:center}
.gauge b{font-size:28px;line-height:1}.counts{display:flex;gap:8px;flex-wrap:wrap}
.pill{border:1px solid var(--line);border-radius:999px;padding:2px 10px;font-size:13px}
.sev{font-weight:600;font-size:12px;text-transform:uppercase;letter-spacing:.04em}
.sev-critical{color:var(--critical)}.sev-high{color:var(--high)}.sev-medium{color:var(--medium)}.sev-low{color:var(--low)}
.finding{border:1px solid var(--line);border-left:4px solid var(--c);border-radius:8px;padding:12px 14px;margin:10px 0;background:var(--card)}
.finding h3{font-size:15px;margin:2px 0}.finding p{margin:6px 0}
code,pre{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:13px}
pre{white-space:pre-wrap;word-break:break-word;background:var(--bg);border:1px solid var(--line);border-radius:6px;padding:8px;margin:6px 0}
details summary{cursor:pointer;color:var(--muted);font-size:13px}.ok{color:var(--ok);font-weight:600}
table{border-collapse:collapse;width:100%;font-size:14px}td,th{border-bottom:1px solid var(--line);padding:6px;text-align:left}
"""

_COLOUR = {
    Severity.CRITICAL: "var(--critical)",
    Severity.HIGH: "var(--high)",
    Severity.MEDIUM: "var(--medium)",
    Severity.LOW: "var(--low)",
}
_BAND_COLOUR = {
    "clean": "var(--ok)",
    "low": "var(--low)",
    "medium": "var(--medium)",
    "high": "var(--high)",
    "critical": "var(--critical)",
}


def _finding(f: Finding) -> str:
    card_text = card(f.rule_id)
    card_html = (
        f"<details><summary>How this attack works</summary><pre>{escape(card_text)}</pre></details>"
        if card_text
        else ""
    )
    owasp = f' <span class="muted">\u00b7 {escape(f.owasp)}</span>' if f.owasp else ""
    return (
        f'<div class="finding" style="--c:{_COLOUR[f.severity]}">'
        f'<span class="sev sev-{f.severity.label}">{f.severity.label}</span> '
        f'<span class="muted">{escape(f.rule_id)} \u00b7 line {f.line}{owasp}</span>'
        f"<h3>{escape(f.title)}</h3>"
        f"<p>{escape(f.message)}</p>"
        f"<pre>{escape(f.evidence)}</pre>"
        f"<p><b>Fix:</b> {escape(f.fix)}</p>{card_html}</div>"
    )


def render(result: ScanResult) -> str:
    """Render the scan result as one HTML document."""
    by_file: dict[str, list[Finding]] = defaultdict(list)
    for f in result.findings:
        by_file[str(f.path)].append(f)
    counts = "".join(
        f'<span class="pill"><span class="sev sev-{s.label}">{s.label}</span> '
        f"{sum(1 for f in result.findings if f.severity is s)}</span>"
        for s in sorted(Severity, reverse=True)
    )
    body: list[str] = []
    if not result.findings:
        body.append('<p class="ok">No findings.</p>')
    for path in sorted(by_file, key=lambda p: (-max(int(f.severity) for f in by_file[p]), p)):
        body.append(f"<h2><code>{escape(path)}</code></h2>")
        body.extend(_finding(f) for f in by_file[path])
    notes = "".join(f"<li>{escape(w)}</li>" for w in result.warnings)
    extra = []
    if result.suppressed:
        extra.append(f"{len(result.suppressed)} suppressed by ignore rules")
    if result.baselined:
        extra.append(f"{len(result.baselined)} accepted in the baseline")
    files = "".join(f"<tr><td><code>{escape(str(p))}</code></td></tr>" for p in result.scanned_files)
    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src 'unsafe-inline'">
<title>Glint report</title><style>{_CSS}</style></head>
<body><main>
<div class="top">
<div class="gauge" style="--score:{result.score};--sev:{_BAND_COLOUR[result.band]}"><div><span><b>{result.score}</b><br>
<span class="muted">{escape(result.band)}</span></span></div></div>
<div><h1>Glint report</h1>
<div class="muted">{escape(result.root)} \u00b7 {len(result.scanned_files)} agent files \u00b7 {len(result.rules)} rules \u00b7 glint {__version__}</div>
<p class="counts">{counts}</p>
<div class="muted">{escape("; ".join(extra))}</div></div></div>
{f"<ul class='muted'>{notes}</ul>" if notes else ""}
{"".join(body)}
<h2>Scanned files</h2><table>{files}</table>
</main></body></html>
"""
