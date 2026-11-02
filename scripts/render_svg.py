"""Render real Glint terminal output as SVG images for the README.

Run from the repository root: python scripts/render_svg.py
The images are generated from actual command output, never edited by hand.
"""

from __future__ import annotations

import contextlib
import io
import os
import re
import sys
from html import escape
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from glint.cli import main  # noqa: E402

OUT = ROOT / "docs" / "images"
CHAR_W, LINE_H, PAD = 7.8, 18, 16
FG, BG = "#e6edf3", "#0d1117"
COLOURS = {"31": "#ff7b72", "32": "#3fb950", "33": "#d29922", "36": "#79c0ff"}
SGR = re.compile(r"\x1b\[([0-9;]*)m")


def capture(args: list[str], columns: int) -> str:
    os.environ["FORCE_COLOR"] = "1"
    os.environ["COLUMNS"] = str(columns)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf), contextlib.redirect_stderr(io.StringIO()):
        main(args)
    return buf.getvalue().rstrip("\n")


def line_to_tspans(line: str) -> str:
    out: list[str] = []
    colour, bold, dim = FG, False, False
    pos = 0
    for match in [*SGR.finditer(line), None]:
        end = match.start() if match else len(line)
        text = line[pos:end]
        if text:
            attrs = [f'fill="{colour}"']
            if bold:
                attrs.append('font-weight="bold"')
            if dim:
                attrs.append('fill-opacity="0.65"')
            out.append(f"<tspan {' '.join(attrs)}>{escape(text)}</tspan>")
        if match is None:
            break
        for code in (match.group(1) or "0").split(";"):
            if code in ("0", ""):
                colour, bold, dim = FG, False, False
            elif code == "1":
                bold = True
            elif code == "2":
                dim = True
            elif code in COLOURS:
                colour = COLOURS[code]
        pos = match.end()
    return "".join(out)


def render(command: str, output: str, path: Path, columns: int) -> None:
    lines = [f"\x1b[32m$\x1b[0m {command}", *output.split("\n")]
    width = int(columns * CHAR_W + 2 * PAD)
    height = int(len(lines) * LINE_H + 2 * PAD + 28)
    rows = "\n".join(
        f'<text x="{PAD}" y="{PAD + 28 + (i + 1) * LINE_H - 4}" xml:space="preserve">{line_to_tspans(line)}</text>'
        for i, line in enumerate(lines)
    )
    svg = f"""<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" viewBox="0 0 {width} {height}" role="img" aria-label="{escape(command)}">
<rect width="100%" height="100%" rx="10" fill="{BG}"/>
<circle cx="20" cy="18" r="6" fill="#ff5f57"/><circle cx="40" cy="18" r="6" fill="#febc2e"/><circle cx="60" cy="18" r="6" fill="#28c840"/>
<g font-family="ui-monospace,SFMono-Regular,Menlo,Consolas,monospace" font-size="13">
{rows}
</g></svg>
"""
    path.write_text(svg, encoding="utf-8")
    print(f"wrote {path.relative_to(ROOT)} ({len(lines)} lines)")


def main_() -> None:
    os.chdir(ROOT)
    OUT.mkdir(parents=True, exist_ok=True)
    shots = [
        ("glint scan demo/vulnerable-agent --rules GL-002,GL-005,GL-011,GL-012,GL-015", "scan.svg", 112),
        ("glint reveal demo/vulnerable-agent/CLAUDE.md", "reveal.svg", 112),
        ("glint graph demo/vulnerable-agent", "graph.svg", 112),
    ]
    for command, name, columns in shots:
        render(command, capture(command.split()[1:], columns), OUT / name, columns)


if __name__ == "__main__":
    main_()
