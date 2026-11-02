"""Glint desktop app (tkinter, part of the Python standard library).

Start it with ``glint gui [PATH]`` or the ``glint-gui`` command (which opens
without a console window on Windows).
"""

from __future__ import annotations

import queue
import sys
import threading
import webbrowser
from pathlib import Path
from typing import Any

try:
    import tkinter as tk
    from tkinter import filedialog, messagebox, ttk
except ImportError:  # pragma: no cover - depends on how Python was built
    tk = None  # type: ignore[assignment]

from glint import __version__
from glint.config import ConfigError, load_config
from glint.explain import card
from glint.gui_model import (
    FILTER_ALL,
    FILTER_CHOICES,
    SEVERITY_COLOURS,
    Row,
    details,
    filter_rows,
    finding_file,
    reveal_marks,
    rows,
    summarise,
)
from glint.models import Severity
from glint.reporters import html, json_report, sarif
from glint.reveal import reveal_text, summary_line
from glint.scanner import ScanOptions, ScanResult, scan

__all__ = ["TKINTER_HELP", "GlintApp", "RevealWindow", "main", "run", "tk"]

TKINTER_HELP = (
    "The Glint app needs tkinter, which is missing from this Python.\n"
    "  Windows / macOS: reinstall Python from python.org (tkinter is included).\n"
    "  Ubuntu / Debian: sudo apt install python3-tk\n"
    "  Fedora: sudo dnf install python3-tkinter\n"
    "The command-line scanner works without it: glint scan ."
)

BG = "#f6f8fa"
CARD = "#ffffff"
INK = "#1f2328"
MUTED = "#59636e"
LINE = "#d1d9e0"
ACCENT = "#0969da"
MONO = (
    ("Consolas", 10)
    if sys.platform == "win32"
    else ("Menlo", 11)
    if sys.platform == "darwin"
    else ("DejaVu Sans Mono", 10)
)
SANS = ("Segoe UI", 10) if sys.platform == "win32" else ("Helvetica", 11)


class GlintApp:
    """Main window: choose a folder, scan it, browse findings."""

    def __init__(self, root: Any, initial_path: str | None = None) -> None:
        """Build the window. ``root`` is a ``tk.Tk`` instance."""
        self.root = root
        self.result: ScanResult | None = None
        self.all_rows: list[Row] = []
        self.visible: dict[str, Row] = {}
        self.jobs: queue.Queue[tuple[str, Any]] = queue.Queue()
        self.scanning = False
        self.closed = False
        self._timers: set[str] = set()

        root.title(f"Glint {__version__}")
        root.geometry("1180x760")
        root.minsize(900, 560)
        root.configure(background=BG)
        self._style()

        self.path_var = tk.StringVar(value=initial_path or str(Path.cwd()))
        self.strict_var = tk.BooleanVar(value=False)
        self.filter_var = tk.StringVar(value=FILTER_ALL)
        self.search_var = tk.StringVar()
        self.status_var = tk.StringVar(value="Choose a folder and press Scan.")

        self._build_toolbar()
        self._build_banner()
        self._build_body()
        self._build_statusbar()

        root.bind("<F5>", lambda _e: self.start_scan())
        root.bind("<Control-o>", lambda _e: self.choose_folder())
        root.bind("<Return>", lambda _e: self.start_scan())
        self.filter_var.trace_add("write", lambda *_: self.refresh_table())
        self.search_var.trace_add("write", lambda *_: self.refresh_table())
        root.protocol("WM_DELETE_WINDOW", self.close)
        self._later(100, self._poll)
        if initial_path:
            self._later(200, self.start_scan)

    # ------------------------------------------------------------------ layout

    def _style(self) -> None:
        style = ttk.Style(self.root)
        if "clam" in style.theme_names():
            style.theme_use("clam")
        style.configure(".", background=BG, foreground=INK, font=SANS)
        style.configure("TFrame", background=BG)
        style.configure("Card.TFrame", background=CARD, relief="solid", borderwidth=1)
        style.configure("TLabel", background=BG, foreground=INK)
        style.configure("Card.TLabel", background=CARD)
        style.configure("Muted.TLabel", background=CARD, foreground=MUTED)
        style.configure("Accent.TButton", background=ACCENT, foreground="#ffffff", padding=(14, 6))
        style.map("Accent.TButton", background=[("active", "#0550ae"), ("disabled", "#8c959f")])
        style.configure("TButton", padding=(10, 5))
        style.configure("Treeview", rowheight=26, background=CARD, fieldbackground=CARD, bordercolor=LINE)
        style.configure("Treeview.Heading", font=(SANS[0], SANS[1], "bold"), background="#eaeef2")
        style.map("Treeview", background=[("selected", "#ddf4ff")], foreground=[("selected", INK)])

    def _build_toolbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(14, 12, 14, 6))
        bar.pack(fill="x")
        ttk.Label(bar, text="Folder or file").pack(side="left")
        entry = ttk.Entry(bar, textvariable=self.path_var)
        entry.pack(side="left", fill="x", expand=True, padx=8)
        ttk.Button(bar, text="Browse\u2026", command=self.choose_folder).pack(side="left")
        ttk.Checkbutton(bar, text="Strict (check code examples too)", variable=self.strict_var).pack(
            side="left", padx=12
        )
        self.scan_button = ttk.Button(bar, text="Scan", style="Accent.TButton", command=self.start_scan)
        self.scan_button.pack(side="left")

    def _build_banner(self) -> None:
        banner = ttk.Frame(self.root, style="Card.TFrame", padding=(16, 10))
        banner.pack(fill="x", padx=14, pady=(4, 8))
        self.score_label = tk.Label(
            banner, text="\u2013", font=(SANS[0], 28, "bold"), fg=MUTED, bg=CARD, width=4, anchor="center"
        )
        self.score_label.pack(side="left")
        text = ttk.Frame(banner, style="Card.TFrame", padding=0)
        text.configure(borderwidth=0)
        text.pack(side="left", fill="x", expand=True, padx=(8, 0))
        self.band_label = tk.Label(text, text="Not scanned yet", font=(SANS[0], 13, "bold"), fg=INK, bg=CARD)
        self.band_label.pack(anchor="w")
        self.headline_label = ttk.Label(text, text="", style="Muted.TLabel")
        self.headline_label.pack(anchor="w")
        self.trifecta_label = tk.Label(text, text="", font=(SANS[0], SANS[1], "bold"), bg=CARD)
        self.trifecta_label.pack(anchor="w")
        counts = ttk.Frame(banner, style="Card.TFrame", padding=0)
        counts.configure(borderwidth=0)
        counts.pack(side="right")
        self.count_labels: dict[str, Any] = {}
        for severity in sorted(Severity, reverse=True):
            cell = tk.Frame(counts, bg=CARD, padx=10)
            cell.pack(side="left")
            number = tk.Label(cell, text="0", font=(SANS[0], 18, "bold"), fg=SEVERITY_COLOURS[severity], bg=CARD)
            number.pack()
            tk.Label(cell, text=severity.label, fg=MUTED, bg=CARD).pack()
            self.count_labels[severity.label] = number

    def _build_body(self) -> None:
        panes = ttk.PanedWindow(self.root, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=14)

        left = ttk.Frame(panes)
        filters = ttk.Frame(left, padding=(0, 0, 0, 6))
        filters.pack(fill="x")
        ttk.Combobox(filters, textvariable=self.filter_var, values=FILTER_CHOICES, state="readonly", width=16).pack(
            side="left"
        )
        ttk.Label(filters, text="Search").pack(side="left", padx=(12, 4))
        ttk.Entry(filters, textvariable=self.search_var).pack(side="left", fill="x", expand=True)

        table_frame = ttk.Frame(left)
        table_frame.pack(fill="both", expand=True)
        columns = ("severity", "rule", "title", "location")
        self.table = ttk.Treeview(table_frame, columns=columns, show="headings", selectmode="browse")
        for column, heading, width in (
            ("severity", "Severity", 80),
            ("rule", "Rule", 64),
            ("title", "Problem", 220),
            ("location", "File", 190),
        ):
            self.table.heading(column, text=heading)
            self.table.column(column, width=width, anchor="w", stretch=column in ("title", "location"))
        for severity in Severity:
            self.table.tag_configure(severity.label, foreground=SEVERITY_COLOURS[severity])
        scroll = ttk.Scrollbar(table_frame, orient="vertical", command=self.table.yview)
        self.table.configure(yscrollcommand=scroll.set)
        self.table.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.table.bind("<<TreeviewSelect>>", lambda _e: self.show_selected())
        self.table.bind("<Double-1>", lambda _e: self.reveal_selected())
        panes.add(left, weight=3)

        right = ttk.Frame(panes, style="Card.TFrame", padding=(14, 12))
        self.detail = tk.Text(
            right, wrap="word", relief="flat", bg=CARD, fg=INK, font=SANS, padx=4, pady=4, cursor="arrow"
        )
        self.detail.tag_configure("title", font=(SANS[0], 14, "bold"), spacing3=4)
        self.detail.tag_configure("label", font=(SANS[0], SANS[1], "bold"), foreground=MUTED, spacing1=2)
        self.detail.tag_configure("body", font=SANS, spacing2=2)
        self.detail.tag_configure("code", font=MONO, background="#f6f8fa", lmargin1=6, lmargin2=6, rmargin=6)
        self.detail.pack(fill="both", expand=True)
        actions = ttk.Frame(right, style="Card.TFrame", padding=(0, 8, 0, 0))
        actions.configure(borderwidth=0)
        actions.pack(fill="x")
        self.reveal_button = ttk.Button(actions, text="Reveal hidden text in this file", command=self.reveal_selected)
        self.reveal_button.pack(side="left")
        self._set_detail([("Select a finding to see the evidence, the fix and how the attack works.", "body")])
        panes.add(right, weight=2)
        self.panes = panes
        # Give the findings list enough room for every column once the window has a size.
        self._later(50, self._place_sash)

    def _place_sash(self) -> None:
        width = max(580, int(self.root.winfo_width() * 0.54))
        self.panes.sashpos(0, width)  # type: ignore[no-untyped-call]

    def _build_statusbar(self) -> None:
        bar = ttk.Frame(self.root, padding=(14, 8))
        bar.pack(fill="x")
        ttk.Label(bar, textvariable=self.status_var, foreground=MUTED).pack(side="left")
        self.export_buttons = [
            ttk.Button(bar, text="Export SARIF", command=lambda: self.export("sarif")),
            ttk.Button(bar, text="Export JSON", command=lambda: self.export("json")),
            ttk.Button(bar, text="Open HTML report", command=lambda: self.export("html")),
        ]
        for button in self.export_buttons:
            button.pack(side="right", padx=(6, 0))
            button.state(["disabled"])

    def _later(self, ms: int, callback: Any) -> None:
        """Schedule ``callback`` on the Tk loop, tracked so close() can cancel it."""
        if self.closed:
            return
        timer: str = ""

        def run() -> None:
            self._timers.discard(timer)
            if not self.closed:
                callback()

        timer = self.root.after(ms, run)
        self._timers.add(timer)

    def close(self) -> None:
        """Cancel pending timers and close the window."""
        self.closed = True
        for timer in list(self._timers):
            self.root.after_cancel(timer)
        self._timers.clear()
        self.root.destroy()

    # ------------------------------------------------------------------ actions

    def choose_folder(self) -> None:
        """Ask for a folder to scan."""
        chosen = filedialog.askdirectory(initialdir=self.path_var.get() or str(Path.cwd()), mustexist=True)
        if chosen:
            self.path_var.set(chosen)
            self.start_scan()

    def start_scan(self) -> None:
        """Scan in a background thread so the window stays responsive."""
        if self.scanning:
            return
        target = Path(self.path_var.get().strip()).expanduser()
        if not target.exists():
            messagebox.showerror("Glint", f"Path not found:\n{target}")
            return
        self.scanning = True
        self.scan_button.state(["disabled"])
        self.status_var.set(f"Scanning {target} \u2026")
        options = ScanOptions(strict=self.strict_var.get())

        def work() -> None:
            try:
                config = load_config(target.resolve())
                self.jobs.put(("done", scan(target, options, config)))
            except (ConfigError, ValueError, OSError) as exc:
                self.jobs.put(("error", str(exc)))

        threading.Thread(target=work, daemon=True).start()

    def _poll(self) -> None:
        try:
            while True:
                kind, payload = self.jobs.get_nowait()
                self.scanning = False
                self.scan_button.state(["!disabled"])
                if kind == "done":
                    self.show_result(payload)
                else:
                    self.status_var.set("Scan failed.")
                    messagebox.showerror("Glint", str(payload))
        except queue.Empty:
            pass
        self._later(100, self._poll)

    def show_result(self, result: ScanResult) -> None:
        """Fill the banner and the table from a scan result."""
        self.result = result
        self.all_rows = rows(result)
        summary = summarise(result)
        self.score_label.configure(text=str(summary.score), fg=summary.colour)
        self.band_label.configure(text=f"Risk {summary.band.upper()}", fg=summary.colour)
        self.headline_label.configure(text=summary.headline)
        if summary.trifecta:
            self.trifecta_label.configure(
                text="\u26a0 Lethal trifecta: private data + untrusted content + a way out (see GL-011)",
                fg=SEVERITY_COLOURS[Severity.CRITICAL],
            )
        else:
            self.trifecta_label.configure(text="Lethal trifecta: not present", fg="#1a7f37")
        for label, widget in self.count_labels.items():
            widget.configure(text=str(summary.counts.get(label, 0)))
        for button in self.export_buttons:
            button.state(["!disabled"])
        self.refresh_table()
        extra = f", {len(result.suppressed)} suppressed" if result.suppressed else ""
        self.status_var.set(f"Scanned {summary.files} agent file(s) with {len(result.rules)} rules{extra}.")
        if self.visible:
            first = next(iter(self.visible))
            self.table.selection_set(first)
            self.table.focus(first)
        else:
            self._set_detail([(summary.headline, "body")])

    def refresh_table(self) -> None:
        """Re-apply the severity filter and search box."""
        self.table.delete(*self.table.get_children())
        self.visible = {}
        for row in filter_rows(self.all_rows, self.filter_var.get(), self.search_var.get()):
            self.table.insert(
                "",
                "end",
                iid=row.key,
                values=(row.severity, row.rule_id, row.title, row.location),
                tags=(row.finding.severity.label,),
            )
            self.visible[row.key] = row

    def selected_row(self) -> Row | None:
        """The row currently selected in the table."""
        selection = self.table.selection()
        return self.visible.get(selection[0]) if selection else None

    def show_selected(self) -> None:
        """Show details for the selected finding."""
        row = self.selected_row()
        if row is not None:
            self._set_detail(details(row.finding, card(row.finding.rule_id)))

    def _set_detail(self, parts: list[tuple[str, str]]) -> None:
        self.detail.configure(state="normal")
        self.detail.delete("1.0", "end")
        for text, tag in parts:
            self.detail.insert("end", text, tag)
        self.detail.configure(state="disabled")

    def reveal_selected(self) -> None:
        """Open the side-by-side view for the selected finding's file."""
        row = self.selected_row()
        if row is None or self.result is None:
            return
        path = finding_file(self.result.root, row.finding)
        try:
            text = path.read_bytes().decode("utf-8", errors="replace")
        except OSError as exc:
            messagebox.showerror("Glint", f"Cannot read {path}:\n{exc}")
            return
        RevealWindow(self.root, path, text)

    def export(self, fmt: str) -> None:
        """Save the current result as SARIF, JSON or HTML (HTML opens in the browser)."""
        if self.result is None:
            return
        ext = {"sarif": ".sarif", "json": ".json", "html": ".html"}[fmt]
        target = filedialog.asksaveasfilename(
            defaultextension=ext,
            initialfile=f"glint-report{ext}",
            filetypes=[(fmt.upper(), f"*{ext}"), ("All files", "*.*")],
        )
        if not target:
            return
        render = {"sarif": sarif.render, "json": json_report.render, "html": html.render}[fmt]
        Path(target).write_text(render(self.result) + "\n", encoding="utf-8")
        self.status_var.set(f"Saved {target}")
        if fmt == "html":
            webbrowser.open(Path(target).resolve().as_uri())


class RevealWindow:
    """What a human sees next to what the agent reads, with hidden parts in red."""

    def __init__(self, master: Any, path: Path, text: str) -> None:
        """Open a window comparing both views of ``text``."""
        result = reveal_text(text)
        win = tk.Toplevel(master)
        win.title(f"Reveal \u2013 {path.name}")
        win.geometry("1100x640")
        win.configure(background=BG)
        ttk.Label(win, text=summary_line(result), padding=(14, 10)).pack(fill="x")
        panes = ttk.PanedWindow(win, orient="horizontal")
        panes.pack(fill="both", expand=True, padx=14, pady=(0, 14))
        for heading, body, marks in (
            ("Human sees", result.human, []),
            ("Agent reads", result.agent, reveal_marks(result)),
        ):
            frame = ttk.Frame(panes)
            ttk.Label(frame, text=heading, font=(SANS[0], SANS[1], "bold")).pack(anchor="w", pady=(0, 4))
            box = tk.Text(frame, wrap="word", font=MONO, bg=CARD, fg=INK, relief="solid", borderwidth=1, padx=8)
            box.insert("1.0", body)
            box.tag_configure("hidden", background="#ffebe9", foreground="#a40e26")
            for start, end in marks:
                box.tag_add("hidden", f"1.0+{start}c", f"1.0+{end}c")
            box.configure(state="disabled")
            box.pack(fill="both", expand=True)
            panes.add(frame, weight=1)
        self.window = win


def run(initial_path: str | None = None) -> int:
    """Open the app and block until it is closed."""
    if tk is None:
        print(TKINTER_HELP, file=sys.stderr)
        return 2
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"glint: cannot open a window ({exc}). Is a display available?", file=sys.stderr)
        return 2
    GlintApp(root, initial_path)
    root.mainloop()
    return 0


def main() -> int:
    """Entry point for the ``glint-gui`` command."""
    return run(sys.argv[1] if len(sys.argv) > 1 else None)


if __name__ == "__main__":
    raise SystemExit(main())
