"""
Sentinel Octopus — Unified Animation System
Industry-grade progress bars, spinners, and status displays.
All 28 Progress() calls in main.py use sentinel_progress() from here.
"""

from rich.progress import (
    Progress, SpinnerColumn, TextColumn, BarColumn,
    TimeElapsedColumn, TaskProgressColumn, MofNCompleteColumn,
    ProgressColumn
)
from rich.live import Live
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.align import Align
from rich.style import Style
from rich.text import Text
from rich.console import Console
from contextlib import contextmanager
import threading
import time


# ─────────────────────────────────────────────────────────────
# Custom Spinner — Octopus tentacle wave
# ─────────────────────────────────────────────────────────────
OCTOPUS_FRAMES = [
    "🐙 ",
    "🐙〜",
    "🐙〜〜",
    "🐙〜〜〜",
    " 🐙〜〜",
    "  🐙〜",
    "   🐙",
    "  〜🐙",
    " 〜〜🐙",
    "〜〜〜🐙",
    "〜〜🐙 ",
    "〜🐙  ",
]

# Fallback ASCII for terminals without emoji support
ASCII_FRAMES = [
    "~o~ ",
    "~o~~",
    " ~o~",
    "~~o~",
    "~~~o",
    "~~o ",
    "~o  ",
    " o~ ",
]


class OctopusSpinner(SpinnerColumn):
    """Custom spinner with octopus tentacle animation."""

    def __init__(self):
        super().__init__(spinner_name="dots")
        self._frames = OCTOPUS_FRAMES
        self._frame_idx = 0

    def render(self, task):
        frame = self._frames[self._frame_idx % len(self._frames)]
        self._frame_idx += 1
        return Text(frame, style="bold cyan")


# ─────────────────────────────────────────────────────────────
# Custom Bar — Tentacle fill style
# ─────────────────────────────────────────────────────────────
class TentacleBar(BarColumn):
    """
    Progress bar that looks like octopus tentacles spreading.
    Complete: ━  Incomplete: ╌  Pulse: 〜
    """

    def __init__(self, bar_width=38):
        super().__init__(
            bar_width=bar_width,
            style=Style(color="cyan"),
            complete_style=Style(color="cyan", bold=True),
            finished_style=Style(color="green", bold=True),
            pulse_style=Style(color="bright_cyan"),
        )


# ─────────────────────────────────────────────────────────────
# Percentage column — clean right-aligned
# ─────────────────────────────────────────────────────────────
class CleanPercent(ProgressColumn):
    """Shows percentage like [cyan] 73%[/cyan]"""

    def render(self, task):
        pct = task.percentage
        if pct >= 100:
            return Text("100%", style="bold green")
        color = "cyan" if pct < 80 else "bright_cyan"
        return Text(f"{pct:>3.0f}%", style=color)


# ─────────────────────────────────────────────────────────────
# Main factory — use this everywhere instead of Progress(...)
# ─────────────────────────────────────────────────────────────
def sentinel_progress(console: Console = None) -> Progress:
    """
    Returns a fully configured Sentinel-themed Progress instance.

    Usage (drop-in replacement):
        with sentinel_progress(console=self.console) as progress:
            task = progress.add_task("[cyan]Scanning...", total=100)
            progress.update(task, advance=10)
    """
    return Progress(
        OctopusSpinner(),
        TextColumn(
            "[progress.description]{task.description}",
            table_column=None,
        ),
        TentacleBar(),
        CleanPercent(),
        TimeElapsedColumn(),
        console=console,
        transient=False,
        expand=False,
    )


# ═════════════════════════════════════════════════════════════
# CINEMATIC INTRO
# ═════════════════════════════════════════════════════════════

OCTOPUS_ASCII = [
    "          .::::::::::.          ",
    "       .:::::::::::::::::.       ",
    "      ::::(o):::::::(o)::::      ",
    "      ::::::::  ___  ::::::::    ",
    "      ::::::: /     \\ :::::::    ",
    "       ':::::::::::::::::'       ",
    "    ~~/~\\\\:::::::::::::/~\\\\~~    ",
    "   ~~/ /~\\\\:::::::::::/~\\\\ \\\\~~  ",
    "  ~/ /   \\\\:::::::::/   \\\\ \\\\~   ",
    "  ~\\\\_\\\\   \\\\:::::::/   /_/~     ",
    "   ~~~     '::::::'     ~~~      ",
]

MORPH_TEXT   = "AI SENTINEL-OCTOPUS"
MORPH_BYLINE = "by who_is_the_black_hat"


def _center(text: str, width: int) -> str:
    return text.center(width)


def cinematic_intro(console: Console = None):
    import shutil
    con = console or Console()
    width = shutil.get_terminal_size((100, 30)).columns

    con.clear()
    time.sleep(0.1)

    title = MORPH_TEXT
    centered_title = _center(title, width)
    pad = len(centered_title) - len(centered_title.lstrip())

    for _ in range(6):
        con.print()

    line_buf = ""
    for ch in title:
        line_buf += ch
        con.print(f"\r{' ' * pad}[bold cyan]{line_buf}[/bold cyan]", end="", highlight=False)
        time.sleep(0.055)
    con.print()
    time.sleep(0.15)

    byline_centered = _center(MORPH_BYLINE, width)
    byline_buf = ""
    for ch in MORPH_BYLINE:
        byline_buf += ch
        byline_pad = len(byline_centered) - len(byline_centered.lstrip())
        con.print(f"\r{' ' * byline_pad}[dim cyan]{byline_buf}[/dim cyan]", end="", highlight=False)
        time.sleep(0.04)
    con.print()
    time.sleep(0.4)

    glitch_frames = [
        f"[bold cyan]{_center(MORPH_TEXT, width)}[/bold cyan]",
        f"[bold bright_cyan]{_center('AI S3NT1N3L-0CTOPUS', width)}[/bold bright_cyan]",
        f"[cyan]{_center('.. SENTINEL .. OCTOPUS ..', width)}[/cyan]",
        f"[dim cyan]{_center('~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~', width)}[/dim cyan]",
    ]

    con.print("\033[4A", end="")
    for frame in glitch_frames:
        con.print(" " * width)
        con.print(frame, highlight=False)
        con.print(" " * width)
        time.sleep(0.09)
        con.print("\033[4A", end="")

    for _ in range(4):
        con.print(" " * width)
    con.print("\033[5A", end="")

    oct_width = max(len(l) for l in OCTOPUS_ASCII)
    oct_pad = (width - oct_width) // 2
    colors = ["bold cyan", "bold bright_cyan", "bold cyan", "cyan", "bold cyan"]
    for i, line in enumerate(OCTOPUS_ASCII):
        color = colors[i % len(colors)]
        con.print(f"{' ' * oct_pad}[{color}]{line}[/{color}]")
        time.sleep(0.045)

    con.print()
    con.print(_center("[bold cyan]SENTINEL OCTOPUS  v3.1[/bold cyan]", width), highlight=False)
    con.print(_center("[dim]Eight arms. Zero mercy.  ·  by who_is_the_black_hat[/dim]", width), highlight=False)
    con.print()
    time.sleep(0.3)


# ═════════════════════════════════════════════════════════════
# SENTINEL LIVE PANEL
# ═════════════════════════════════════════════════════════════

class SentinelLivePanel:
    def __init__(self, console: Console = None, refresh_per_second: int = 4):
        self.console = console or Console(stderr=True)
        self._rps = refresh_per_second
        self._state = {
            'target':       '—',
            'module':       '—',
            'mod_status':   'idle',
            'findings':     {},
            'uptime_start': time.time(),
            'tor':          False,
            'cpu':          '—',
            'mem':          '—',
            'license':      'Open Source',
            'last_cmd':     '—',
            'total_scans':  0,
        }
        self._lock     = threading.Lock()
        self._stop_evt = threading.Event()
        self._thread   = None
        self._frame    = 0

    def set_target(self, target: str):
        with self._lock:
            self._state['target'] = target[:28]

    def set_module(self, name: str, status: str = 'active'):
        with self._lock:
            self._state['module']     = name
            self._state['mod_status'] = status
            if status == 'active':
                self._state['total_scans'] += 1

    def set_module_done(self):
        with self._lock:
            self._state['mod_status'] = 'done'

    def set_module_error(self):
        with self._lock:
            self._state['mod_status'] = 'error'

    def add_finding(self, key: str, value):
        with self._lock:
            self._state['findings'][key] = value

    def clear_findings(self):
        with self._lock:
            self._state['findings'] = {}

    def set_last_cmd(self, cmd: str):
        with self._lock:
            self._state['last_cmd'] = cmd[:28]

    def set_license(self, plan: str):
        with self._lock:
            self._state['license'] = plan

    def _refresh_sys(self):
        try:
            import psutil
            self._state['cpu'] = f"{psutil.cpu_percent(interval=None):.0f}%"
            self._state['mem'] = f"{psutil.virtual_memory().percent:.0f}%"
        except Exception:
            pass
        try:
            import config
            self._state['tor'] = config.is_tor_active()
        except Exception:
            pass

    def _render(self) -> Panel:
        self._frame += 1
        pulse = self._frame % 2 == 0

        with self._lock:
            s        = dict(self._state)
            findings = dict(s['findings'])

        uptime_secs = int(time.time() - s['uptime_start'])
        uptime = f"{uptime_secs // 3600:02d}:{(uptime_secs % 3600) // 60:02d}:{uptime_secs % 60:02d}"

        mod_status = s['mod_status']
        if mod_status == 'active':
            mod_color = "bold cyan"
            mod_icon  = Text("●" if pulse else "○", style="bold cyan")
        elif mod_status == 'done':
            mod_color = "green"
            mod_icon  = Text("✓", style="green")
        elif mod_status == 'error':
            mod_color = "red"
            mod_icon  = Text("✗", style="red")
        else:
            mod_color = "dim"
            mod_icon  = Text("○", style="dim")

        tor_str = "[green]ON 🧅[/green]" if s['tor'] else "[red]OFF[/red]"

        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
        table.add_column(width=12, style="dim")
        table.add_column(justify="left")

        def row(k, v, vstyle=""):
            table.add_row(Text(k, style="dim"), Text(str(v), style=vstyle) if vstyle else Text(str(v)))

        def sep():
            table.add_row(Text("─" * 12, style="dim cyan"), Text("─" * 14, style="dim cyan"))

        table.add_row(Text("🐙 SESSION", style="bold cyan"), Text(""))
        row("TARGET",   s['target'],          "cyan")
        row("UPTIME",   uptime,               "cyan")
        row("SCANS",    str(s['total_scans']), "cyan")
        row("LAST CMD", s['last_cmd'],         "dim")
        sep()
        table.add_row(Text("MODULE", style="bold cyan"), Text(""))
        table.add_row(Text(s['module'], style=mod_color), mod_icon)
        sep()
        table.add_row(Text("FINDINGS", style="bold cyan"), Text(""))
        if findings:
            for k, v in list(findings.items())[:8]:
                row(k.upper()[:12], str(v), "green")
        else:
            row("—", "collecting...", "dim")
        sep()
        table.add_row(Text("SYSTEM", style="bold cyan"), Text(""))
        table.add_row(Text("TOR", style="dim"), tor_str)
        row("CPU", s['cpu'], "yellow")
        row("MEM", s['mem'], "yellow")
        sep()
        table.add_row(Text("LICENSE", style="bold cyan"), Text(""))
        row("PLAN", s['license'], "cyan")

        return Panel(table, title="[bold cyan]🐙 SENTINEL[/bold cyan]",
                     border_style="cyan", expand=False, width=34)

    def _run(self):
        interval    = 1.0 / self._rps
        sys_refresh = 0
        while not self._stop_evt.is_set():
            time.sleep(interval)
            sys_refresh += interval
            if sys_refresh >= 2.0:
                self._refresh_sys()
                sys_refresh = 0

    def start(self):
        self._refresh_sys()
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=2)

    def print_panel(self):
        self.console.print(self._render())


# ═════════════════════════════════════════════════════════════
# MODULE PROGRESS
# ═════════════════════════════════════════════════════════════

@contextmanager
def module_progress(description: str, console: Console = None,
                    panel: SentinelLivePanel = None, color: str = "cyan",
                    total: int = 100):
    if panel:
        panel.set_module(description, 'active')

    progress = Progress(
        OctopusSpinner(),
        TextColumn(f"[bold {color}]{{task.description}}[/bold {color}]"),
        TentacleBar(bar_width=32),
        CleanPercent(),
        TimeElapsedColumn(),
        console=console or Console(),
        transient=True,
    )

    try:
        with progress:
            yield progress
        if panel:
            panel.set_module_done()
    except Exception:
        if panel:
            panel.set_module_error()
        raise


# ═════════════════════════════════════════════════════════════
# CINEMATIC INTRO
# ═════════════════════════════════════════════════════════════

OCTOPUS_ASCII = [
    "          .::::::::::.          ",
    "       .:::::::::::::::::.       ",
    "      ::::(o):::::::(o)::::      ",
    "      ::::::::  ___  ::::::::    ",
    "      ::::::: /     \\ :::::::    ",
    "       ':::::::::::::::::'       ",
    "    ~~/~\\\\:::::::::::::/~\\\\~~    ",
    "   ~~/ /~\\\\:::::::::::/~\\\\ \\\\~~  ",
    "  ~/ /   \\\\:::::::::/   \\\\ \\\\~   ",
    "  ~\\\\_\\\\   \\\\:::::::/   /_/~     ",
    "   ~~~     '::::::'     ~~~      ",
]

MORPH_TEXT   = "AI SENTINEL-OCTOPUS"
MORPH_BYLINE = "by who_is_the_black_hat"


def _center(text, width):
    return text.center(width)


def cinematic_intro(console=None):
    import shutil
    con = console or Console()
    width = shutil.get_terminal_size((100, 30)).columns
    con.clear()
    time.sleep(0.1)
    title = MORPH_TEXT
    centered_title = _center(title, width)
    pad = len(centered_title) - len(centered_title.lstrip())
    for _ in range(6):
        con.print()
    line_buf = ""
    for ch in title:
        line_buf += ch
        con.print(f"\r{' ' * pad}[bold cyan]{line_buf}[/bold cyan]", end="", highlight=False)
        time.sleep(0.055)
    con.print()
    time.sleep(0.15)
    byline_centered = _center(MORPH_BYLINE, width)
    byline_buf = ""
    for ch in MORPH_BYLINE:
        byline_buf += ch
        byline_pad = len(byline_centered) - len(byline_centered.lstrip())
        con.print(f"\r{' ' * byline_pad}[dim cyan]{byline_buf}[/dim cyan]", end="", highlight=False)
        time.sleep(0.04)
    con.print()
    time.sleep(0.4)
    glitch_frames = [
        f"[bold cyan]{_center(MORPH_TEXT, width)}[/bold cyan]",
        f"[bold bright_cyan]{_center('AI S3NT1N3L-0CTOPUS', width)}[/bold bright_cyan]",
        f"[cyan]{_center('.. SENTINEL .. OCTOPUS ..', width)}[/cyan]",
        f"[dim cyan]{_center('~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~ ~', width)}[/dim cyan]",
    ]
    con.print("\033[4A", end="")
    for frame in glitch_frames:
        con.print(" " * width)
        con.print(frame, highlight=False)
        con.print(" " * width)
        time.sleep(0.09)
        con.print("\033[4A", end="")
    for _ in range(4):
        con.print(" " * width)
    con.print("\033[5A", end="")
    oct_width = max(len(l) for l in OCTOPUS_ASCII)
    oct_pad = (width - oct_width) // 2
    colors = ["bold cyan", "bold bright_cyan", "bold cyan", "cyan", "bold cyan"]
    for i, line in enumerate(OCTOPUS_ASCII):
        color = colors[i % len(colors)]
        con.print(f"{' ' * oct_pad}[{color}]{line}[/{color}]")
        time.sleep(0.045)
    con.print()
    con.print(_center("[bold cyan]SENTINEL OCTOPUS  v3.1[/bold cyan]", width), highlight=False)
    con.print(_center("[dim]Eight arms. Zero mercy.  by who_is_the_black_hat[/dim]", width), highlight=False)
    con.print()
    time.sleep(0.3)


# ═════════════════════════════════════════════════════════════
# SENTINEL LIVE PANEL
# ═════════════════════════════════════════════════════════════

class SentinelLivePanel:
    def __init__(self, console=None, refresh_per_second=4):
        self.console   = console or Console(stderr=True)
        self._rps      = refresh_per_second
        self._state    = {
            'target': '—', 'module': '—', 'mod_status': 'idle',
            'findings': {}, 'uptime_start': time.time(),
            'tor': False, 'cpu': '—', 'mem': '—',
            'license': 'Open Source', 'last_cmd': '—', 'total_scans': 0,
        }
        self._lock     = threading.Lock()
        self._stop_evt = threading.Event()
        self._thread   = None
        self._frame    = 0

    def set_target(self, target):
        with self._lock: self._state['target'] = target[:28]

    def set_module(self, name, status='active'):
        with self._lock:
            self._state['module'] = name
            self._state['mod_status'] = status
            if status == 'active':
                self._state['total_scans'] += 1

    def set_module_done(self):
        with self._lock: self._state['mod_status'] = 'done'

    def set_module_error(self):
        with self._lock: self._state['mod_status'] = 'error'

    def add_finding(self, key, value):
        with self._lock: self._state['findings'][key] = value

    def clear_findings(self):
        with self._lock: self._state['findings'] = {}

    def set_last_cmd(self, cmd):
        with self._lock: self._state['last_cmd'] = cmd[:28]

    def set_license(self, plan):
        with self._lock: self._state['license'] = plan

    def _refresh_sys(self):
        try:
            import psutil
            self._state['cpu'] = f"{psutil.cpu_percent(interval=None):.0f}%"
            self._state['mem'] = f"{psutil.virtual_memory().percent:.0f}%"
        except Exception:
            pass
        try:
            import config
            self._state['tor'] = config.is_tor_active()
        except Exception:
            pass

    def _render(self):
        self._frame += 1
        pulse = self._frame % 2 == 0
        with self._lock:
            s = dict(self._state)
            findings = dict(s['findings'])
        uptime_secs = int(time.time() - s['uptime_start'])
        uptime = f"{uptime_secs//3600:02d}:{(uptime_secs%3600)//60:02d}:{uptime_secs%60:02d}"
        ms = s['mod_status']
        if ms == 'active':
            mod_color, mod_icon = "bold cyan", Text("●" if pulse else "○", style="bold cyan")
        elif ms == 'done':
            mod_color, mod_icon = "green", Text("✓", style="green")
        elif ms == 'error':
            mod_color, mod_icon = "red", Text("✗", style="red")
        else:
            mod_color, mod_icon = "dim", Text("○", style="dim")
        tor_str = "[green]ON 🧅[/green]" if s['tor'] else "[red]OFF[/red]"
        table = Table(box=None, show_header=False, pad_edge=False, padding=(0, 1))
        table.add_column(width=12, style="dim")
        table.add_column(justify="left")
        def row(k, v, vstyle=""):
            table.add_row(Text(k, style="dim"), Text(str(v), style=vstyle) if vstyle else Text(str(v)))
        def sep():
            table.add_row(Text("─"*12, style="dim cyan"), Text("─"*14, style="dim cyan"))
        table.add_row(Text("🐙 SESSION", style="bold cyan"), Text(""))
        row("TARGET",   s['target'],           "cyan")
        row("UPTIME",   uptime,                "cyan")
        row("SCANS",    str(s['total_scans']), "cyan")
        row("LAST CMD", s['last_cmd'],         "dim")
        sep()
        table.add_row(Text("MODULE", style="bold cyan"), Text(""))
        table.add_row(Text(s['module'], style=mod_color), mod_icon)
        sep()
        table.add_row(Text("FINDINGS", style="bold cyan"), Text(""))
        if findings:
            for k, v in list(findings.items())[:8]:
                row(k.upper()[:12], str(v), "green")
        else:
            row("—", "collecting...", "dim")
        sep()
        table.add_row(Text("SYSTEM", style="bold cyan"), Text(""))
        table.add_row(Text("TOR", style="dim"), tor_str)
        row("CPU", s['cpu'], "yellow")
        row("MEM", s['mem'], "yellow")
        sep()
        table.add_row(Text("LICENSE", style="bold cyan"), Text(""))
        row("PLAN", s['license'], "cyan")
        return Panel(table, title="[bold cyan]🐙 SENTINEL[/bold cyan]",
                     border_style="cyan", expand=False, width=34)

    def _run(self):
        interval = 1.0 / self._rps
        sys_refresh = 0
        while not self._stop_evt.is_set():
            time.sleep(interval)
            sys_refresh += interval
            if sys_refresh >= 2.0:
                self._refresh_sys()
                sys_refresh = 0

    def start(self):
        self._refresh_sys()
        self._stop_evt.clear()
        self._thread = threading.Thread(target=self._run, daemon=True)
        self._thread.start()

    def stop(self):
        self._stop_evt.set()
        if self._thread:
            self._thread.join(timeout=2)

    def print_panel(self):
        self.console.print(self._render())


# ═════════════════════════════════════════════════════════════
# MODULE PROGRESS
# ═════════════════════════════════════════════════════════════

@contextmanager
def module_progress(description, console=None, panel=None, color="cyan", total=100):
    if panel:
        panel.set_module(description, 'active')
    progress = Progress(
        OctopusSpinner(),
        TextColumn(f"[bold {color}]{{task.description}}[/bold {color}]"),
        TentacleBar(bar_width=32),
        CleanPercent(),
        TimeElapsedColumn(),
        console=console or Console(),
        transient=True,
    )
    try:
        with progress:
            yield progress
        if panel:
            panel.set_module_done()
    except Exception:
        if panel:
            panel.set_module_error()
        raise
