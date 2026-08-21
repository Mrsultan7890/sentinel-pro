"""
Sentinel Chat Mode
==================
Full conversational AI interface — user baat kare, brain plan banaye,
agents real-time execute karein, user beech mein interrupt kar sake.

Usage:
    from sentinel_brain.chat_mode import ChatMode
    chat = ChatMode(sentinel=sentinel_instance)
    chat.run()
"""

import re
import sys
import time
import threading
import logging
from datetime import datetime
from queue import Queue, Empty

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.live import Live
from rich.spinner import Spinner
from rich.columns import Columns
from rich import box

logger = logging.getLogger(__name__)

# ── Interrupt signals ─────────────────────────────────────────────────────────
PAUSE_SIGNALS  = {'ruko', 'stop', 'pause', 'wait', 'hold', 'rok do', 'ruk jao', 'ruk'}
RESUME_SIGNALS = {'chalo', 'continue', 'resume', 'proceed', 'go', 'haan', 'yes', 'y', 'ok', 'theek hai'}
SKIP_SIGNALS   = {'skip', 'next', 'agle pe jao', 'skip karo', 'chodo', 'ignore'}
CANCEL_SIGNALS = {'cancel', 'band karo', 'stop all', 'abort', 'quit task', 'task band'}
EXIT_SIGNALS   = {'exit', 'quit', 'bye', 'q', 'band karo chat', 'exit chat'}


class ChatMode:
    """
    Full conversational interface with real-time agent streaming.
    - Brain plans before acting
    - Real-time output from every agent
    - User can pause/resume/skip/cancel anytime
    - Natural conversation when no task
    """

    PROMPT = "[bold orange1]you[/bold orange1][dim] ›[/dim] "
    VERSION = "1.0"

    def __init__(self, sentinel=None):
        self.console   = Console()
        self.sentinel  = sentinel
        self._brain    = None
        self._groq     = None

        # Execution control
        self._paused   = threading.Event()
        self._cancelled = threading.Event()
        self._paused.set()   # not paused initially

        # Output queue — agents push here, UI reads
        self._output_q: Queue = Queue()

        # Current task state
        self._current_task   = None
        self._current_plan   = []
        self._current_step   = 0
        self._task_running   = False

        self._load_brain()
        self._load_groq()

    # ── Init ──────────────────────────────────────────────────────────────────

    def _load_brain(self):
        try:
            from sentinel_brain.brain import SentinelBrain
            # Brain ko custom print function do jo queue mein push kare
            self._brain = SentinelBrain(
                sentinel=self.sentinel,
                console=self._brain_print,
                auto=True
            )
        except Exception as e:
            logger.error(f"Brain load failed: {e}")
            self._brain = None

    def _load_groq(self):
        try:
            from modules.ml_engine.groq_llm import GroqLLM
            if GroqLLM.is_available():
                g = GroqLLM()
                self._groq = g if g.is_ready else None
        except Exception as e:
            logger.debug(f"Groq load: {e}")

    def _brain_print(self, msg: str):
        """Brain ka har print yahan aata hai — queue mein push karo."""
        self._output_q.put(('brain', str(msg)))

    # ── Main Loop ─────────────────────────────────────────────────────────────

    def run(self):
        self._print_header()
        self._print_help()

        while True:
            try:
                user_input = self._get_input()
            except (KeyboardInterrupt, EOFError):
                self._goodbye()
                break

            if not user_input.strip():
                continue

            lower = user_input.strip().lower()

            # Exit
            if lower in EXIT_SIGNALS:
                self._goodbye()
                break

            # Agar task chal raha hai — interrupt handle karo
            if self._task_running:
                self._handle_interrupt(user_input)
                continue

            # Classify: task hai ya conversation
            intent = self._classify_intent(user_input)

            if intent == 'task':
                self._run_task(user_input)
            else:
                self._converse(user_input)

    # ── Input ─────────────────────────────────────────────────────────────────

    def _get_input(self) -> str:
        self.console.print()
        self.console.print(self.PROMPT, end="")
        return input()

    # ── Intent Classification ─────────────────────────────────────────────────

    def _classify_intent(self, text: str) -> str:
        """Task hai ya sirf baat? Groq se poocho, fallback heuristic."""
        task_keywords = [
            'scan', 'recon', 'hack', 'exploit', 'osint', 'breach', 'check',
            'investigate', 'find', 'search', 'analyze', 'audit', 'test',
            'karo', 'dekho', 'dhundo', 'nikalo', 'chalao', 'run', 'start',
            'nmap', 'sqlmap', 'nikto', 'nuclei', 'gobuster', 'subfinder',
            'email', 'phone', 'domain', 'ip', 'target', 'website', 'url',
            'vulnerability', 'vuln', 'cve', 'darkweb', 'tor', 'report',
        ]
        lower = text.lower()
        # Domain/IP/email pattern
        if re.search(r'[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}|[\w.+-]+@[\w-]+\.\w+|\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', text):
            if any(k in lower for k in task_keywords):
                return 'task'
        if any(k in lower for k in task_keywords):
            return 'task'
        return 'conversation'

    # ── Task Execution ────────────────────────────────────────────────────────

    def _run_task(self, user_input: str):
        """Plan banao, confirm karo, execute karo."""
        self._current_task = user_input
        self._cancelled.clear()
        self._paused.set()

        # Step 1: Plan banao
        plan = self._make_plan(user_input)
        if not plan:
            self._say("Samajh nahi aaya — thoda aur detail mein batao?")
            return

        # Step 2: Plan dikhao
        self._show_plan(plan, user_input)

        # Step 3: Confirm
        confirmed = self._confirm_plan()
        if not confirmed:
            self._say("Theek hai, cancel kar diya.")
            return

        # Step 4: Execute
        self._task_running = True
        self._current_plan = plan
        self._current_step = 0

        t = threading.Thread(target=self._execute_task, args=(user_input,), daemon=True)
        t.start()

        # Main thread: output stream karo + interrupt suno
        self._stream_output(t)

        self._task_running = False

    def _make_plan(self, user_input: str) -> list:
        """Groq se plan banwao — real steps, no fake."""
        self.console.print()

        with self.console.status("[cyan]Planning...[/cyan]", spinner="dots"):
            if self._groq:
                prompt = f"""You are a security AI planner. User request: "{user_input}"

Create a step-by-step execution plan using ONLY these available agents:
recon, bugbounty, osint, breach, threat_intel, network, darkweb, report

Rules:
- Only include agents that are RELEVANT to the request
- Always end with 'report' if it's a security task
- Return ONLY a JSON list like: ["recon", "bugbounty", "report"]
- No explanations, just the JSON list"""

                try:
                    resp = self._groq.ask(prompt, max_tokens=200)
                    # JSON extract karo
                    m = re.search(r'\[.*?\]', resp, re.DOTALL)
                    if m:
                        import json
                        steps = json.loads(m.group(0))
                        if isinstance(steps, list) and steps:
                            return steps
                except Exception as e:
                    logger.debug(f"Plan generation: {e}")

        # Fallback heuristic
        lower = user_input.lower()
        if any(w in lower for w in ['breach', 'leak', 'password']):
            return ['breach', 'report']
        if any(w in lower for w in ['recon', 'subdomain', 'dns']):
            return ['recon', 'report']
        if any(w in lower for w in ['osint', 'person', 'email', 'phone']):
            return ['osint', 'report']
        if any(w in lower for w in ['darkweb', 'tor', 'onion']):
            return ['darkweb', 'report']
        return ['recon', 'threat_intel', 'bugbounty', 'report']

    def _show_plan(self, plan: list, task: str):
        """Plan ko nicely dikhao."""
        self.console.print()

        # Task summary
        self._say(f"Samajh gaya. Ye kaam karunga:", newline=False)
        self.console.print()

        # Plan steps
        step_icons = {
            'recon': '🔍', 'bugbounty': '🐛', 'osint': '🕵️',
            'breach': '💥', 'threat_intel': '🧠', 'network': '🌐',
            'darkweb': '🕸️', 'report': '📄', 'kali_recon': '⚡',
            'kali_exploit': '💣',
        }
        lines = []
        for i, step in enumerate(plan, 1):
            icon = step_icons.get(step, '▸')
            lines.append(f"  [dim]{i}.[/dim] {icon}  [cyan]{step}[/cyan]")

        self.console.print(
            Panel(
                "\n".join(lines),
                title="[bold orange1]Execution Plan[/bold orange1]",
                border_style="orange1",
                box=box.ROUNDED,
                padding=(0, 2),
            )
        )
        self.console.print()
        self.console.print(
            f"  [dim]Beech mein rok sakte ho — bas '[/dim][bold]ruko[/bold][dim]' likho[/dim]"
        )

    def _confirm_plan(self) -> bool:
        """User se confirm karo."""
        self.console.print()
        self.console.print("  [bold]Shuru karoon?[/bold] [dim](Enter = haan, 'nahi' = cancel)[/dim] ", end="")
        try:
            ans = input().strip().lower()
            return ans not in {'nahi', 'no', 'n', 'cancel', 'nhi', 'mat karo'}
        except (KeyboardInterrupt, EOFError):
            return False

    def _execute_task(self, user_input: str):
        """Background thread mein brain run karo."""
        try:
            if self._brain:
                self._brain.run(user_input)
            else:
                self._output_q.put(('error', 'Brain not loaded — check logs'))
        except Exception as e:
            self._output_q.put(('error', f'Task failed: {e}'))
        finally:
            self._output_q.put(('done', ''))

    def _stream_output(self, thread: threading.Thread):
        """Output queue se real-time print karo, interrupt suno."""
        input_q: Queue = Queue()

        # Background mein user input suno
        def _listen():
            while thread.is_alive():
                try:
                    line = input()
                    input_q.put(line)
                except (EOFError, KeyboardInterrupt):
                    break

        listener = threading.Thread(target=_listen, daemon=True)
        listener.start()

        self.console.print()
        self.console.rule("[dim]execution started[/dim]", style="dim")
        self.console.print()

        while thread.is_alive() or not self._output_q.empty():
            # Check user interrupt
            try:
                user_line = input_q.get_nowait()
                self._handle_interrupt(user_line)
            except Empty:
                pass

            # Print brain output
            try:
                kind, msg = self._output_q.get(timeout=0.1)
                if kind == 'done':
                    break
                elif kind == 'error':
                    self.console.print(f"  [red]✗[/red]  {msg}")
                elif kind == 'brain':
                    self._format_brain_line(msg)
            except Empty:
                # Paused check
                if not self._paused.is_set():
                    self.console.print(
                        "\n  [yellow]⏸[/yellow]  [bold]Paused[/bold] — "
                        "[dim]'chalo' likho resume karne ke liye[/dim]"
                    )
                    self._paused.wait()
                    if self._cancelled.is_set():
                        break
                    self.console.print("  [green]▶[/green]  Resuming...\n")

        self.console.print()
        self.console.rule("[dim]execution complete[/dim]", style="dim")
        self.console.print()

        if self._cancelled.is_set():
            self._say("Task cancel kar diya.")
        else:
            self._say("Kaam ho gaya! Kuch aur chahiye?")

    def _format_brain_line(self, msg: str):
        """Brain output ko nicely format karo."""
        msg = msg.strip()
        if not msg or msg == '=' * 60:
            return

        # Color coding based on content
        if '[ReAct]' in msg:
            step_m = re.search(r'Step (\d+): (.+)', msg)
            if step_m:
                self.console.print(
                    f"  [bold cyan]Step {step_m.group(1)}[/bold cyan]  "
                    f"[white]{step_m.group(2)}[/white]"
                )
                return
        if '[Brain]' in msg:
            clean = msg.replace('[Brain]', '').strip()
            self.console.print(f"  [orange1]▸[/orange1]  {clean}")
            return
        if 'CRITICAL' in msg or '🔴' in msg:
            self.console.print(f"  [bold red]🔴  {msg}[/bold red]")
            return
        if 'HIGH' in msg or '🟠' in msg:
            self.console.print(f"  [bold yellow]{msg}[/bold yellow]")
            return
        if '✓' in msg or 'success' in msg.lower() or 'complete' in msg.lower():
            self.console.print(f"  [green]✓[/green]  {msg.replace('✓','').strip()}")
            return
        if '✗' in msg or 'fail' in msg.lower() or 'error' in msg.lower():
            self.console.print(f"  [red]✗[/red]  {msg.replace('✗','').strip()}")
            return
        if '[RL]' in msg:
            self.console.print(f"  [dim]{msg}[/dim]")
            return
        if msg.startswith('='):
            return
        # Default
        self.console.print(f"  [dim]│[/dim]  {msg}")

    # ── Interrupt Handling ────────────────────────────────────────────────────

    def _handle_interrupt(self, user_input: str):
        lower = user_input.strip().lower()

        if any(s in lower for s in PAUSE_SIGNALS):
            self._paused.clear()
            # Brain ko bhi signal karo
            if self._brain:
                self._brain.auto = False

        elif any(s in lower for s in RESUME_SIGNALS):
            if not self._paused.is_set():
                self._paused.set()
                if self._brain:
                    self._brain.auto = True

        elif any(s in lower for s in CANCEL_SIGNALS):
            self._cancelled.set()
            self._paused.set()  # unblock if paused
            self.console.print("\n  [red]✗[/red]  Cancelling task...")

        elif any(s in lower for s in SKIP_SIGNALS):
            # Current step skip — resume karo
            self._paused.set()
            self.console.print("  [yellow]⏭[/yellow]  Skipping current step...")

        else:
            # User ne kuch aur likha — Groq se samjho
            self._say(f"Task chal raha hai. Rok ne ke liye 'ruko', cancel ke liye 'cancel' likho.")

    # ── Conversation ──────────────────────────────────────────────────────────

    def _converse(self, user_input: str):
        """Task nahi — sirf baat karo."""
        with self.console.status("[dim]thinking...[/dim]", spinner="dots2"):
            if self._groq:
                prompt = f"""You are Sentinel, an AI security assistant. 
User said: "{user_input}"
Reply naturally and helpfully in the same language the user used.
Be concise — max 3 sentences."""
                try:
                    resp = self._groq.ask(prompt, max_tokens=300)
                    if resp:
                        self._say(resp)
                        return
                except Exception:
                    pass

        # Fallback
        self._say("Samajh gaya. Koi security task ho to batao — main kar dunga.")

    # ── UI Helpers ────────────────────────────────────────────────────────────

    def _say(self, msg: str, newline: bool = True):
        """Sentinel ka response."""
        prefix = "\n  [bold orange1]sentinel[/bold orange1][dim] ›[/dim] "
        self.console.print(f"{prefix}{msg}", end="\n" if newline else "")

    def _print_header(self):
        self.console.clear()
        self.console.print()
        self.console.print(
            Panel(
                Text.from_markup(
                    "[bold orange1]SENTINEL CHAT[/bold orange1]  [dim]v{v}[/dim]\n"
                    "[dim]Autonomous AI Security Assistant[/dim]\n\n"
                    "[dim]Baat karo — main plan bana ke kaam kar dunga[/dim]".format(v=self.VERSION)
                ),
                border_style="orange1",
                box=box.DOUBLE_EDGE,
                padding=(1, 4),
            )
        )

    def _print_help(self):
        self.console.print()
        self.console.print("  [dim]Commands during execution:[/dim]")
        self.console.print("  [dim]  ruko       → pause[/dim]")
        self.console.print("  [dim]  chalo      → resume[/dim]")
        self.console.print("  [dim]  skip       → skip current step[/dim]")
        self.console.print("  [dim]  cancel     → cancel task[/dim]")
        self.console.print("  [dim]  exit       → exit chat[/dim]")
        self.console.print()

    def _goodbye(self):
        self.console.print()
        self._say("Theek hai, band karta hoon. Allah Hafiz! 👋")
        self.console.print()
