"""
Sentinel Chat Mode v2.0
=======================
Conversational AI interface — user talks, brain plans, agents execute in real-time.
"""

import re
import json
import threading
import logging
from queue import Queue, Empty

from rich.console import Console
from rich.panel import Panel
from rich.text import Text
from rich.table import Table
from rich.rule import Rule
from rich import box

logger = logging.getLogger(__name__)

PAUSE_SIGNALS   = {'stop', 'pause', 'wait', 'hold'}
RESUME_SIGNALS  = {'continue', 'resume', 'go', 'yes', 'y', 'ok', 'proceed'}
SKIP_SIGNALS    = {'skip', 'next', 'skip this'}
CANCEL_SIGNALS  = {'cancel', 'abort', 'stop all', 'cancel task'}
EXIT_SIGNALS    = {'exit', 'quit', 'bye', 'q'}

AGENT_ICONS = {
    'recon':       ('🔍', 'Reconnaissance'),
    'bugbounty':   ('🐛', 'Vulnerability Scan'),
    'osint':       ('🕵️',  'OSINT Investigation'),
    'breach':      ('💥', 'Breach Check'),
    'threat_intel':('🧠', 'Threat Intelligence'),
    'network':     ('🌐', 'Network Mapping'),
    'darkweb':     ('🕸️',  'Dark Web'),
    'report':      ('📄', 'Report Generation'),
    'kali_recon':  ('⚡', 'Kali Recon'),
    'kali_exploit':('💣', 'Exploit'),
}


class ChatMode:
    VERSION = '2.0'

    def __init__(self, sentinel=None):
        self.console    = Console()
        self.sentinel   = sentinel
        self._brain     = None
        self._groq      = None
        self._octopus   = None
        self._paused    = threading.Event()
        self._cancelled = threading.Event()
        self._paused.set()
        self._output_q: Queue = Queue()
        self._task_running    = False
        self._load_brain()
        self._load_groq()
        self._load_octopus()

    # ── Loaders ───────────────────────────────────────────────────────────────

    def _load_brain(self):
        try:
            from sentinel_brain.brain import SentinelBrain
            self._brain = SentinelBrain(
                sentinel=self.sentinel,
                console=lambda m: self._output_q.put(('brain', str(m))),
                auto=True,
            )
        except Exception as e:
            logger.error(f'Brain load failed: {e}')

    def _load_groq(self):
        try:
            from modules.ml_engine.groq_llm import GroqLLM
            if GroqLLM.is_available():
                g = GroqLLM()
                self._groq = g if g.is_ready else None
        except Exception as e:
            logger.debug(f'Groq: {e}')

    def _load_octopus(self):
        try:
            from modules.ml_engine.sentinel_octopus import SentinelOctopus
            if SentinelOctopus.is_available():
                oc = SentinelOctopus()
                if oc.load():
                    self._octopus = oc
                    return
        except Exception as e:
            logger.debug(f'SentinelOctopus: {e}')
        self._octopus = None

    # ── Main Loop ─────────────────────────────────────────────────────────────

    def run(self):
        self._draw_header()

        while True:
            try:
                user_input = self._prompt()
            except (KeyboardInterrupt, EOFError):
                self._exit()
                break

            if not user_input.strip():
                continue

            if user_input.strip().lower() in EXIT_SIGNALS:
                self._exit()
                break

            if self._task_running:
                self._handle_interrupt(user_input)
                continue

            if self._is_task(user_input):
                self._run_task(user_input)
            else:
                self._chat(user_input)

    # ── Prompt ────────────────────────────────────────────────────────────────

    def _prompt(self) -> str:
        self.console.print()
        self.console.print('  [bold white]you[/bold white]  [dim]›[/dim]  ', end='', highlight=False)
        try:
            return input()
        except UnicodeDecodeError:
            return ''

    # ── Intent ────────────────────────────────────────────────────────────────

    def _is_task(self, text: str) -> bool:
        # Questions are never tasks
        question_words = ('what', 'how', 'why', 'when', 'who', 'which', 'explain',
                          'tell me', 'describe', 'define', 'what is', 'what are')
        lower = text.lower().strip()
        if any(lower.startswith(q) for q in question_words):
            return False
        if lower.endswith('?'):
            return False

        action_keywords = [
            'scan', 'recon', 'hack', 'exploit', 'osint', 'breach',
            'investigate', 'audit', 'test', 'run', 'start', 'check',
            'sqlmap', 'nikto', 'nuclei', 'gobuster', 'subfinder',
            'vulnerability', 'vuln', 'cve', 'darkweb', 'report',
        ]
        has_target = bool(re.search(
            r'(?:https?://)?[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}(?:/\S*)?'
            r'|[\w.+-]+@[\w-]+\.\w+'
            r'|\d{1,3}(\.\d{1,3}){3}',
            text
        ))
        has_action = any(k in lower for k in action_keywords)
        # Need both a target AND an action keyword, or a strong action alone
        return (has_target and has_action) or has_action

    # ── Task Flow ─────────────────────────────────────────────────────────────

    def _run_task(self, user_input: str):
        self._cancelled.clear()
        self._paused.set()

        # 1. Plan
        plan = self._build_plan(user_input)
        if not plan:
            self._reply('Could not determine a plan. Please be more specific.')
            return

        # 2. Show plan
        self._show_plan(plan)

        # 3. Confirm
        if not self._confirm():
            self._reply('Cancelled.')
            return

        # 4. Execute
        self._task_running = True
        t = threading.Thread(target=self._execute, args=(user_input,), daemon=True)
        t.start()
        self._stream(t)
        self._task_running = False

    def _build_plan(self, user_input: str) -> list:
        with self.console.status('  [dim]Planning...[/dim]', spinner='dots'):
            if self._groq:
                prompt = (
                    f'User request: "{user_input}"\n\n'
                    'Create an execution plan using ONLY these agents:\n'
                    'recon, bugbounty, osint, breach, threat_intel, network, darkweb, report\n\n'
                    'Rules:\n'
                    '- Include only agents relevant to the request\n'
                    '- Always end with "report" for security tasks\n'
                    '- Return ONLY a JSON array, e.g. ["recon", "bugbounty", "report"]\n'
                    '- No explanation, just the JSON array'
                )
                try:
                    resp = self._groq.ask(prompt, max_tokens=150)
                    m = re.search(r'\[.*?\]', resp, re.DOTALL)
                    if m:
                        steps = json.loads(m.group(0))
                        if isinstance(steps, list) and steps:
                            return steps
                except Exception as e:
                    logger.debug(f'Plan: {e}')

            # SentinelOctopus fallback for planning
            if self._octopus:
                try:
                    prompt = (
                        f'User request: "{user_input}"\n'
                        'Return ONLY a JSON array of agents from: recon, bugbounty, osint, breach, threat_intel, network, darkweb, report\n'
                        'Example: ["recon", "bugbounty", "report"]'
                    )
                    resp = self._octopus.generate(prompt)
                    m = re.search(r'\[.*?\]', resp, re.DOTALL)
                    if m:
                        steps = json.loads(m.group(0))
                        if isinstance(steps, list) and steps:
                            return steps
                except Exception as e:
                    logger.debug(f'Octopus plan: {e}')

        # Heuristic fallback
        lower = user_input.lower()
        if any(w in lower for w in ['breach', 'leak', 'password', 'credential']):
            return ['breach', 'report']
        if any(w in lower for w in ['recon', 'subdomain', 'dns', 'whois']):
            return ['recon', 'report']
        if any(w in lower for w in ['osint', 'person', 'email', 'phone', 'social']):
            return ['osint', 'report']
        if any(w in lower for w in ['darkweb', 'tor', 'onion']):
            return ['darkweb', 'report']
        return ['recon', 'threat_intel', 'bugbounty', 'report']

    def _show_plan(self, plan: list):
        self.console.print()
        table = Table(
            box=box.SIMPLE,
            show_header=False,
            padding=(0, 2),
            border_style='dim',
        )
        table.add_column('', style='dim', width=4)
        table.add_column('', width=3)
        table.add_column('', style='cyan')
        table.add_column('', style='dim')

        for i, step in enumerate(plan, 1):
            icon, label = AGENT_ICONS.get(step, ('▸', step))
            table.add_row(str(i), icon, step, label)

        self.console.print(Panel(
            table,
            title='[bold]Execution Plan[/bold]',
            border_style='orange1',
            box=box.ROUNDED,
            padding=(0, 1),
        ))
        self.console.print(
            '  [dim]You can type [/dim]stop[dim], [/dim]skip[dim], or [/dim]cancel'
            '[dim] at any time during execution.[/dim]'
        )

    def _confirm(self) -> bool:
        self.console.print()
        self.console.print('  [bold]Proceed?[/bold]  [dim](Enter = yes,  no = cancel)[/dim]  ', end='')
        try:
            ans = input().strip().lower()
            return ans not in {'no', 'n', 'cancel', 'abort'}
        except (KeyboardInterrupt, EOFError):
            return False

    def _execute(self, user_input: str):
        try:
            if self._brain:
                self._brain.run(user_input)
            else:
                self._output_q.put(('error', 'Brain not available'))
        except Exception as e:
            self._output_q.put(('error', str(e)))
        finally:
            self._output_q.put(('done', ''))

    # ── Streaming ─────────────────────────────────────────────────────────────

    def _stream(self, thread: threading.Thread):
        interrupt_q: Queue = Queue()

        def _listen():
            while thread.is_alive():
                try:
                    interrupt_q.put(input())
                except (EOFError, KeyboardInterrupt):
                    break

        threading.Thread(target=_listen, daemon=True).start()

        self.console.print()
        self.console.print(Rule('[dim]  running  [/dim]', style='dim'))
        self.console.print()

        while thread.is_alive() or not self._output_q.empty():
            # Check interrupts
            try:
                self._handle_interrupt(interrupt_q.get_nowait())
            except Empty:
                pass

            # Print output
            try:
                kind, msg = self._output_q.get(timeout=0.05)
                if kind == 'done':
                    break
                elif kind == 'error':
                    self.console.print(f'  [red]✗[/red]  {msg}')
                elif kind == 'brain':
                    self._render_line(msg)
            except Empty:
                if not self._paused.is_set():
                    self.console.print(
                        '\n  [yellow]⏸[/yellow]  [bold]Paused[/bold]  '
                        '[dim]— type [/dim]continue[dim] to resume[/dim]'
                    )
                    self._paused.wait()
                    if self._cancelled.is_set():
                        break
                    self.console.print('  [green]▶[/green]  Resuming\n')

        self.console.print()
        self.console.print(Rule('[dim]  done  [/dim]', style='dim'))
        self.console.print()

        if self._cancelled.is_set():
            self._reply('Task cancelled.')
        else:
            self._reply('Done. Anything else?')

    def _render_line(self, msg: str):
        msg = msg.strip()
        if not msg or set(msg) <= {'=', '-', ' '}:
            return

        # Step header
        m = re.search(r'\[ReAct\].*?Step (\d+): (.+)', msg)
        if m:
            self.console.print(
                f'\n  [bold orange1]Step {m.group(1)}[/bold orange1]  '
                f'[white]{m.group(2)}[/white]'
            )
            return

        # Brain tag
        if '[Brain]' in msg:
            clean = re.sub(r'\[Brain\]', '', msg).strip()
            self.console.print(f'  [orange1]›[/orange1]  {clean}')
            return

        # Severity
        if 'CRITICAL' in msg:
            self.console.print(f'  [bold red]● CRITICAL[/bold red]  {msg}')
            return
        if 'HIGH' in msg and '[' in msg:
            self.console.print(f'  [bold yellow]● HIGH[/bold yellow]  {msg}')
            return

        # Success / fail
        if re.search(r'✓|success|complete|found \d', msg, re.I):
            self.console.print(f'  [green]✓[/green]  {msg.replace("✓", "").strip()}')
            return
        if re.search(r'✗|failed|error', msg, re.I):
            self.console.print(f'  [red]✗[/red]  {msg.replace("✗", "").strip()}')
            return

        # RL noise — dim
        if '[RL]' in msg or 'reward=' in msg:
            self.console.print(f'  [dim]{msg}[/dim]')
            return

        self.console.print(f'  [dim]│[/dim]  {msg}')

    # ── Interrupt ─────────────────────────────────────────────────────────────

    def _handle_interrupt(self, text: str):
        lower = text.strip().lower()
        if any(s in lower for s in PAUSE_SIGNALS):
            self._paused.clear()
            if self._brain:
                self._brain.auto = False
        elif any(s in lower for s in RESUME_SIGNALS):
            if not self._paused.is_set():
                self._paused.set()
                if self._brain:
                    self._brain.auto = True
        elif any(s in lower for s in CANCEL_SIGNALS):
            self._cancelled.set()
            self._paused.set()
            self.console.print('\n  [red]✗[/red]  Cancelling...')
        elif any(s in lower for s in SKIP_SIGNALS):
            self._paused.set()
            self.console.print('  [yellow]⏭[/yellow]  Skipping step...')
        else:
            self.console.print(
                '  [dim]Task running — type [/dim]stop[dim], [/dim]skip'
                '[dim], or [/dim]cancel'
            )

    # ── Conversation ──────────────────────────────────────────────────────────

    def _chat(self, user_input: str):
        with self.console.status('  [dim]...[/dim]', spinner='dots'):
            # Try Groq first
            if self._groq:
                try:
                    resp = self._groq.ask(
                        f'You are Sentinel, an AI security assistant. '
                        f'Answer this concisely in the same language the user used. '
                        f'Max 2 sentences. No thinking tags, no preamble.\n\n'
                        f'User: {user_input}',
                        max_tokens=512,
                    )
                    if resp:
                        self._reply(resp)
                        return
                except Exception:
                    pass
            # Fallback: SentinelOctopus local model
            if self._octopus:
                try:
                    resp = self._octopus.generate(user_input)
                    if resp:
                        self._reply(resp)
                        return
                except Exception:
                    pass
        self._reply('Ready. Give me a target or task.')

    # ── UI ────────────────────────────────────────────────────────────────────

    def _reply(self, msg: str):
        self.console.print(f'\n  [bold orange1]sentinel[/bold orange1]  [dim]›[/dim]  {msg}')

    def _draw_header(self):
        self.console.clear()
        self.console.print()

        # ASCII art header
        lines = [
            '[orange1]  ░██████╗███████╗███╗░░██╗████████╗██╗███╗░░██╗███████╗██╗░░░░░[/orange1]',
            '[orange1]  ██╔════╝██╔════╝████╗░██║╚══██╔══╝██║████╗░██║██╔════╝██║░░░░░[/orange1]',
            '[orange1]  ╚█████╗░█████╗░░██╔██╗██║░░░██║░░░██║██╔██╗██║█████╗░░██║░░░░░[/orange1]',
            '[orange1]  ░╚═══██╗██╔══╝░░██║╚████║░░░██║░░░██║██║╚████║██╔══╝░░██║░░░░░[/orange1]',
            '[orange1]  ██████╔╝███████╗██║░╚███║░░░██║░░░██║██║░╚███║███████╗███████╗[/orange1]',
            '[orange1]  ╚═════╝░╚══════╝╚═╝░░╚══╝░░░╚═╝░░░╚═╝╚═╝░░╚══╝╚══════╝╚══════╝[/orange1]',
            '',
            f'[dim]  Chat Mode v{self.VERSION}  ·  Autonomous AI Security Assistant[/dim]',
        ]
        self.console.print(Panel(
            '\n'.join(lines),
            border_style='orange1',
            box=box.DOUBLE_EDGE,
            padding=(1, 2),
        ))

        # Controls table
        self.console.print()
        t = Table(box=None, show_header=False, padding=(0, 3))
        t.add_column(style='dim', width=12)
        t.add_column(style='dim')
        t.add_row('stop',     'pause execution')
        t.add_row('continue', 'resume execution')
        t.add_row('skip',     'skip current step')
        t.add_row('cancel',   'cancel task')
        t.add_row('exit',     'exit chat mode')
        self.console.print(Panel(
            t,
            title='[dim]controls[/dim]',
            border_style='dim',
            box=box.SIMPLE_HEAD,
            padding=(0, 2),
        ))
        self.console.print()

    def _exit(self):
        self.console.print()
        self._reply('Goodbye.')
        self.console.print()
