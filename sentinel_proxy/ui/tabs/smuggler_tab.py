# ============================================================================
# Sentinel Pro v3.1 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
HTTP Smuggling Tab
==================
Go smuggler binary ke through CL.TE / TE.CL / TE.TE detection.
Results display + save to DB.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import subprocess
import shutil
import json
import time
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


def _find_smuggler() -> str:
    try:
        from config import BASE_DIR
        p = BASE_DIR / 'smuggler' / 'smuggler'
        if p.is_file():
            return str(p)
    except Exception:
        pass
    return shutil.which('smuggler') or ''


class SmugglerTab:

    def __init__(self, notebook, app):
        self.app   = app
        self.db    = app.db
        self._proc = None
        self._running = False

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='⇢ HTTP Smuggling')
        self._build()

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW, CYAN,
            FONT_MONO, FONT_MONO_SM, FONT_MONO_XS
        )
        self._C = dict(BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, ACCENT=ACCENT,
                       TEXT=TEXT, TEXT2=TEXT2, GREEN=GREEN, RED=RED,
                       ORANGE=ORANGE, YELLOW=YELLOW, CYAN=CYAN)

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = tk.Frame(self.frame, bg=BG3)
        tb.pack(fill='x')

        self._run_btn = ttk.Button(tb, text='▶  RUN SCAN', style='Cyan.TButton',
            command=self._run)
        self._run_btn.pack(side='left', padx=8, pady=6)

        self._stop_btn = ttk.Button(tb, text='■  STOP', style='Red.TButton',
            command=self._stop, state='disabled')
        self._stop_btn.pack(side='left', padx=4, pady=6)

        ttk.Button(tb, text='FROM PROXY', style='Ghost.TButton',
            command=self._from_proxy).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=4, pady=6)

        self._status_lbl = tk.Label(tb, text='', bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=12)

        # ── Config row ────────────────────────────────────────────────────────
        cfg = tk.Frame(self.frame, bg=BG3)
        cfg.pack(fill='x', padx=10, pady=6)

        tk.Label(cfg, text='TARGET', bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 5))
        self._target_entry = ttk.Entry(cfg, width=40, font=FONT_MONO)
        self._target_entry.pack(side='left', padx=(0, 12))

        tk.Label(cfg, text='NOTE', bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 5))
        tk.Label(cfg, text='domain only (e.g. example.com)', bg=BG3, fg=CYAN,
            font=('Fira Code', 8)).pack(side='left', padx=(0, 12))

        # ── Split pane ────────────────────────────────────────────────────────
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: output
        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=3)

        lh = tk.Frame(lf, bg=BG3)
        lh.pack(fill='x')
        tk.Frame(lh, bg=CYAN, width=3).pack(side='left', fill='y')
        tk.Label(lh, text='  SCAN OUTPUT', bg=BG3, fg=CYAN,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        out_f = tk.Frame(lf, bg=BG)
        out_f.pack(fill='both', expand=True)
        self._out_txt = tk.Text(out_f, bg=BG2, fg=GREEN,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8, state='disabled')
        vs = ttk.Scrollbar(out_f, orient='vertical', command=self._out_txt.yview)
        hs = ttk.Scrollbar(out_f, orient='horizontal', command=self._out_txt.xview)
        self._out_txt.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side='right', fill='y')
        hs.pack(side='bottom', fill='x')
        self._out_txt.pack(fill='both', expand=True)

        # Right: findings
        rf = tk.Frame(pw, bg=BG)
        pw.add(rf, weight=1)

        rh = tk.Frame(rf, bg=BG3)
        rh.pack(fill='x')
        tk.Frame(rh, bg=RED, width=3).pack(side='left', fill='y')
        tk.Label(rh, text='  FINDINGS', bg=BG3, fg=RED,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        cols = ('Type', 'Severity', 'Detail')
        self._tree = ttk.Treeview(rf, columns=cols, show='headings', height=20)
        for c, w in zip(cols, [80, 70, 200]):
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, minwidth=50)
        vs2 = ttk.Scrollbar(rf, orient='vertical', command=self._tree.yview)
        self._tree.configure(yscrollcommand=vs2.set)
        vs2.pack(side='right', fill='y')
        self._tree.pack(fill='both', expand=True)

    # ── Core ──────────────────────────────────────────────────────────────────

    def _get_binary(self):
        return _find_smuggler() or None

    def _run(self):
        target = self._target_entry.get().strip()
        if not target:
            messagebox.showwarning('HTTP Smuggling', 'Enter a target URL or host')
            return

        binary = self._get_binary()
        if not binary:
            self._append(
                '[ERROR] smuggler binary not found.\n'
                'Build it: cd /home/kali/osints/smuggler && go build -o smuggler .\n'
            )
            return

        self._running = True
        self._run_btn.config(state='disabled')
        self._stop_btn.config(state='normal')
        self._status_lbl.config(text='Scanning...', fg=self._C['YELLOW'])
        self._out_txt.config(state='normal')
        self._out_txt.delete('1.0', 'end')
        self._out_txt.config(state='disabled')
        for row in self._tree.get_children():
            self._tree.delete(row)

        threading.Thread(target=self._scan_thread,
                         args=(binary, target), daemon=True).start()

    def _scan_thread(self, binary, target):
        # binary sirf domain leta hai — koi flags nahi
        # target mein se domain extract karo
        domain = target.replace('https://', '').replace('http://', '').split('/')[0]
        cmd = [binary, domain]

        try:
            self._proc = subprocess.Popen(
                cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                text=True
            )
            stdout, _ = self._proc.communicate()

            try:
                pretty = json.dumps(json.loads(stdout.strip()), indent=2)
            except Exception:
                pretty = stdout
            self.app.root.after(0, lambda o=pretty: self._append(o))

            findings = []
            try:
                data = json.loads(stdout.strip())
                for f in data.get('findings', []):
                    findings.append((
                        f.get('technique', 'Unknown'),
                        f.get('severity', 'HIGH'),
                        f.get('evidence', '')
                    ))
                    self.app.root.after(0, lambda fi=findings[-1]: self._add_finding(*fi))
            except json.JSONDecodeError:
                pass

            done_msg = f'\n[DONE] Scan complete — {len(findings)} finding(s)\n'
            self.app.root.after(0, lambda: self._append(done_msg))
            self.app.root.after(0, lambda: self._status_lbl.config(
                text=f'{len(findings)} finding(s)',
                fg=self._C['RED'] if findings else self._C['GREEN']))
            if findings:
                self.app.root.after(100, lambda f=findings, t=self._target_entry.get():
                    self._ai_analyze(f, t))
        except Exception as e:
            self.app.root.after(0, lambda: self._append(f'[ERROR] {e}\n'))
        finally:
            self._running = False
            self.app.root.after(0, lambda: self._run_btn.config(state='normal'))
            self.app.root.after(0, lambda: self._stop_btn.config(state='disabled'))

    def _stop(self):
        if self._proc:
            try:
                self._proc.terminate()
            except Exception:
                pass
        self._running = False
        self._run_btn.config(state='normal')
        self._stop_btn.config(state='disabled')
        self._status_lbl.config(text='Stopped', fg=self._C['ORANGE'])

    def _append(self, text):
        self._out_txt.config(state='normal')
        self._out_txt.insert('end', text)
        self._out_txt.see('end')
        self._out_txt.config(state='disabled')

    def _add_finding(self, typ, sev, detail):
        tag = sev.lower()
        self._tree.insert('', 'end', values=(typ, sev, detail), tags=(tag,))
        self._tree.tag_configure('critical', foreground=self._C['RED'])
        self._tree.tag_configure('high',     foreground=self._C['ORANGE'])

    def _ai_analyze(self, findings: list, target: str):
        analyzer = self.app.analyzer
        if not hasattr(analyzer, '_groq') or not analyzer._groq:
            return

        def _run():
            summary = '\n'.join(f"  [{s}] {t}: {d}" for t, s, d in findings)
            prompt = (
                f"HTTP Request Smuggling findings for {target}:\n{summary}\n\n"
                f"1. Explain each technique (CL.TE / TE.CL / TE.TE) and real attack scenario\n"
                f"2. How to exploit to poison cache / bypass security controls\n"
                f"3. Remediation. Be concise."
            )
            try:
                result = analyzer._groq.ask(prompt, max_tokens=400)
                self.app.root.after(0, lambda r=result:
                    self._append(f'\n── Groq AI Analysis ──\n{r}\n'))
            except Exception:
                pass

        import threading
        threading.Thread(target=_run, daemon=True).start()

    def _from_proxy(self):
        req_id = getattr(self.app, 'selected_req', None)
        if not req_id:
            messagebox.showwarning('HTTP Smuggling', 'Select a request in Proxy tab first')
            return
        req = self.db.get_request(req_id)
        if req:
            self._target_entry.delete(0, 'end')
            self._target_entry.insert(0, req.get('url', ''))

    def _clear(self):
        self._out_txt.config(state='normal')
        self._out_txt.delete('1.0', 'end')
        self._out_txt.config(state='disabled')
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._status_lbl.config(text='')
