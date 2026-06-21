# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
#
# Unauthorized copying, distribution, or modification of this software,
# via any medium, is strictly prohibited without written permission.
#
# Licensed users may use this software under the terms of their license.
# For licensing: https://github.com/Mrsultan7890/osints
# ============================================================================

"""
AI Payload Generator Tab
========================
Groq llama-3.3-70b se target-specific, context-aware payloads generate karo.
SentinelNet se threat classify karo, phir AI se custom payloads banao.

Features:
  - Target URL + tech stack analysis
  - Groq se custom payload generation per vuln type
  - WAF bypass variants auto-generate
  - Payload history + export
  - Direct → Intruder / Repeater send
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class AIPayloadTab:
    """
    Tab: AI Payload Generator.
    Uses Groq + SentinelNet to generate smart, context-aware payloads.
    """

    def __init__(self, notebook, app):
        self.app        = app
        self.db         = app.db
        self._running   = False
        self._payloads  = []   # generated payloads list

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='✦ AI Payloads')
        self._build()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW, CYAN, PURPLE,
            FONT_MONO, FONT_MONO_SM, FONT_MONO_XS, FONT_BOLD
        )
        C = self._C = dict(
            BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, BORDER2=BORDER2,
            ACCENT=ACCENT, ACCENT3=ACCENT3, TEXT=TEXT, TEXT2=TEXT2,
            TEXT3=TEXT3, GREEN=GREEN, RED=RED, ORANGE=ORANGE,
            YELLOW=YELLOW, CYAN=CYAN, PURPLE=PURPLE,
        )

        # ── Config bar ────────────────────────────────────────────────────────
        cfg = tk.Frame(self.frame, bg=C['BG3'])
        cfg.pack(fill='x')

        inner = tk.Frame(cfg, bg=C['BG3'])
        inner.pack(padx=10, pady=8, fill='x')

        # Row 1
        r1 = tk.Frame(inner, bg=C['BG3'])
        r1.pack(fill='x', pady=3)

        self._lbl(r1, 'TARGET URL')
        self._url_entry = ttk.Entry(r1, width=45, font=FONT_MONO)
        self._url_entry.pack(side='left', padx=(0, 12))

        self._lbl(r1, 'VULN TYPE')
        self._vuln_type = ttk.Combobox(r1, width=18, state='readonly',
            values=['SQLi', 'XSS', 'LFI', 'SSRF', 'SSTI', 'RCE', 'XXE',
                    'Open Redirect', 'Path Traversal', 'CORS', 'JWT',
                    'OAuth', 'Prototype Pollution', 'CRLF', 'LDAP',
                    'NoSQL', 'GraphQL', 'WAF Bypass', 'Custom'])
        self._vuln_type.set('SQLi')
        self._vuln_type.pack(side='left', padx=(0, 12))

        self._lbl(r1, 'COUNT')
        self._count_var = ttk.Entry(r1, width=5)
        self._count_var.insert(0, '20')
        self._count_var.pack(side='left', padx=(0, 12))

        # Row 2
        r2 = tk.Frame(inner, bg=C['BG3'])
        r2.pack(fill='x', pady=3)

        self._lbl(r2, 'TECH STACK')
        self._tech_entry = ttk.Entry(r2, width=30)
        self._tech_entry.insert(0, 'e.g. PHP, MySQL, nginx, WAF: Cloudflare')
        self._tech_entry.pack(side='left', padx=(0, 12))

        self._lbl(r2, 'CONTEXT')
        self._context_entry = ttk.Entry(r2, width=35)
        self._context_entry.insert(0, 'e.g. login form, search param, file upload')
        self._context_entry.pack(side='left', padx=(0, 12))

        # Row 3 — buttons
        r3 = tk.Frame(inner, bg=C['BG3'])
        r3.pack(fill='x', pady=3)

        ttk.Button(r3, text='✦  GENERATE WITH AI', style='Cyan.TButton',
            command=self._generate).pack(side='left', padx=(0, 8))
        ttk.Button(r3, text='WAF BYPASS VARIANTS', style='Red.TButton',
            command=self._generate_waf_bypass).pack(side='left', padx=(0, 8))
        ttk.Button(r3, text='FROM PROXY SELECTION', style='Ghost.TButton',
            command=self._from_proxy).pack(side='left', padx=(0, 8))
        ttk.Button(r3, text='STOP', style='Ghost.TButton',
            command=self._stop).pack(side='left', padx=(0, 8))
        ttk.Button(r3, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=(0, 8))

        self._status_lbl = tk.Label(r3, text='',
            bg=C['BG3'], fg=C['TEXT2'], font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=8)

        # ── Main split ────────────────────────────────────────────────────────
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: generated payloads list
        lf = tk.Frame(pw, bg=C['BG'])
        pw.add(lf, weight=2)

        lh = tk.Frame(lf, bg=C['BG3'])
        lh.pack(fill='x')
        tk.Frame(lh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(lh, text='  GENERATED PAYLOADS', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)
        ttk.Button(lh, text='→ Intruder', style='Ghost.TButton',
            command=self._send_to_intruder).pack(side='right', padx=4, pady=3)
        ttk.Button(lh, text='→ Repeater', style='Ghost.TButton',
            command=self._send_to_repeater).pack(side='right', padx=2, pady=3)
        ttk.Button(lh, text='EXPORT', style='Ghost.TButton',
            command=self._export).pack(side='right', padx=2, pady=3)
        ttk.Button(lh, text='COPY ALL', style='Ghost.TButton',
            command=self._copy_all).pack(side='right', padx=2, pady=3)

        cols = ('idx', 'payload', 'type', 'bypass', 'score')
        self._tree = ttk.Treeview(lf, columns=cols, show='headings')
        for col, w, h in [
            ('idx', 35, '#'), ('payload', 380, 'Payload'),
            ('type', 90, 'Type'), ('bypass', 70, 'WAF Bypass'),
            ('score', 60, 'AI Score'),
        ]:
            self._tree.heading(col, text=h)
            self._tree.column(col, width=w,
                anchor='w' if col == 'payload' else 'center')
        self._tree.tag_configure('high',   foreground=C['RED'])
        self._tree.tag_configure('medium', foreground=C['ORANGE'])
        self._tree.tag_configure('bypass', foreground=C['PURPLE'])
        vsb = ttk.Scrollbar(lf, orient='vertical', command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self._tree.pack(fill='both', expand=True)
        self._tree.bind('<<TreeviewSelect>>', self._on_select)
        self._tree.bind('<Button-3>', self._context_menu)

        # Right: AI reasoning + explanation
        rf = tk.Frame(pw, bg=C['BG'])
        pw.add(rf, weight=1)

        rh = tk.Frame(rf, bg=C['BG3'])
        rh.pack(fill='x')
        tk.Frame(rh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(rh, text='  AI REASONING', bg=C['BG3'], fg=C['ACCENT'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        detail_f = tk.Frame(rf, bg=C['BG'])
        detail_f.pack(fill='both', expand=True)
        self._txt_reason = tk.Text(detail_f, bg=C['BG2'], fg=C['CYAN'],
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8)
        vs2 = ttk.Scrollbar(detail_f, orient='vertical', command=self._txt_reason.yview)
        self._txt_reason.configure(yscrollcommand=vs2.set)
        vs2.pack(side='right', fill='y')
        self._txt_reason.pack(fill='both', expand=True)

    def _lbl(self, parent, text):
        from sentinel_proxy.ui.app import FONT_MONO_XS, BG3, TEXT2
        tk.Label(parent, text=text, bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 5))

    # ── Generation ────────────────────────────────────────────────────────────

    def _generate(self):
        if self._running:
            return
        url      = self._url_entry.get().strip()
        vtype    = self._vuln_type.get()
        tech     = self._tech_entry.get().strip()
        context  = self._context_entry.get().strip()
        if tech.startswith('e.g.'): tech = ''
        if context.startswith('e.g.'): context = ''
        try:
            count = int(self._count_var.get() or 20)
        except ValueError:
            count = 20

        self._running = True
        self._status_lbl.config(text='Generating with AI...', fg=self._C['YELLOW'])
        threading.Thread(target=self._run_generate,
                         args=(url, vtype, tech, context, count, False),
                         daemon=True).start()

    def _generate_waf_bypass(self):
        if self._running:
            return
        url     = self._url_entry.get().strip()
        vtype   = self._vuln_type.get()
        tech    = self._tech_entry.get().strip()
        context = self._context_entry.get().strip()
        if tech.startswith('e.g.'): tech = ''
        if context.startswith('e.g.'): context = ''
        try:
            count = int(self._count_var.get() or 20)
        except ValueError:
            count = 20

        self._running = True
        self._status_lbl.config(text='Generating WAF bypass payloads...', fg=self._C['YELLOW'])
        threading.Thread(target=self._run_generate,
                         args=(url, vtype, tech, context, count, True),
                         daemon=True).start()

    def _run_generate(self, url: str, vtype: str, tech: str,
                      context: str, count: int, waf_bypass: bool):
        try:
            analyzer = self.app.analyzer
            payloads = []
            reasoning = ''

            # Try Groq first
            if hasattr(analyzer, '_groq') and analyzer._groq:
                bypass_note = (
                    '\nFocus on WAF bypass techniques: encoding, case variation, '
                    'comment injection, whitespace tricks, unicode, double encoding.'
                    if waf_bypass else ''
                )
                prompt = (
                    f"You are a professional penetration tester.\n"
                    f"Generate {count} unique, effective {vtype} payloads.\n"
                    f"Target URL: {url or 'unknown'}\n"
                    f"Tech stack: {tech or 'unknown'}\n"
                    f"Context: {context or 'general parameter'}\n"
                    f"{bypass_note}\n\n"
                    f"Return ONLY a JSON object:\n"
                    f'{{"payloads": ["payload1", "payload2", ...], '
                    f'"reasoning": "brief explanation of why these payloads work", '
                    f'"risk_scores": [0.9, 0.8, ...]}}\n'
                    f"No markdown, no extra text."
                )
                raw = analyzer._groq.ask(prompt, max_tokens=1500)
                reasoning = ''
                try:
                    import re
                    m = re.search(r'\{.*\}', raw, re.DOTALL)
                    if m:
                        data      = json.loads(m.group())
                        payloads  = data.get('payloads', [])
                        reasoning = data.get('reasoning', '')
                        scores    = data.get('risk_scores', [])
                    else:
                        # Fallback: extract lines
                        payloads = [l.strip().strip('"\'') for l in raw.split('\n')
                                    if l.strip() and not l.startswith('{')][:count]
                        scores   = []
                except Exception:
                    payloads = [l.strip().strip('"\'') for l in raw.split('\n')
                                if l.strip()][:count]
                    scores   = []
            else:
                # Fallback: load from payload files
                payloads  = self._load_from_file(vtype, count)
                scores    = []
                reasoning = f'Groq not available — loaded {len(payloads)} payloads from file.'

            if not payloads:
                payloads  = self._load_from_file(vtype, count)
                reasoning = f'AI returned empty — loaded {len(payloads)} payloads from file.'

            self._payloads = payloads
            self.app.root.after(0, lambda p=payloads, r=reasoning,
                                       s=scores, w=waf_bypass:
                self._show_results(p, r, s, w))

        except Exception as e:
            self.app.root.after(0, lambda: self._status_lbl.config(
                text=f'Error: {str(e)[:60]}', fg=self._C['RED']))
        finally:
            self._running = False

    def _show_results(self, payloads: list, reasoning: str,
                      scores: list, waf_bypass: bool):
        for i in self._tree.get_children():
            self._tree.delete(i)

        vtype = self._vuln_type.get()
        for idx, p in enumerate(payloads, 1):
            score = scores[idx - 1] if idx - 1 < len(scores) else 0.0
            score_str = f'{score:.2f}' if isinstance(score, float) else str(score)
            tag = 'bypass' if waf_bypass else ('high' if score >= 0.8 else 'medium')
            self._tree.insert('', 'end',
                values=(idx, str(p)[:120], vtype,
                        'YES' if waf_bypass else 'NO', score_str),
                tags=(tag,))

        self._txt_reason.delete('1.0', 'end')
        self._txt_reason.insert('1.0',
            f'Vuln Type  : {vtype}\n'
            f'Count      : {len(payloads)}\n'
            f'WAF Bypass : {"YES" if waf_bypass else "NO"}\n'
            f'{"="*45}\n\n'
            f'AI Reasoning:\n{reasoning}\n')

        self._status_lbl.config(
            text=f'{len(payloads)} payloads generated', fg=self._C['GREEN'])
        self.app._set_status(f'AI Payload Generator: {len(payloads)} {vtype} payloads ready')

    def _load_from_file(self, vtype: str, count: int) -> list:
        FILE_MAP = {
            'SQLi': 'sqli.txt', 'XSS': 'xss.txt', 'LFI': 'lfi.txt',
            'SSRF': 'ssrf.txt', 'SSTI': 'ssti.txt', 'RCE': 'rce.txt',
            'XXE': 'xxe.txt', 'Open Redirect': 'open_redirect.txt',
            'LDAP': 'ldap.txt', 'NoSQL': 'nosql.txt', 'GraphQL': 'graphql.txt',
            'JWT': 'jwt.txt', 'CORS': 'cors.txt', 'CRLF': 'crlf.txt',
            'Path Traversal': 'path_traversal.txt',
            'Prototype Pollution': 'prototype_pollution.txt',
        }
        fname = FILE_MAP.get(vtype)
        if not fname:
            return []
        try:
            import sys as _sys
            from pathlib import Path
            if getattr(_sys, 'frozen', False):
                _proxy_base = Path(_sys.executable).resolve().parent / '_internal' / 'sentinel_proxy'
            else:
                _proxy_base = Path(__file__).parents[2]
            fpath = _proxy_base / 'payloads' / fname
            lines = fpath.read_text(errors='ignore').splitlines()
            return [l for l in lines if l.strip()][:count]
        except Exception:
            return []

    # ── Actions ───────────────────────────────────────────────────────────────

    def _from_proxy(self):
        req_id = getattr(self.app, 'selected_req', None)
        if not req_id:
            messagebox.showwarning('AI Payloads', 'Select a request in Proxy tab first')
            return
        req = self.db.get_request(req_id)
        if not req:
            return
        self._url_entry.delete(0, 'end')
        self._url_entry.insert(0, req.get('url', ''))
        # Auto-detect tech from response headers
        try:
            rhdrs = json.loads(req.get('resp_headers', '{}'))
            server = rhdrs.get('Server', rhdrs.get('server', ''))
            powered = rhdrs.get('X-Powered-By', rhdrs.get('x-powered-by', ''))
            tech = ', '.join(filter(None, [server, powered]))
            if tech:
                self._tech_entry.delete(0, 'end')
                self._tech_entry.insert(0, tech)
        except Exception:
            pass
        self.app._set_status('Request loaded into AI Payload Generator')

    def _on_select(self, event=None):
        sel = self._tree.selection()
        if not sel:
            return
        vals = self._tree.item(sel[0], 'values')
        if vals:
            payload = vals[1]
            self._txt_reason.delete('1.0', 'end')
            self._txt_reason.insert('1.0',
                f'Selected Payload:\n\n{payload}\n\n'
                f'Type      : {vals[2]}\n'
                f'WAF Bypass: {vals[3]}\n'
                f'AI Score  : {vals[4]}\n\n'
                f'Right-click for more options.\n')

    def _context_menu(self, event):
        item = self._tree.identify_row(event.y)
        if not item:
            return
        self._tree.selection_set(item)
        vals = self._tree.item(item, 'values')
        payload = vals[1] if vals else ''
        C = self._C
        m = tk.Menu(self.app.root, tearoff=0,
            bg=C['BG3'], fg=C['TEXT'],
            activebackground=C['BG4'], activeforeground=C['ACCENT'],
            font=('Fira Code', 9))
        m.add_command(label='  Copy Payload',
            command=lambda: [self.app.root.clipboard_clear(),
                             self.app.root.clipboard_append(payload)])
        m.add_command(label='  → Send to Intruder',
            command=self._send_to_intruder)
        m.add_command(label='  → Send to Repeater',
            command=self._send_to_repeater)
        m.add_command(label='  → Send to Active Scanner',
            command=self._send_to_scanner)
        m.post(event.x_root, event.y_root)

    def _send_to_intruder(self):
        if not self._payloads:
            messagebox.showwarning('AI Payloads', 'Generate payloads first')
            return
        url = self._url_entry.get().strip()
        if url:
            self.app.int_url.delete(0, 'end')
            self.app.int_url.insert(0, url)
        self.app.int_payloads_txt.delete('1.0', 'end')
        self.app.int_payloads_txt.insert('1.0', '\n'.join(str(p) for p in self._payloads))
        self.app.nb.select(2)
        self.app._set_status(f'Sent {len(self._payloads)} AI payloads to Intruder')

    def _send_to_repeater(self):
        sel = self._tree.selection()
        if not sel:
            messagebox.showwarning('AI Payloads', 'Select a payload first')
            return
        vals    = self._tree.item(sel[0], 'values')
        payload = vals[1] if vals else ''
        url     = self._url_entry.get().strip()
        if url:
            self.app.rep_url.delete(0, 'end')
            self.app.rep_url.insert(0, f'{url}?q={payload}')
        self.app.nb.select(1)

    def _send_to_scanner(self):
        url = self._url_entry.get().strip()
        if url:
            self.app.scan_url.delete(0, 'end')
            self.app.scan_url.insert(0, url)
            self.app.nb.select(3)

    def _copy_all(self):
        if not self._payloads:
            return
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append('\n'.join(str(p) for p in self._payloads))
        self.app._set_status(f'Copied {len(self._payloads)} payloads to clipboard')

    def _export(self):
        from tkinter import filedialog
        if not self._payloads:
            messagebox.showwarning('AI Payloads', 'No payloads to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[('Text', '*.txt'), ('JSON', '*.json')],
            initialfile=f'ai_payloads_{int(time.time())}.txt')
        if not path:
            return
        with open(path, 'w') as f:
            if path.endswith('.json'):
                json.dump(self._payloads, f, indent=2)
            else:
                f.write('\n'.join(str(p) for p in self._payloads))
        self.app._set_status(f'Exported {len(self._payloads)} payloads → {path}')

    def _stop(self):
        self._running = False
        self._status_lbl.config(text='Stopped', fg=self._C['ORANGE'])

    def _clear(self):
        self._payloads = []
        for i in self._tree.get_children():
            self._tree.delete(i)
        self._txt_reason.delete('1.0', 'end')
        self._status_lbl.config(text='')
