"""
Param Miner Tab — Hidden parameter discovery
=============================================
Burp Suite Param Miner ka full alternative.
Hidden GET/POST params, headers, JSON keys discover karo.

Features:
  - URL query param mining
  - POST body param mining
  - Hidden header mining (X-Forwarded-For, X-Original-URL, etc.)
  - JSON key mining
  - Wordlist-based + AI-suggested param names
  - Response diff detection (length, status, reflection)
  - Groq AI: interesting param analysis
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import time
import urllib.parse
import logging
from datetime import datetime
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor

logger = logging.getLogger(__name__)

# Built-in param wordlist — common hidden params
PARAM_WORDLIST = [
    'debug', 'test', 'admin', 'id', 'user', 'username', 'email', 'password',
    'token', 'key', 'api_key', 'apikey', 'secret', 'auth', 'access_token',
    'redirect', 'url', 'next', 'return', 'returnUrl', 'redirect_uri',
    'callback', 'file', 'path', 'dir', 'include', 'page', 'template',
    'view', 'action', 'cmd', 'exec', 'command', 'query', 'search', 'q',
    'lang', 'language', 'locale', 'format', 'output', 'type', 'mode',
    'sort', 'order', 'limit', 'offset', 'page', 'size', 'count',
    'from', 'to', 'start', 'end', 'date', 'time', 'timestamp',
    'ref', 'source', 'src', 'dest', 'destination', 'target',
    'host', 'domain', 'site', 'origin', 'referer',
    'data', 'payload', 'body', 'content', 'message', 'text',
    'name', 'title', 'label', 'tag', 'category', 'group',
    'role', 'permission', 'scope', 'level', 'rank',
    'version', 'v', 'ver', 'release', 'build',
    'config', 'setting', 'option', 'param', 'value',
    'hash', 'checksum', 'signature', 'nonce', 'state',
    'code', 'error', 'status', 'result', 'response',
    'upload', 'download', 'export', 'import', 'backup',
    'log', 'trace', 'verbose', 'dev', 'development', 'staging',
    'internal', 'private', 'hidden', 'bypass', 'override',
    'X-Forwarded-For', 'X-Real-IP', 'X-Original-URL',
    'X-Rewrite-URL', 'X-Custom-IP-Authorization',
    'X-Forwarded-Host', 'X-Host', 'X-HTTP-Method-Override',
    'X-Override-URL', 'X-Forwarded-Proto', 'X-Debug',
    'X-Admin', 'X-Internal', 'X-Api-Key', 'X-Auth-Token',
]

HEADER_WORDLIST = [
    'X-Forwarded-For', 'X-Real-IP', 'X-Original-URL', 'X-Rewrite-URL',
    'X-Custom-IP-Authorization', 'X-Forwarded-Host', 'X-Host',
    'X-HTTP-Method-Override', 'X-Override-URL', 'X-Forwarded-Proto',
    'X-Debug', 'X-Admin', 'X-Internal', 'X-Api-Key', 'X-Auth-Token',
    'X-User-ID', 'X-Role', 'X-Permission', 'X-Bypass', 'X-Dev',
    'X-Requested-With', 'X-CSRF-Token', 'X-Frame-Options',
    'Authorization', 'Cookie', 'Referer', 'Origin',
]


class ParamMinerTab:
    """
    Tab: Param Miner — hidden parameter discovery.
    """

    def __init__(self, notebook, app):
        self.app      = app
        self.db       = app.db
        self._running = False
        self._results = []
        self._base_len = None

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='  ⌕ Param Miner  ')
        self._build()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW, CYAN, PURPLE,
            FONT_MONO, FONT_MONO_SM, FONT_MONO_XS
        )
        C = self._C = dict(
            BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, BORDER2=BORDER2,
            ACCENT=ACCENT, ACCENT3=ACCENT3, TEXT=TEXT, TEXT2=TEXT2,
            TEXT3=TEXT3, GREEN=GREEN, RED=RED, ORANGE=ORANGE,
            YELLOW=YELLOW, CYAN=CYAN, PURPLE=PURPLE,
        )

        # ── Config ────────────────────────────────────────────────────────────
        cfg = tk.Frame(self.frame, bg=C['BG3'])
        cfg.pack(fill='x')
        inner = tk.Frame(cfg, bg=C['BG3'])
        inner.pack(padx=10, pady=8, fill='x')

        r1 = tk.Frame(inner, bg=C['BG3'])
        r1.pack(fill='x', pady=3)
        self._lbl(r1, 'TARGET URL')
        self._url_entry = ttk.Entry(r1, width=50, font=FONT_MONO)
        self._url_entry.pack(side='left', padx=(0, 12))
        self._lbl(r1, 'METHOD')
        self._method = ttk.Combobox(r1, width=8, state='readonly',
            values=['GET', 'POST', 'PUT', 'PATCH'])
        self._method.set('GET')
        self._method.pack(side='left', padx=(0, 12))
        self._lbl(r1, 'THREADS')
        self._threads = ttk.Entry(r1, width=4)
        self._threads.insert(0, '10')
        self._threads.pack(side='left', padx=(0, 12))
        self._lbl(r1, 'DIFF THRESHOLD')
        self._threshold = ttk.Entry(r1, width=5)
        self._threshold.insert(0, '20')
        self._threshold.pack(side='left')

        r2 = tk.Frame(inner, bg=C['BG3'])
        r2.pack(fill='x', pady=3)

        self._mine_query_var  = tk.BooleanVar(value=True)
        self._mine_body_var   = tk.BooleanVar(value=True)
        self._mine_header_var = tk.BooleanVar(value=True)
        self._mine_json_var   = tk.BooleanVar(value=False)
        self._ai_suggest_var  = tk.BooleanVar(value=True)

        for text, var in [
            ('Query Params', self._mine_query_var),
            ('POST Body',    self._mine_body_var),
            ('Headers',      self._mine_header_var),
            ('JSON Keys',    self._mine_json_var),
            ('AI Suggest',   self._ai_suggest_var),
        ]:
            ttk.Checkbutton(r2, text=text, variable=var).pack(side='left', padx=8)

        r3 = tk.Frame(inner, bg=C['BG3'])
        r3.pack(fill='x', pady=3)

        ttk.Button(r3, text='▶  START MINING', style='Cyan.TButton',
            command=self._start).pack(side='left', padx=(0, 8))
        ttk.Button(r3, text='STOP', style='Ghost.TButton',
            command=self._stop).pack(side='left', padx=(0, 8))
        ttk.Button(r3, text='FROM PROXY', style='Ghost.TButton',
            command=self._from_proxy).pack(side='left', padx=(0, 8))
        ttk.Button(r3, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=(0, 8))
        ttk.Button(r3, text='EXPORT', style='Ghost.TButton',
            command=self._export).pack(side='left', padx=(0, 8))
        ttk.Button(r3, text='→ INTRUDER', style='Ghost.TButton',
            command=self._send_to_intruder).pack(side='left', padx=(0, 8))

        self._status_lbl = tk.Label(r3, text='',
            bg=C['BG3'], fg=C['TEXT2'], font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=8)

        self._progress_lbl = tk.Label(r3, text='',
            bg=C['BG3'], fg=C['ACCENT'], font=FONT_MONO_XS)
        self._progress_lbl.pack(side='right', padx=8)

        # ── Main split ────────────────────────────────────────────────────────
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: results
        lf = tk.Frame(pw, bg=C['BG'])
        pw.add(lf, weight=3)

        lh = tk.Frame(lf, bg=C['BG3'])
        lh.pack(fill='x')
        tk.Frame(lh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(lh, text='  DISCOVERED PARAMETERS', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)
        self._count_lbl = tk.Label(lh, text='0 found',
            bg=C['BG3'], fg=C['ACCENT'], font=FONT_MONO_XS)
        self._count_lbl.pack(side='right', padx=12)

        cols = ('param', 'location', 'status', 'base_len', 'new_len',
                'diff', 'reflected', 'interesting')
        self._tree = ttk.Treeview(lf, columns=cols, show='headings')
        for col, w, h in [
            ('param', 160, 'Parameter'), ('location', 80, 'Location'),
            ('status', 55, 'Status'), ('base_len', 70, 'Base Len'),
            ('new_len', 70, 'New Len'), ('diff', 65, 'Diff'),
            ('reflected', 70, 'Reflected'), ('interesting', 80, 'Interesting'),
        ]:
            self._tree.heading(col, text=h,
                command=lambda c=col: self._sort(c))
            self._tree.column(col, width=w,
                anchor='w' if col == 'param' else 'center')

        self._tree.tag_configure('interesting', foreground=C['ORANGE'], background='#1a1200')
        self._tree.tag_configure('critical',    foreground=C['RED'],    background='#1a0000')
        self._tree.tag_configure('reflected',   foreground=C['PURPLE'])

        vsb = ttk.Scrollbar(lf, orient='vertical', command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self._tree.pack(fill='both', expand=True)
        self._tree.bind('<<TreeviewSelect>>', self._on_select)
        self._tree.bind('<Button-3>', self._context_menu)

        # Right: detail + AI
        rf = tk.Frame(pw, bg=C['BG'])
        pw.add(rf, weight=1)

        rh = tk.Frame(rf, bg=C['BG3'])
        rh.pack(fill='x')
        tk.Frame(rh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(rh, text='  DETAIL + AI ANALYSIS', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        detail_f = tk.Frame(rf, bg=C['BG'])
        detail_f.pack(fill='both', expand=True)
        self._txt_detail = tk.Text(detail_f, bg=C['BG2'], fg=C['CYAN'],
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8)
        vs2 = ttk.Scrollbar(detail_f, orient='vertical', command=self._txt_detail.yview)
        self._txt_detail.configure(yscrollcommand=vs2.set)
        vs2.pack(side='right', fill='y')
        self._txt_detail.pack(fill='both', expand=True)

    def _lbl(self, parent, text):
        from sentinel_proxy.ui.app import FONT_MONO_XS, BG3, TEXT2
        tk.Label(parent, text=text, bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 5))

    # ── Mining ────────────────────────────────────────────────────────────────

    def _start(self):
        if self._running:
            return
        url = self._url_entry.get().strip()
        if not url:
            messagebox.showwarning('Param Miner', 'Enter a target URL')
            return
        if not url.startswith('http'):
            url = 'http://' + url
            self._url_entry.delete(0, 'end')
            self._url_entry.insert(0, url)

        self._running   = True
        self._results   = []
        self._base_len  = None
        for i in self._tree.get_children():
            self._tree.delete(i)
        self._txt_detail.delete('1.0', 'end')
        self._status_lbl.config(text='Mining...', fg=self._C['YELLOW'])

        threading.Thread(target=self._run_mining, args=(url,),
                         daemon=True).start()

    def _run_mining(self, url: str):
        import requests as _req

        method = self._method.get()
        try:
            threshold = int(self._threshold.get() or 20)
        except ValueError:
            threshold = 20
        try:
            threads_n = int(self._threads.get() or 10)
        except ValueError:
            threads_n = 10

        # Get baseline
        try:
            r0 = _req.request(method, url, verify=False, timeout=8,
                              allow_redirects=False)
            self._base_len = len(r0.content)
            base_status    = r0.status_code
        except Exception as e:
            self.app.root.after(0, lambda: self._status_lbl.config(
                text=f'Baseline error: {str(e)[:50]}', fg=self._C['RED']))
            self._running = False
            return

        # Build wordlist
        wordlist = list(PARAM_WORDLIST)

        # AI-suggested params
        if self._ai_suggest_var.get():
            ai_params = self._get_ai_suggestions(url)
            wordlist  = list(dict.fromkeys(wordlist + ai_params))  # dedupe

        total   = 0
        if self._mine_query_var.get():  total += len(wordlist)
        if self._mine_body_var.get():   total += len(wordlist)
        if self._mine_header_var.get(): total += len(HEADER_WORDLIST)
        if self._mine_json_var.get():   total += len(wordlist)

        done = [0]

        def _test_param(args):
            param, location = args
            if not self._running:
                return
            try:
                import requests as _r
                if location == 'query':
                    sep      = '&' if '?' in url else '?'
                    test_url = f'{url}{sep}{param}=SENTINEL_PROBE_1337'
                    r        = _r.request(method, test_url, verify=False,
                                          timeout=6, allow_redirects=False)
                elif location == 'body':
                    r = _r.request(method, url,
                                   data={param: 'SENTINEL_PROBE_1337'},
                                   verify=False, timeout=6, allow_redirects=False)
                elif location == 'header':
                    r = _r.request(method, url,
                                   headers={param: 'SENTINEL_PROBE_1337'},
                                   verify=False, timeout=6, allow_redirects=False)
                elif location == 'json':
                    r = _r.request(method, url,
                                   json={param: 'SENTINEL_PROBE_1337'},
                                   headers={'Content-Type': 'application/json'},
                                   verify=False, timeout=6, allow_redirects=False)
                else:
                    return

                new_len   = len(r.content)
                diff      = new_len - self._base_len
                reflected = 'SENTINEL_PROBE_1337' in r.text
                status_diff = r.status_code != base_status
                interesting = (abs(diff) >= threshold or reflected or status_diff)
                tag = ('critical' if (reflected and abs(diff) > 100)
                       else ('interesting' if interesting else ''))

                done[0] += 1
                if interesting or reflected:
                    result = {
                        'param': param, 'location': location,
                        'status': r.status_code, 'base_len': self._base_len,
                        'new_len': new_len, 'diff': diff,
                        'reflected': reflected, 'interesting': interesting,
                        'tag': tag, 'response': r.text[:500],
                    }
                    self._results.append(result)
                    self.app.root.after(0, lambda res=result, d=done[0]:
                        self._add_row(res, d, total))
                else:
                    self.app.root.after(0, lambda d=done[0]:
                        self._progress_lbl.config(text=f'{d}/{total}'))

            except Exception:
                done[0] += 1

        # Build jobs
        jobs = []
        if self._mine_query_var.get():
            jobs += [(p, 'query')  for p in wordlist]
        if self._mine_body_var.get():
            jobs += [(p, 'body')   for p in wordlist]
        if self._mine_header_var.get():
            jobs += [(p, 'header') for p in HEADER_WORDLIST]
        if self._mine_json_var.get():
            jobs += [(p, 'json')   for p in wordlist]

        with ThreadPoolExecutor(max_workers=threads_n) as ex:
            ex.map(_test_param, jobs)

        self._running = False
        found = len(self._results)
        self.app.root.after(0, lambda: [
            self._status_lbl.config(
                text=f'Done  ·  {found} interesting params found', fg=self._C['GREEN']),
            self._progress_lbl.config(text=f'{total}/{total}'),
            self._count_lbl.config(text=f'{found} found'),
            self.app._set_status(f'Param Miner done  ·  {found} params discovered'),
        ])

        # AI analysis of interesting results
        if found > 0:
            threading.Thread(target=self._ai_analyze_results,
                             daemon=True).start()

    def _get_ai_suggestions(self, url: str) -> list:
        try:
            analyzer = self.app.analyzer
            if not hasattr(analyzer, '_groq') or not analyzer._groq:
                return []
            prompt = (
                f"URL: {url}\n"
                f"Suggest 30 hidden HTTP parameter names likely to exist on this endpoint. "
                f"Return ONLY a JSON array of strings: [\"param1\", \"param2\", ...]\n"
                f"No explanation, no markdown."
            )
            raw = analyzer._groq.ask(prompt, max_tokens=400)
            import re
            m = re.search(r'\[.*?\]', raw, re.DOTALL)
            if m:
                return json.loads(m.group())
        except Exception:
            pass
        return []

    def _ai_analyze_results(self):
        try:
            analyzer = self.app.analyzer
            if not hasattr(analyzer, '_groq') or not analyzer._groq:
                return
            interesting = [r for r in self._results if r['interesting']][:10]
            if not interesting:
                return
            summary = '\n'.join(
                f"  {r['param']} ({r['location']}) — diff:{r['diff']} reflected:{r['reflected']}"
                for r in interesting
            )
            prompt = (
                f"Param Miner found these interesting hidden parameters:\n{summary}\n\n"
                f"For each, explain:\n"
                f"1. What vulnerability it might indicate\n"
                f"2. How to exploit it\n"
                f"Be concise, one line per param."
            )
            result = analyzer._groq.ask(prompt, max_tokens=500)
            self.app.root.after(0, lambda r=result: [
                self._txt_detail.delete('1.0', 'end'),
                self._txt_detail.insert('1.0',
                    f'AI Analysis of {len(interesting)} interesting params:\n\n{r}\n'),
            ])
        except Exception:
            pass

    def _add_row(self, result: dict, done: int, total: int):
        tag = result.get('tag', '')
        diff = result['diff']
        self._tree.insert('', 'end',
            values=(result['param'], result['location'],
                    result['status'], result['base_len'],
                    result['new_len'],
                    f'+{diff}' if diff > 0 else str(diff),
                    'YES' if result['reflected'] else 'NO',
                    '!!' if tag == 'critical' else ('!' if tag == 'interesting' else '')),
            tags=(tag,) if tag else ())
        self._progress_lbl.config(text=f'{done}/{total}')
        self._count_lbl.config(text=f'{len(self._results)} found')

    # ── Actions ───────────────────────────────────────────────────────────────

    def _from_proxy(self):
        req_id = getattr(self.app, 'selected_req', None)
        if not req_id:
            messagebox.showwarning('Param Miner', 'Select a request in Proxy tab first')
            return
        req = self.db.get_request(req_id)
        if not req:
            return
        self._url_entry.delete(0, 'end')
        self._url_entry.insert(0, req.get('url', ''))
        self._method.set(req.get('method', 'GET'))
        self.app._set_status('Request loaded into Param Miner')

    def _on_select(self, event=None):
        sel = self._tree.selection()
        if not sel:
            return
        idx = self._tree.index(sel[0])
        if idx >= len(self._results):
            return
        # Find matching result
        vals = self._tree.item(sel[0], 'values')
        param    = vals[0]
        location = vals[1]
        result   = next((r for r in self._results
                         if r['param'] == param and r['location'] == location), None)
        if not result:
            return
        out = (f"{'='*50}\n"
               f"Parameter : {result['param']}\n"
               f"Location  : {result['location']}\n"
               f"Status    : {result['status']}\n"
               f"Base Len  : {result['base_len']}\n"
               f"New Len   : {result['new_len']}\n"
               f"Diff      : {result['diff']}\n"
               f"Reflected : {result['reflected']}\n"
               f"{'='*50}\n\n"
               f"Response Preview:\n{result.get('response', '')[:400]}\n")
        self._txt_detail.delete('1.0', 'end')
        self._txt_detail.insert('1.0', out)

    def _context_menu(self, event):
        item = self._tree.identify_row(event.y)
        if not item:
            return
        self._tree.selection_set(item)
        vals = self._tree.item(item, 'values')
        param = vals[0] if vals else ''
        C = self._C
        m = tk.Menu(self.app.root, tearoff=0,
            bg=C['BG3'], fg=C['TEXT'],
            activebackground=C['BG4'], activeforeground=C['ACCENT'],
            font=('Fira Code', 9))
        m.add_command(label='  Copy Param Name',
            command=lambda: [self.app.root.clipboard_clear(),
                             self.app.root.clipboard_append(param)])
        m.add_command(label='  → Send to Intruder',
            command=self._send_to_intruder)
        m.add_command(label='  → Send to Active Scanner',
            command=lambda: [self.app.as_url.delete(0, 'end'),
                             self.app.as_url.insert(0, self._url_entry.get()),
                             self.app.nb.select(
                                 next(i for i in range(self.app.nb.index('end'))
                                      if 'Active' in self.app.nb.tab(i, 'text')))])
        m.post(event.x_root, event.y_root)

    def _send_to_intruder(self):
        url = self._url_entry.get().strip()
        if url:
            self.app.int_url.delete(0, 'end')
            self.app.int_url.insert(0, url)
        interesting = [r['param'] for r in self._results if r['interesting']]
        if interesting:
            self.app.int_param.delete(0, 'end')
            self.app.int_param.insert(0, interesting[0])
        self.app.nb.select(2)
        self.app._set_status(f'Sent {len(interesting)} params to Intruder')

    def _sort(self, col):
        items = [(self._tree.set(i, col), i) for i in self._tree.get_children()]
        try:
            items.sort(key=lambda x: int(x[0].lstrip('+-')) if x[0].lstrip('+-').isdigit() else x[0])
        except Exception:
            items.sort()
        for idx, (_, iid) in enumerate(items):
            self._tree.move(iid, '', idx)

    def _stop(self):
        self._running = False
        self._status_lbl.config(text='Stopped', fg=self._C['ORANGE'])

    def _clear(self):
        self._results  = []
        self._base_len = None
        for i in self._tree.get_children():
            self._tree.delete(i)
        self._txt_detail.delete('1.0', 'end')
        self._status_lbl.config(text='')
        self._progress_lbl.config(text='')
        self._count_lbl.config(text='0 found')

    def _export(self):
        from tkinter import filedialog
        if not self._results:
            messagebox.showwarning('Param Miner', 'No results to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json'), ('Text', '*.txt')],
            initialfile=f'param_miner_{int(time.time())}.json')
        if not path:
            return
        with open(path, 'w') as f:
            json.dump(self._results, f, indent=2)
        self.app._set_status(f'Exported {len(self._results)} results → {path}')
