# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
Autorize Tab — Automatic Access Control Testing
Burp Suite Autorize-style: replay every request with low-priv / no-auth tokens
and flag privilege escalation / IDOR / auth bypass automatically.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import requests
import json
import time
import urllib3

urllib3.disable_warnings()

# ── Colors (match app.py palette) ────────────────────────────────────────────
BG        = '#080c0e'
BG2       = '#0d1214'
BG3       = '#111a1d'
BG4       = '#162024'
BORDER2   = '#0f4a52'
ACCENT    = '#00e5c0'
ACCENT3   = '#003d35'
GREEN     = '#39ff6e'
RED       = '#ff3b5c'
ORANGE    = '#ff8c00'
YELLOW    = '#ffe033'
TEXT      = '#cde8e0'
TEXT2     = '#5a8a80'
TEXT3     = '#2a4a45'

FONT_MONO    = ('Fira Code', 10)
FONT_MONO_SM = ('Fira Code', 9)
FONT_MONO_XS = ('Fira Code', 8)
FONT_BOLD    = ('Fira Code', 10, 'bold')

# Result status colors
STATUS_COLOR = {
    'BYPASSED':  RED,
    'ENFORCED':  GREEN,
    'MODIFIED':  ORANGE,
    'PENDING':   TEXT2,
    'ERROR':     YELLOW,
}


class AutorizeTab:
    """
    Replays intercepted requests with:
      - Low-privilege token  (e.g. user-level cookie/JWT)
      - No-auth token        (stripped Authorization header)
    Compares response size/status to detect access control failures.
    """

    def __init__(self, notebook: ttk.Notebook, app):
        self.app     = app
        self.db      = app.db
        self._running = False
        self._results = []   # list of result dicts

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='🔐 Autorize')
        self._build(self.frame)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self, parent):
        # ── Config bar ───────────────────────────────────────────────────────
        cfg = tk.Frame(parent, bg=BG3)
        cfg.pack(fill='x')

        tk.Label(cfg, text='  LOW-PRIV TOKEN', bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(8, 4), pady=8)
        self.entry_token = ttk.Entry(cfg, width=55, font=FONT_MONO_SM,
            show='')
        self.entry_token.pack(side='left', padx=(0, 8), pady=8)

        tk.Label(cfg, text='HEADER', bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 4))
        self.combo_header = ttk.Combobox(cfg, width=18, state='readonly',
            values=['Cookie', 'Authorization', 'X-Auth-Token',
                    'X-API-Key', 'X-Access-Token', 'Bearer'])
        self.combo_header.set('Cookie')
        self.combo_header.pack(side='left', padx=(0, 8), pady=8)

        # ── Second row ───────────────────────────────────────────────────────
        cfg2 = tk.Frame(parent, bg=BG4)
        cfg2.pack(fill='x')

        tk.Label(cfg2, text='  MATCH SIZE DIFF >', bg=BG4, fg=TEXT2,
            font=FONT_MONO_XS).pack(side='left', padx=(8, 4), pady=6)
        self.entry_diff = ttk.Entry(cfg2, width=6)
        self.entry_diff.insert(0, '50')
        self.entry_diff.pack(side='left', padx=(0, 12), pady=6)

        self.var_strip_auth = tk.BooleanVar(value=True)
        ttk.Checkbutton(cfg2, text='Also test with NO auth (stripped)',
            variable=self.var_strip_auth).pack(side='left', padx=8, pady=6)

        self.var_scope_only = tk.BooleanVar(value=True)
        ttk.Checkbutton(cfg2, text='In-scope only',
            variable=self.var_scope_only).pack(side='left', padx=8, pady=6)

        self.var_auto = tk.BooleanVar(value=True)
        ttk.Checkbutton(cfg2, text='Auto-test new requests',
            variable=self.var_auto).pack(side='left', padx=8, pady=6)

        # ── Action bar ───────────────────────────────────────────────────────
        ab = tk.Frame(parent, bg=BG3)
        ab.pack(fill='x')

        ttk.Button(ab, text='▶  TEST SELECTED', style='Cyan.TButton',
            command=self._test_selected).pack(side='left', padx=8, pady=6)
        ttk.Button(ab, text='▶  TEST ALL HISTORY', style='Cyan.TButton',
            command=self._test_all).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='STOP', style='Ghost.TButton',
            command=self._stop).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='BYPASSED ONLY', style='Red.TButton',
            command=self._filter_bypassed).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='SHOW ALL', style='Ghost.TButton',
            command=self._show_all).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='EXPORT', style='Ghost.TButton',
            command=self._export).pack(side='left', padx=4, pady=6)

        self.lbl_status = tk.Label(ab, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.lbl_status.pack(side='right', padx=12)

        # ── Results tree ─────────────────────────────────────────────────────
        pw = ttk.PanedWindow(parent, orient='vertical')
        pw.pack(fill='both', expand=True)

        top = tk.Frame(pw, bg=BG)
        pw.add(top, weight=3)

        cols = ('status', 'method', 'url', 'orig_code', 'orig_len',
                'low_code', 'low_len', 'noauth_code', 'noauth_len', 'diff')
        self.tree = ttk.Treeview(top, columns=cols, show='headings')

        for col, w, h in [
            ('status',     80,  'Result'),
            ('method',     55,  'Method'),
            ('url',        300, 'URL'),
            ('orig_code',  60,  'Orig'),
            ('orig_len',   65,  'Orig Len'),
            ('low_code',   60,  'Low'),
            ('low_len',    65,  'Low Len'),
            ('noauth_code',60,  'NoAuth'),
            ('noauth_len', 65,  'NoAuth Len'),
            ('diff',       60,  'Diff'),
        ]:
            self.tree.heading(col, text=h,
                command=lambda c=col: self._sort(c))
            self.tree.column(col, width=w,
                anchor='center' if col not in ('url',) else 'w')

        self.tree.tag_configure('BYPASSED', foreground=RED,    background='#1a0000')
        self.tree.tag_configure('ENFORCED', foreground=GREEN,  background='#001a08')
        self.tree.tag_configure('MODIFIED', foreground=ORANGE, background='#1a0d00')
        self.tree.tag_configure('ERROR',    foreground=YELLOW)
        self.tree.tag_configure('PENDING',  foreground=TEXT2)

        vsb = ttk.Scrollbar(top, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Button-3>', self._context_menu)

        # ── Detail panel ─────────────────────────────────────────────────────
        bot = tk.Frame(pw, bg=BG)
        pw.add(bot, weight=1)

        det_nb = ttk.Notebook(bot)
        det_nb.pack(fill='both', expand=True)

        orig_f = ttk.Frame(det_nb)
        det_nb.add(orig_f, text='  Original Response  ')
        self.txt_orig = self._make_text(orig_f, fg=TEXT)

        low_f = ttk.Frame(det_nb)
        det_nb.add(low_f, text='  Low-Priv Response  ')
        self.txt_low = self._make_text(low_f, fg=ORANGE)

        noauth_f = ttk.Frame(det_nb)
        det_nb.add(noauth_f, text='  No-Auth Response  ')
        self.txt_noauth = self._make_text(noauth_f, fg=RED)

        # AI Analysis tab
        ai_f = ttk.Frame(det_nb)
        det_nb.add(ai_f, text='  ✦ AI Analysis  ')
        self.txt_ai = self._make_text(ai_f, fg=ACCENT)
        ttk.Button(bot, text='✦ ANALYZE BYPASSED WITH AI', style='Ghost.TButton',
            command=self._ai_analyze_bypassed).pack(side='bottom', pady=4)

    # ── AI Analysis ────────────────────────────────────────────────────────────

    def _ai_analyze_bypassed(self):
        bypassed = [r for r in self._results if r['status'] == 'BYPASSED']
        self.txt_ai.delete('1.0', 'end')
        if not bypassed:
            self.txt_ai.insert('1.0', 'No BYPASSED results to analyze.\n')
            return
        analyzer = self.app.analyzer
        if not hasattr(analyzer, '_groq') or not analyzer._groq:
            self.txt_ai.insert('1.0', 'Groq not available.\n')
            return
        self.txt_ai.insert('1.0', f'Analyzing {len(bypassed)} bypassed results...\n')

        def _run():
            summary = '\n'.join(
                f"  {r['method']} {r['url'][:70]}  orig:{r['orig_code']} low:{r['low_code']}"
                for r in bypassed[:10]
            )
            prompt = (
                f"Access control bypass detected:\n{summary}\n\n"
                f"For each bypassed endpoint:\n"
                f"1. What privilege escalation / IDOR is possible?\n"
                f"2. Impact (data exposure, account takeover, etc.)\n"
                f"3. Remediation. Be concise."
            )
            try:
                result = analyzer._groq.ask(prompt, max_tokens=500)
                self.app.root.after(0, lambda r=result: [
                    self.txt_ai.delete('1.0', 'end'),
                    self.txt_ai.insert('1.0', f'Groq AI Analysis:\n\n{r}\n')
                ])
            except Exception as e:
                self.app.root.after(0, lambda: self.txt_ai.insert('end', f'Error: {e}\n'))

        import threading
        threading.Thread(target=_run, daemon=True).start()
        url     = req.get('url', '')
        method  = req.get('method', 'GET')
        body    = req.get('body', '')
        try:
            hdrs = json.loads(req.get('headers', '{}'))
        except Exception:
            hdrs = {}

        token       = self.entry_token.get().strip()
        hdr_name    = self.combo_header.get()
        strip_auth  = self.var_strip_auth.get()
        try:
            diff_thresh = int(self.entry_diff.get() or 50)
        except ValueError:
            diff_thresh = 50

        orig_code = req.get('status_code', 0)
        orig_len  = req.get('resp_length', 0)

        def _send(headers_override: dict) -> tuple:
            """Returns (status_code, body_len, resp_text)"""
            try:
                h = dict(hdrs)
                h.update(headers_override)
                # Remove proxy-specific headers
                for k in ['proxy-connection', 'proxy-authorization']:
                    h.pop(k, None)
                r = requests.request(
                    method, url,
                    headers=h,
                    data=body.encode() if body else None,
                    verify=False, timeout=10,
                    allow_redirects=False,
                )
                return r.status_code, len(r.content), r.text[:3000]
            except Exception as e:
                return 0, 0, f'Error: {e}'

        # Low-priv replay
        low_hdrs = {hdr_name: token} if token else {}
        low_code, low_len, low_body = _send(low_hdrs)

        # No-auth replay
        noauth_code, noauth_len, noauth_body = 0, 0, ''
        if strip_auth:
            no_hdrs = {k: v for k, v in hdrs.items()
                       if k.lower() not in ('cookie', 'authorization',
                                            'x-auth-token', 'x-api-key',
                                            'x-access-token')}
            noauth_code, noauth_len, noauth_body = _send(no_hdrs)

        # Classify result
        def _classify(test_code, test_len) -> str:
            if test_code == 0:
                return 'ERROR'
            if orig_code in (401, 403) and test_code in (401, 403):
                return 'ENFORCED'
            if test_code in (401, 403):
                return 'ENFORCED'
            if orig_code == test_code and abs(test_len - orig_len) <= diff_thresh:
                return 'BYPASSED'
            if abs(test_len - orig_len) > diff_thresh:
                return 'MODIFIED'
            return 'ENFORCED'

        low_status    = _classify(low_code, low_len)
        noauth_status = _classify(noauth_code, noauth_len) if strip_auth else 'N/A'

        # Overall: worst case
        overall = 'ENFORCED'
        for s in (low_status, noauth_status):
            if s == 'BYPASSED':
                overall = 'BYPASSED'
                break
            if s == 'MODIFIED' and overall != 'BYPASSED':
                overall = 'MODIFIED'

        diff = abs(low_len - orig_len)

        return {
            'url':         url,
            'method':      method,
            'status':      overall,
            'orig_code':   orig_code,
            'orig_len':    orig_len,
            'low_code':    low_code,
            'low_len':     low_len,
            'low_body':    low_body,
            'noauth_code': noauth_code,
            'noauth_len':  noauth_len,
            'noauth_body': noauth_body,
            'diff':        diff,
            'orig_body':   req.get('resp_body', '')[:3000],
        }

    def _add_result(self, r: dict):
        self._results.append(r)
        status = r['status']
        diff   = r['diff']
        self.tree.insert('', 'end',
            values=(
                status,
                r['method'],
                r['url'][:80],
                r['orig_code'],
                r['orig_len'],
                r['low_code']    or '-',
                r['low_len']     or '-',
                r['noauth_code'] or '-',
                r['noauth_len']  or '-',
                f'+{diff}' if diff > 0 else str(diff),
            ),
            tags=(status,))

    def _test_requests(self, reqs: list):
        self._running = True
        done = [0]
        total = len(reqs)

        def _run():
            for req in reqs:
                if not self._running:
                    break
                if self.var_scope_only.get():
                    if not self.db.check_scope(req.get('host', '')):
                        continue
                result = self._replay(req)
                done[0] += 1
                self.app.root.after(0, lambda r=result, d=done[0]: [
                    self._add_result(r),
                    self.lbl_status.config(
                        text=f'{d}/{total}  ·  {sum(1 for x in self._results if x["status"]=="BYPASSED")} bypassed',
                        fg=RED if any(x['status'] == 'BYPASSED' for x in self._results) else TEXT2)
                ])
            self._running = False
            bypassed = sum(1 for x in self._results if x['status'] == 'BYPASSED')
            self.app.root.after(0, lambda: self.lbl_status.config(
                text=f'Done  ·  {done[0]} tested  ·  {bypassed} BYPASSED',
                fg=RED if bypassed else GREEN))

        threading.Thread(target=_run, daemon=True).start()

    def _test_selected(self):
        sel = self.app.tree.selection()
        if not sel:
            messagebox.showwarning('Autorize', 'Select requests in Proxy tab first')
            return
        reqs = []
        for iid in sel:
            row_id = int(iid)
            req = self.db.get_request(row_id)
            if req:
                reqs.append(req)
        if not reqs:
            return
        self.lbl_status.config(text=f'Testing {len(reqs)} requests...', fg=YELLOW)
        self._test_requests(reqs)

    def _test_all(self):
        reqs = self.db.get_requests(500)
        if not reqs:
            messagebox.showwarning('Autorize', 'No requests in history')
            return
        self.lbl_status.config(text=f'Testing {len(reqs)} requests...', fg=YELLOW)
        self._test_requests(reqs)

    def on_new_request(self, req: dict):
        """Called automatically when a new request arrives (if auto-test enabled)."""
        if not self.var_auto.get() or not self._running is False:
            return
        if not self.entry_token.get().strip():
            return
        if self.var_scope_only.get() and not self.db.check_scope(req.get('host', '')):
            return

        def _bg():
            result = self._replay(req)
            self.app.root.after(0, lambda r=result: self._add_result(r))

        threading.Thread(target=_bg, daemon=True).start()

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx >= len(self._results):
            return
        r = self._results[idx]
        self.txt_orig.delete('1.0', 'end')
        self.txt_orig.insert('1.0',
            f"HTTP {r['orig_code']}  ·  {r['orig_len']} bytes\n\n{r.get('orig_body','')}")
        self.txt_low.delete('1.0', 'end')
        self.txt_low.insert('1.0',
            f"HTTP {r['low_code']}  ·  {r['low_len']} bytes\n\n{r.get('low_body','')}")
        self.txt_noauth.delete('1.0', 'end')
        self.txt_noauth.insert('1.0',
            f"HTTP {r['noauth_code']}  ·  {r['noauth_len']} bytes\n\n{r.get('noauth_body','')}")

    def _context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        idx = self.tree.index(item)
        if idx >= len(self._results):
            return
        r = self._results[idx]
        m = tk.Menu(self.app.root, tearoff=0,
            bg=BG3, fg=TEXT, activebackground=BG4,
            activeforeground=ACCENT, font=FONT_MONO_SM)
        m.add_command(label='  Copy URL',
            command=lambda: [self.app.root.clipboard_clear(),
                             self.app.root.clipboard_append(r['url'])])
        m.add_command(label='  Send to Repeater',
            command=lambda: self._send_to_repeater(r))
        m.add_command(label='  Send to Intruder',
            command=lambda: self._send_to_intruder(r))
        m.post(event.x_root, event.y_root)

    def _send_to_repeater(self, r: dict):
        self.app.rep_url.delete(0, 'end')
        self.app.rep_url.insert(0, r['url'])
        self.app.rep_method.set(r['method'])
        self.app.nb.select(0)

    def _send_to_intruder(self, r: dict):
        self.app.int_url.delete(0, 'end')
        self.app.int_url.insert(0, r['url'])
        self.app.nb.select(0)

    def _filter_bypassed(self):
        for iid in self.tree.get_children():
            idx = self.tree.index(iid)
            if idx < len(self._results) and self._results[idx]['status'] != 'BYPASSED':
                self.tree.detach(iid)

    def _show_all(self):
        self._clear()
        for r in self._results:
            self._add_result_direct(r)

    def _add_result_direct(self, r: dict):
        status = r['status']
        diff   = r['diff']
        self.tree.insert('', 'end',
            values=(
                status, r['method'], r['url'][:80],
                r['orig_code'], r['orig_len'],
                r['low_code'] or '-', r['low_len'] or '-',
                r['noauth_code'] or '-', r['noauth_len'] or '-',
                f'+{diff}' if diff > 0 else str(diff),
            ),
            tags=(status,))

    def _stop(self):
        self._running = False
        self.lbl_status.config(text='Stopped', fg=ORANGE)

    def _clear(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._results.clear()
        self.txt_orig.delete('1.0', 'end')
        self.txt_low.delete('1.0', 'end')
        self.txt_noauth.delete('1.0', 'end')
        self.lbl_status.config(text='')

    def _sort(self, col):
        items = [(self.tree.set(i, col), i) for i in self.tree.get_children()]
        try:
            items.sort(key=lambda x: int(x[0]) if str(x[0]).lstrip('+-').isdigit() else x[0])
        except Exception:
            items.sort()
        for idx, (_, iid) in enumerate(items):
            self.tree.move(iid, '', idx)

    def _export(self):
        from tkinter import filedialog
        if not self._results:
            messagebox.showwarning('Autorize', 'No results to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json')],
            initialfile=f'autorize_{int(time.time())}.json')
        if not path:
            return
        export = [{k: v for k, v in r.items() if k not in ('orig_body','low_body','noauth_body')}
                  for r in self._results]
        with open(path, 'w') as f:
            json.dump(export, f, indent=2)
        self.lbl_status.config(text=f'Exported {len(export)} results → {path}', fg=GREEN)

    def _make_text(self, parent, fg=None):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill='both', expand=True)
        t = tk.Text(f, bg=BG2, fg=fg or TEXT,
            insertbackground=ACCENT,
            selectbackground=ACCENT3, selectforeground=ACCENT,
            font=FONT_MONO_SM, relief='flat', borderwidth=0,
            wrap='none', padx=12, pady=10)
        vs = ttk.Scrollbar(f, orient='vertical',   command=t.yview)
        hs = ttk.Scrollbar(f, orient='horizontal', command=t.xview)
        t.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side='right',  fill='y')
        hs.pack(side='bottom', fill='x')
        t.pack(fill='both', expand=True)
        return t
