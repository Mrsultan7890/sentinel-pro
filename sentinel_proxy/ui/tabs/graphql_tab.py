# ============================================================================
# Sentinel Pro v3.1 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
GraphQL Tab
===========
GraphQL endpoint testing:
  - Introspection query
  - Schema visualizer
  - Query/Mutation fuzzing
  - Batching attack
  - Field suggestion attack
  - Common misconfig detection
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import urllib.request
import urllib.error
import logging

logger = logging.getLogger(__name__)

INTROSPECTION_QUERY = """
{
  __schema {
    queryType { name }
    mutationType { name }
    subscriptionType { name }
    types {
      name
      kind
      fields {
        name
        type { name kind ofType { name kind } }
        args { name type { name kind } }
      }
    }
  }
}
""".strip()

BATCH_ATTACK = '[{"query":"{__typename}"},{"query":"{__typename}"},{"query":"{__typename}"}]'

FIELD_SUGGESTIONS = [
    '{ user { id email password token secret } }',
    '{ users { id email role isAdmin } }',
    '{ me { id email password apiKey } }',
    '{ admin { id email password } }',
    '{ config { secretKey dbPassword } }',
    '{ __schema { types { name } } }',
]


class GraphQLTab:

    def __init__(self, notebook, app):
        self.app = app
        self.db  = app.db
        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='◈ GraphQL')
        self._build()

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, ACCENT, TEXT, TEXT2, TEXT3,
            GREEN, RED, ORANGE, YELLOW, CYAN, FONT_MONO, FONT_MONO_XS
        )
        self._C = dict(BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, ACCENT=ACCENT,
                       TEXT=TEXT, TEXT2=TEXT2, TEXT3=TEXT3, GREEN=GREEN,
                       RED=RED, ORANGE=ORANGE, YELLOW=YELLOW, CYAN=CYAN)

        # ── Toolbar ───────────────────────────────────────────────────────────
        tb = tk.Frame(self.frame, bg=BG3)
        tb.pack(fill='x')

        ttk.Button(tb, text='▶  SEND', style='Cyan.TButton',
            command=self._send).pack(side='left', padx=8, pady=6)
        ttk.Button(tb, text='INTROSPECT', style='Green.TButton',
            command=self._introspect).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='BATCH ATTACK', style='Red.TButton',
            command=self._batch_attack).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='FIELD FUZZ', style='Ghost.TButton',
            command=self._field_fuzz).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='FROM PROXY', style='Ghost.TButton',
            command=self._from_proxy).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=4, pady=6)

        self._status_lbl = tk.Label(tb, text='', bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=12)

        # ── Config row ────────────────────────────────────────────────────────
        cfg = tk.Frame(self.frame, bg=BG3)
        cfg.pack(fill='x', padx=10, pady=5)

        def lbl(t):
            tk.Label(cfg, text=t, bg=BG3, fg=TEXT2,
                font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 5))

        lbl('ENDPOINT')
        self._url_entry = ttk.Entry(cfg, width=45, font=FONT_MONO)
        self._url_entry.pack(side='left', padx=(0, 12))

        lbl('METHOD')
        self._method_var = ttk.Combobox(cfg, width=8, state='readonly',
            values=['POST', 'GET'])
        self._method_var.set('POST')
        self._method_var.pack(side='left', padx=(0, 12))

        lbl('HEADERS')
        self._headers_entry = ttk.Entry(cfg, width=30, font=FONT_MONO)
        self._headers_entry.insert(0, 'Content-Type: application/json')
        self._headers_entry.pack(side='left')

        # ── Main split ────────────────────────────────────────────────────────
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: query editor
        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=1)

        lh = tk.Frame(lf, bg=BG3)
        lh.pack(fill='x')
        tk.Frame(lh, bg=CYAN, width=3).pack(side='left', fill='y')
        tk.Label(lh, text='  QUERY EDITOR', bg=BG3, fg=CYAN,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        # Quick templates
        qb = tk.Frame(lf, bg=BG4)
        qb.pack(fill='x')
        tk.Label(qb, text='  Templates:', bg=BG4, fg=TEXT3,
            font=('Fira Code', 8)).pack(side='left', padx=(8, 4), pady=3)
        for name, query in [
            ('Introspect', INTROSPECTION_QUERY),
            ('__typename', '{ __typename }'),
            ('Batch', BATCH_ATTACK),
        ]:
            ttk.Button(qb, text=name, style='Ghost.TButton',
                command=lambda q=query: self._set_query(q)).pack(side='left', padx=2, pady=2)

        query_f = tk.Frame(lf, bg=BG)
        query_f.pack(fill='both', expand=True)
        self._query_txt = tk.Text(query_f, bg=BG2, fg=CYAN,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8, insertbackground=ACCENT)
        vs = ttk.Scrollbar(query_f, orient='vertical', command=self._query_txt.yview)
        self._query_txt.configure(yscrollcommand=vs.set)
        vs.pack(side='right', fill='y')
        self._query_txt.pack(fill='both', expand=True)
        self._query_txt.insert('1.0', '{ __typename }')

        # Right: response + schema
        rf = tk.Frame(pw, bg=BG)
        pw.add(rf, weight=2)

        rnb = ttk.Notebook(rf)
        rnb.pack(fill='both', expand=True)

        # Response tab
        resp_f = ttk.Frame(rnb)
        rnb.add(resp_f, text=' Response ')
        self._resp_txt = tk.Text(resp_f, bg=BG2, fg=GREEN,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8, state='disabled')
        vs2 = ttk.Scrollbar(resp_f, orient='vertical', command=self._resp_txt.yview)
        self._resp_txt.configure(yscrollcommand=vs2.set)
        vs2.pack(side='right', fill='y')
        self._resp_txt.pack(fill='both', expand=True)

        # Schema tab
        schema_f = ttk.Frame(rnb)
        rnb.add(schema_f, text=' Schema ')
        self._schema_txt = tk.Text(schema_f, bg=BG2, fg=TEXT2,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8, state='disabled')
        vs3 = ttk.Scrollbar(schema_f, orient='vertical', command=self._schema_txt.yview)
        self._schema_txt.configure(yscrollcommand=vs3.set)
        vs3.pack(side='right', fill='y')
        self._schema_txt.pack(fill='both', expand=True)

        # Findings tab
        findings_f = ttk.Frame(rnb)
        rnb.add(findings_f, text=' Findings ')
        cols = ('Severity', 'Issue')
        self._findings_tree = ttk.Treeview(findings_f, columns=cols, show='headings', height=12)
        for c, w in zip(cols, [80, 350]):
            self._findings_tree.heading(c, text=c)
            self._findings_tree.column(c, width=w)
        self._findings_tree.tag_configure('critical', foreground=RED)
        self._findings_tree.tag_configure('high',     foreground=ORANGE)
        self._findings_tree.tag_configure('medium',   foreground=YELLOW)
        vs4 = ttk.Scrollbar(findings_f, orient='vertical', command=self._findings_tree.yview)
        self._findings_tree.configure(yscrollcommand=vs4.set)
        vs4.pack(side='right', fill='y')
        self._findings_tree.pack(fill='both', expand=True)
        ttk.Button(findings_f, text='✦ AI ANALYZE FINDINGS', style='Ghost.TButton',
            command=self._ai_analyze_findings).pack(pady=4)

        # AI Analysis tab
        ai_f = ttk.Frame(rnb)
        rnb.add(ai_f, text=' ✦ AI ')
        self._ai_txt = tk.Text(ai_f, bg=BG2, fg=CYAN,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8, state='disabled')
        vs5 = ttk.Scrollbar(ai_f, orient='vertical', command=self._ai_txt.yview)
        self._ai_txt.configure(yscrollcommand=vs5.set)
        vs5.pack(side='right', fill='y')
        self._ai_txt.pack(fill='both', expand=True)

    # ── Core ──────────────────────────────────────────────────────────────────

    def _send(self):
        url   = self._url_entry.get().strip()
        query = self._query_txt.get('1.0', 'end').strip()
        if not url:
            messagebox.showwarning('GraphQL', 'Enter endpoint URL')
            return
        if not url.startswith('http'):
            url = 'https://' + url
        self._status_lbl.config(text='Sending...', fg=self._C['YELLOW'])
        threading.Thread(target=self._send_thread,
                         args=(url, query), daemon=True).start()

    def _send_thread(self, url, query):
        try:
            method = self._method_var.get()
            hdrs   = {'Content-Type': 'application/json', 'Accept': 'application/json'}

            for h in self._headers_entry.get().split(','):
                h = h.strip()
                if ':' in h:
                    k, _, v = h.partition(':')
                    hdrs[k.strip()] = v.strip()

            # Detect if query is already JSON (batch attack)
            try:
                body = json.loads(query)
                data = json.dumps(body).encode()
            except Exception:
                data = json.dumps({'query': query}).encode()

            req = urllib.request.Request(url, data=data, headers=hdrs, method=method)
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = resp.read().decode('utf-8', 'replace')

            try:
                pretty = json.dumps(json.loads(raw), indent=2)
            except Exception:
                pretty = raw

            findings = self._analyze_response(raw)
            self.app.root.after(0, lambda: self._write_resp(pretty))
            self.app.root.after(0, lambda: self._show_findings(findings))
            self.app.root.after(0, lambda: self._status_lbl.config(
                text=f'Done — {len(findings)} finding(s)',
                fg=self._C['RED'] if findings else self._C['GREEN']))

        except urllib.error.HTTPError as e:
            raw = e.read().decode('utf-8', 'replace')
            self.app.root.after(0, lambda: self._write_resp(f'HTTP {e.code}\n\n{raw}'))
            self.app.root.after(0, lambda: self._status_lbl.config(
                text=f'HTTP {e.code}', fg=self._C['ORANGE']))
        except Exception as e:
            self.app.root.after(0, lambda: self._write_resp(f'[ERROR] {e}'))
            self.app.root.after(0, lambda: self._status_lbl.config(
                text='Error', fg=self._C['RED']))

    def _introspect(self):
        self._set_query(INTROSPECTION_QUERY)
        url = self._url_entry.get().strip()
        if not url:
            messagebox.showwarning('GraphQL', 'Enter endpoint URL first')
            return
        self._status_lbl.config(text='Running introspection...', fg=self._C['YELLOW'])
        threading.Thread(target=self._introspect_thread, args=(url,), daemon=True).start()

    def _introspect_thread(self, url):
        if not url.startswith('http'):
            url = 'https://' + url
        try:
            data = json.dumps({'query': INTROSPECTION_QUERY}).encode()
            req  = urllib.request.Request(url, data=data,
                headers={'Content-Type': 'application/json'}, method='POST')
            with urllib.request.urlopen(req, timeout=15) as resp:
                raw = json.loads(resp.read())

            schema_out = self._parse_schema(raw)
            findings   = self._analyze_response(json.dumps(raw))
            findings.append(('HIGH', 'Introspection enabled — schema exposed'))

            self.app.root.after(0, lambda: self._write_resp(json.dumps(raw, indent=2)))
            self.app.root.after(0, lambda: self._write_schema(schema_out))
            self.app.root.after(0, lambda: self._show_findings(findings))
            self.app.root.after(0, lambda: self._status_lbl.config(
                text='Introspection done', fg=self._C['RED']))
        except Exception as e:
            self.app.root.after(0, lambda: self._write_resp(f'[ERROR] {e}'))
            self.app.root.after(0, lambda: self._status_lbl.config(
                text='Error', fg=self._C['RED']))

    def _batch_attack(self):
        self._set_query(BATCH_ATTACK)
        self._status_lbl.config(text='Batch query loaded — click SEND', fg=self._C['ORANGE'])

    def _field_fuzz(self):
        url = self._url_entry.get().strip()
        if not url:
            messagebox.showwarning('GraphQL', 'Enter endpoint URL first')
            return
        if not url.startswith('http'):
            url = 'https://' + url
        self._status_lbl.config(text='Field fuzzing...', fg=self._C['YELLOW'])
        threading.Thread(target=self._field_fuzz_thread, args=(url,), daemon=True).start()

    def _field_fuzz_thread(self, url):
        findings = []
        results  = []
        for query in FIELD_SUGGESTIONS:
            try:
                data = json.dumps({'query': query}).encode()
                req  = urllib.request.Request(url, data=data,
                    headers={'Content-Type': 'application/json'}, method='POST')
                with urllib.request.urlopen(req, timeout=10) as resp:
                    raw = resp.read().decode()
                parsed = json.loads(raw)
                errors = parsed.get('errors', [])
                data_r = parsed.get('data', {})

                if data_r and any(v for v in data_r.values() if v is not None):
                    findings.append(('CRITICAL', f'Data returned: {query[:60]}'))
                elif errors:
                    msg = errors[0].get('message', '')
                    if 'Did you mean' in msg or 'suggestion' in msg.lower():
                        findings.append(('MEDIUM', f'Field suggestion leak: {msg[:80]}'))
                results.append(f'Query: {query[:50]}\nResponse: {raw[:200]}\n\n')
            except Exception as e:
                results.append(f'Query: {query[:50]}\nError: {e}\n\n')

        out = ''.join(results)
        self.app.root.after(0, lambda: self._write_resp(out))
        self.app.root.after(0, lambda: self._show_findings(findings))
        self.app.root.after(0, lambda: self._status_lbl.config(
            text=f'Field fuzz done — {len(findings)} finding(s)',
            fg=self._C['RED'] if findings else self._C['GREEN']))

    def _analyze_response(self, raw: str) -> list:
        findings = []
        low = raw.lower()
        if '"errors"' in low:
            if 'stacktrace' in low or 'exception' in low or 'traceback' in low:
                findings.append(('HIGH', 'Stack trace / exception in error response'))
            if 'did you mean' in low:
                findings.append(('MEDIUM', 'Field suggestion in error — schema info leak'))
        if '"__schema"' in raw or '"__type"' in raw:
            findings.append(('HIGH', 'Introspection data in response'))
        if 'password' in low or 'secret' in low or 'token' in low:
            findings.append(('CRITICAL', 'Sensitive field name in response'))
        return findings

    def _parse_schema(self, data: dict) -> str:
        try:
            types = data['data']['__schema']['types']
            out   = '── GraphQL Schema ──\n\n'
            for t in types:
                if t['name'].startswith('__'):
                    continue
                kind   = t.get('kind', '')
                fields = t.get('fields') or []
                out   += f'{kind} {t["name"]}\n'
                for f in fields:
                    ft = f.get('type', {})
                    out += f'  {f["name"]}: {ft.get("name") or ft.get("ofType", {}).get("name", "?")}\n'
                out += '\n'
            return out
        except Exception:
            return 'Schema parse error — check Response tab'

    def _set_query(self, q: str):
        self._query_txt.delete('1.0', 'end')
        self._query_txt.insert('1.0', q)

    def _write_resp(self, text: str):
        self._resp_txt.config(state='normal')
        self._resp_txt.delete('1.0', 'end')
        self._resp_txt.insert('1.0', text)
        self._resp_txt.config(state='disabled')

    def _write_schema(self, text: str):
        self._schema_txt.config(state='normal')
        self._schema_txt.delete('1.0', 'end')
        self._schema_txt.insert('1.0', text)
        self._schema_txt.config(state='disabled')

    def _show_findings(self, findings: list):
        for row in self._findings_tree.get_children():
            self._findings_tree.delete(row)
        for sev, issue in findings:
            self._findings_tree.insert('', 'end', values=(sev, issue),
                tags=(sev.lower(),))

    def _ai_analyze_findings(self):
        findings = [(self._findings_tree.item(i, 'values')) for i in self._findings_tree.get_children()]
        self._ai_txt.config(state='normal')
        self._ai_txt.delete('1.0', 'end')
        if not findings:
            self._ai_txt.insert('1.0', 'No findings to analyze.\n')
            self._ai_txt.config(state='disabled')
            return
        analyzer = self.app.analyzer
        if not hasattr(analyzer, '_groq') or not analyzer._groq:
            self._ai_txt.insert('1.0', 'Groq not available.\n')
            self._ai_txt.config(state='disabled')
            return
        url = self._url_entry.get().strip()
        self._ai_txt.insert('1.0', 'Running Groq analysis...\n')
        self._ai_txt.config(state='disabled')

        def _run():
            import threading
            summary = '\n'.join(f"  [{f[0]}] {f[1]}" for f in findings)
            prompt = (
                f"GraphQL endpoint: {url}\n"
                f"Security findings:\n{summary}\n\n"
                f"For each finding:\n"
                f"1. Explain the real-world impact\n"
                f"2. How to exploit it\n"
                f"3. Remediation\nBe concise and technical."
            )
            try:
                result = analyzer._groq.ask(prompt, max_tokens=500)
                self.app.root.after(0, lambda r=result: [
                    self._ai_txt.config(state='normal'),
                    self._ai_txt.delete('1.0', 'end'),
                    self._ai_txt.insert('1.0', f'Groq AI Analysis:\n\n{r}\n'),
                    self._ai_txt.config(state='disabled')
                ])
            except Exception as e:
                self.app.root.after(0, lambda: [
                    self._ai_txt.config(state='normal'),
                    self._ai_txt.insert('end', f'Error: {e}\n'),
                    self._ai_txt.config(state='disabled')
                ])

        import threading
        threading.Thread(target=_run, daemon=True).start()

    def _from_proxy(self):
        req_id = getattr(self.app, 'selected_req', None)
        if not req_id:
            messagebox.showwarning('GraphQL', 'Select a request in Proxy tab first')
            return
        req = self.db.get_request(req_id)
        if req:
            self._url_entry.delete(0, 'end')
            self._url_entry.insert(0, req.get('url', ''))
            body = req.get('body', '')
            if body:
                try:
                    parsed = json.loads(body)
                    q = parsed.get('query', body)
                    self._set_query(q)
                except Exception:
                    self._set_query(body)

    def _clear(self):
        self._write_resp('')
        self._write_schema('')
        for row in self._findings_tree.get_children():
            self._findings_tree.delete(row)
        self._url_entry.delete(0, 'end')
        self._status_lbl.config(text='')
