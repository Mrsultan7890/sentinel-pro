# ============================================================================
# Sentinel Pro v3.1 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
TLS Inspector Tab
=================
Target ka TLS/SSL certificate inspect karo:
  - Certificate details (subject, issuer, SAN, validity)
  - Cipher suite + TLS version
  - Certificate chain
  - Expiry warning
  - Weak config detection
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import ssl
import socket
import json
import logging
from datetime import datetime, timezone

logger = logging.getLogger(__name__)


class TLSInspectorTab:

    def __init__(self, notebook, app):
        self.app = app
        self.db  = app.db
        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='⊟ TLS Inspector')
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

        ttk.Button(tb, text='▶  INSPECT', style='Cyan.TButton',
            command=self._inspect).pack(side='left', padx=8, pady=6)
        ttk.Button(tb, text='FROM PROXY', style='Ghost.TButton',
            command=self._from_proxy).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=4, pady=6)

        self._status_lbl = tk.Label(tb, text='', bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=12)

        # ── Config row ────────────────────────────────────────────────────────
        cfg = tk.Frame(self.frame, bg=BG3)
        cfg.pack(fill='x', padx=10, pady=6)

        def lbl(t):
            tk.Label(cfg, text=t, bg=BG3, fg=TEXT2,
                font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 5))

        lbl('HOST')
        self._host_entry = ttk.Entry(cfg, width=35, font=FONT_MONO)
        self._host_entry.pack(side='left', padx=(0, 12))
        self._host_entry.bind('<Return>', lambda e: self._inspect())

        lbl('PORT')
        self._port_entry = ttk.Entry(cfg, width=6, font=FONT_MONO)
        self._port_entry.insert(0, '443')
        self._port_entry.pack(side='left', padx=(0, 12))

        self._verify_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(cfg, text='Verify Cert', variable=self._verify_var).pack(side='left', padx=4)

        # ── Split pane ────────────────────────────────────────────────────────
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: cert details
        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=2)

        lh = tk.Frame(lf, bg=BG3)
        lh.pack(fill='x')
        tk.Frame(lh, bg=CYAN, width=3).pack(side='left', fill='y')
        tk.Label(lh, text='  CERTIFICATE DETAILS', bg=BG3, fg=CYAN,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        detail_f = tk.Frame(lf, bg=BG)
        detail_f.pack(fill='both', expand=True)
        self._detail_txt = tk.Text(detail_f, bg=BG2, fg=TEXT,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8, state='disabled')
        vs = ttk.Scrollbar(detail_f, orient='vertical', command=self._detail_txt.yview)
        hs = ttk.Scrollbar(detail_f, orient='horizontal', command=self._detail_txt.xview)
        self._detail_txt.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side='right', fill='y')
        hs.pack(side='bottom', fill='x')
        self._detail_txt.pack(fill='both', expand=True)

        # Right: findings
        rf = tk.Frame(pw, bg=BG)
        pw.add(rf, weight=1)

        rh = tk.Frame(rf, bg=BG3)
        rh.pack(fill='x')
        tk.Frame(rh, bg=ORANGE, width=3).pack(side='left', fill='y')
        tk.Label(rh, text='  SECURITY FINDINGS', bg=BG3, fg=ORANGE,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        cols = ('Severity', 'Issue')
        self._tree = ttk.Treeview(rf, columns=cols, show='headings', height=20)
        for c, w in zip(cols, [80, 280]):
            self._tree.heading(c, text=c)
            self._tree.column(c, width=w, minwidth=50)
        self._tree.tag_configure('critical', foreground=RED)
        self._tree.tag_configure('high',     foreground=ORANGE)
        self._tree.tag_configure('medium',   foreground=YELLOW)
        self._tree.tag_configure('low',      foreground=GREEN)

        vs2 = ttk.Scrollbar(rf, orient='vertical', command=self._tree.yview)
        self._tree.configure(yscrollcommand=vs2.set)
        vs2.pack(side='right', fill='y')
        self._tree.pack(fill='both', expand=True)

    # ── Core ──────────────────────────────────────────────────────────────────

    def _inspect(self):
        host = self._host_entry.get().strip()
        host = host.replace('https://', '').replace('http://', '').split('/')[0]
        if not host:
            messagebox.showwarning('TLS Inspector', 'Enter a host')
            return
        try:
            port = int(self._port_entry.get().strip())
        except ValueError:
            port = 443

        self._status_lbl.config(text='Inspecting...', fg=self._C['YELLOW'])
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._write('')

        threading.Thread(target=self._inspect_thread,
                         args=(host, port), daemon=True).start()

    def _inspect_thread(self, host, port):
        try:
            ctx = ssl.create_default_context()
            if not self._verify_var.get():
                ctx.check_hostname = False
                ctx.verify_mode    = ssl.CERT_NONE

            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert        = ssock.getpeercert()
                    cipher      = ssock.cipher()
                    tls_version = ssock.version()
                    der_cert    = ssock.getpeercert(binary_form=True)

            output, findings = self._analyze(host, cert, cipher, tls_version, der_cert)
            self.app.root.after(0, lambda: self._write(output))
            self.app.root.after(0, lambda: self._show_findings(findings))
            self.app.root.after(0, lambda: self._status_lbl.config(
                text=f'{len(findings)} issue(s) found',
                fg=self._C['RED'] if findings else self._C['GREEN']))

        except ssl.SSLError as e:
            err = f'[SSL ERROR] {e}\n'
            self.app.root.after(0, lambda: self._write(err))
            self.app.root.after(0, lambda: self._status_lbl.config(
                text='SSL Error', fg=self._C['RED']))
        except Exception as e:
            err = f'[ERROR] {e}\n'
            self.app.root.after(0, lambda: self._write(err))
            self.app.root.after(0, lambda: self._status_lbl.config(
                text='Error', fg=self._C['RED']))

    def _analyze(self, host, cert, cipher, tls_version, der_cert):
        findings = []
        out = f'{"="*50}\n  TLS INSPECTION — {host}\n{"="*50}\n\n'

        # TLS version
        out += f'TLS Version  : {tls_version}\n'
        out += f'Cipher Suite : {cipher[0] if cipher else "Unknown"}\n'
        out += f'Key Bits     : {cipher[2] if cipher and len(cipher) > 2 else "?"}\n\n'

        if tls_version in ('SSLv2', 'SSLv3', 'TLSv1', 'TLSv1.1'):
            findings.append(('CRITICAL', f'Outdated protocol: {tls_version}'))
        elif tls_version == 'TLSv1.2':
            findings.append(('MEDIUM', 'TLSv1.2 in use — TLSv1.3 preferred'))

        if cipher:
            c = cipher[0].upper()
            if 'RC4' in c or 'DES' in c or 'NULL' in c or 'EXPORT' in c:
                findings.append(('CRITICAL', f'Weak cipher: {cipher[0]}'))
            if 'MD5' in c:
                findings.append(('HIGH', f'MD5 in cipher suite: {cipher[0]}'))
            if cipher[2] and cipher[2] < 128:
                findings.append(('HIGH', f'Short key length: {cipher[2]} bits'))

        # Subject
        subject = dict(x[0] for x in cert.get('subject', []))
        issuer  = dict(x[0] for x in cert.get('issuer', []))
        out += '── Subject ──\n'
        for k, v in subject.items():
            out += f'  {k:<20}: {v}\n'
        out += '\n── Issuer ──\n'
        for k, v in issuer.items():
            out += f'  {k:<20}: {v}\n'
        out += '\n'

        # Self-signed check
        if subject == issuer:
            findings.append(('HIGH', 'Self-signed certificate'))

        # SAN
        san = cert.get('subjectAltName', [])
        if san:
            out += '── Subject Alt Names ──\n'
            for typ, val in san:
                out += f'  {typ}: {val}\n'
            out += '\n'

        # Validity
        not_before_str = cert.get('notBefore', '')
        not_after_str  = cert.get('notAfter', '')
        out += '── Validity ──\n'
        out += f'  Not Before : {not_before_str}\n'
        out += f'  Not After  : {not_after_str}\n'

        try:
            fmt = '%b %d %H:%M:%S %Y %Z'
            not_after  = datetime.strptime(not_after_str, fmt).replace(tzinfo=timezone.utc)
            not_before = datetime.strptime(not_before_str, fmt).replace(tzinfo=timezone.utc)
            now        = datetime.now(timezone.utc)
            days_left  = (not_after - now).days

            out += f'  Days Left  : {days_left}\n\n'

            if days_left < 0:
                findings.append(('CRITICAL', f'Certificate EXPIRED {abs(days_left)} days ago'))
            elif days_left < 14:
                findings.append(('CRITICAL', f'Certificate expires in {days_left} days'))
            elif days_left < 30:
                findings.append(('HIGH', f'Certificate expires in {days_left} days'))
            elif days_left < 90:
                findings.append(('MEDIUM', f'Certificate expires in {days_left} days'))

            validity_days = (not_after - not_before).days
            if validity_days > 398:
                findings.append(('LOW', f'Certificate validity > 398 days ({validity_days}d) — browsers may reject'))
        except Exception:
            out += '\n'

        # Serial + fingerprint
        serial = cert.get('serialNumber', 'N/A')
        out += f'── Other ──\n'
        out += f'  Serial     : {serial}\n'

        if der_cert:
            import hashlib
            fp_sha256 = hashlib.sha256(der_cert).hexdigest()
            fp_fmt    = ':'.join(fp_sha256[i:i+2].upper() for i in range(0, len(fp_sha256), 2))
            out += f'  SHA-256    : {fp_fmt[:47]}...\n'

        # Host match check
        if san:
            san_values = [v for _, v in san]
            matched = any(
                host == v or (v.startswith('*.') and host.endswith(v[1:]))
                for v in san_values
            )
            if not matched:
                findings.append(('HIGH', f'Hostname mismatch: {host} not in SAN'))

        if not findings:
            out += '\n✓ No security issues detected\n'

        return out, findings

    def _show_findings(self, findings):
        for sev, issue in findings:
            tag = sev.lower()
            self._tree.insert('', 'end', values=(sev, issue), tags=(tag,))
        if findings:
            self._ai_analyze_findings(findings)

    def _ai_analyze_findings(self, findings: list):
        analyzer = self.app.analyzer
        if not hasattr(analyzer, '_groq') or not analyzer._groq:
            return
        host = self._host_entry.get().strip()

        def _run():
            summary = '\n'.join(f"  [{s}] {i}" for s, i in findings)
            prompt = (
                f"TLS/SSL inspection findings for {host}:\n{summary}\n\n"
                f"For each finding:\n"
                f"1. Real-world attack scenario\n"
                f"2. Remediation command/config\nBe concise."
            )
            try:
                result = analyzer._groq.ask(prompt, max_tokens=400)
                self.app.root.after(0, lambda r=result: [
                    self._detail_txt.config(state='normal'),
                    self._detail_txt.insert('end',
                        f'\n{"─"*50}\n  Groq AI Analysis\n{"─"*50}\n{r}\n'),
                    self._detail_txt.config(state='disabled')
                ])
            except Exception:
                pass

        import threading
        threading.Thread(target=_run, daemon=True).start()

    def _write(self, text):
        self._detail_txt.config(state='normal')
        self._detail_txt.delete('1.0', 'end')
        self._detail_txt.insert('1.0', text)
        self._detail_txt.config(state='disabled')

    def _from_proxy(self):
        req_id = getattr(self.app, 'selected_req', None)
        if not req_id:
            messagebox.showwarning('TLS Inspector', 'Select a request in Proxy tab first')
            return
        req = self.db.get_request(req_id)
        if req:
            host = req.get('host', '')
            self._host_entry.delete(0, 'end')
            self._host_entry.insert(0, host)
            self._inspect()

    def _clear(self):
        self._write('')
        for row in self._tree.get_children():
            self._tree.delete(row)
        self._status_lbl.config(text='')
        self._host_entry.delete(0, 'end')
