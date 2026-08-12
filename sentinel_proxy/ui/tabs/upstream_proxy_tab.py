# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
Upstream Proxy Tab — Chain traffic through Tor / SOCKS5 / HTTP proxy
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import socket

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


class UpstreamProxyTab:
    """
    Route all proxy traffic through an upstream proxy:
      - SOCKS5  (Tor, custom)
      - HTTP    (corporate, Burp chaining)
      - Tor     (one-click 127.0.0.1:9050)
    """

    def __init__(self, notebook: ttk.Notebook, app):
        self.app  = app
        self._enabled = False

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='🔗 Upstream')
        self._build(self.frame)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self, parent):
        # ── Header ───────────────────────────────────────────────────────────
        hdr = tk.Frame(parent, bg=BG3)
        hdr.pack(fill='x')
        tk.Frame(hdr, bg=ACCENT, width=3).pack(side='left', fill='y')
        tk.Label(hdr, text='  UPSTREAM PROXY CHAINING',
            bg=BG3, fg=ACCENT, font=('Fira Code', 9, 'bold')).pack(side='left', padx=8, pady=8)
        tk.Label(hdr,
            text='Route all traffic through Tor / SOCKS5 / HTTP proxy',
            bg=BG3, fg=TEXT3, font=FONT_MONO_XS).pack(side='left', padx=4)

        self.lbl_status = tk.Label(hdr, text='● DISABLED',
            bg=BG3, fg=RED, font=('Fira Code', 9, 'bold'))
        self.lbl_status.pack(side='right', padx=16)

        # ── Quick presets ─────────────────────────────────────────────────────
        pf = tk.Frame(parent, bg=BG4)
        pf.pack(fill='x', padx=0)
        tk.Label(pf, text='  QUICK PRESETS:', bg=BG4, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(8, 4), pady=8)

        presets = [
            ('🧅 Tor',             self._preset_tor),
            ('🏢 HTTP Proxy :8080', self._preset_http_8080),
            ('🔒 HTTP Proxy :8090', self._preset_http_8090),
            ('🌐 Custom SOCKS5',   self._preset_socks5),
        ]
        for label, cmd in presets:
            ttk.Button(pf, text=label, style='Ghost.TButton',
                command=cmd).pack(side='left', padx=4, pady=6)

        # ── Config form ───────────────────────────────────────────────────────
        cf = tk.Frame(parent, bg=BG2)
        cf.pack(fill='x', padx=16, pady=12)

        def row(label, widget_fn, row_n):
            tk.Label(cf, text=label, bg=BG2, fg=TEXT2,
                font=('Fira Code', 8, 'bold'), width=18,
                anchor='e').grid(row=row_n, column=0, padx=(0, 8), pady=6, sticky='e')
            w = widget_fn(cf)
            w.grid(row=row_n, column=1, padx=(0, 16), pady=6, sticky='w')
            return w

        # Proxy type
        self.combo_type = ttk.Combobox(cf, width=14, state='readonly',
            values=['socks5', 'http', 'tor'])
        self.combo_type.set('socks5')
        self.combo_type.bind('<<ComboboxSelected>>', self._on_type_change)
        row('PROXY TYPE', lambda p: self.combo_type, 0)

        # Host
        self.entry_host = ttk.Entry(cf, width=30, font=FONT_MONO)
        self.entry_host.insert(0, '127.0.0.1')
        row('HOST', lambda p: self.entry_host, 1)

        # Port
        self.entry_port = ttk.Entry(cf, width=8, font=FONT_MONO)
        self.entry_port.insert(0, '9050')
        row('PORT', lambda p: self.entry_port, 2)

        # Username (optional)
        self.entry_user = ttk.Entry(cf, width=22, font=FONT_MONO)
        row('USERNAME (opt)', lambda p: self.entry_user, 3)

        # Password (optional)
        self.entry_pass = ttk.Entry(cf, width=22, font=FONT_MONO, show='●')
        row('PASSWORD (opt)', lambda p: self.entry_pass, 4)

        # ── Action buttons ────────────────────────────────────────────────────
        ab = tk.Frame(parent, bg=BG3)
        ab.pack(fill='x', padx=0)

        self.btn_enable = ttk.Button(ab, text='▶  ENABLE UPSTREAM PROXY',
            style='Cyan.TButton', command=self._enable)
        self.btn_enable.pack(side='left', padx=8, pady=8)

        ttk.Button(ab, text='■  DISABLE', style='Red.TButton',
            command=self._disable).pack(side='left', padx=4, pady=8)

        ttk.Button(ab, text='⚡ TEST CONNECTION', style='Ghost.TButton',
            command=self._test).pack(side='left', padx=4, pady=8)

        self.lbl_test = tk.Label(ab, text='', bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.lbl_test.pack(side='left', padx=12)

        # ── Info panel ────────────────────────────────────────────────────────
        info = tk.Frame(parent, bg=BG)
        info.pack(fill='both', expand=True, padx=16, pady=8)

        tk.Frame(info, bg=BORDER2, height=1).pack(fill='x', pady=(0, 8))

        rows = [
            ('Tor',            'socks5', '127.0.0.1', '9050',  'Anonymous routing via Tor network — sudo apt install tor'),
            ('HTTP Proxy',     'http',   '127.0.0.1', '8080',  'Chain through any local HTTP proxy on port 8080'),
            ('HTTP Proxy',     'http',   '127.0.0.1', '8090',  'Chain through any local HTTP proxy on port 8090'),
            ('Corporate',      'http',   '<proxy>',   '<port>', 'Route through corporate HTTP proxy'),
            ('Custom SOCKS5',  'socks5', '<host>',    '<port>', 'Any SOCKS5 proxy with optional auth'),
        ]

        cols = ('Name', 'Type', 'Host', 'Port', 'Notes')
        tree = ttk.Treeview(info, columns=cols, show='headings', height=6)
        for col, w in zip(cols, [120, 70, 120, 60, 350]):
            tree.heading(col, text=col)
            tree.column(col, width=w, anchor='w')
        tree.tag_configure('tor',  foreground='#c77dff')
        tree.tag_configure('http', foreground=ACCENT)
        for name, ptype, host, port, note in rows:
            tree.insert('', 'end', values=(name, ptype, host, port, note),
                tags=(ptype,))
        tree.pack(fill='both', expand=True)
        tree.bind('<Double-1>', lambda e: self._load_from_table(tree))

        tk.Label(info, text='  Double-click a row to load preset',
            bg=BG, fg=TEXT3, font=FONT_MONO_XS, anchor='w').pack(fill='x', pady=4)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _enable(self):
        host = self.entry_host.get().strip()
        port_str = self.entry_port.get().strip()
        ptype = self.combo_type.get()

        if not host:
            messagebox.showwarning('Upstream Proxy', 'Enter proxy host')
            return
        try:
            port = int(port_str)
            if not 1 <= port <= 65535:
                raise ValueError
        except ValueError:
            messagebox.showwarning('Upstream Proxy', 'Enter valid port (1-65535)')
            return

        bridge = getattr(self.app, '_rust_bridge', None) or getattr(self.app, 'proxy', None)
        if bridge and hasattr(bridge, 'set_upstream_proxy'):
            bridge.set_upstream_proxy(
                enabled=True,
                proxy_type=ptype,
                host=host,
                port=port,
                username=self.entry_user.get().strip(),
                password=self.entry_pass.get().strip(),
            )

        self._enabled = True
        self.lbl_status.config(text=f'● ENABLED  [{ptype.upper()}  {host}:{port}]', fg=GREEN)
        self.lbl_test.config(text='')
        try:
            self.app._set_status(f'Upstream proxy: {ptype}://{host}:{port}')
        except Exception:
            pass

    def _disable(self):
        bridge = getattr(self.app, '_rust_bridge', None) or getattr(self.app, 'proxy', None)
        if bridge and hasattr(bridge, 'set_upstream_proxy'):
            bridge.set_upstream_proxy(enabled=False)
        self._enabled = False
        self.lbl_status.config(text='● DISABLED', fg=RED)
        self.lbl_test.config(text='')
        try:
            self.app._set_status('Upstream proxy disabled — direct connection')
        except Exception:
            pass

    def _test(self):
        host = self.entry_host.get().strip()
        port_str = self.entry_port.get().strip()
        if not host or not port_str:
            self.lbl_test.config(text='Enter host and port first', fg=YELLOW)
            return
        try:
            port = int(port_str)
        except ValueError:
            self.lbl_test.config(text='Invalid port', fg=RED)
            return

        self.lbl_test.config(text='Testing...', fg=YELLOW)

        def _run():
            try:
                s = socket.create_connection((host, port), timeout=5)
                s.close()
                self.app.root.after(0, lambda: self.lbl_test.config(
                    text=f'✓ Reachable  {host}:{port}', fg=GREEN))
            except Exception as e:
                self.app.root.after(0, lambda: self.lbl_test.config(
                    text=f'✗ Unreachable: {e}', fg=RED))

        threading.Thread(target=_run, daemon=True).start()

    # ── Presets ───────────────────────────────────────────────────────────────

    def _preset_tor(self):
        self.combo_type.set('socks5')
        self.entry_host.delete(0, 'end'); self.entry_host.insert(0, '127.0.0.1')
        self.entry_port.delete(0, 'end'); self.entry_port.insert(0, '9050')
        self.entry_user.delete(0, 'end')
        self.entry_pass.delete(0, 'end')

    def _preset_http_8080(self):
        self.combo_type.set('http')
        self.entry_host.delete(0, 'end'); self.entry_host.insert(0, '127.0.0.1')
        self.entry_port.delete(0, 'end'); self.entry_port.insert(0, '8080')
        self.entry_user.delete(0, 'end')
        self.entry_pass.delete(0, 'end')

    def _preset_http_8090(self):
        self.combo_type.set('http')
        self.entry_host.delete(0, 'end'); self.entry_host.insert(0, '127.0.0.1')
        self.entry_port.delete(0, 'end'); self.entry_port.insert(0, '8090')
        self.entry_user.delete(0, 'end')
        self.entry_pass.delete(0, 'end')

    def _preset_socks5(self):
        self.combo_type.set('socks5')
        self.entry_host.delete(0, 'end'); self.entry_host.insert(0, '')
        self.entry_port.delete(0, 'end'); self.entry_port.insert(0, '1080')
        self.entry_user.delete(0, 'end')
        self.entry_pass.delete(0, 'end')

    def _on_type_change(self, event=None):
        if self.combo_type.get() == 'tor':
            self._preset_tor()

    def _load_from_table(self, tree):
        sel = tree.selection()
        if not sel:
            return
        vals = tree.item(sel[0], 'values')
        if not vals or '<' in vals[2]:
            return
        _, ptype, host, port, _ = vals
        self.combo_type.set(ptype)
        self.entry_host.delete(0, 'end'); self.entry_host.insert(0, host)
        self.entry_port.delete(0, 'end'); self.entry_port.insert(0, port)
