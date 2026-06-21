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
WebSocket Tab — intercept and replay WS messages
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import time
from datetime import datetime


class WebSocketTab:
    """
    Tab 15: WebSocket traffic viewer + replayer.
    Shows all WS messages, allows replay/edit.
    """

    def __init__(self, notebook, app):
        self.app    = app
        self.db     = app.db
        self._msgs  = []   # all captured messages

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='⇆ WebSocket')
        self._build()

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW, CYAN, PURPLE,
            FONT_MONO, FONT_MONO_SM, FONT_MONO_XS, FONT_BOLD
        )
        self._colors = dict(
            BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, BORDER2=BORDER2,
            ACCENT=ACCENT, ACCENT3=ACCENT3, TEXT=TEXT, TEXT2=TEXT2,
            TEXT3=TEXT3, GREEN=GREEN, RED=RED, ORANGE=ORANGE,
            YELLOW=YELLOW, CYAN=CYAN, PURPLE=PURPLE,
        )
        C = self._colors

        # Toolbar
        tb = tk.Frame(self.frame, bg=C['BG3'])
        tb.pack(fill='x')

        tk.Label(tb, text='HOST FILTER', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(8,4), pady=6)
        self._host_var = tk.StringVar()
        ttk.Entry(tb, textvariable=self._host_var, width=22).pack(side='left', padx=(0,8), pady=6)

        ttk.Button(tb, text='FILTER', style='Ghost.TButton',
            command=self._apply_filter).pack(side='left', padx=2, pady=6)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=2, pady=6)
        ttk.Button(tb, text='EXPORT JSON', style='Ghost.TButton',
            command=self._export).pack(side='left', padx=2, pady=6)

        self._count_lbl = tk.Label(tb, text='0 messages',
            bg=C['BG3'], fg=C['TEXT2'], font=('Fira Code', 8))
        self._count_lbl.pack(side='right', padx=12)

        # Split
        pw = ttk.PanedWindow(self.frame, orient='vertical')
        pw.pack(fill='both', expand=True)

        # Top: message list
        top = tk.Frame(pw, bg=C['BG'])
        pw.add(top, weight=2)

        cols = ('id', 'ts', 'host', 'dir', 'length', 'preview')
        self.tree = ttk.Treeview(top, columns=cols, show='headings')
        for col, w, h in [
            ('id', 40, '#'), ('ts', 75, 'Time'), ('host', 180, 'Host'),
            ('dir', 110, 'Direction'), ('length', 65, 'Length'),
            ('preview', 400, 'Content Preview'),
        ]:
            self.tree.heading(col, text=h)
            self.tree.column(col, width=w,
                anchor='center' if col in ('id', 'ts', 'length') else 'w')

        self.tree.tag_configure('client', foreground=C['CYAN'])
        self.tree.tag_configure('server', foreground=C['GREEN'])
        self.tree.tag_configure('binary', foreground=C['ORANGE'])

        vsb = ttk.Scrollbar(top, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Button-3>', self._context_menu)

        # Bottom: detail + replay
        bot = tk.Frame(pw, bg=C['BG'])
        pw.add(bot, weight=1)

        # Detail notebook
        dn = ttk.Notebook(bot)
        dn.pack(fill='both', expand=True)

        # Raw content
        raw_f = ttk.Frame(dn)
        dn.add(raw_f, text='  Content  ')
        self._txt_content = self._make_text(raw_f, C)

        # Replay panel
        rep_f = ttk.Frame(dn)
        dn.add(rep_f, text='  Replay  ')

        rep_tb = tk.Frame(rep_f, bg=C['BG3'])
        rep_tb.pack(fill='x')
        tk.Label(rep_tb, text='HOST', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(8,4), pady=6)
        self._rep_host = ttk.Entry(rep_tb, width=30, font=FONT_MONO)
        self._rep_host.pack(side='left', padx=(0,8), pady=6)
        ttk.Button(rep_tb, text='▶ SEND', style='Cyan.TButton',
            command=self._replay_send).pack(side='left', padx=4, pady=6)
        self._rep_status = tk.Label(rep_tb, text='',
            bg=C['BG3'], fg=C['TEXT2'], font=('Fira Code', 8))
        self._rep_status.pack(side='right', padx=12)

        self._txt_replay = self._make_text(rep_f, C)

    def _make_text(self, parent, C):
        f = tk.Frame(parent, bg=C['BG'])
        f.pack(fill='both', expand=True)
        t = tk.Text(f, bg=C['BG2'], fg=C['TEXT'],
            insertbackground=C['ACCENT'],
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8)
        vs = ttk.Scrollbar(f, orient='vertical', command=t.yview)
        hs = ttk.Scrollbar(f, orient='horizontal', command=t.xview)
        t.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side='right', fill='y')
        hs.pack(side='bottom', fill='x')
        t.pack(fill='both', expand=True)
        return t

    def add_message(self, msg: dict):
        """Called from proxy thread via root.after."""
        self._msgs.append(msg)
        ts      = msg.get('timestamp', '')[:19][11:]
        tag     = 'client' if msg.get('from_client') else 'server'
        if msg.get('is_binary'):
            tag = 'binary'
        preview = msg.get('content', '')[:80].replace('\n', ' ')
        self.tree.insert('', 0, iid=str(msg['id']),
            values=(len(self._msgs), ts, msg.get('host', ''),
                    msg.get('direction', ''), msg.get('length', 0), preview),
            tags=(tag,))
        self._count_lbl.config(text=f'{len(self._msgs)} messages')

    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        iid = int(sel[0])
        msg = next((m for m in self._msgs if m['id'] == iid), None)
        if not msg:
            return
        self._txt_content.delete('1.0', 'end')
        out = (f"Direction : {msg.get('direction','')}\n"
               f"Host      : {msg.get('host','')}\n"
               f"URL       : {msg.get('url','')}\n"
               f"Length    : {msg.get('length',0)} bytes\n"
               f"Binary    : {msg.get('is_binary',False)}\n"
               f"Time      : {msg.get('timestamp','')}\n"
               f"{'='*50}\n\n"
               f"{msg.get('content','')}")
        self._txt_content.insert('1.0', out)
        # Pre-fill replay
        self._rep_host.delete(0, 'end')
        self._rep_host.insert(0, msg.get('host', ''))
        self._txt_replay.delete('1.0', 'end')
        self._txt_replay.insert('1.0', msg.get('content', ''))

    def _replay_send(self):
        host    = self._rep_host.get().strip()
        payload = self._txt_replay.get('1.0', 'end').strip()
        if not host or not payload:
            messagebox.showwarning('WebSocket Replay', 'Enter host and payload')
            return

        def _go():
            try:
                import websocket as ws_lib
                self.app.root.after(0, lambda: self._rep_status.config(
                    text='Connecting...', fg=self._colors['YELLOW']))
                ws = ws_lib.create_connection(f'ws://{host}', timeout=10)
                ws.send(payload)
                resp = ws.recv()
                ws.close()
                self.app.root.after(0, lambda: [
                    self._rep_status.config(text='Response received', fg=self._colors['GREEN']),
                    self._txt_content.delete('1.0', 'end'),
                    self._txt_content.insert('1.0', f'RESPONSE:\n{resp}'),
                ])
            except ImportError:
                self.app.root.after(0, lambda: self._rep_status.config(
                    text='pip install websocket-client', fg=self._colors['RED']))
            except Exception as e:
                self.app.root.after(0, lambda: self._rep_status.config(
                    text=str(e)[:60], fg=self._colors['RED']))

        threading.Thread(target=_go, daemon=True).start()

    def _apply_filter(self):
        host = self._host_var.get().strip()
        for i in self.tree.get_children():
            self.tree.delete(i)
        filtered = [m for m in self._msgs if not host or host in m.get('host', '')]
        for idx, msg in enumerate(filtered, 1):
            ts      = msg.get('timestamp', '')[:19][11:]
            tag     = 'client' if msg.get('from_client') else 'server'
            if msg.get('is_binary'):
                tag = 'binary'
            preview = msg.get('content', '')[:80].replace('\n', ' ')
            self.tree.insert('', 'end', iid=str(msg['id']),
                values=(idx, ts, msg.get('host', ''),
                        msg.get('direction', ''), msg.get('length', 0), preview),
                tags=(tag,))
        self._count_lbl.config(text=f'{len(filtered)} messages')

    def _clear(self):
        self._msgs.clear()
        for i in self.tree.get_children():
            self.tree.delete(i)
        self._txt_content.delete('1.0', 'end')
        self._count_lbl.config(text='0 messages')

    def _export(self):
        from tkinter import filedialog
        if not self._msgs:
            messagebox.showwarning('WebSocket', 'No messages to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json')],
            initialfile=f'ws_messages_{int(time.time())}.json')
        if not path:
            return
        with open(path, 'w') as f:
            json.dump(self._msgs, f, indent=2)
        self.app._set_status(f'Exported {len(self._msgs)} WS messages → {path}')

    def _context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        C = self._colors
        m = tk.Menu(self.app.root, tearoff=0,
            bg=C['BG3'], fg=C['TEXT'],
            activebackground=C['BG4'], activeforeground=C['ACCENT'],
            font=('Fira Code', 9))
        m.add_command(label='  Copy Content',
            command=lambda: self._copy_content(int(item)))
        m.add_command(label='  Send to Replay',
            command=lambda: self._on_select())
        m.post(event.x_root, event.y_root)

    def _copy_content(self, iid: int):
        msg = next((m for m in self._msgs if m['id'] == iid), None)
        if msg:
            self.app.root.clipboard_clear()
            self.app.root.clipboard_append(msg.get('content', ''))
