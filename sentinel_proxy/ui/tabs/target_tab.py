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
Target Tab — Site map tree like Burp Suite Target
==================================================
Shows all discovered hosts, paths, endpoints.
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import threading
from urllib.parse import urlparse


class TargetTab:
    """
    Tab: Target Site Map.
    Left: host/path tree. Right: request detail.
    """

    def __init__(self, notebook, app):
        self.app   = app
        self.db    = app.db
        self._tree_data = {}   # host -> set of paths

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='  ◎ Target  ')
        self._build()

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW,
            FONT_MONO, FONT_MONO_SM, FONT_MONO_XS
        )
        C = dict(BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, BORDER2=BORDER2,
                 ACCENT=ACCENT, ACCENT3=ACCENT3, TEXT=TEXT, TEXT2=TEXT2,
                 TEXT3=TEXT3, GREEN=GREEN, RED=RED, ORANGE=ORANGE, YELLOW=YELLOW)
        self._C = C

        # Toolbar
        tb = tk.Frame(self.frame, bg=C['BG3'])
        tb.pack(fill='x')
        ttk.Button(tb, text='↺ REFRESH', style='Ghost.TButton',
            command=self.refresh).pack(side='left', padx=6, pady=6)
        ttk.Button(tb, text='EXPAND ALL', style='Ghost.TButton',
            command=self._expand_all).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='COLLAPSE ALL', style='Ghost.TButton',
            command=self._collapse_all).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='→ SCOPE', style='Ghost.TButton',
            command=self._add_to_scope).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='→ SCANNER', style='Ghost.TButton',
            command=self._send_to_scanner).pack(side='left', padx=4, pady=6)

        self._stats_lbl = tk.Label(tb, text='',
            bg=C['BG3'], fg=C['TEXT2'], font=FONT_MONO_XS)
        self._stats_lbl.pack(side='right', padx=12)

        # Main split
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: site map tree
        lf = tk.Frame(pw, bg=C['BG'])
        pw.add(lf, weight=1)

        lh = tk.Frame(lf, bg=C['BG3'], height=26)
        lh.pack(fill='x')
        lh.pack_propagate(False)
        tk.Frame(lh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(lh, text='  SITE MAP', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=4)

        self.site_tree = ttk.Treeview(lf, show='tree headings',
            columns=('requests', 'issues'), selectmode='browse')
        self.site_tree.heading('#0', text='Host / Path')
        self.site_tree.heading('requests', text='Reqs')
        self.site_tree.heading('issues', text='Issues')
        self.site_tree.column('#0', width=280)
        self.site_tree.column('requests', width=50, anchor='center')
        self.site_tree.column('issues', width=60, anchor='center')

        self.site_tree.tag_configure('host',     foreground=C['ACCENT'])
        self.site_tree.tag_configure('path',     foreground=C['TEXT'])
        self.site_tree.tag_configure('risky',    foreground=C['ORANGE'])
        self.site_tree.tag_configure('critical', foreground=C['RED'])

        vsb = ttk.Scrollbar(lf, orient='vertical', command=self.site_tree.yview)
        self.site_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.site_tree.pack(fill='both', expand=True)
        self.site_tree.bind('<<TreeviewSelect>>', self._on_select)
        self.site_tree.bind('<Button-3>', self._context_menu)

        # Right: request list for selected path
        rf = tk.Frame(pw, bg=C['BG'])
        pw.add(rf, weight=2)

        rh = tk.Frame(rf, bg=C['BG3'], height=26)
        rh.pack(fill='x')
        rh.pack_propagate(False)
        tk.Frame(rh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(rh, text='  REQUESTS', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=4)

        cols = ('id', 'method', 'status', 'length', 'risk', 'time')
        self.req_tree = ttk.Treeview(rf, columns=cols, show='headings', height=10)
        for col, w, h in [
            ('id', 40, '#'), ('method', 65, 'Method'), ('status', 55, 'Status'),
            ('length', 70, 'Length'), ('risk', 75, 'Risk'), ('time', 65, 'Time'),
        ]:
            self.req_tree.heading(col, text=h)
            self.req_tree.column(col, width=w, anchor='center')

        from sentinel_proxy.ui.app import SEV_COLOR
        for sev, color in SEV_COLOR.items():
            self.req_tree.tag_configure(sev, foreground=color)

        vsb2 = ttk.Scrollbar(rf, orient='vertical', command=self.req_tree.yview)
        self.req_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side='right', fill='y')
        self.req_tree.pack(fill='both', expand=True)
        self.req_tree.bind('<<TreeviewSelect>>', self._on_req_select)
        self.req_tree.bind('<Double-1>', self._send_req_to_repeater)

        # Detail
        dh = tk.Frame(rf, bg=C['BG3'], height=26)
        dh.pack(fill='x')
        dh.pack_propagate(False)
        tk.Frame(dh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(dh, text='  REQUEST DETAIL', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=4)

        detail_f = tk.Frame(rf, bg=C['BG'])
        detail_f.pack(fill='both', expand=True)
        self._txt_detail = tk.Text(detail_f, bg=C['BG2'], fg=C['TEXT'],
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='none', padx=10, pady=8)
        vs = ttk.Scrollbar(detail_f, orient='vertical', command=self._txt_detail.yview)
        hs = ttk.Scrollbar(detail_f, orient='horizontal', command=self._txt_detail.xview)
        self._txt_detail.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side='right', fill='y')
        hs.pack(side='bottom', fill='x')
        self._txt_detail.pack(fill='both', expand=True)

        self._selected_host = ''
        self._selected_path = ''

    def refresh(self):
        """Rebuild site map from DB."""
        def _run():
            rows = self.db.get_requests(5000)
            # Build tree: host -> path -> [requests]
            tree = {}
            for r in rows:
                host = r.get('host', 'unknown')
                path = r.get('path', '/').split('?')[0] or '/'
                if host not in tree:
                    tree[host] = {}
                if path not in tree[host]:
                    tree[host][path] = []
                tree[host][path].append(r)
            self.app.root.after(0, lambda: self._populate(tree, rows))

        threading.Thread(target=_run, daemon=True).start()

    def _populate(self, tree: dict, all_rows: list):
        for i in self.site_tree.get_children():
            self.site_tree.delete(i)

        total_hosts = len(tree)
        total_paths = sum(len(paths) for paths in tree.values())

        for host, paths in sorted(tree.items()):
            host_reqs   = sum(len(reqs) for reqs in paths.values())
            host_issues = sum(
                1 for reqs in paths.values()
                for r in reqs if r.get('ai_risk') in ('HIGH', 'CRITICAL')
            )
            tag = 'critical' if host_issues > 0 else 'host'
            host_iid = self.site_tree.insert('', 'end',
                text=f'  {host}',
                values=(host_reqs, host_issues or ''),
                tags=(tag,), open=False)

            for path, reqs in sorted(paths.items()):
                path_issues = sum(1 for r in reqs if r.get('ai_risk') in ('HIGH', 'CRITICAL'))
                ptag = 'risky' if path_issues > 0 else 'path'
                self.site_tree.insert(host_iid, 'end',
                    text=f'  {path}',
                    values=(len(reqs), path_issues or ''),
                    tags=(ptag,),
                    iid=f'{host}||{path}')

        self._tree_data = tree
        self._stats_lbl.config(
            text=f'{total_hosts} hosts  ·  {total_paths} paths  ·  {len(all_rows)} requests')

    def _on_select(self, event=None):
        sel = self.site_tree.selection()
        if not sel:
            return
        iid = sel[0]
        if '||' in iid:
            host, path = iid.split('||', 1)
            self._selected_host = host
            self._selected_path = path
            reqs = self._tree_data.get(host, {}).get(path, [])
            self._populate_req_tree(reqs)
        else:
            # Host node selected — show all requests for host
            host = self.site_tree.item(iid, 'text').strip()
            self._selected_host = host
            self._selected_path = ''
            all_reqs = []
            for reqs in self._tree_data.get(host, {}).values():
                all_reqs.extend(reqs)
            self._populate_req_tree(all_reqs)

    def _populate_req_tree(self, reqs: list):
        for i in self.req_tree.get_children():
            self.req_tree.delete(i)
        for r in reqs:
            risk = r.get('ai_risk', 'UNKNOWN')
            ts   = r.get('timestamp', '')[:19][11:]
            self.req_tree.insert('', 'end', iid=str(r['id']),
                values=(r['id'], r.get('method', ''), r.get('status_code', ''),
                        r.get('resp_length', ''), risk, ts),
                tags=(risk,))

    def _on_req_select(self, event=None):
        sel = self.req_tree.selection()
        if not sel:
            return
        row_id = int(sel[0])
        req    = self.db.get_request(row_id)
        if not req:
            return
        try:
            hdrs = json.loads(req.get('headers', '{}'))
        except Exception:
            hdrs = {}
        out = (f"{'='*50}\n"
               f"ID     : {req['id']}\n"
               f"Method : {req.get('method','')}\n"
               f"URL    : {req.get('url','')}\n"
               f"Status : {req.get('status_code','')}\n"
               f"Risk   : {req.get('ai_risk','')}\n"
               f"{'='*50}\n\nHEADERS:\n")
        for k, v in hdrs.items():
            out += f"  {k}: {v}\n"
        if req.get('body'):
            out += f"\nBODY:\n{req['body'][:1000]}\n"
        if req.get('ai_summary'):
            out += f"\nAI SUMMARY:\n{req['ai_summary']}\n"
        self._txt_detail.delete('1.0', 'end')
        self._txt_detail.insert('1.0', out)

    def _send_req_to_repeater(self, event=None):
        sel = self.req_tree.selection()
        if not sel:
            return
        self.app.selected_req = int(sel[0])
        self.app._send_to_repeater()

    def _expand_all(self):
        for iid in self.site_tree.get_children():
            self.site_tree.item(iid, open=True)

    def _collapse_all(self):
        for iid in self.site_tree.get_children():
            self.site_tree.item(iid, open=False)

    def _add_to_scope(self):
        if self._selected_host:
            self.app.scope_pattern.delete(0, 'end')
            self.app.scope_pattern.insert(0, self._selected_host)
            self.app.scope_type.set('include')
            self.app._scope_add()

    def _send_to_scanner(self):
        if self._selected_host:
            url = f'http://{self._selected_host}{self._selected_path or "/"}'
            self.app.scan_url.delete(0, 'end')
            self.app.scan_url.insert(0, url)
            # Switch to scanner tab
            for i in range(self.app.nb.index('end')):
                if 'Scanner' in self.app.nb.tab(i, 'text') and 'Active' not in self.app.nb.tab(i, 'text'):
                    self.app.nb.select(i)
                    break

    def _context_menu(self, event):
        item = self.site_tree.identify_row(event.y)
        if not item:
            return
        self.site_tree.selection_set(item)
        C = self._C
        m = tk.Menu(self.app.root, tearoff=0,
            bg=C['BG3'], fg=C['TEXT'],
            activebackground=C['BG4'], activeforeground=C['ACCENT'],
            font=('Fira Code', 9))
        m.add_command(label='  Add to Scope',    command=self._add_to_scope)
        m.add_command(label='  Send to Scanner', command=self._send_to_scanner)
        m.add_command(label='  Expand All',      command=self._expand_all)
        m.post(event.x_root, event.y_root)

    def on_new_request(self, flow: dict, row_id: int):
        """Called when proxy captures a new request — live update."""
        host = flow.get('host', '')
        path = flow.get('path', '/').split('?')[0] or '/'
        if host not in self._tree_data:
            self._tree_data[host] = {}
        if path not in self._tree_data[host]:
            self._tree_data[host][path] = []
        # We don't have full row yet, just track count
        self._tree_data[host][path].append({'id': row_id, **flow})
        # Update tree node if exists
        iid = f'{host}||{path}'
        try:
            if self.site_tree.exists(iid):
                count = len(self._tree_data[host][path])
                vals  = list(self.site_tree.item(iid, 'values'))
                vals[0] = count
                self.site_tree.item(iid, values=tuple(vals))
            else:
                # Add host node if missing
                if not self.site_tree.exists(host):
                    self.site_tree.insert('', 'end', iid=host,
                        text=f'  {host}', values=(1, ''), tags=('host',))
                self.site_tree.insert(host, 'end', iid=iid,
                    text=f'  {path}', values=(1, ''), tags=('path',))
        except Exception:
            pass
