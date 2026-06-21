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
Organizer Tab — manually save and annotate requests
====================================================
Like Burp Suite Organizer: save interesting requests,
add notes, tags, group by investigation.
"""

import tkinter as tk
from tkinter import ttk, messagebox, simpledialog
import json
import time
from datetime import datetime


class OrganizerTab:
    """
    Tab: Organizer.
    Save requests with notes/tags for manual investigation.
    """

    def __init__(self, notebook, app):
        self.app = app
        self.db  = app.db

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='⊞ Organizer')
        self._build()
        self._load()

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW, PURPLE,
            FONT_MONO, FONT_MONO_SM, FONT_MONO_XS, SEV_COLOR
        )
        C = dict(BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, BORDER2=BORDER2,
                 ACCENT=ACCENT, ACCENT3=ACCENT3, TEXT=TEXT, TEXT2=TEXT2,
                 TEXT3=TEXT3, GREEN=GREEN, RED=RED, ORANGE=ORANGE,
                 YELLOW=YELLOW, PURPLE=PURPLE)
        self._C = C

        # Toolbar
        tb = tk.Frame(self.frame, bg=C['BG3'])
        tb.pack(fill='x')

        ttk.Button(tb, text='↺ REFRESH', style='Ghost.TButton',
            command=self._load).pack(side='left', padx=6, pady=6)
        ttk.Button(tb, text='ADD NOTE', style='Cyan.TButton',
            command=self._add_note).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='ADD TAG', style='Ghost.TButton',
            command=self._add_tag).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='DELETE', style='Red.TButton',
            command=self._delete_selected).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='EXPORT', style='Ghost.TButton',
            command=self._export).pack(side='left', padx=4, pady=6)

        tk.Frame(tb, bg=C['BORDER2'], width=1).pack(side='left', fill='y', padx=8)

        tk.Label(tb, text='FILTER TAG', bg=C['BG3'], fg=C['TEXT2'],
            font=FONT_MONO_XS).pack(side='left', padx=(0,4))
        self._tag_filter = tk.StringVar()
        ttk.Entry(tb, textvariable=self._tag_filter, width=14).pack(side='left', padx=(0,4))
        ttk.Button(tb, text='GO', style='Ghost.TButton',
            command=self._filter_by_tag).pack(side='left', padx=2)

        self._count_lbl = tk.Label(tb, text='',
            bg=C['BG3'], fg=C['TEXT2'], font=FONT_MONO_XS)
        self._count_lbl.pack(side='right', padx=12)

        # Split
        pw = ttk.PanedWindow(self.frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: saved requests list
        lf = tk.Frame(pw, bg=C['BG'])
        pw.add(lf, weight=2)

        cols = ('id', 'method', 'host', 'path', 'risk', 'tags', 'note', 'saved')
        self.tree = ttk.Treeview(lf, columns=cols, show='headings')
        for col, w, h in [
            ('id', 40, '#'), ('method', 65, 'Method'), ('host', 160, 'Host'),
            ('path', 200, 'Path'), ('risk', 75, 'Risk'),
            ('tags', 120, 'Tags'), ('note', 200, 'Note'), ('saved', 70, 'Saved'),
        ]:
            self.tree.heading(col, text=h)
            self.tree.column(col, width=w,
                anchor='center' if col in ('id', 'method', 'risk', 'saved') else 'w')

        for sev, color in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)

        vsb = ttk.Scrollbar(lf, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Button-3>', self._context_menu)
        self.tree.bind('<Double-1>', self._edit_note)

        # Right: detail
        rf = tk.Frame(pw, bg=C['BG'])
        pw.add(rf, weight=1)

        # Note editor
        nh = tk.Frame(rf, bg=C['BG3'], height=26)
        nh.pack(fill='x')
        nh.pack_propagate(False)
        tk.Frame(nh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(nh, text='  NOTES', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=4)
        ttk.Button(nh, text='SAVE', style='Cyan.TButton',
            command=self._save_note).pack(side='right', padx=4, pady=2)

        self._note_txt = tk.Text(rf, bg=C['BG2'], fg=C['TEXT'],
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8, height=8)
        self._note_txt.pack(fill='x')

        # Request detail
        dh = tk.Frame(rf, bg=C['BG3'], height=26)
        dh.pack(fill='x')
        dh.pack_propagate(False)
        tk.Frame(dh, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(dh, text='  REQUEST', bg=C['BG3'], fg=C['TEXT2'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=4)
        ttk.Button(dh, text='→ Repeater', style='Ghost.TButton',
            command=self._to_repeater).pack(side='right', padx=4, pady=2)

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

        self._selected_id = None

    def _load(self, rows=None):
        if rows is None:
            rows = self.db.get_organizer_items()
        for i in self.tree.get_children():
            self.tree.delete(i)
        for r in rows:
            risk = r.get('ai_risk', 'UNKNOWN')
            ts   = r.get('saved_at', '')[:10]
            self.tree.insert('', 'end', iid=str(r['id']),
                values=(r['id'], r.get('method', ''), r.get('host', '')[:30],
                        r.get('path', '')[:50], risk,
                        r.get('tags', ''), r.get('note', '')[:60], ts),
                tags=(risk,))
        self._count_lbl.config(text=f'{len(rows)} saved')

    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        self._selected_id = int(sel[0])
        item = self.db.get_organizer_item(self._selected_id)
        if not item:
            return
        # Show note
        self._note_txt.delete('1.0', 'end')
        self._note_txt.insert('1.0', item.get('note', ''))
        # Show request
        try:
            hdrs = json.loads(item.get('headers', '{}'))
        except Exception:
            hdrs = {}
        out = (f"{'='*50}\n"
               f"Method : {item.get('method','')}\n"
               f"URL    : {item.get('url','')}\n"
               f"Status : {item.get('status_code','')}\n"
               f"Risk   : {item.get('ai_risk','')}\n"
               f"Tags   : {item.get('tags','')}\n"
               f"{'='*50}\n\nHEADERS:\n")
        for k, v in hdrs.items():
            out += f"  {k}: {v}\n"
        if item.get('body'):
            out += f"\nBODY:\n{item['body'][:1000]}\n"
        self._txt_detail.delete('1.0', 'end')
        self._txt_detail.insert('1.0', out)

    def _save_note(self):
        if not self._selected_id:
            return
        note = self._note_txt.get('1.0', 'end').strip()
        self.db.update_organizer_note(self._selected_id, note)
        self._load()
        self.app._set_status('Note saved')

    def _add_note(self):
        if not self._selected_id:
            messagebox.showwarning('Organizer', 'Select a request first')
            return
        self._note_txt.focus_set()

    def _add_tag(self):
        if not self._selected_id:
            messagebox.showwarning('Organizer', 'Select a request first')
            return
        tag = simpledialog.askstring('Add Tag', 'Enter tag:',
            parent=self.app.root)
        if tag:
            self.db.add_organizer_tag(self._selected_id, tag.strip())
            self._load()

    def _edit_note(self, event=None):
        self._note_txt.focus_set()

    def _delete_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        if messagebox.askyesno('Delete', f'Delete {len(sel)} item(s)?'):
            for iid in sel:
                self.db.delete_organizer_item(int(iid))
            self._load()

    def _filter_by_tag(self):
        tag = self._tag_filter.get().strip()
        rows = self.db.get_organizer_items(tag_filter=tag)
        self._load(rows)

    def _to_repeater(self):
        if not self._selected_id:
            return
        item = self.db.get_organizer_item(self._selected_id)
        if not item:
            return
        self.app.selected_req = item.get('request_id')
        self.app._send_to_repeater()

    def _export(self):
        from tkinter import filedialog
        rows = self.db.get_organizer_items()
        if not rows:
            messagebox.showwarning('Organizer', 'Nothing to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json')],
            initialfile=f'organizer_{int(time.time())}.json')
        if not path:
            return
        with open(path, 'w') as f:
            json.dump(rows, f, indent=2, default=str)
        self.app._set_status(f'Exported {len(rows)} items → {path}')

    def _context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        self._selected_id = int(item)
        C = self._C
        m = tk.Menu(self.app.root, tearoff=0,
            bg=C['BG3'], fg=C['TEXT'],
            activebackground=C['BG4'], activeforeground=C['ACCENT'],
            font=('Fira Code', 9))
        m.add_command(label='  → Send to Repeater', command=self._to_repeater)
        m.add_command(label='  Add Tag',            command=self._add_tag)
        m.add_command(label='  Edit Note',          command=self._edit_note)
        m.add_separator()
        m.add_command(label='  Delete',             command=self._delete_selected)
        m.post(event.x_root, event.y_root)

    def save_request(self, request_id: int):
        """Called from proxy tab context menu to save a request here."""
        req = self.db.get_request(request_id)
        if not req:
            return
        self.db.save_to_organizer(request_id, req)
        self._load()
        self.app._set_status(f'Request #{request_id} saved to Organizer')
