# ============================================================================
# Sentinel Pro v3.1 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
Intercept Rules Tab
===================
Burp-style per-rule intercept filtering.
Abhi sirf global ON/OFF tha — ab granular rules:
  - URL pattern match
  - HTTP method filter
  - Content-Type filter
  - Response code filter
  - Request / Response direction
Rules DB mein save hote hain (intercept_rules table).
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import re
import logging

logger = logging.getLogger(__name__)


class InterceptRulesTab:

    def __init__(self, notebook, app):
        self.app = app
        self.db  = app.db

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='⚙ Intercept Rules')
        self._ensure_table()
        self._build()

    # ── DB ────────────────────────────────────────────────────────────────────

    def _ensure_table(self):
        self.db._db.executescript("""
            CREATE TABLE IF NOT EXISTS intercept_rules (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                enabled      INTEGER DEFAULT 1,
                direction    TEXT DEFAULT 'Request',
                match_type   TEXT DEFAULT 'URL',
                match_value  TEXT DEFAULT '',
                operator     TEXT DEFAULT 'Contains',
                created_at   TEXT DEFAULT (datetime('now'))
            );
        """)
        self.db._db.commit()

    def _get_rules(self):
        rows = self.db._db.execute(
            "SELECT * FROM intercept_rules ORDER BY id"
        ).fetchall()
        return [dict(r) for r in rows]

    def _add_rule(self, direction, match_type, operator, match_value):
        self.db._db.execute(
            "INSERT INTO intercept_rules (direction, match_type, operator, match_value) VALUES (?,?,?,?)",
            (direction, match_type, operator, match_value)
        )
        self.db._db.commit()

    def _toggle_rule(self, rule_id, enabled):
        self.db._db.execute(
            "UPDATE intercept_rules SET enabled=? WHERE id=?",
            (1 if enabled else 0, rule_id)
        )
        self.db._db.commit()

    def _delete_rule(self, rule_id):
        self.db._db.execute("DELETE FROM intercept_rules WHERE id=?", (rule_id,))
        self.db._db.commit()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, ACCENT, TEXT, TEXT2, TEXT3,
            GREEN, RED, ORANGE, YELLOW, CYAN, BORDER2,
            FONT_MONO, FONT_MONO_XS
        )
        self._C = dict(BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, ACCENT=ACCENT,
                       TEXT=TEXT, TEXT2=TEXT2, TEXT3=TEXT3, GREEN=GREEN,
                       RED=RED, ORANGE=ORANGE, YELLOW=YELLOW, CYAN=CYAN)

        # ── Info bar ──────────────────────────────────────────────────────────
        tk.Label(self.frame,
            text='  Intercept only requests/responses matching these rules. '
                 'All rules must match (AND logic). Empty = intercept all.',
            bg=BG, fg=TEXT2, font=FONT_MONO_XS, anchor='w').pack(fill='x', pady=4)

        # ── Add rule bar ──────────────────────────────────────────────────────
        ab = tk.Frame(self.frame, bg=BG3)
        ab.pack(fill='x')

        def lbl(parent, text):
            tk.Label(parent, text=text, bg=BG3, fg=TEXT2,
                font=('Fira Code', 8, 'bold')).pack(side='left', padx=(8, 4), pady=8)

        lbl(ab, 'DIRECTION')
        self._dir_var = ttk.Combobox(ab, width=10, state='readonly',
            values=['Request', 'Response', 'Both'])
        self._dir_var.set('Request')
        self._dir_var.pack(side='left', padx=(0, 8))

        lbl(ab, 'MATCH')
        self._type_var = ttk.Combobox(ab, width=14, state='readonly',
            values=['URL', 'Method', 'Content-Type', 'Status Code',
                    'Request Header', 'Response Header', 'Body'])
        self._type_var.set('URL')
        self._type_var.pack(side='left', padx=(0, 8))

        lbl(ab, 'OPERATOR')
        self._op_var = ttk.Combobox(ab, width=10, state='readonly',
            values=['Contains', 'Not Contains', 'Regex', 'Equals', 'Starts With'])
        self._op_var.set('Contains')
        self._op_var.pack(side='left', padx=(0, 8))

        lbl(ab, 'VALUE')
        self._val_entry = ttk.Entry(ab, width=28, font=FONT_MONO)
        self._val_entry.pack(side='left', padx=(0, 8))
        self._val_entry.bind('<Return>', lambda e: self._add())

        ttk.Button(ab, text='ADD RULE', style='Cyan.TButton',
            command=self._add).pack(side='left', padx=4)
        ttk.Button(ab, text='CLEAR ALL', style='Ghost.TButton',
            command=self._clear_all).pack(side='left', padx=4)

        self._status_lbl = tk.Label(ab, text='', bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=12)

        # ── Quick presets ─────────────────────────────────────────────────────
        pb = tk.Frame(self.frame, bg=BG4)
        pb.pack(fill='x')
        tk.Label(pb, text='  PRESETS:', bg=BG4, fg=TEXT3,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(8, 4), pady=5)

        presets = [
            ('Only POST',        'Request',  'Method',       'Equals',   'POST'),
            ('No Static Files',  'Request',  'URL',          'Not Contains', '.js'),
            ('Only JSON',        'Request',  'Content-Type', 'Contains', 'application/json'),
            ('Only 200',         'Response', 'Status Code',  'Equals',   '200'),
            ('No Images',        'Request',  'URL',          'Regex',    r'\.(png|jpg|gif|ico|svg|woff)'),
        ]
        for label, *args in presets:
            ttk.Button(pb, text=label, style='Ghost.TButton',
                command=lambda a=args: self._add_preset(*a)).pack(side='left', padx=3, pady=4)

        # ── Rules tree ────────────────────────────────────────────────────────
        cols = ('id', 'enabled', 'direction', 'match_type', 'operator', 'value')
        self._tree = ttk.Treeview(self.frame, columns=cols, show='headings', height=16)
        for col, w, h in [
            ('id',        35,  '#'),
            ('enabled',   60,  'Active'),
            ('direction', 80,  'Direction'),
            ('match_type',110, 'Match On'),
            ('operator',  100, 'Operator'),
            ('value',     350, 'Value'),
        ]:
            self._tree.heading(col, text=h)
            self._tree.column(col, width=w,
                anchor='center' if col in ('id', 'enabled', 'direction') else 'w')

        self._tree.tag_configure('enabled',  foreground=GREEN)
        self._tree.tag_configure('disabled', foreground=TEXT3)

        vsb = ttk.Scrollbar(self.frame, orient='vertical', command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self._tree.pack(fill='both', expand=True)

        self._tree.bind('<Double-1>', self._on_double_click)
        self._tree.bind('<Button-3>', self._context_menu)

        tk.Label(self.frame,
            text='  Double-click to enable/disable  ·  Right-click to delete',
            bg=BG, fg=TEXT3, font=FONT_MONO_XS, anchor='w').pack(fill='x', pady=3)

        self._load()

    # ── Actions ───────────────────────────────────────────────────────────────

    def _add(self):
        val = self._val_entry.get().strip()
        if not val:
            messagebox.showwarning('Intercept Rules', 'Enter a match value')
            return
        op = self._op_var.get()
        if op == 'Regex':
            try:
                re.compile(val)
            except re.error as e:
                messagebox.showerror('Intercept Rules', f'Invalid regex: {e}')
                return
        self._add_rule(
            self._dir_var.get(),
            self._type_var.get(),
            op, val
        )
        self._val_entry.delete(0, 'end')
        self._load()
        self._status_lbl.config(text='Rule added', fg=self._C['GREEN'])
        self._sync_to_proxy()

    def _add_preset(self, direction, match_type, operator, value):
        self._add_rule(direction, match_type, operator, value)
        self._load()
        self._status_lbl.config(text=f'Preset added: {value}', fg=self._C['CYAN'])
        self._sync_to_proxy()

    def _load(self):
        for row in self._tree.get_children():
            self._tree.delete(row)
        for r in self._get_rules():
            tag = 'enabled' if r['enabled'] else 'disabled'
            self._tree.insert('', 'end', iid=str(r['id']), tags=(tag,),
                values=(
                    r['id'],
                    '✓' if r['enabled'] else '✗',
                    r['direction'],
                    r['match_type'],
                    r['operator'],
                    r['match_value'],
                ))

    def _on_double_click(self, event):
        sel = self._tree.selection()
        if not sel:
            return
        rule_id = int(sel[0])
        row = self.db._db.execute(
            "SELECT enabled FROM intercept_rules WHERE id=?", (rule_id,)
        ).fetchone()
        if row:
            new_state = 0 if row[0] else 1
            self._toggle_rule(rule_id, new_state)
            self._load()
            self._sync_to_proxy()

    def _context_menu(self, event):
        sel = self._tree.identify_row(event.y)
        if not sel:
            return
        self._tree.selection_set(sel)
        menu = tk.Menu(self.frame, tearoff=0,
            bg=self._C['BG3'], fg=self._C['TEXT'],
            activebackground=self._C['ACCENT'], activeforeground='white')
        menu.add_command(label='Toggle Enable/Disable',
            command=lambda: self._on_double_click(None) or self._load())
        menu.add_separator()
        menu.add_command(label='Delete Rule',
            command=lambda: self._delete_selected(int(sel)))
        menu.tk_popup(event.x_root, event.y_root)

    def _delete_selected(self, rule_id):
        self._delete_rule(rule_id)
        self._load()
        self._sync_to_proxy()
        self._status_lbl.config(text='Rule deleted', fg=self._C['ORANGE'])

    def _clear_all(self):
        if not messagebox.askyesno('Intercept Rules', 'Delete all rules?'):
            return
        self.db._db.execute("DELETE FROM intercept_rules")
        self.db._db.commit()
        self._load()
        self._sync_to_proxy()
        self._status_lbl.config(text='All rules cleared', fg=self._C['ORANGE'])

    def _sync_to_proxy(self):
        """Active rules proxy ke intercept filter mein sync karo."""
        try:
            rules = [r for r in self._get_rules() if r['enabled']]
            if hasattr(self.app, 'proxy') and self.app.proxy:
                if hasattr(self.app.proxy, 'set_intercept_rules'):
                    self.app.proxy.set_intercept_rules(rules)
        except Exception as e:
            logger.debug(f'Intercept rules sync: {e}')

    # ── Public: check if a flow matches active rules ──────────────────────────

    def matches(self, flow: dict, direction: str = 'Request') -> bool:
        """
        True = intercept karo, False = pass through.
        Koi rule nahi = sab intercept karo.
        """
        rules = [r for r in self._get_rules()
                 if r['enabled'] and r['direction'] in (direction, 'Both')]
        if not rules:
            return True

        for rule in rules:
            if not self._match_rule(rule, flow, direction):
                return False
        return True

    def _match_rule(self, rule: dict, flow: dict, direction: str) -> bool:
        mt  = rule['match_type']
        op  = rule['operator']
        val = rule['match_value']

        if mt == 'URL':
            target = flow.get('url', '')
        elif mt == 'Method':
            target = flow.get('method', '')
        elif mt == 'Content-Type':
            try:
                hdrs = json.loads(flow.get('headers', '{}'))
                target = hdrs.get('Content-Type', hdrs.get('content-type', ''))
            except Exception:
                target = ''
        elif mt == 'Status Code':
            target = str(flow.get('status_code', ''))
        elif mt == 'Request Header':
            try:
                target = json.dumps(json.loads(flow.get('headers', '{}')))
            except Exception:
                target = ''
        elif mt == 'Response Header':
            try:
                target = json.dumps(json.loads(flow.get('resp_headers', '{}')))
            except Exception:
                target = ''
        elif mt == 'Body':
            target = flow.get('body', '') or flow.get('resp_body', '')
        else:
            target = ''

        return self._apply_operator(op, target, val)

    @staticmethod
    def _apply_operator(op: str, target: str, val: str) -> bool:
        t = target.lower()
        v = val.lower()
        if op == 'Contains':
            return v in t
        if op == 'Not Contains':
            return v not in t
        if op == 'Equals':
            return t == v
        if op == 'Starts With':
            return t.startswith(v)
        if op == 'Regex':
            try:
                return bool(re.search(val, target, re.IGNORECASE))
            except Exception:
                return False
        return True
