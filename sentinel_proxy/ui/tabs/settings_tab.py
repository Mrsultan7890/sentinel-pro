# ============================================================================
# Sentinel Pro v3.1 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
Settings Tab — SentinelProxy global settings
Persistent settings saved to ~/.sentinel_proxy/settings.json
"""

import tkinter as tk
from tkinter import ttk, messagebox
import json
import threading
from pathlib import Path

SETTINGS_FILE = Path.home() / '.sentinel_proxy' / 'settings.json'

DEFAULTS = {
    # Autorize
    'autorize_token':       '',
    'autorize_header':      'Cookie',
    'autorize_diff':        '50',
    'autorize_auto':        True,
    # Scan defaults
    'scan_threads':         '10',
    'scan_timeout':         '8',
    'scan_diff_threshold':  '20',
    # Crawler defaults
    'crawler_depth':        '3',
    'crawler_max_pages':    '200',
    # Collaborator
    'collab_port':          '0',
    # Race condition
    'race_requests':        '20',
    'race_threads':         '20',
    # Proxy behavior
    'intercept_on_start':   False,
    'auto_refresh_interval':'3000',
    'max_history':          '5000',
    # AI pipeline
    'ai_pipeline_enabled':  True,
    'groq_analysis_enabled':True,
    'sentinelnet_enabled':  True,
    # Display
    'font_size':            '9',
    'show_ms_column':       True,
    'tree_row_height':      '26',
}


def load_settings() -> dict:
    try:
        if SETTINGS_FILE.exists():
            data = json.loads(SETTINGS_FILE.read_text())
            return {**DEFAULTS, **data}
    except Exception:
        pass
    return dict(DEFAULTS)


def save_settings(data: dict):
    SETTINGS_FILE.parent.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(data, indent=2))


# Global settings cache — loaded once at import
_settings = load_settings()


def get(key: str):
    return _settings.get(key, DEFAULTS.get(key))


def set_and_save(key: str, value):
    _settings[key] = value
    threading.Thread(target=lambda: save_settings(_settings), daemon=True).start()


class SettingsTab:

    def __init__(self, notebook, app):
        self.app = app
        self._vars = {}

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='⚙ Settings')
        self._build()
        self._load_into_ui()

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW,
            FONT_MONO, FONT_MONO_XS
        )
        self._C = dict(BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, BORDER2=BORDER2,
                       ACCENT=ACCENT, TEXT=TEXT, TEXT2=TEXT2, TEXT3=TEXT3,
                       GREEN=GREEN, RED=RED, ORANGE=ORANGE, YELLOW=YELLOW)

        # Toolbar
        tb = tk.Frame(self.frame, bg=BG3)
        tb.pack(fill='x')
        ttk.Button(tb, text='💾  SAVE SETTINGS', style='Cyan.TButton',
            command=self._save).pack(side='left', padx=8, pady=6)
        ttk.Button(tb, text='↺  RESET DEFAULTS', style='Ghost.TButton',
            command=self._reset).pack(side='left', padx=4, pady=6)
        self._status_lbl = tk.Label(tb, text='', bg=BG3, fg=TEXT2,
            font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=12)

        # Scrollable canvas
        canvas = tk.Canvas(self.frame, bg=BG, highlightthickness=0)
        vsb = ttk.Scrollbar(self.frame, orient='vertical', command=canvas.yview)
        canvas.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        canvas.pack(fill='both', expand=True)

        inner = tk.Frame(canvas, bg=BG)
        canvas.create_window((0, 0), window=inner, anchor='nw')
        inner.bind('<Configure>',
            lambda e: canvas.configure(scrollregion=canvas.bbox('all')))
        canvas.bind('<MouseWheel>',
            lambda e: canvas.yview_scroll(-1 * (e.delta // 120), 'units'))

        self._inner = inner
        self._build_sections(inner)

    def _build_sections(self, parent):
        C = self._C

        sections = [
            ('🤖  AI Pipeline', [
                ('ai_pipeline_enabled',  'bool',  'Enable AI analysis pipeline (SentinelNet + Groq)'),
                ('groq_analysis_enabled','bool',  'Enable Groq LLM deep analysis'),
                ('sentinelnet_enabled',  'bool',  'Enable SentinelNet v5.0 threat classification'),
            ]),
            ('🔐  Autorize Defaults', [
                ('autorize_token',  'entry', 'Default low-privilege token (Cookie/JWT value)'),
                ('autorize_header', 'combo', 'Default auth header',
                    ['Cookie', 'Authorization', 'X-Auth-Token', 'X-API-Key']),
                ('autorize_diff',   'entry', 'Response size diff threshold (bytes)'),
                ('autorize_auto',   'bool',  'Auto-test new requests'),
            ]),
            ('⚡  Scan Defaults', [
                ('scan_threads',        'entry', 'Default thread count (Intruder / Param Miner / Race)'),
                ('scan_timeout',        'entry', 'Request timeout (seconds)'),
                ('scan_diff_threshold', 'entry', 'Response diff threshold (bytes)'),
            ]),
            ('🕷  Crawler Defaults', [
                ('crawler_depth',     'entry', 'Default crawl depth'),
                ('crawler_max_pages', 'entry', 'Default max pages'),
            ]),
            ('◎  Collaborator', [
                ('collab_port', 'entry', 'Default listener port (0 = auto)'),
            ]),
            ('⚡  Race Condition Defaults', [
                ('race_requests', 'entry', 'Default request count'),
                ('race_threads',  'entry', 'Default thread count'),
            ]),
            ('⬡  Proxy Behavior', [
                ('intercept_on_start',   'bool',  'Start with intercept ON'),
                ('auto_refresh_interval','entry', 'Logger auto-refresh interval (ms)'),
                ('max_history',          'entry', 'Max requests to keep in history'),
            ]),
            ('🖥  Display', [
                ('font_size',       'entry', 'Monospace font size (requires restart)'),
                ('tree_row_height', 'entry', 'Tree row height px (requires restart)'),
                ('show_ms_column',  'bool',  'Show response time (ms) column in Proxy'),
            ]),
        ]

        for section_title, fields in sections:
            self._section(parent, section_title, fields)

    def _section(self, parent, title, fields):
        C = self._C
        from sentinel_proxy.ui.app import FONT_MONO_XS, FONT_MONO

        # Section header
        hdr = tk.Frame(parent, bg=C['BG3'])
        hdr.pack(fill='x', pady=(12, 0))
        tk.Frame(hdr, bg=C['ACCENT'], width=3).pack(side='left', fill='y')
        tk.Label(hdr, text=f'  {title}', bg=C['BG3'], fg=C['ACCENT'],
            font=('Fira Code', 9, 'bold')).pack(side='left', padx=6, pady=6)

        body = tk.Frame(parent, bg=C['BG2'])
        body.pack(fill='x', padx=0, pady=0)

        for field in fields:
            key   = field[0]
            ftype = field[1]
            label = field[2]
            opts  = field[3] if len(field) > 3 else None

            row = tk.Frame(body, bg=C['BG2'])
            row.pack(fill='x', padx=16, pady=5)

            tk.Label(row, text=label, bg=C['BG2'], fg=C['TEXT2'],
                font=FONT_MONO_XS, width=52, anchor='w').pack(side='left')

            if ftype == 'bool':
                var = tk.BooleanVar()
                ttk.Checkbutton(row, variable=var).pack(side='left')
                self._vars[key] = var
            elif ftype == 'combo':
                var = tk.StringVar()
                ttk.Combobox(row, textvariable=var, values=opts,
                    width=22, state='readonly').pack(side='left')
                self._vars[key] = var
            else:  # entry
                var = tk.StringVar()
                ttk.Entry(row, textvariable=var, width=14,
                    font=FONT_MONO).pack(side='left')
                self._vars[key] = var

    def _load_into_ui(self):
        s = load_settings()
        for key, var in self._vars.items():
            val = s.get(key, DEFAULTS.get(key, ''))
            try:
                if isinstance(var, tk.BooleanVar):
                    var.set(bool(val))
                else:
                    var.set(str(val))
            except Exception:
                pass

    def _save(self):
        data = dict(_settings)
        for key, var in self._vars.items():
            try:
                data[key] = var.get()
            except Exception:
                pass
        _settings.update(data)
        save_settings(data)
        self._apply_to_app(data)
        self._status_lbl.config(text='✓ Settings saved', fg=self._C['GREEN'])
        self.app.root.after(2000, lambda: self._status_lbl.config(text=''))

    def _reset(self):
        if not messagebox.askyesno('Reset', 'Reset all settings to defaults?'):
            return
        _settings.update(DEFAULTS)
        save_settings(DEFAULTS)
        self._load_into_ui()
        self._status_lbl.config(text='Reset to defaults', fg=self._C['ORANGE'])

    def _apply_to_app(self, data: dict):
        """Apply settings to live app components."""
        try:
            # Autorize tab
            if hasattr(self.app, '_autorize_tab'):
                at = self.app._autorize_tab
                if data.get('autorize_token'):
                    at.entry_token.delete(0, 'end')
                    at.entry_token.insert(0, data['autorize_token'])
                at.combo_header.set(data.get('autorize_header', 'Cookie'))
                at.entry_diff.delete(0, 'end')
                at.entry_diff.insert(0, data.get('autorize_diff', '50'))
                at.var_auto.set(bool(data.get('autorize_auto', True)))

            # Crawler tab
            if hasattr(self.app, '_crawler_tab'):
                ct = self.app._crawler_tab
                ct.entry_depth.delete(0, 'end')
                ct.entry_depth.insert(0, data.get('crawler_depth', '3'))
                ct.entry_max.delete(0, 'end')
                ct.entry_max.insert(0, data.get('crawler_max_pages', '200'))

            # Collaborator tab
            if hasattr(self.app, '_collaborator_tab'):
                self.app._collaborator_tab._port_var.set(
                    data.get('collab_port', '0'))

            # Race condition tab
            if hasattr(self.app, '_race_tab'):
                rt = self.app._race_tab
                rt._req_count.delete(0, 'end')
                rt._req_count.insert(0, data.get('race_requests', '20'))
                rt._threads.delete(0, 'end')
                rt._threads.insert(0, data.get('race_threads', '20'))

            # Param miner tab
            if hasattr(self.app, '_param_miner_tab'):
                pm = self.app._param_miner_tab
                pm._threads.delete(0, 'end')
                pm._threads.insert(0, data.get('scan_threads', '10'))
                pm._threshold.delete(0, 'end')
                pm._threshold.insert(0, data.get('scan_diff_threshold', '20'))

        except Exception:
            pass
