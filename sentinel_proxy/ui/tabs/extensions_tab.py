# ============================================================================
# Sentinel Pro v3.1 — SentinelProxy Extensions Tab
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import shutil, os

BG     = '#0d1117'
BG2    = '#161b22'
BG3    = '#1c2128'
TEXT   = '#e6edf3'
ACCENT = '#58a6ff'
GREEN  = '#3fb950'
RED    = '#f85149'
ORANGE = '#d29922'
MUTED  = '#8b949e'
FONT_MONO    = ('Fira Code', 10)
FONT_MONO_SM = ('Fira Code', 9)
FONT_BOLD    = ('Fira Code', 11, 'bold')


class ExtensionsTab:
    def __init__(self, parent_nb, ext_manager):
        self.mgr = ext_manager
        self.frame = ttk.Frame(parent_nb)
        parent_nb.add(self.frame, text='🧩 Extensions')
        self._build()

    def _build(self):
        # Toolbar
        tb = tk.Frame(self.frame, bg=BG3)
        tb.pack(fill='x')

        tk.Label(tb, text='  EXTENSIONS', bg=BG3, fg=ACCENT,
            font=FONT_BOLD).pack(side='left', padx=8, pady=8)

        ttk.Button(tb, text='Load File',
            command=self._load_file).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='Install to Folder',
            command=self._install_file).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='Reload All',
            command=self._reload_all).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='Open Folder',
            command=self._open_folder).pack(side='left', padx=4, pady=6)

        tk.Frame(self.frame, bg=ACCENT, height=1).pack(fill='x')

        # Extensions list
        cols = ('enabled', 'name', 'version', 'author', 'description')
        self.tree = ttk.Treeview(self.frame, columns=cols,
            show='headings', height=12)
        for col, w, h in [
            ('enabled', 70,  'Enabled'),
            ('name',    180, 'Name'),
            ('version', 60,  'Version'),
            ('author',  120, 'Author'),
            ('description', 400, 'Description'),
        ]:
            self.tree.heading(col, text=h)
            self.tree.column(col, width=w,
                anchor='center' if col == 'enabled' else 'w')

        vsb = ttk.Scrollbar(self.frame, orient='vertical',
            command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True, padx=8, pady=4)
        self.tree.bind('<Double-1>', self._toggle_selected)

        # Action bar
        ab = tk.Frame(self.frame, bg=BG2)
        ab.pack(fill='x', padx=8, pady=4)
        ttk.Button(ab, text='Enable / Disable',
            command=self._toggle_selected).pack(side='left', padx=4)
        ttk.Button(ab, text='Unload',
            command=self._unload_selected).pack(side='left', padx=4)

        # Info panel
        info_frame = tk.Frame(self.frame, bg=BG2)
        info_frame.pack(fill='x', padx=8, pady=4)
        self.info_lbl = tk.Label(info_frame,
            text='Double-click to toggle · Load .py files from disk',
            bg=BG2, fg=MUTED, font=FONT_MONO_SM, anchor='w')
        self.info_lbl.pack(fill='x', padx=8, pady=4)

        self._refresh()

    # ── Actions ───────────────────────────────────────────────────────────────

    def _refresh(self):
        for i in self.tree.get_children():
            self.tree.delete(i)
        for ext in self.mgr.list_extensions():
            status = '✓' if ext['enabled'] else '✗'
            fg_tag = 'enabled' if ext['enabled'] else 'disabled'
            self.tree.insert('', 'end', iid=ext['name'], tags=(fg_tag,),
                values=(status, ext['name'], ext['version'],
                        ext['author'], ext['description']))
        self.tree.tag_configure('enabled',  foreground=GREEN)
        self.tree.tag_configure('disabled', foreground=MUTED)
        count = len(self.mgr)
        self.info_lbl.config(
            text=f'{count} extension(s) loaded · Double-click to toggle')

    def _load_file(self):
        path = filedialog.askopenfilename(
            title='Load Extension', filetypes=[('Python files', '*.py')])
        if not path:
            return
        ok, msg = self.mgr.load_file(path)
        if ok:
            self._refresh()
            self.info_lbl.config(text=msg, fg=GREEN)
        else:
            messagebox.showerror('Load Failed', msg)

    def _install_file(self):
        """Copy .py file into extensions folder and load it."""
        path = filedialog.askopenfilename(
            title='Install Extension', filetypes=[('Python files', '*.py')])
        if not path:
            return
        from sentinel_proxy.extensions.loader import EXTENSIONS_DIR
        dst = os.path.join(EXTENSIONS_DIR, os.path.basename(path))
        try:
            shutil.copy2(path, dst)
            ok, msg = self.mgr.load_file(dst)
            if ok:
                self._refresh()
                self.info_lbl.config(text=f'Installed: {os.path.basename(path)}', fg=GREEN)
            else:
                messagebox.showerror('Load Failed', msg)
        except Exception as e:
            messagebox.showerror('Install Failed', str(e))

    def _reload_all(self):
        # Unload all then reload
        for ext in list(self.mgr.list_extensions()):
            self.mgr.unload(ext['name'])
        self.mgr.load_all()
        self._refresh()
        self.info_lbl.config(
            text=f'Reloaded — {len(self.mgr)} extension(s)', fg=ACCENT)

    def _open_folder(self):
        import subprocess
        from sentinel_proxy.extensions.loader import EXTENSIONS_DIR
        subprocess.Popen(['xdg-open', EXTENSIONS_DIR])

    def _toggle_selected(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        name    = sel[0]
        new_state = self.mgr.toggle(name)
        self._refresh()
        self.tree.selection_set(name)
        self.info_lbl.config(
            text=f'{name} — {"Enabled" if new_state else "Disabled"}',
            fg=GREEN if new_state else MUTED)

    def _unload_selected(self):
        sel = self.tree.selection()
        if not sel:
            return
        name = sel[0]
        if messagebox.askyesno('Unload', f'Unload extension: {name}?'):
            ok, msg = self.mgr.unload(name)
            self._refresh()
            self.info_lbl.config(text=msg, fg=ORANGE if ok else RED)
