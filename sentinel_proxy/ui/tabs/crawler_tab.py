# ============================================================================
# Sentinel Pro v3.0 — Professional OSINT & Bug Bounty Platform
# Copyright (c) 2026 @who_is_the_black_hat. All rights reserved.
# ============================================================================

"""
Crawler Tab — Auto-crawl target + scan discovered URLs
Burp Suite Spider/Crawler equivalent
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import requests
import urllib.parse
import re
import time
from collections import deque

urllib3_available = True
try:
    import urllib3
    urllib3.disable_warnings()
except ImportError:
    urllib3_available = False

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
PURPLE    = '#c77dff'
TEXT      = '#cde8e0'
TEXT2     = '#5a8a80'
TEXT3     = '#2a4a45'

FONT_MONO    = ('Fira Code', 10)
FONT_MONO_SM = ('Fira Code', 9)
FONT_MONO_XS = ('Fira Code', 8)


class CrawlerTab:
    """
    Auto-crawl a target URL:
      1. Fetch page → extract all links (href, src, action, JS fetch/axios)
      2. BFS crawl up to max_depth / max_pages
      3. Feed discovered URLs into Active Scanner automatically
      4. Show crawl map in tree view
    """

    def __init__(self, notebook: ttk.Notebook, app):
        self.app      = app
        self._running = False
        self._visited = set()
        self._queue   = deque()
        self._results = []

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='🕷 Crawler')
        self._build(self.frame)

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self, parent):
        # ── Config bar ───────────────────────────────────────────────────────
        cfg = tk.Frame(parent, bg=BG3)
        cfg.pack(fill='x')

        tk.Label(cfg, text='  TARGET URL', bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(8, 4), pady=8)
        self.entry_url = ttk.Entry(cfg, width=50, font=FONT_MONO)
        self.entry_url.pack(side='left', padx=(0, 12), pady=8)

        tk.Label(cfg, text='DEPTH', bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 4))
        self.entry_depth = ttk.Entry(cfg, width=4)
        self.entry_depth.insert(0, '3')
        self.entry_depth.pack(side='left', padx=(0, 12))

        tk.Label(cfg, text='MAX PAGES', bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 4))
        self.entry_max = ttk.Entry(cfg, width=5)
        self.entry_max.insert(0, '200')
        self.entry_max.pack(side='left', padx=(0, 12))

        # ── Options row ───────────────────────────────────────────────────────
        opt = tk.Frame(parent, bg=BG4)
        opt.pack(fill='x')

        self.var_subdomains = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text='Include subdomains',
            variable=self.var_subdomains).pack(side='left', padx=8, pady=6)

        self.var_forms = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text='Extract forms',
            variable=self.var_forms).pack(side='left', padx=8, pady=6)

        self.var_js = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text='Extract JS endpoints',
            variable=self.var_js).pack(side='left', padx=8, pady=6)

        self.var_auto_scan = tk.BooleanVar(value=False)
        ttk.Checkbutton(opt, text='Auto-send to Active Scanner',
            variable=self.var_auto_scan).pack(side='left', padx=8, pady=6)

        self.var_scope_only = tk.BooleanVar(value=True)
        ttk.Checkbutton(opt, text='Stay in scope',
            variable=self.var_scope_only).pack(side='left', padx=8, pady=6)

        # ── Action bar ────────────────────────────────────────────────────────
        ab = tk.Frame(parent, bg=BG3)
        ab.pack(fill='x')

        ttk.Button(ab, text='▶  START CRAWL', style='Cyan.TButton',
            command=self._start).pack(side='left', padx=8, pady=6)
        ttk.Button(ab, text='■  STOP', style='Red.TButton',
            command=self._stop).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='→ Active Scanner', style='Ghost.TButton',
            command=self._send_all_to_scanner).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='→ Intruder', style='Ghost.TButton',
            command=self._send_to_intruder).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='EXPORT', style='Ghost.TButton',
            command=self._export).pack(side='left', padx=4, pady=6)

        self.lbl_status = tk.Label(ab, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.lbl_status.pack(side='right', padx=12)

        # ── Split: tree + detail ──────────────────────────────────────────────
        pw = ttk.PanedWindow(parent, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: crawl tree
        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=2)

        hdr = tk.Frame(lf, bg=BG3)
        hdr.pack(fill='x')
        tk.Frame(hdr, bg=ACCENT, width=3).pack(side='left', fill='y')
        tk.Label(hdr, text='  CRAWL MAP', bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)
        self.lbl_count = tk.Label(hdr, text='0 URLs',
            bg=BG3, fg=ACCENT, font=FONT_MONO_XS)
        self.lbl_count.pack(side='right', padx=8)

        cols = ('status', 'method', 'url', 'type', 'depth', 'forms', 'params')
        self.tree = ttk.Treeview(lf, columns=cols, show='headings')
        for col, w, h in [
            ('status', 55,  'Code'),
            ('method', 55,  'Method'),
            ('url',    380, 'URL'),
            ('type',   70,  'Type'),
            ('depth',  45,  'Depth'),
            ('forms',  45,  'Forms'),
            ('params', 55,  'Params'),
        ]:
            self.tree.heading(col, text=h,
                command=lambda c=col: self._sort(c))
            self.tree.column(col, width=w,
                anchor='w' if col == 'url' else 'center')

        self.tree.tag_configure('ok',    foreground=GREEN)
        self.tree.tag_configure('redir', foreground=YELLOW)
        self.tree.tag_configure('error', foreground=RED)
        self.tree.tag_configure('form',  foreground=PURPLE)
        self.tree.tag_configure('js',    foreground=ORANGE)

        vsb = ttk.Scrollbar(lf, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Button-3>', self._context_menu)

        # Right: detail
        rf = tk.Frame(pw, bg=BG)
        pw.add(rf, weight=1)

        hdr2 = tk.Frame(rf, bg=BG3)
        hdr2.pack(fill='x')
        tk.Frame(hdr2, bg=ACCENT, width=3).pack(side='left', fill='y')
        tk.Label(hdr2, text='  PAGE DETAIL', bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)

        det_nb = ttk.Notebook(rf)
        det_nb.pack(fill='both', expand=True)

        links_f = ttk.Frame(det_nb)
        det_nb.add(links_f, text=' Links ')
        self.txt_links = self._make_text(links_f, fg=ACCENT)

        forms_f = ttk.Frame(det_nb)
        det_nb.add(forms_f, text=' Forms ')
        self.txt_forms = self._make_text(forms_f, fg=PURPLE)

        js_f = ttk.Frame(det_nb)
        det_nb.add(js_f, text=' JS Endpoints ')
        self.txt_js = self._make_text(js_f, fg=ORANGE)

    # ── Crawl engine ──────────────────────────────────────────────────────────

    def _start(self):
        url = self.entry_url.get().strip()
        if not url:
            messagebox.showwarning('Crawler', 'Enter a target URL')
            return
        if not url.startswith('http'):
            url = 'https://' + url
            self.entry_url.delete(0, 'end')
            self.entry_url.insert(0, url)

        try:
            max_depth = int(self.entry_depth.get() or 3)
            max_pages = int(self.entry_max.get() or 200)
        except ValueError:
            max_depth, max_pages = 3, 200

        self._clear()
        self._running = True
        self.lbl_status.config(text='Crawling...', fg=YELLOW)

        threading.Thread(
            target=self._crawl,
            args=(url, max_depth, max_pages),
            daemon=True
        ).start()

    def _crawl(self, start_url: str, max_depth: int, max_pages: int):
        base = urllib.parse.urlparse(start_url)
        base_host = base.netloc

        queue = deque([(start_url, 0)])
        visited = set()

        session = requests.Session()
        session.headers['User-Agent'] = 'SentinelProxy-Crawler/2.0'
        session.verify = False

        while queue and self._running and len(visited) < max_pages:
            url, depth = queue.popleft()
            if url in visited:
                continue
            visited.add(url)

            try:
                r = session.get(url, timeout=8, allow_redirects=True)
                status = r.status_code
                ct = r.headers.get('content-type', '')

                links, forms, js_eps = [], [], []

                if 'html' in ct or 'text' in ct:
                    links  = self._extract_links(r.text, url)
                    forms  = self._extract_forms(r.text, url) if self.var_forms.get() else []
                    js_eps = self._extract_js_endpoints(r.text) if self.var_js.get() else []

                # Count params
                parsed = urllib.parse.urlparse(url)
                param_count = len(urllib.parse.parse_qs(parsed.query))

                url_type = 'form' if forms else ('js' if js_eps else 'page')
                tag = 'ok' if status < 300 else ('redir' if status < 400 else 'error')
                if forms: tag = 'form'

                result = {
                    'url': url, 'status': status, 'method': 'GET',
                    'type': url_type, 'depth': depth,
                    'forms': len(forms), 'params': param_count,
                    'links': links, 'form_data': forms, 'js_eps': js_eps,
                }
                self._results.append(result)

                self.app.root.after(0, lambda r=result, tg=tag: self._add_row(r, tg))

                # Auto-send to scanner
                if self.var_auto_scan.get():
                    self.app.root.after(0, lambda u=url: self._send_url_to_scanner(u))

                # Enqueue new links
                if depth < max_depth:
                    for link in links:
                        lp = urllib.parse.urlparse(link)
                        if not self.var_subdomains.get():
                            if lp.netloc and lp.netloc != base_host:
                                continue
                        if link not in visited:
                            queue.append((link, depth + 1))

                count = len(visited)
                self.app.root.after(0, lambda c=count, q=len(queue): self.lbl_status.config(
                    text=f'{c} crawled  ·  {q} queued', fg=TEXT2))
                self.app.root.after(0, lambda c=count: self.lbl_count.config(
                    text=f'{c} URLs'))

            except Exception as e:
                self.app.root.after(0, lambda u=url, err=str(e): self.tree.insert(
                    '', 'end', values=('ERR', 'GET', u[:80], 'error', '-', '-', '-'),
                    tags=('error',)))

        self._running = False
        total = len(visited)
        bypassed = sum(1 for r in self._results if r.get('forms'))
        self.app.root.after(0, lambda: self.lbl_status.config(
            text=f'Done  ·  {total} URLs  ·  {bypassed} with forms', fg=GREEN))

    def _extract_links(self, html: str, base_url: str) -> list:
        links = []
        seen = set()
        # href, src, action
        for pattern in [
            r'href=["\']([^"\'#\s]+)["\']',
            r'action=["\']([^"\'#\s]+)["\']',
            r'src=["\']([^"\'#\s]+\.(?:js|php|asp|aspx|jsp))["\']',
        ]:
            for m in re.finditer(pattern, html, re.IGNORECASE):
                raw = m.group(1)
                full = urllib.parse.urljoin(base_url, raw)
                p = urllib.parse.urlparse(full)
                if p.scheme in ('http', 'https') and full not in seen:
                    seen.add(full)
                    links.append(full)
        return links[:100]

    def _extract_forms(self, html: str, base_url: str) -> list:
        forms = []
        for m in re.finditer(
            r'<form[^>]*action=["\']?([^"\'>\s]*)["\']?[^>]*>(.*?)</form>',
            html, re.IGNORECASE | re.DOTALL
        ):
            action = urllib.parse.urljoin(base_url, m.group(1) or base_url)
            inputs = re.findall(r'name=["\']([^"\']+)["\']', m.group(2), re.IGNORECASE)
            forms.append({'action': action, 'inputs': inputs})
        return forms

    def _extract_js_endpoints(self, html: str) -> list:
        eps = set()
        patterns = [
            r'fetch\(["\']([^"\']+)["\']',
            r'axios\.[a-z]+\(["\']([^"\']+)["\']',
            r'\.get\(["\']([/][^"\']+)["\']',
            r'\.post\(["\']([/][^"\']+)["\']',
            r'url:\s*["\']([/][^"\']+)["\']',
            r'["\'](/api/[^"\']+)["\']',
            r'["\'](/v\d+/[^"\']+)["\']',
        ]
        for pat in patterns:
            for m in re.finditer(pat, html, re.IGNORECASE):
                ep = m.group(1)
                if ep.startswith('/') or ep.startswith('http'):
                    eps.add(ep)
        return list(eps)[:50]

    # ── UI helpers ────────────────────────────────────────────────────────────

    def _add_row(self, r: dict, tag: str):
        self.tree.insert('', 'end',
            values=(
                r['status'], r['method'],
                r['url'][:90],
                r['type'], r['depth'],
                r['forms'], r['params'],
            ),
            tags=(tag,))

    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx >= len(self._results):
            return
        r = self._results[idx]

        self.txt_links.delete('1.0', 'end')
        self.txt_links.insert('1.0', '\n'.join(r.get('links', [])))

        self.txt_forms.delete('1.0', 'end')
        for f in r.get('form_data', []):
            self.txt_forms.insert('end',
                f"Action : {f['action']}\nInputs : {', '.join(f['inputs'])}\n\n")

        self.txt_js.delete('1.0', 'end')
        self.txt_js.insert('1.0', '\n'.join(r.get('js_eps', [])))

    def _context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        idx = self.tree.index(item)
        if idx >= len(self._results):
            return
        url = self._results[idx]['url']
        m = tk.Menu(self.app.root, tearoff=0,
            bg=BG3, fg=TEXT, activebackground=BG4,
            activeforeground=ACCENT, font=FONT_MONO_SM)
        m.add_command(label='  → Active Scanner',
            command=lambda: self._send_url_to_scanner(url))
        m.add_command(label='  → Repeater',
            command=lambda: self._send_url_to_repeater(url))
        m.add_command(label='  → Intruder',
            command=lambda: self._send_url_to_intruder(url))
        m.add_separator()
        m.add_command(label='  Copy URL',
            command=lambda: [self.app.root.clipboard_clear(),
                             self.app.root.clipboard_append(url)])
        m.post(event.x_root, event.y_root)

    def _send_url_to_scanner(self, url: str):
        try:
            self.app.as_url.delete(0, 'end')
            self.app.as_url.insert(0, url)
            self.app.nb_analysis.select(
                next(i for i in range(self.app.nb_analysis.index('end'))
                     if 'Scanner+' in self.app.nb_analysis.tab(i, 'text')))
        except Exception:
            pass

    def _send_url_to_repeater(self, url: str):
        try:
            self.app.rep_url.delete(0, 'end')
            self.app.rep_url.insert(0, url)
            self.app.nb.select(0)
        except Exception:
            pass

    def _send_url_to_intruder(self, url: str):
        try:
            self.app.int_url.delete(0, 'end')
            self.app.int_url.insert(0, url)
            self.app.nb.select(0)
        except Exception:
            pass

    def _send_all_to_scanner(self):
        if not self._results:
            messagebox.showwarning('Crawler', 'No URLs crawled yet')
            return
        urls = [r['url'] for r in self._results]
        try:
            self.app.as_url.delete(0, 'end')
            self.app.as_url.insert(0, urls[0])
            self.app._set_status(f'Crawler: {len(urls)} URLs sent to Active Scanner')
        except Exception:
            pass

    def _send_to_intruder(self):
        sel = self.tree.selection()
        if not sel:
            return
        idx = self.tree.index(sel[0])
        if idx < len(self._results):
            self._send_url_to_intruder(self._results[idx]['url'])

    def _sort(self, col):
        items = [(self.tree.set(i, col), i) for i in self.tree.get_children()]
        try:
            items.sort(key=lambda x: int(x[0]) if str(x[0]).isdigit() else x[0])
        except Exception:
            items.sort()
        for idx, (_, iid) in enumerate(items):
            self.tree.move(iid, '', idx)

    def _stop(self):
        self._running = False
        self.lbl_status.config(text='Stopped', fg=ORANGE)

    def _clear(self):
        for iid in self.tree.get_children():
            self.tree.delete(iid)
        self._results.clear()
        self._visited.clear()
        self.txt_links.delete('1.0', 'end')
        self.txt_forms.delete('1.0', 'end')
        self.txt_js.delete('1.0', 'end')
        self.lbl_status.config(text='')
        self.lbl_count.config(text='0 URLs')

    def _export(self):
        from tkinter import filedialog
        import json
        if not self._results:
            messagebox.showwarning('Crawler', 'No results to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json'), ('Text', '*.txt')],
            initialfile=f'crawl_{int(time.time())}.json')
        if not path:
            return
        export = [{'url': r['url'], 'status': r['status'], 'depth': r['depth'],
                   'forms': r['forms'], 'params': r['params']} for r in self._results]
        with open(path, 'w') as f:
            json.dump(export, f, indent=2)
        self.lbl_status.config(text=f'Exported {len(export)} URLs → {path}', fg=GREEN)

    def _make_text(self, parent, fg=None):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill='both', expand=True)
        t = tk.Text(f, bg=BG2, fg=fg or TEXT,
            insertbackground=ACCENT,
            selectbackground=ACCENT3, selectforeground=ACCENT,
            font=FONT_MONO_SM, relief='flat', borderwidth=0,
            wrap='none', padx=12, pady=10)
        vs = ttk.Scrollbar(f, orient='vertical',   command=t.yview)
        hs = ttk.Scrollbar(f, orient='horizontal', command=t.xview)
        t.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side='right',  fill='y')
        hs.pack(side='bottom', fill='x')
        t.pack(fill='both', expand=True)
        return t
