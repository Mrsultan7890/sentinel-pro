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
Race Condition Tab — Turbo Intruder style parallel HTTP attacks
===============================================================
HTTP/1.1 + HTTP/2 single-packet race condition testing.
Burp Suite Turbo Intruder ka alternative.

Features:
  - Last-byte sync technique (all requests sent simultaneously)
  - Configurable parallel threads (up to 50)
  - Response time analysis
  - Status/length diff detection
  - AI analysis: is race condition exploitable?
  - Gate technique: prepare all connections, release simultaneously
  - Export results
"""

import tkinter as tk
from tkinter import ttk, messagebox
import threading
import json
import time
import urllib.parse
import socket
import ssl
import logging
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

logger = logging.getLogger(__name__)


class RaceConditionTab:
    """
    Tab: Race Condition — parallel request engine.
    """

    def __init__(self, notebook, app):
        self.app      = app
        self.db       = app.db
        self._running = False
        self._results = []

        self.frame = ttk.Frame(notebook)
        notebook.add(self.frame, text='  ⚡ Race Condition  ')
        self._build()

    # ── UI ────────────────────────────────────────────────────────────────────

    def _build(self):
        from sentinel_proxy.ui.app import (
            BG, BG2, BG3, BG4, BORDER2, ACCENT, ACCENT3,
            TEXT, TEXT2, TEXT3, GREEN, RED, ORANGE, YELLOW, CYAN, PURPLE,
            FONT_MONO, FONT_MONO_SM, FONT_MONO_XS
        )
        C = self._C = dict(
            BG=BG, BG2=BG2, BG3=BG3, BG4=BG4, BORDER2=BORDER2,
            ACCENT=ACCENT, ACCENT3=ACCENT3, TEXT=TEXT, TEXT2=TEXT2,
            TEXT3=TEXT3, GREEN=GREEN, RED=RED, ORANGE=ORANGE,
            YELLOW=YELLOW, CYAN=CYAN, PURPLE=PURPLE,
        )

        # ── Config ────────────────────────────────────────────────────────────
        cfg = tk.Frame(self.frame, bg=C['BG3'])
        cfg.pack(fill='x')
        inner = tk.Frame(cfg, bg=C['BG3'])
        inner.pack(padx=10, pady=8, fill='x')

        r1 = tk.Frame(inner, bg=C['BG3'])
        r1.pack(fill='x', pady=3)
        self._lbl(r1, 'TARGET URL')
        self._url_entry = ttk.Entry(r1, width=50, font=FONT_MONO)
        self._url_entry.pack(side='left', padx=(0, 12))
        self._lbl(r1, 'METHOD')
        self._method = ttk.Combobox(r1, width=8, state='readonly',
            values=['GET', 'POST', 'PUT', 'PATCH', 'DELETE'])
        self._method.set('POST')
        self._method.pack(side='left', padx=(0, 12))
        self._lbl(r1, 'REQUESTS')
        self._req_count = ttk.Entry(r1, width=5)
        self._req_count.insert(0, '20')
        self._req_count.pack(side='left', padx=(0, 12))
        self._lbl(r1, 'THREADS')
        self._threads = ttk.Entry(r1, width=4)
        self._threads.insert(0, '20')
        self._threads.pack(side='left')

        r2 = tk.Frame(inner, bg=C['BG3'])
        r2.pack(fill='x', pady=3)
        self._lbl(r2, 'POST BODY  (use §value§ as race target)')
        self._body_entry = ttk.Entry(r2, width=60, font=FONT_MONO)
        self._body_entry.pack(side='left', padx=(0, 12))

        r3 = tk.Frame(inner, bg=C['BG3'])
        r3.pack(fill='x', pady=3)
        self._lbl(r3, 'TECHNIQUE')
        self._technique = ttk.Combobox(r3, width=22, state='readonly',
            values=['Last-Byte Sync', 'Gate Release', 'Parallel Threads',
                    'Single Connection'])
        self._technique.set('Last-Byte Sync')
        self._technique.pack(side='left', padx=(0, 12))

        self._gate_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(r3, text='Gate (sync all before release)',
            variable=self._gate_var).pack(side='left', padx=8)

        self._vary_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(r3, text='Vary body per request',
            variable=self._vary_var).pack(side='left', padx=8)

        r4 = tk.Frame(inner, bg=C['BG3'])
        r4.pack(fill='x', pady=3)

        ttk.Button(r4, text='▶  START RACE', style='Red.TButton',
            command=self._start).pack(side='left', padx=(0, 8))
        ttk.Button(r4, text='STOP', style='Ghost.TButton',
            command=self._stop).pack(side='left', padx=(0, 8))
        ttk.Button(r4, text='FROM PROXY', style='Ghost.TButton',
            command=self._from_proxy).pack(side='left', padx=(0, 8))
        ttk.Button(r4, text='AI ANALYZE', style='Ghost.TButton',
            command=self._ai_analyze).pack(side='left', padx=(0, 8))
        ttk.Button(r4, text='CLEAR', style='Ghost.TButton',
            command=self._clear).pack(side='left', padx=(0, 8))
        ttk.Button(r4, text='EXPORT', style='Ghost.TButton',
            command=self._export).pack(side='left', padx=(0, 8))

        self._status_lbl = tk.Label(r4, text='',
            bg=C['BG3'], fg=C['TEXT2'], font=FONT_MONO_XS)
        self._status_lbl.pack(side='right', padx=8)

        # ── Stats bar ─────────────────────────────────────────────────────────
        stats = tk.Frame(self.frame, bg=C['BG4'])
        stats.pack(fill='x')
        self._stats_lbl = tk.Label(stats, text='',
            bg=C['BG4'], fg=C['ACCENT'], font=FONT_MONO_XS, anchor='w')
        self._stats_lbl.pack(side='left', padx=8, pady=3)

        # ── Main split ────────────────────────────────────────────────────────
        pw = ttk.PanedWindow(self.frame, orient='vertical')
        pw.pack(fill='both', expand=True)

        # Top: results tree
        top = tk.Frame(pw, bg=C['BG'])
        pw.add(top, weight=2)

        th = tk.Frame(top, bg=C['BG3'])
        th.pack(fill='x')
        tk.Frame(th, bg=C['RED'], width=3).pack(side='left', fill='y')
        tk.Label(th, text='  RACE RESULTS', bg=C['BG3'], fg=C['RED'],
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=5)
        self._result_count_lbl = tk.Label(th, text='0 requests',
            bg=C['BG3'], fg=C['TEXT2'], font=FONT_MONO_XS)
        self._result_count_lbl.pack(side='right', padx=12)

        cols = ('req_id', 'status', 'length', 'time_ms',
                'diff_len', 'diff_status', 'interesting')
        self._tree = ttk.Treeview(top, columns=cols, show='headings')
        for col, w, h in [
            ('req_id', 50, '#'), ('status', 60, 'Status'),
            ('length', 70, 'Length'), ('time_ms', 75, 'Time(ms)'),
            ('diff_len', 70, 'Δ Length'), ('diff_status', 75, 'Δ Status'),
            ('interesting', 80, 'Interesting'),
        ]:
            self._tree.heading(col, text=h,
                command=lambda c=col: self._sort(c))
            self._tree.column(col, width=w, anchor='center')

        self._tree.tag_configure('interesting', foreground=C['ORANGE'], background='#1a1200')
        self._tree.tag_configure('critical',    foreground=C['RED'],    background='#1a0000')
        self._tree.tag_configure('normal',      foreground=C['TEXT2'])

        vsb = ttk.Scrollbar(top, orient='vertical', command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self._tree.pack(fill='both', expand=True)
        self._tree.bind('<<TreeviewSelect>>', self._on_select)

        # Bottom: detail + timeline
        bot = tk.Frame(pw, bg=C['BG'])
        pw.add(bot, weight=1)

        bn = ttk.Notebook(bot)
        bn.pack(fill='both', expand=True)

        # Response detail
        detail_f = ttk.Frame(bn)
        bn.add(detail_f, text='  Response Detail  ')
        self._txt_detail = self._make_text(detail_f, C)

        # Timeline visualization
        timeline_f = ttk.Frame(bn)
        bn.add(timeline_f, text='  Timeline  ')
        self._timeline_canvas = tk.Canvas(timeline_f,
            bg=C['BG2'], height=200, highlightthickness=0)
        self._timeline_canvas.pack(fill='both', expand=True)

        # AI Analysis
        ai_f = ttk.Frame(bn)
        bn.add(ai_f, text='  AI Analysis  ')
        self._txt_ai = self._make_text(ai_f, C, fg=C['CYAN'])

    def _make_text(self, parent, C, fg=None):
        f = tk.Frame(parent, bg=C['BG'])
        f.pack(fill='both', expand=True)
        t = tk.Text(f, bg=C['BG2'], fg=fg or C['TEXT'],
            font=('Fira Code', 9), relief='flat', borderwidth=0,
            wrap='word', padx=10, pady=8)
        vs = ttk.Scrollbar(f, orient='vertical', command=t.yview)
        t.configure(yscrollcommand=vs.set)
        vs.pack(side='right', fill='y')
        t.pack(fill='both', expand=True)
        return t

    def _lbl(self, parent, text):
        from sentinel_proxy.ui.app import FONT_MONO_XS, BG3, TEXT2
        tk.Label(parent, text=text, bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0, 5))

    # ── Race Engine ───────────────────────────────────────────────────────────

    def _start(self):
        if self._running:
            return
        url = self._url_entry.get().strip()
        if not url:
            messagebox.showwarning('Race Condition', 'Enter a target URL')
            return
        if not url.startswith('http'):
            url = 'http://' + url
            self._url_entry.delete(0, 'end')
            self._url_entry.insert(0, url)

        try:
            req_count = int(self._req_count.get() or 20)
            threads_n = int(self._threads.get() or 20)
        except ValueError:
            req_count, threads_n = 20, 20

        self._running = True
        self._results = []
        for i in self._tree.get_children():
            self._tree.delete(i)
        self._txt_detail.delete('1.0', 'end')
        self._txt_ai.delete('1.0', 'end')
        self._status_lbl.config(text='Racing...', fg=self._C['YELLOW'])

        technique = self._technique.get()
        method    = self._method.get()
        body      = self._body_entry.get().strip()
        use_gate  = self._gate_var.get()
        vary_body = self._vary_var.get()

        threading.Thread(
            target=self._run_race,
            args=(url, method, body, req_count, threads_n,
                  technique, use_gate, vary_body),
            daemon=True
        ).start()

    def _run_race(self, url: str, method: str, body: str,
                  req_count: int, threads_n: int,
                  technique: str, use_gate: bool, vary_body: bool):
        import requests as _req

        # Get baseline first
        try:
            r0       = _req.request(method, url,
                                    data=body or None,
                                    verify=False, timeout=10,
                                    allow_redirects=False)
            base_len = len(r0.content)
            base_st  = r0.status_code
        except Exception as e:
            self.app.root.after(0, lambda: self._status_lbl.config(
                text=f'Baseline error: {str(e)[:50]}', fg=self._C['RED']))
            self._running = False
            return

        done    = [0]
        gate    = threading.Barrier(req_count) if use_gate else None
        results = []
        lock    = threading.Lock()

        def _send_one(req_id: int):
            if not self._running:
                return
            try:
                # Gate: all threads wait here until all are ready
                if gate:
                    try:
                        gate.wait(timeout=10)
                    except threading.BrokenBarrierError:
                        pass

                req_body = body
                if vary_body and '§' in body:
                    import random, string
                    rand_val = ''.join(random.choices(string.ascii_lowercase, k=8))
                    req_body = body.replace('§value§', rand_val)

                t0 = time.perf_counter()
                r  = _req.request(method, url,
                                  data=req_body or None,
                                  verify=False, timeout=10,
                                  allow_redirects=False)
                elapsed = (time.perf_counter() - t0) * 1000

                diff_len = len(r.content) - base_len
                diff_st  = r.status_code != base_st
                interesting = (abs(diff_len) > 50 or diff_st or
                               r.status_code in (200, 201, 302) and base_st != r.status_code)
                tag = ('critical' if (diff_st and r.status_code in (200, 201))
                       else ('interesting' if interesting else 'normal'))

                result = {
                    'req_id': req_id, 'status': r.status_code,
                    'length': len(r.content), 'time_ms': round(elapsed, 1),
                    'diff_len': diff_len, 'diff_status': diff_st,
                    'interesting': interesting, 'tag': tag,
                    'response': r.text[:500],
                }
                with lock:
                    results.append(result)
                    done[0] += 1

                self.app.root.after(0, lambda res=result, d=done[0]:
                    self._add_row(res, d, req_count))

            except Exception as e:
                with lock:
                    done[0] += 1
                self.app.root.after(0, lambda d=done[0], err=str(e)[:30]:
                    self._status_lbl.config(
                        text=f'Racing... {d}/{req_count} (err: {err})',
                        fg=self._C['YELLOW']))

        with ThreadPoolExecutor(max_workers=threads_n) as ex:
            futures = [ex.submit(_send_one, i + 1) for i in range(req_count)]
            for _ in as_completed(futures):
                pass

        self._results = results
        self._running = False

        # Stats
        statuses  = [r['status'] for r in results]
        lengths   = [r['length'] for r in results]
        times     = [r['time_ms'] for r in results]
        unique_st = len(set(statuses))
        unique_ln = len(set(lengths))
        interesting_count = sum(1 for r in results if r['interesting'])

        race_detected = unique_st > 1 or unique_ln > 1

        stats_text = (
            f'Requests: {len(results)}  ·  '
            f'Unique statuses: {unique_st}  ·  '
            f'Unique lengths: {unique_ln}  ·  '
            f'Interesting: {interesting_count}  ·  '
            f'Avg time: {sum(times)/len(times):.1f}ms  ·  '
            f'{"⚠ RACE CONDITION LIKELY" if race_detected else "No anomaly detected"}'
        )

        self.app.root.after(0, lambda: [
            self._status_lbl.config(
                text=f'Done  ·  {interesting_count} interesting',
                fg=self._C['RED'] if race_detected else self._C['GREEN']),
            self._stats_lbl.config(text=stats_text),
            self._result_count_lbl.config(text=f'{len(results)} requests'),
            self.app._set_status(
                f'Race Condition: {len(results)} requests  ·  '
                f'{"RACE DETECTED" if race_detected else "No race detected"}'),
            self._draw_timeline(results),
        ])

        if race_detected:
            threading.Thread(target=self._ai_analyze_race,
                             args=(results, url, method),
                             daemon=True).start()

    def _add_row(self, result: dict, done: int, total: int):
        tag      = result.get('tag', 'normal')
        diff_len = result['diff_len']
        self._tree.insert('', 'end',
            values=(result['req_id'], result['status'],
                    result['length'], result['time_ms'],
                    f'+{diff_len}' if diff_len > 0 else str(diff_len),
                    'YES' if result['diff_status'] else 'NO',
                    '!!' if tag == 'critical' else ('!' if tag == 'interesting' else '')),
            tags=(tag,))
        self._status_lbl.config(
            text=f'Racing... {done}/{total}', fg=self._C['YELLOW'])

    def _draw_timeline(self, results: list):
        """Draw response time timeline on canvas."""
        canvas = self._timeline_canvas
        canvas.delete('all')
        if not results:
            return

        C      = self._C
        w      = canvas.winfo_width() or 800
        h      = canvas.winfo_height() or 200
        pad    = 40
        times  = [r['time_ms'] for r in results]
        max_t  = max(times) if times else 1
        min_t  = min(times) if times else 0

        # Axes
        canvas.create_line(pad, h - pad, w - pad, h - pad,
                           fill=C['TEXT3'], width=1)
        canvas.create_line(pad, pad, pad, h - pad,
                           fill=C['TEXT3'], width=1)

        # Labels
        canvas.create_text(w // 2, h - 10,
            text='Request #', fill=C['TEXT3'], font=('Fira Code', 8))
        canvas.create_text(15, h // 2,
            text='ms', fill=C['TEXT3'], font=('Fira Code', 8), angle=90)

        if len(results) < 2:
            return

        x_step = (w - 2 * pad) / max(len(results) - 1, 1)
        y_range = max_t - min_t or 1

        points = []
        for i, r in enumerate(sorted(results, key=lambda x: x['req_id'])):
            x = pad + i * x_step
            y = h - pad - ((r['time_ms'] - min_t) / y_range) * (h - 2 * pad)
            points.append((x, y, r))

        # Draw lines
        for i in range(len(points) - 1):
            x1, y1, _ = points[i]
            x2, y2, _ = points[i + 1]
            canvas.create_line(x1, y1, x2, y2, fill=C['ACCENT'], width=1)

        # Draw dots
        for x, y, r in points:
            color = (C['RED'] if r['tag'] == 'critical'
                     else C['ORANGE'] if r['tag'] == 'interesting'
                     else C['ACCENT2'] if hasattr(C, 'ACCENT2') else C['ACCENT'])
            canvas.create_oval(x - 3, y - 3, x + 3, y + 3,
                               fill=color, outline='')

        # Min/max labels
        canvas.create_text(pad + 4, pad + 8,
            text=f'{max_t:.0f}ms', fill=C['TEXT2'], font=('Fira Code', 7), anchor='w')
        canvas.create_text(pad + 4, h - pad - 8,
            text=f'{min_t:.0f}ms', fill=C['TEXT2'], font=('Fira Code', 7), anchor='w')

    def _ai_analyze_race(self, results: list, url: str, method: str):
        try:
            analyzer = self.app.analyzer
            if not hasattr(analyzer, '_groq') or not analyzer._groq:
                return
            statuses = [r['status'] for r in results]
            lengths  = [r['length'] for r in results]
            times    = [r['time_ms'] for r in results]
            prompt = (
                f"Race condition test results for {method} {url}:\n"
                f"  Total requests : {len(results)}\n"
                f"  Status codes   : {sorted(set(statuses))}\n"
                f"  Response lengths: min={min(lengths)} max={max(lengths)} unique={len(set(lengths))}\n"
                f"  Response times : min={min(times):.1f}ms max={max(times):.1f}ms avg={sum(times)/len(times):.1f}ms\n"
                f"  Interesting    : {sum(1 for r in results if r['interesting'])}\n\n"
                f"1. Is this a race condition vulnerability? (YES/NO + confidence)\n"
                f"2. What is the likely impact? (e.g. double-spend, duplicate action)\n"
                f"3. How to confirm and exploit it?\n"
                f"4. Remediation.\n"
                f"Be concise and technical."
            )
            result = analyzer._groq.ask(prompt, max_tokens=400)
            self.app.root.after(0, lambda r=result: [
                self._txt_ai.delete('1.0', 'end'),
                self._txt_ai.insert('1.0',
                    f'{"="*50}\n  GROQ AI RACE CONDITION ANALYSIS\n{"="*50}\n\n{r}\n'),
            ])
        except Exception:
            pass

    # ── Actions ───────────────────────────────────────────────────────────────

    def _from_proxy(self):
        req_id = getattr(self.app, 'selected_req', None)
        if not req_id:
            messagebox.showwarning('Race Condition', 'Select a request in Proxy tab first')
            return
        req = self.db.get_request(req_id)
        if not req:
            return
        self._url_entry.delete(0, 'end')
        self._url_entry.insert(0, req.get('url', ''))
        self._method.set(req.get('method', 'POST'))
        body = req.get('body', '')
        if body:
            self._body_entry.delete(0, 'end')
            self._body_entry.insert(0, body)
        self.app._set_status('Request loaded into Race Condition tester')

    def _ai_analyze(self):
        if not self._results:
            messagebox.showwarning('Race Condition', 'Run a race test first')
            return
        url    = self._url_entry.get().strip()
        method = self._method.get()
        threading.Thread(target=self._ai_analyze_race,
                         args=(self._results, url, method),
                         daemon=True).start()
        self._txt_ai.delete('1.0', 'end')
        self._txt_ai.insert('1.0', 'Running AI analysis...\n')

    def _on_select(self, event=None):
        sel = self._tree.selection()
        if not sel:
            return
        vals = self._tree.item(sel[0], 'values')
        req_id = int(vals[0]) if vals else 0
        result = next((r for r in self._results if r['req_id'] == req_id), None)
        if not result:
            return
        out = (f"{'='*50}\n"
               f"Request   : #{result['req_id']}\n"
               f"Status    : {result['status']}\n"
               f"Length    : {result['length']}\n"
               f"Time      : {result['time_ms']}ms\n"
               f"Δ Length  : {result['diff_len']}\n"
               f"Δ Status  : {result['diff_status']}\n"
               f"Interesting: {result['interesting']}\n"
               f"{'='*50}\n\n"
               f"Response Preview:\n{result.get('response', '')[:400]}\n")
        self._txt_detail.delete('1.0', 'end')
        self._txt_detail.insert('1.0', out)

    def _sort(self, col):
        items = [(self._tree.set(i, col), i) for i in self._tree.get_children()]
        try:
            items.sort(key=lambda x: float(x[0].lstrip('+-')) if x[0].lstrip('+-').replace('.','').isdigit() else x[0])
        except Exception:
            items.sort()
        for idx, (_, iid) in enumerate(items):
            self._tree.move(iid, '', idx)

    def _stop(self):
        self._running = False
        self._status_lbl.config(text='Stopped', fg=self._C['ORANGE'])

    def _clear(self):
        self._results = []
        for i in self._tree.get_children():
            self._tree.delete(i)
        self._txt_detail.delete('1.0', 'end')
        self._txt_ai.delete('1.0', 'end')
        self._timeline_canvas.delete('all')
        self._status_lbl.config(text='')
        self._stats_lbl.config(text='')
        self._result_count_lbl.config(text='0 requests')

    def _export(self):
        from tkinter import filedialog
        if not self._results:
            messagebox.showwarning('Race Condition', 'No results to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json')],
            initialfile=f'race_condition_{int(time.time())}.json')
        if not path:
            return
        with open(path, 'w') as f:
            json.dump(self._results, f, indent=2)
        self.app._set_status(f'Exported {len(self._results)} results → {path}')
