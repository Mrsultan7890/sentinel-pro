"""
SentinelProxy UI — Professional Hacker Theme
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading, json, sys, time, requests
from datetime import datetime

sys.path.insert(0, '/home/kali/osints')

# ── Color Palette ─────────────────────────────────────────────────────────────
BG        = '#0a0e17'   # deep dark navy
BG2       = '#0f1623'   # panel bg
BG3       = '#151d2e'   # slightly lighter
BG4       = '#1a2438'   # hover/selected
BORDER    = '#1e2d45'   # subtle border
ACCENT    = '#00d4ff'   # cyan accent
ACCENT2   = '#0099cc'   # darker cyan
GREEN     = '#00ff88'   # success green
RED       = '#ff3355'   # danger red
ORANGE    = '#ff8c00'   # warning
YELLOW    = '#ffd700'   # info
PURPLE    = '#9d4edd'   # purple accent
TEXT      = '#cdd6f4'   # main text
TEXT2     = '#6c7a96'   # muted text
TEXT3     = '#3d4f6b'   # very muted
CRITICAL  = '#ff3355'
HIGH      = '#ff8c00'
MEDIUM    = '#ffd700'
LOW       = '#00ff88'

SEV_COLOR = {
    'CRITICAL': CRITICAL, 'HIGH': HIGH,
    'MEDIUM': MEDIUM, 'LOW': LOW, 'UNKNOWN': TEXT2
}

METHOD_COLOR = {
    'GET': '#00d4ff', 'POST': '#00ff88', 'PUT': '#ffd700',
    'DELETE': '#ff3355', 'PATCH': '#ff8c00',
    'OPTIONS': '#9d4edd', 'HEAD': '#6c7a96',
}

FONT_MONO  = ('JetBrains Mono', 10) if True else ('Consolas', 10)
FONT_MONO_SM = ('JetBrains Mono', 9)
FONT_MONO_LG = ('JetBrains Mono', 12, 'bold')
FONT_UI    = ('Segoe UI', 10)


class SentinelProxyApp:

    def __init__(self):
        self.root = tk.Tk()
        self.root.title("SentinelProxy  v1.0")
        self.root.geometry("1500x920")
        self.root.configure(bg=BG)
        self.root.minsize(1200, 700)

        # Try to set icon
        try:
            self.root.iconbitmap('/home/kali/osints/sentinel_proxy/ui/icon.ico')
        except Exception:
            pass

        self.proxy_running  = False
        self.intercept_mode = tk.BooleanVar(value=False)
        self.selected_req   = None
        self.filter_host    = tk.StringVar()
        self.filter_method  = tk.StringVar(value='ALL')
        self._intruder_running = False

        from sentinel_proxy.db.proxy_db import ProxyDB
        from sentinel_proxy.ai.analyzer import AIAnalyzer
        self.db       = ProxyDB()
        self.analyzer = AIAnalyzer()
        self.proxy    = None

        self._setup_styles()
        self._build_ui()
        self._load_history()

    # ── Styles ────────────────────────────────────────────────────────────────

    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use('clam')

        s.configure('.', background=BG, foreground=TEXT,
            fieldbackground=BG2, bordercolor=BORDER,
            troughcolor=BG3, selectbackground=ACCENT,
            selectforeground=BG, font=FONT_MONO)

        # Notebook
        s.configure('TNotebook', background=BG, borderwidth=0, tabmargins=0)
        s.configure('TNotebook.Tab', background=BG2, foreground=TEXT2,
            padding=[20, 9], font=('Consolas', 10), borderwidth=0)
        s.map('TNotebook.Tab',
            background=[('selected', BG3), ('active', BG4)],
            foreground=[('selected', ACCENT), ('active', TEXT)])

        s.configure('TFrame', background=BG)
        s.configure('TLabel', background=BG, foreground=TEXT)
        s.configure('TPanedwindow', background=BORDER)

        # Buttons
        s.configure('TButton', background=BG3, foreground=TEXT,
            bordercolor=BORDER, relief='flat', padding=[10, 5],
            font=('Consolas', 9))
        s.map('TButton',
            background=[('active', BG4), ('pressed', ACCENT2)],
            foreground=[('active', ACCENT)])

        s.configure('Cyan.TButton', background=ACCENT2, foreground=BG,
            font=('Consolas', 9, 'bold'), padding=[10, 5])
        s.map('Cyan.TButton', background=[('active', ACCENT)])

        s.configure('Green.TButton', background='#004d2a', foreground=GREEN,
            font=('Consolas', 9, 'bold'), padding=[10, 5])
        s.map('Green.TButton', background=[('active', '#006635')])

        s.configure('Red.TButton', background='#4d0011', foreground=RED,
            font=('Consolas', 9, 'bold'), padding=[10, 5])
        s.map('Red.TButton', background=[('active', '#660016')])

        s.configure('Ghost.TButton', background=BG, foreground=TEXT2,
            bordercolor=BORDER, relief='flat', padding=[8, 4],
            font=('Consolas', 9))
        s.map('Ghost.TButton',
            background=[('active', BG3)],
            foreground=[('active', TEXT)])

        # Entry
        s.configure('TEntry', fieldbackground=BG3, foreground=TEXT,
            insertcolor=ACCENT, bordercolor=BORDER, padding=[6, 4])

        # Combobox
        s.configure('TCombobox', fieldbackground=BG3, foreground=TEXT,
            selectbackground=ACCENT, bordercolor=BORDER)
        s.map('TCombobox', fieldbackground=[('readonly', BG3)])

        # Treeview
        s.configure('Treeview', background=BG2, foreground=TEXT,
            fieldbackground=BG2, rowheight=26, borderwidth=0)
        s.configure('Treeview.Heading', background=BG3, foreground=TEXT2,
            font=('Consolas', 9, 'bold'), relief='flat', padding=[8, 6])
        s.map('Treeview',
            background=[('selected', BG4)],
            foreground=[('selected', ACCENT)])
        s.map('Treeview.Heading',
            background=[('active', BG4)],
            foreground=[('active', ACCENT)])

        # Scrollbar
        s.configure('TScrollbar', background=BG3, troughcolor=BG2,
            bordercolor=BG, arrowcolor=TEXT3, relief='flat', width=8)
        s.map('TScrollbar', background=[('active', BG4)])

        # Checkbutton
        s.configure('TCheckbutton', background=BG3, foreground=TEXT2,
            font=('Consolas', 9))
        s.map('TCheckbutton', foreground=[('active', ACCENT)])

        # Separator
        s.configure('TSeparator', background=BORDER)

    # ── Main UI ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Title bar ──
        title = tk.Frame(self.root, bg=BG2, height=52)
        title.pack(fill='x', side='top')
        title.pack_propagate(False)

        # Left: logo + name
        left_title = tk.Frame(title, bg=BG2)
        left_title.pack(side='left', padx=0)

        # Accent bar on left edge
        tk.Frame(left_title, bg=ACCENT, width=3).pack(side='left', fill='y')

        tk.Label(left_title, text="  SENTINEL", bg=BG2, fg=ACCENT,
            font=('Consolas', 15, 'bold')).pack(side='left')
        tk.Label(left_title, text="PROXY", bg=BG2, fg=TEXT,
            font=('Consolas', 15, 'bold')).pack(side='left')
        tk.Label(left_title, text="  v1.0", bg=BG2, fg=TEXT3,
            font=('Consolas', 10)).pack(side='left', pady=2)

        tk.Label(left_title, text="  |  Autonomous Web Security Proxy",
            bg=BG2, fg=TEXT3, font=('Consolas', 9)).pack(side='left')

        # Right: status indicators
        right_title = tk.Frame(title, bg=BG2)
        right_title.pack(side='right', padx=16)

        # AI status
        ai_ok = self.analyzer._sentinel is not None
        gr_ok = self.analyzer._groq is not None
        ai_color = GREEN if ai_ok else TEXT3
        gr_color = GREEN if gr_ok else TEXT3

        tk.Label(right_title, text="SentinelNet",
            bg=BG2, fg=ai_color, font=('Consolas', 9)).pack(side='right', padx=4)
        tk.Label(right_title, text="AI:", bg=BG2, fg=TEXT3,
            font=('Consolas', 9)).pack(side='right')
        tk.Label(right_title, text="  |  ", bg=BG2, fg=TEXT3,
            font=('Consolas', 9)).pack(side='right')
        tk.Label(right_title, text="Groq",
            bg=BG2, fg=gr_color, font=('Consolas', 9)).pack(side='right', padx=4)
        tk.Label(right_title, text="LLM:", bg=BG2, fg=TEXT3,
            font=('Consolas', 9)).pack(side='right')

        self.lbl_req_count = tk.Label(right_title, text="0 requests",
            bg=BG2, fg=TEXT2, font=('Consolas', 9))
        self.lbl_req_count.pack(side='right', padx=12)

        self.lbl_proxy_status = tk.Label(right_title,
            text="OFFLINE", bg=BG2, fg=RED,
            font=('Consolas', 9, 'bold'))
        self.lbl_proxy_status.pack(side='right', padx=4)

        tk.Label(right_title, text="PROXY:", bg=BG2, fg=TEXT3,
            font=('Consolas', 9)).pack(side='right')

        # ── Control bar ──
        ctrl = tk.Frame(self.root, bg=BG3, height=42)
        ctrl.pack(fill='x', side='top')
        ctrl.pack_propagate(False)

        # Left controls
        lc = tk.Frame(ctrl, bg=BG3)
        lc.pack(side='left', padx=8, pady=5)

        self.btn_proxy = ttk.Button(lc, text="START PROXY",
            style='Green.TButton', command=self._toggle_proxy)
        self.btn_proxy.pack(side='left', padx=(0, 8))

        # Intercept toggle
        self.btn_intercept = tk.Label(lc, text="INTERCEPT: OFF",
            bg=BG4, fg=TEXT3, font=('Consolas', 9, 'bold'),
            padx=10, pady=4, cursor='hand2')
        self.btn_intercept.pack(side='left', padx=4)
        self.btn_intercept.bind('<Button-1>', self._toggle_intercept)

        # Separator
        tk.Frame(lc, bg=BORDER, width=1).pack(side='left', fill='y', padx=8)

        # Filter
        tk.Label(lc, text="HOST", bg=BG3, fg=TEXT3,
            font=('Consolas', 8)).pack(side='left', padx=(0,4))
        self.entry_filter = ttk.Entry(lc, textvariable=self.filter_host, width=22)
        self.entry_filter.pack(side='left', padx=(0,4))

        self.combo_method = ttk.Combobox(lc, textvariable=self.filter_method,
            values=['ALL','GET','POST','PUT','DELETE','PATCH','OPTIONS'],
            width=7, state='readonly')
        self.combo_method.pack(side='left', padx=(0,4))

        ttk.Button(lc, text="FILTER", style='Ghost.TButton',
            command=self._apply_filter).pack(side='left', padx=2)
        ttk.Button(lc, text="CLEAR", style='Ghost.TButton',
            command=self._clear_history).pack(side='left', padx=2)

        # Right controls
        rc = tk.Frame(ctrl, bg=BG3)
        rc.pack(side='right', padx=8, pady=5)

        ttk.Button(rc, text="INSTALL CERT", style='Cyan.TButton',
            command=self._show_cert_window).pack(side='right', padx=4)

        tk.Label(rc, text="PORT", bg=BG3, fg=TEXT3,
            font=('Consolas', 8)).pack(side='right', padx=(0,4))
        self.entry_port = ttk.Entry(rc, width=6)
        self.entry_port.insert(0, '8082')
        self.entry_port.pack(side='right', padx=(0,8))

        # ── Notebook ──
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill='both', expand=True)

        self._build_proxy_tab()
        self._build_repeater_tab()
        self._build_intruder_tab()
        self._build_scanner_tab()
        self._build_decoder_tab()

        # ── Status bar ──
        sb = tk.Frame(self.root, bg=BG2, height=22)
        sb.pack(fill='x', side='bottom')
        sb.pack_propagate(False)

        tk.Frame(sb, bg=ACCENT, width=2).pack(side='left', fill='y')

        self.lbl_status = tk.Label(sb,
            text="Ready  —  Set browser proxy to 127.0.0.1:8082",
            bg=BG2, fg=TEXT3, font=('Consolas', 8))
        self.lbl_status.pack(side='left', padx=8)

        tk.Label(sb, text="@who_is_the_black_hat",
            bg=BG2, fg=TEXT3, font=('Consolas', 8)).pack(side='right', padx=8)

    # ── Tab 1: Proxy ──────────────────────────────────────────────────────────

    def _build_proxy_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  Proxy  ')

        pw = ttk.PanedWindow(frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # ── Left: request list ──
        left = tk.Frame(pw, bg=BG)
        pw.add(left, weight=2)

        # Column headers label
        hdr = tk.Frame(left, bg=BG3, height=28)
        hdr.pack(fill='x')
        hdr.pack_propagate(False)
        for txt, w in [('#', 40),('Method', 70),('Host', 200),
                       ('Path', 260),('Status', 60),('Risk', 80),('Length', 70)]:
            tk.Label(hdr, text=txt, bg=BG3, fg=TEXT2,
                font=('Consolas', 8, 'bold'),
                width=w//8, anchor='w').pack(side='left', padx=4)

        # Treeview
        tree_frame = tk.Frame(left, bg=BG)
        tree_frame.pack(fill='both', expand=True)

        cols = ('id','method','host','path','status','risk','length')
        self.tree = ttk.Treeview(tree_frame, columns=cols,
            show='headings', selectmode='browse')

        self.tree.heading('id',     text='#')
        self.tree.heading('method', text='Method')
        self.tree.heading('host',   text='Host')
        self.tree.heading('path',   text='Path')
        self.tree.heading('status', text='Status')
        self.tree.heading('risk',   text='Risk')
        self.tree.heading('length', text='Length')

        self.tree.column('id',     width=40,  minwidth=40,  anchor='center')
        self.tree.column('method', width=70,  minwidth=60,  anchor='center')
        self.tree.column('host',   width=200, minwidth=120)
        self.tree.column('path',   width=260, minwidth=150)
        self.tree.column('status', width=60,  minwidth=50,  anchor='center')
        self.tree.column('risk',   width=80,  minwidth=70,  anchor='center')
        self.tree.column('length', width=70,  minwidth=60,  anchor='center')

        for sev, color in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)
        self.tree.tag_configure('flagged', background='#1a1000')
        self.tree.tag_configure('GET',    foreground='#00d4ff')
        self.tree.tag_configure('POST',   foreground='#00ff88')
        self.tree.tag_configure('DELETE', foreground='#ff3355')

        vsb = ttk.Scrollbar(tree_frame, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)
        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Double-1>', self._send_to_repeater)
        self.tree.bind('<Button-3>', self._tree_context_menu)

        # ── Right: detail ──
        right = tk.Frame(pw, bg=BG)
        pw.add(right, weight=3)

        # Action bar
        ab = tk.Frame(right, bg=BG3, height=34)
        ab.pack(fill='x')
        ab.pack_propagate(False)

        for txt, cmd in [
            ('Send to Repeater', self._send_to_repeater),
            ('Send to Intruder', self._send_to_intruder),
            ('Deep AI Scan',     self._deep_ai_scan),
            ('Flag Request',     self._flag_request),
            ('Copy URL',         self._copy_url),
        ]:
            ttk.Button(ab, text=txt, style='Ghost.TButton',
                command=cmd).pack(side='left', padx=4, pady=4)

        # Detail notebook
        dn = ttk.Notebook(right)
        dn.pack(fill='both', expand=True, padx=0, pady=0)

        rf = ttk.Frame(dn)
        dn.add(rf, text='  Request  ')
        self.txt_request = self._text(rf)

        rsf = ttk.Frame(dn)
        dn.add(rsf, text='  Response  ')
        self.txt_response = self._text(rsf)

        af = ttk.Frame(dn)
        dn.add(af, text='  AI Analysis  ')
        self.txt_ai = self._text(af, fg=GREEN)

    # ── Tab 2: Repeater ───────────────────────────────────────────────────────

    def _build_repeater_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  Repeater  ')

        # URL bar
        ub = tk.Frame(frame, bg=BG3, height=38)
        ub.pack(fill='x')
        ub.pack_propagate(False)

        self.rep_method = ttk.Combobox(ub,
            values=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'],
            width=8, state='readonly')
        self.rep_method.set('GET')
        self.rep_method.pack(side='left', padx=8, pady=5)

        self.rep_url = ttk.Entry(ub, font=('Consolas', 10))
        self.rep_url.pack(side='left', fill='x', expand=True, padx=4, pady=5)

        ttk.Button(ub, text="SEND", style='Cyan.TButton',
            command=self._repeater_send).pack(side='left', padx=4, pady=5)
        ttk.Button(ub, text="SAVE", style='Ghost.TButton',
            command=self._repeater_save).pack(side='left', padx=(0,8), pady=5)

        # Status
        self.rep_status_lbl = tk.Label(ub, text="",
            bg=BG3, fg=GREEN, font=('Consolas', 9, 'bold'))
        self.rep_status_lbl.pack(side='right', padx=12)

        # Split
        pw = ttk.PanedWindow(frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=1)
        tk.Label(lf, text="REQUEST", bg=BG, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(anchor='w', padx=8, pady=4)
        self.rep_req_txt = self._text(lf)

        rf2 = tk.Frame(pw, bg=BG)
        pw.add(rf2, weight=1)
        tk.Label(rf2, text="RESPONSE", bg=BG, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(anchor='w', padx=8, pady=4)
        self.rep_resp_txt = self._text(rf2)

    # ── Tab 3: Intruder ───────────────────────────────────────────────────────

    def _build_intruder_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  Intruder  ')

        # Config panel
        cfg = tk.Frame(frame, bg=BG3)
        cfg.pack(fill='x', padx=0, pady=0)

        inner = tk.Frame(cfg, bg=BG3)
        inner.pack(padx=12, pady=8)

        def lbl(parent, text):
            tk.Label(parent, text=text, bg=BG3, fg=TEXT3,
                font=('Consolas', 8, 'bold')).grid(
                row=0, column=0, sticky='w', padx=(0,6))

        # Row 1
        r1 = tk.Frame(inner, bg=BG3)
        r1.pack(fill='x', pady=2)
        tk.Label(r1, text="TARGET URL", bg=BG3, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(side='left', padx=(0,8))
        self.int_url = ttk.Entry(r1, width=55, font=('Consolas', 10))
        self.int_url.pack(side='left', padx=(0,16))
        tk.Label(r1, text="PARAMETER", bg=BG3, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(side='left', padx=(0,8))
        self.int_param = ttk.Entry(r1, width=18)
        self.int_param.pack(side='left')

        # Row 2
        r2 = tk.Frame(inner, bg=BG3)
        r2.pack(fill='x', pady=2)
        tk.Label(r2, text="ATTACK TYPE", bg=BG3, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(side='left', padx=(0,8))
        self.int_type = ttk.Combobox(r2, width=20, state='readonly',
            values=['SQLi','XSS','LFI','SSRF','SSTI','RCE','XXE',
                    'Open Redirect','LDAP','NoSQL','GraphQL','JWT',
                    'CORS','CRLF','Path Traversal','File Upload',
                    'Prototype Pollution','Request Smuggling',
                    'Cache Deception','XPATH','Custom'])
        self.int_type.set('SQLi')
        self.int_type.pack(side='left', padx=(0,16))
        self.int_type.bind('<<ComboboxSelected>>', self._load_payloads)
        tk.Label(r2, text="THREADS", bg=BG3, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(side='left', padx=(0,8))
        self.int_threads = ttk.Entry(r2, width=5)
        self.int_threads.insert(0, '10')
        self.int_threads.pack(side='left', padx=(0,16))
        ttk.Button(r2, text="START ATTACK", style='Red.TButton',
            command=self._intruder_start).pack(side='left', padx=4)
        ttk.Button(r2, text="STOP", style='Ghost.TButton',
            command=self._intruder_stop).pack(side='left', padx=4)
        self.int_progress = tk.Label(r2, text="",
            bg=BG3, fg=TEXT2, font=('Consolas', 9))
        self.int_progress.pack(side='left', padx=8)

        # Split
        pw = ttk.PanedWindow(frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=1)
        tk.Label(lf, text="PAYLOADS", bg=BG, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(anchor='w', padx=8, pady=4)
        self.int_payloads_txt = self._text(lf)

        rf3 = tk.Frame(pw, bg=BG)
        pw.add(rf3, weight=2)
        tk.Label(rf3, text="RESULTS", bg=BG, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(anchor='w', padx=8, pady=4)

        cols = ('payload','status','length','flag')
        self.int_tree = ttk.Treeview(rf3, columns=cols, show='headings')
        self.int_tree.heading('payload', text='Payload')
        self.int_tree.heading('status',  text='Status',  anchor='center')
        self.int_tree.heading('length',  text='Length',  anchor='center')
        self.int_tree.heading('flag',    text='!',       anchor='center')
        self.int_tree.column('payload', width=320)
        self.int_tree.column('status',  width=65,  anchor='center')
        self.int_tree.column('length',  width=80,  anchor='center')
        self.int_tree.column('flag',    width=30,  anchor='center')
        self.int_tree.tag_configure('interesting', foreground=ORANGE)
        vsb2 = ttk.Scrollbar(rf3, orient='vertical', command=self.int_tree.yview)
        self.int_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side='right', fill='y')
        self.int_tree.pack(fill='both', expand=True)
        self._load_payloads()

    # ── Tab 4: Scanner ────────────────────────────────────────────────────────

    def _build_scanner_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  Scanner  ')

        ub = tk.Frame(frame, bg=BG3, height=38)
        ub.pack(fill='x')
        ub.pack_propagate(False)

        tk.Label(ub, text="TARGET", bg=BG3, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(side='left', padx=8, pady=10)
        self.scan_url = ttk.Entry(ub, width=50, font=('Consolas', 10))
        self.scan_url.pack(side='left', padx=4, pady=5)
        ttk.Button(ub, text="RUN AI SCAN", style='Cyan.TButton',
            command=self._scanner_run).pack(side='left', padx=4, pady=5)
        ttk.Button(ub, text="CLEAR", style='Ghost.TButton',
            command=lambda: self.scan_out.delete('1.0','end')).pack(side='left', padx=4, pady=5)

        self.scan_out = self._text(frame, fg=GREEN)

    # ── Tab 5: Decoder ────────────────────────────────────────────────────────

    def _build_decoder_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  Decoder  ')

        ub = tk.Frame(frame, bg=BG3, height=38)
        ub.pack(fill='x')
        ub.pack_propagate(False)

        modes = ['URL Encode','URL Decode','Base64 Encode','Base64 Decode',
                 'HTML Encode','HTML Decode','Hex Encode','Hex Decode',
                 'MD5 Hash','SHA1 Hash','SHA256 Hash']
        self.dec_mode = ttk.Combobox(ub, values=modes, width=18, state='readonly')
        self.dec_mode.set('URL Decode')
        self.dec_mode.pack(side='left', padx=8, pady=5)
        ttk.Button(ub, text="CONVERT", style='Cyan.TButton',
            command=self._decode_convert).pack(side='left', padx=4, pady=5)
        ttk.Button(ub, text="SWAP", style='Ghost.TButton',
            command=self._decode_swap).pack(side='left', padx=4, pady=5)

        pw = ttk.PanedWindow(frame, orient='vertical')
        pw.pack(fill='both', expand=True)

        tf = tk.Frame(pw, bg=BG)
        pw.add(tf, weight=1)
        tk.Label(tf, text="INPUT", bg=BG, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(anchor='w', padx=8, pady=4)
        self.dec_input = self._text(tf)

        bf = tk.Frame(pw, bg=BG)
        pw.add(bf, weight=1)
        tk.Label(bf, text="OUTPUT", bg=BG, fg=TEXT3,
            font=('Consolas', 8, 'bold')).pack(anchor='w', padx=8, pady=4)
        self.dec_output = self._text(bf)

    # ── Helper ────────────────────────────────────────────────────────────────

    def _text(self, parent, fg=None):
        f = tk.Frame(parent, bg=BG)
        f.pack(fill='both', expand=True)
        t = tk.Text(f, bg=BG2, fg=fg or TEXT,
            insertbackground=ACCENT,
            selectbackground=BG4, selectforeground=ACCENT,
            font=('Consolas', 10), relief='flat',
            borderwidth=0, wrap='none',
            padx=8, pady=6)
        vs = ttk.Scrollbar(f, orient='vertical', command=t.yview)
        hs = ttk.Scrollbar(f, orient='horizontal', command=t.xview)
        t.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side='right', fill='y')
        hs.pack(side='bottom', fill='x')
        t.pack(fill='both', expand=True)
        return t

    def _set_status(self, msg):
        self.lbl_status.config(text=msg)

    # ── Proxy ─────────────────────────────────────────────────────────────────

    def _toggle_proxy(self):
        if self.proxy_running:
            if self.proxy: self.proxy.stop()
            self.proxy_running = False
            self.btn_proxy.config(text="START PROXY", style='Green.TButton')
            self.lbl_proxy_status.config(text="OFFLINE", fg=RED)
            self._set_status("Proxy stopped")
        else:
            port = int(self.entry_port.get() or 8082)
            from sentinel_proxy.core.proxy_core import ProxyCore
            self.proxy = ProxyCore(port=port)
            self.proxy.on_request  = self._on_proxy_request
            self.proxy.on_response = self._on_proxy_response
            if self.proxy.start():
                self.proxy_running = True
                self.btn_proxy.config(text="STOP PROXY", style='Red.TButton')
                self.lbl_proxy_status.config(
                    text=f"ONLINE :{port}", fg=GREEN)
                self._set_status(f"Proxy running on 127.0.0.1:{port}")
            else:
                messagebox.showerror("Error", "pip install mitmproxy")

    def _toggle_intercept(self, event=None):
        val = not self.intercept_mode.get()
        self.intercept_mode.set(val)
        if val:
            self.btn_intercept.config(text="INTERCEPT: ON",
                bg='#001a00', fg=GREEN)
        else:
            self.btn_intercept.config(text="INTERCEPT: OFF",
                bg=BG4, fg=TEXT3)

    def _on_proxy_request(self, flow):
        row_id = self.db.save_request(flow)
        result = self.analyzer.analyze(flow)
        self.db.update_ai(row_id, result['risk'], result['vulns'], result['summary'])
        flow['_ai'] = result
        self.root.after(0, self._add_to_tree, flow, row_id, result)

    def _on_proxy_response(self, flow): pass

    def _add_to_tree(self, flow, row_id, ai):
        risk = ai.get('risk','UNKNOWN')
        self.tree.insert('', 0, iid=str(row_id),
            values=(row_id, flow.get('method',''),
                    flow.get('host','')[:40], flow.get('path','')[:60],
                    flow.get('status_code','') or '',
                    risk, flow.get('resp_length','') or ''),
            tags=(risk,))
        if risk == 'CRITICAL':
            self.db.flag_request(row_id, True)
            self.tree.item(str(row_id), tags=(risk,'flagged'))
        count = len(self.tree.get_children())
        self.lbl_req_count.config(text=f"{count} requests")

    # ── Selection ─────────────────────────────────────────────────────────────

    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel: return
        row_id = int(sel[0])
        self.selected_req = row_id
        req = self.db.get_request(row_id)
        if not req: return

        self.txt_request.delete('1.0','end')
        hdrs = json.loads(req.get('headers','{}'))
        rt = f"{req.get('method','')} {req.get('path','')} HTTP/1.1\nHost: {req.get('host','')}\n"
        for k,v in hdrs.items(): rt += f"{k}: {v}\n"
        if req.get('body'): rt += f"\n{req['body']}"
        self.txt_request.insert('1.0', rt)

        self.txt_response.delete('1.0','end')
        if req.get('status_code'):
            rsp = f"HTTP/1.1 {req.get('status_code','')}\n"
            if req.get('resp_body'): rsp += f"\n{req['resp_body'][:5000]}"
            self.txt_response.insert('1.0', rsp)

        self.txt_ai.delete('1.0','end')
        vulns = json.loads(req.get('ai_vulns','[]'))
        risk  = req.get('ai_risk','UNKNOWN')
        at = f"Risk     : {risk}\nSummary  : {req.get('ai_summary','')}\n\n"
        if vulns:
            at += "Vulnerabilities:\n"
            for v in vulns:
                at += f"  [{v.get('severity','?')}] {v.get('type','?')}\n"
                at += f"    {v.get('detail','')}\n\n"
            at += "Suggested Payloads:\n"
            for v in vulns[:2]:
                at += f"\n  {v.get('type','')}:\n"
                for p in self.analyzer.suggest_payloads(v.get('type',''))[:4]:
                    at += f"    {p}\n"
        else:
            at += "No vulnerabilities detected.\nUse Deep AI Scan for Groq analysis.\n"
        self.txt_ai.insert('1.0', at)

    def _tree_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if not item: return
        self.tree.selection_set(item)
        self.selected_req = int(item)
        m = tk.Menu(self.root, tearoff=0, bg=BG3, fg=TEXT,
            activebackground=BG4, activeforeground=ACCENT,
            font=('Consolas', 9))
        m.add_command(label="Send to Repeater", command=self._send_to_repeater)
        m.add_command(label="Send to Intruder", command=self._send_to_intruder)
        m.add_command(label="Deep AI Scan",     command=self._deep_ai_scan)
        m.add_separator()
        m.add_command(label="Flag / Unflag",    command=self._flag_request)
        m.add_command(label="Copy URL",         command=self._copy_url)
        m.post(event.x_root, event.y_root)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _send_to_repeater(self, event=None):
        if not self.selected_req: return
        req = self.db.get_request(self.selected_req)
        if not req: return
        self.rep_method.set(req.get('method','GET'))
        self.rep_url.delete(0,'end')
        self.rep_url.insert(0, req.get('url',''))
        hdrs = json.loads(req.get('headers','{}'))
        rt = f"{req.get('method','')} {req.get('path','')} HTTP/1.1\nHost: {req.get('host','')}\n"
        for k,v in hdrs.items(): rt += f"{k}: {v}\n"
        if req.get('body'): rt += f"\n{req['body']}"
        self.rep_req_txt.delete('1.0','end')
        self.rep_req_txt.insert('1.0', rt)
        self.nb.select(1)

    def _send_to_intruder(self):
        if not self.selected_req: return
        req = self.db.get_request(self.selected_req)
        if not req: return
        self.int_url.delete(0,'end')
        self.int_url.insert(0, req.get('url',''))
        self.nb.select(2)

    def _deep_ai_scan(self):
        if not self.selected_req: return
        req = self.db.get_request(self.selected_req)
        if not req: return
        self.txt_ai.insert('end', "\n\nRunning Groq deep analysis...\n")
        def cb(r):
            self.root.after(0, lambda: self.txt_ai.insert('end',
                f"\n-- Groq --\nRisk: {r.get('risk','?')}\n"
                f"Vulns: {', '.join(r.get('vulns',[]))}\n"
                f"Detail: {r.get('detail','')}\n"
                f"Fix: {r.get('fix','')}\n"))
        self.analyzer.analyze_deep(req, callback=cb)

    def _flag_request(self):
        if not self.selected_req: return
        req = self.db.get_request(self.selected_req)
        flagged = not bool(req.get('flagged',0))
        self.db.flag_request(self.selected_req, flagged)
        self._set_status(f"{'Flagged' if flagged else 'Unflagged'}: #{self.selected_req}")

    def _copy_url(self):
        if not self.selected_req: return
        req = self.db.get_request(self.selected_req)
        if req:
            self.root.clipboard_clear()
            self.root.clipboard_append(req.get('url',''))
            self._set_status("URL copied")

    # ── Repeater ──────────────────────────────────────────────────────────────

    def _repeater_send(self):
        url = self.rep_url.get().strip()
        method = self.rep_method.get()
        if not url: return
        raw = self.rep_req_txt.get('1.0','end').strip()
        headers, body, in_body = {}, '', False
        for line in raw.split('\n')[1:]:
            if not line.strip(): in_body = True; continue
            if in_body: body += line + '\n'
            elif ':' in line:
                k,_,v = line.partition(':')
                headers[k.strip()] = v.strip()
        def _go():
            try:
                self.root.after(0, lambda: self.rep_status_lbl.config(
                    text="Sending...", fg=YELLOW))
                r = requests.request(method, url, headers=headers,
                    data=body.encode() if body else None,
                    verify=False, timeout=15, allow_redirects=False)
                sc = GREEN if r.status_code < 400 else (ORANGE if r.status_code < 500 else RED)
                rt = f"HTTP/1.1 {r.status_code} {r.reason}\n"
                for k,v in r.headers.items(): rt += f"{k}: {v}\n"
                rt += f"\n{r.text[:10000]}"
                self.root.after(0, lambda: [
                    self.rep_resp_txt.delete('1.0','end'),
                    self.rep_resp_txt.insert('1.0', rt),
                    self.rep_status_lbl.config(
                        text=f"{r.status_code} {r.reason}  {len(r.content)}b", fg=sc)])
            except Exception as e:
                self.root.after(0, lambda: self.rep_status_lbl.config(
                    text=str(e)[:60], fg=RED))
        threading.Thread(target=_go, daemon=True).start()

    def _repeater_save(self):
        url = self.rep_url.get().strip()
        if url:
            self.db.save_to_repeater(f"{self.rep_method.get()} {url[:40]}",
                self.rep_method.get(), url, {}, '')
            self._set_status("Saved")

    # ── Intruder ──────────────────────────────────────────────────────────────

    def _load_payloads(self, event=None):
        vuln_type = self.int_type.get()
        p = self._load_payloads_from_file(vuln_type)
        if not p:
            p = self.analyzer.suggest_payloads(vuln_type)
        self.int_payloads_txt.delete('1.0','end')
        self.int_payloads_txt.insert('1.0', '\n'.join(p))

    def _load_payloads_from_file(self, vuln_type: str) -> list:
        FILE_MAP = {
            'SQLi': 'sqli.txt', 'XSS': 'xss.txt', 'LFI': 'lfi.txt',
            'SSRF': 'ssrf.txt', 'SSTI': 'ssti.txt', 'RCE': 'rce.txt',
            'XXE': 'xxe.txt', 'Open Redirect': 'open_redirect.txt',
            'LDAP': 'ldap.txt', 'NoSQL': 'nosql.txt', 'GraphQL': 'graphql.txt',
            'JWT': 'jwt.txt', 'CORS': 'cors.txt', 'CRLF': 'crlf.txt',
            'Path Traversal': 'path_traversal.txt', 'File Upload': 'file_upload.txt',
            'Prototype Pollution': 'prototype_pollution.txt',
            'Request Smuggling': 'smuggling.txt', 'Cache Deception': 'cache_deception.txt',
            'XPATH': 'xpath.txt',
        }
        fname = FILE_MAP.get(vuln_type)
        if not fname:
            return []
        try:
            from pathlib import Path as _Path
            fpath = _Path(__file__).parent.parent / 'payloads' / fname
            lines = fpath.read_text(errors='ignore').splitlines()
            return [l for l in lines if l.strip()][:2000]  # max 2000
        except Exception:
            return []

    def _intruder_start(self):
        url = self.int_url.get().strip()
        param = self.int_param.get().strip()
        payloads = [p.strip() for p in
            self.int_payloads_txt.get('1.0','end').strip().split('\n') if p.strip()]
        threads_n = int(self.int_threads.get() or 10)
        if not url or not param:
            messagebox.showwarning("Intruder", "URL and Parameter required"); return
        if not payloads:
            messagebox.showwarning("Intruder", "No payloads"); return
        for i in self.int_tree.get_children(): self.int_tree.delete(i)
        self._intruder_running = True
        session_id = str(int(time.time()))
        def _run():
            import urllib.parse
            from concurrent.futures import ThreadPoolExecutor
            done = [0]; base = []
            def _send(payload):
                if not self._intruder_running: return
                try:
                    sep = '&' if '?' in url else '?'
                    r = requests.get(f"{url}{sep}{param}={urllib.parse.quote(payload)}",
                        verify=False, timeout=8, allow_redirects=False)
                    l = len(r.content)
                    interesting = r.status_code not in (200,301,302,404) or \
                        (base and abs(l - base[0]) > 100)
                    if not base: base.append(l)
                    done[0] += 1
                    self.db.save_intruder_result(session_id, payload,
                        r.status_code, l, r.text[:500], interesting)
                    self.root.after(0, lambda p=payload,s=r.status_code,
                        ln=l,i=interesting: [
                        self.int_tree.insert('','end',
                            values=(p[:60],s,ln,'!' if i else ''),
                            tags=('interesting',) if i else ()),
                        self.int_progress.config(text=f"{done[0]}/{len(payloads)}")])
                except: done[0] += 1
            with ThreadPoolExecutor(max_workers=threads_n) as ex:
                ex.map(_send, payloads)
            self.root.after(0, lambda: [
                self.int_progress.config(text=f"Done  {len(payloads)} sent"),
                self._set_status("Intruder complete")])
            self._intruder_running = False
        threading.Thread(target=_run, daemon=True).start()

    def _intruder_stop(self):
        self._intruder_running = False

    # ── Scanner ───────────────────────────────────────────────────────────────

    def _scanner_run(self):
        url = self.scan_url.get().strip()
        if not url: return
        self.scan_out.delete('1.0','end')
        self.scan_out.insert('end', f"Scanning {url}...\n\n")
        def _run():
            for vuln, tu in [('SQLi',f"{url}?id=1'"),('XSS',f"{url}?q=<script>alert(1)</script>"),
                              ('LFI',f"{url}?f=../etc/passwd"),('SSRF',f"{url}?url=http://127.0.0.1/")]:
                try:
                    r = requests.get(tu, verify=False, timeout=5, allow_redirects=False)
                    res = self.analyzer.analyze({'url':tu,'method':'GET','body':'',
                        'params':{},'resp_body':r.text[:2000],'status_code':r.status_code})
                    self.root.after(0, lambda l=f"[{res['risk']}] {vuln}: {res['summary']}\n":
                        self.scan_out.insert('end', l))
                except Exception as e:
                    self.root.after(0, lambda e=e:
                        self.scan_out.insert('end', f"[ERROR] {e}\n"))
            if self.analyzer._groq:
                self.root.after(0, lambda: self.scan_out.insert('end',"\nGroq analysis...\n"))
                out = self.analyzer._groq.ask(
                    f"Quick security assessment of {url}. Check SQLi,XSS,LFI,SSRF. Bullet points.",
                    max_tokens=300)
                self.root.after(0, lambda: self.scan_out.insert('end', f"\n{out}\n"))
            self.root.after(0, lambda: self.scan_out.insert('end',"\nScan complete.\n"))
        threading.Thread(target=_run, daemon=True).start()

    # ── Decoder ───────────────────────────────────────────────────────────────

    def _decode_convert(self):
        text = self.dec_input.get('1.0','end').strip()
        mode = self.dec_mode.get()
        try:
            import urllib.parse, base64, html, hashlib
            r = {
                'URL Encode':     lambda: urllib.parse.quote(text),
                'URL Decode':     lambda: urllib.parse.unquote(text),
                'Base64 Encode':  lambda: base64.b64encode(text.encode()).decode(),
                'Base64 Decode':  lambda: base64.b64decode(text).decode('utf-8','replace'),
                'HTML Encode':    lambda: html.escape(text),
                'HTML Decode':    lambda: html.unescape(text),
                'Hex Encode':     lambda: text.encode().hex(),
                'Hex Decode':     lambda: bytes.fromhex(text).decode('utf-8','replace'),
                'MD5 Hash':       lambda: hashlib.md5(text.encode()).hexdigest(),
                'SHA1 Hash':      lambda: hashlib.sha1(text.encode()).hexdigest(),
                'SHA256 Hash':    lambda: hashlib.sha256(text.encode()).hexdigest(),
            }.get(mode, lambda: text)()
        except Exception as e:
            r = f"Error: {e}"
        self.dec_output.delete('1.0','end')
        self.dec_output.insert('1.0', r)

    def _decode_swap(self):
        a = self.dec_input.get('1.0','end').strip()
        b = self.dec_output.get('1.0','end').strip()
        self.dec_input.delete('1.0','end'); self.dec_input.insert('1.0', b)
        self.dec_output.delete('1.0','end'); self.dec_output.insert('1.0', a)

    # ── Filter / History ──────────────────────────────────────────────────────

    def _apply_filter(self):
        host = self.filter_host.get().strip()
        method = self.filter_method.get()
        if method == 'ALL': method = ''
        rows = self.db.get_requests(500, host, method)
        for i in self.tree.get_children(): self.tree.delete(i)
        for r in rows:
            risk = r.get('ai_risk','UNKNOWN')
            self.tree.insert('','end', iid=str(r['id']),
                values=(r['id'],r.get('method',''),r.get('host','')[:40],
                    r.get('path','')[:60],r.get('status_code',''),
                    risk,r.get('resp_length','')),
                tags=(risk,'flagged') if r.get('flagged') else (risk,))

    def _load_history(self):
        for r in self.db.get_requests(200):
            risk = r.get('ai_risk','UNKNOWN')
            self.tree.insert('','end', iid=str(r['id']),
                values=(r['id'],r.get('method',''),r.get('host','')[:40],
                    r.get('path','')[:60],r.get('status_code',''),
                    risk,r.get('resp_length','')),
                tags=(risk,'flagged') if r.get('flagged') else (risk,))
        self.lbl_req_count.config(
            text=f"{len(self.tree.get_children())} requests")

    def _clear_history(self):
        if messagebox.askyesno("Clear History","Clear all requests?"):
            self.db.clear_history()
            for i in self.tree.get_children(): self.tree.delete(i)
            self.lbl_req_count.config(text="0 requests")

    # ── Cert Window ───────────────────────────────────────────────────────────

    def _show_cert_window(self):
        import shutil, subprocess
        from pathlib import Path
        cert = Path.home() / '.mitmproxy' / 'mitmproxy-ca-cert.pem'

        w = tk.Toplevel(self.root)
        w.title("Install CA Certificate")
        w.geometry("580x480")
        w.configure(bg=BG)
        w.resizable(False, False)

        tk.Frame(w, bg=ACCENT, height=2).pack(fill='x')
        tk.Label(w, text="CA CERTIFICATE INSTALLER", bg=BG, fg=ACCENT,
            font=('Consolas', 13, 'bold')).pack(pady=12)

        sf = tk.Frame(w, bg=BG3)
        sf.pack(fill='x', padx=16, pady=4)
        tk.Label(sf,
            text=("Certificate: " + str(cert)) if cert.exists() else "Start proxy first",
            bg=BG3, fg=GREEN if cert.exists() else RED,
            font=('Consolas', 9)).pack(padx=8, pady=8)

        bf = tk.Frame(w, bg=BG)
        bf.pack(fill='x', padx=16, pady=8)
        ttk.Button(bf, text="Open Folder",
            command=lambda: subprocess.Popen(['xdg-open', str(cert.parent)])).pack(side='left', padx=4)
        ttk.Button(bf, text="Copy Path",
            command=lambda: [w.clipboard_clear(), w.clipboard_append(str(cert))]).pack(side='left', padx=4)
        ttk.Button(bf, text="Install System-wide", style='Green.TButton',
            command=lambda: self._install_cert_system(cert)).pack(side='left', padx=4)

        nb2 = ttk.Notebook(w)
        nb2.pack(fill='both', expand=True, padx=16, pady=8)

        def tab(title, text):
            f = ttk.Frame(nb2); nb2.add(f, text=title)
            t = tk.Text(f, bg=BG2, fg=TEXT, font=('Consolas', 9),
                relief='flat', wrap='word', padx=8, pady=6)
            t.pack(fill='both', expand=True)
            t.insert('1.0', text); t.config(state='disabled')

        tab(' Firefox ', (
            "1. Firefox Settings > Privacy & Security\n"
            "2. Certificates > View Certificates\n"
            "3. Authorities tab > Import\n"
            "4. Select: " + str(cert) + "\n"
            "5. Check: Trust this CA to identify websites\n"
            "6. OK > Restart Firefox\n\n"
            "Proxy: Settings > Network > Manual\n"
            "HTTP Proxy: 127.0.0.1   Port: 8082\n"
            "Also use for HTTPS: checked"))

        tab(' Chromium ', (
            "No cert needed — run with flags:\n\n"
            "chromium --proxy-server=http://127.0.0.1:8082 \\\n"
            "         --ignore-certificate-errors \\\n"
            "         --user-data-dir=/tmp/proxy-test\n\n"
            "Or install cert:\n"
            "Settings > Privacy > Manage Certificates\n"
            "Authorities > Import > " + str(cert)))

        try:
            import socket
            s = socket.socket(); s.connect(('8.8.8.8',80))
            ip = s.getsockname()[0]; s.close()
        except: ip = '192.168.x.x'

        tab(' Mobile ', (
            "1. Connect to same WiFi\n"
            "2. Set WiFi proxy:\n"
            "   Host: " + ip + "\n"
            "   Port: 8082\n\n"
            "3. Open browser > http://mitm.it\n"
            "4. Download & install certificate\n\n"
            "Android: Settings > Security > Install Certificate\n"
            "iOS: Settings > General > VPN & Device Management"))

    def _install_cert_system(self, cert):
        import shutil, subprocess
        try:
            from pathlib import Path
            dst = Path('/usr/local/share/ca-certificates/mitmproxy-ca.crt')
            shutil.copy2(cert, dst)
            subprocess.run(['update-ca-certificates'], check=True)
            messagebox.showinfo("Done", "System CA updated successfully!")
        except Exception:
            messagebox.showerror("Error",
                f"Run manually:\nsudo cp {cert} /usr/local/share/ca-certificates/mitmproxy-ca.crt\nsudo update-ca-certificates")

    def run(self):
        self.root.mainloop()
