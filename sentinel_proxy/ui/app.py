"""
SentinelProxy UI — Professional Hacker Theme
Dark navy · Fira Code · Full featured
"""
import tkinter as tk
from tkinter import ttk, messagebox
import threading, json, sys, time, requests, urllib.parse, re, logging
from datetime import datetime
from pathlib import Path

sys.path.insert(0, '/home/kali/osints')

logger = logging.getLogger(__name__)


class _SafeAnalyzer:
    """Stub analyzer — used when AIAnalyzer fails to load."""
    _sentinel = None
    _groq     = None

    def analyze(self, flow):
        return {'risk': 'UNKNOWN', 'vulns': [], 'summary': '', 'confidence': 0.0}

    def analyze_deep(self, flow, callback=None):
        if callback:
            callback({'risk': 'UNKNOWN', 'vulns': [], 'detail': 'AI not available', 'fix': ''})

    def suggest_payloads(self, vuln_type, param=''):
        return []


# ── Fonts ─────────────────────────────────────────────────────────────────────
FONT_MONO    = ('Fira Code', 10)
FONT_MONO_SM = ('Fira Code', 9)
FONT_MONO_LG = ('Fira Code', 13, 'bold')
FONT_MONO_XS = ('Fira Code', 8)
FONT_BOLD    = ('Fira Code', 10, 'bold')
FONT_TITLE   = ('Fira Code', 15, 'bold')
FONT_ICON    = ('Fira Code', 11)

# ── Color Palette — Deep Hacker Green/Teal on Near-Black ──────────────────────
BG        = '#080c0e'   # deepest black-green
BG2       = '#0d1214'   # panel bg
BG3       = '#111a1d'   # toolbar bg
BG4       = '#162024'   # input bg
BG5       = '#1c2a2f'   # hover
BORDER    = '#1e3035'   # subtle border
BORDER2   = '#0f4a52'   # accent border

ACCENT    = '#00e5c0'   # neon teal — primary accent
ACCENT2   = '#00b89a'   # teal darker
ACCENT3   = '#003d35'   # teal bg tint

GREEN     = '#39ff6e'   # neon green
GREEN2    = '#1a7a3a'   # green darker
GREEN_DIM = '#0d3d1e'   # green bg tint

RED       = '#ff3b5c'   # neon red
RED2      = '#c0213a'   # red darker
RED_DIM   = '#3d0d18'   # red bg tint

ORANGE    = '#ff8c00'   # neon orange
YELLOW    = '#ffe033'   # neon yellow
PURPLE    = '#c77dff'   # neon purple
CYAN      = '#00e5c0'   # same as accent

TEXT      = '#cde8e0'   # soft green-white
TEXT2     = '#5a8a80'   # muted teal
TEXT3     = '#2a4a45'   # very muted

CRITICAL  = '#ff3b5c'
HIGH      = '#ff8c00'
MEDIUM    = '#ffe033'
LOW       = '#39ff6e'

SEV_COLOR = {
    'CRITICAL': CRITICAL, 'HIGH': HIGH,
    'MEDIUM': MEDIUM, 'LOW': LOW, 'UNKNOWN': TEXT2
}

# ── Octopus ASCII art for onboarding ──────────────────────────────────────────
OCTOPUS_ART = r"""
        ___________
       /           \
      | (o)     (o) |
      |      ^      |
      |   \_____/   |
       \___________/
    ~~~/ /  | |  \ \~~~
  ~~~ / /   | |   \ \ ~~~
  ~~ / /    | |    \ \ ~~
  ~ /_(     | |     )_\ ~
  ~~ ~~     | |     ~~ ~~
"""


class SentinelProxyApp:

    def __init__(self, rust_bridge=None):
        self.root = tk.Tk()
        self._rust_bridge = rust_bridge
        self.root.title("SentinelProxy v1.0  —  @who_is_the_black_hat")
        self.root.geometry("1600x950")
        self.root.configure(bg=BG)
        self.root.minsize(1200, 700)

        # Set window icon
        self._icon_photo    = None
        self._icon_photo_32 = None
        self._set_window_icon(self.root)

        self.proxy_running     = False
        self.intercept_on      = False
        self.selected_req      = None
        self.filter_host       = tk.StringVar()
        self.filter_method     = tk.StringVar(value='ALL')
        self._intruder_running = False
        self._req_counter      = 0

        from sentinel_proxy.db.proxy_db import ProxyDB
        from sentinel_proxy.ai.analyzer import AIAnalyzer
        self.db       = ProxyDB()
        self.analyzer = None   # loaded in background
        self.proxy    = None

        # Wire rust_bridge callbacks if provided
        if self._rust_bridge:
            self._rust_bridge.on_request    = self._on_proxy_request
            self._rust_bridge.on_response   = self._on_proxy_response
            self._rust_bridge.on_websocket  = self._on_proxy_websocket
            self._rust_bridge.on_intercepted = self._on_intercept_held

        # Load analyzer synchronously with a safe stub so UI never crashes
        try:
            self.analyzer = AIAnalyzer()
        except Exception:
            self.analyzer = _SafeAnalyzer()

        # Tab state variables — initialized before _build_ui
        self._mr_rules           = []
        self._hl_rules           = []
        self._af_running         = False
        self._af_params          = []
        self._as_running         = False
        self._scope_match_counts = {}
        self._report_html        = ''
        self._intercept_pending  = False   # True when a flow is held
        self._current_intercept_id = ''      # flow_id of held request
        self._rep_history        = []      # Repeater send history

        self._setup_styles()
        self._show_onboarding()

    # ── Icon ──────────────────────────────────────────────────────────────────

    def _set_window_icon(self, window):
        """Set SentinelProxy icon on any Tk window."""
        try:
            from sentinel_proxy.icon_generator import get_tk_icon, ICON_DIR
            ico_path = ICON_DIR / 'sentinel_proxy_icon.ico'
            if not ico_path.exists():
                from sentinel_proxy.icon_generator import generate_all_icons
                generate_all_icons()
            if self._icon_photo is None:
                self._icon_photo    = get_tk_icon(window, 64)
                self._icon_photo_32 = get_tk_icon(window, 32)
            window.iconphoto(True, self._icon_photo, self._icon_photo_32)
        except Exception:
            pass

    # ── Styles ────────────────────────────────────────────────────────────────

    # ── Onboarding Screen ─────────────────────────────────────────────────────

    def _show_onboarding(self):
        """Full-screen onboarding splash — figlet title + octopus art."""
        self.root.withdraw()

        splash = tk.Toplevel()
        splash.title('')
        splash.geometry('980x660')
        splash.configure(bg=BG)
        splash.resizable(False, False)
        splash.overrideredirect(True)
        self._set_window_icon(splash)

        # Center
        splash.update_idletasks()
        sw = splash.winfo_screenwidth()
        sh = splash.winfo_screenheight()
        splash.geometry(f'980x660+{(sw-980)//2}+{(sh-660)//2}')

        # Outer neon border
        outer = tk.Frame(splash, bg=ACCENT, padx=2, pady=2)
        outer.pack(fill='both', expand=True)
        inner = tk.Frame(outer, bg=BG)
        inner.pack(fill='both', expand=True)

        # Top bar
        top = tk.Frame(inner, bg=BG3, height=32)
        top.pack(fill='x')
        top.pack_propagate(False)
        tk.Label(top, text='  ⬡  SENTINELPROXY  —  LOADING',
            bg=BG3, fg=ACCENT, font=('Fira Code', 8, 'bold')).pack(side='left', padx=10, pady=7)
        tk.Label(top, text='v1.0  ·  @who_is_the_black_hat  ',
            bg=BG3, fg=TEXT3, font=FONT_MONO_XS).pack(side='right', pady=7)
        tk.Frame(top, bg=ACCENT, height=1).pack(side='bottom', fill='x')

        # Body
        body = tk.Frame(inner, bg=BG)
        body.pack(fill='both', expand=True)

        # ── Left panel — octopus ──────────────────────────────────────────────
        left = tk.Frame(body, bg=BG2, width=320)
        left.pack(side='left', fill='y')
        left.pack_propagate(False)
        tk.Frame(left, bg=BORDER2, width=1).pack(side='right', fill='y')

        # Icon image on splash left panel
        try:
            from sentinel_proxy.icon_generator import get_tk_icon
            _splash_icon = get_tk_icon(splash, 64)
            icon_lbl = tk.Label(left, image=_splash_icon, bg=BG2)
            icon_lbl.image = _splash_icon   # keep reference
            icon_lbl.pack(pady=(14, 0))
        except Exception:
            pass

        # Figlet "PROXY" in slant font — small, on top of octopus
        try:
            import pyfiglet
            proxy_art = pyfiglet.figlet_format('PROXY', font='slant')
        except Exception:
            proxy_art = '  P R O X Y'

        tk.Label(left, text=proxy_art,
            bg=BG2, fg=ACCENT2,
            font=('Fira Code', 7),
            justify='center').pack(pady=(4, 0), padx=4)

        # Octopus ASCII art
        octo = ("      .  .::::::.  .      \n"
                "    .:::::::::::::::::.    \n"
                "   ::::(o):::::::(o)::::   \n"
                "   ::::::::  ^  ::::::::   \n"
                "   ::::::: \\___/ :::::::   \n"
                "    ':::::::::::::::::'    \n"
                "  ~~/~\\:::::::::::::/~\\~~  \n"
                " ~~/ /~\\:::::::::::/~\\ \\~~ \n"
                "~/ /   \\:::::::::/   \\ \\~  \n"
                "~\\_\\    \\:::::::/    /_/~  \n"
                " ~~~     '::::::'     ~~~  ")
        tk.Label(left, text=octo,
            bg=BG2, fg=ACCENT,
            font=('Fira Code', 10),
            justify='center').pack(pady=(4, 0))

        tk.Label(left, text='SENTINEL OCTOPUS',
            bg=BG2, fg=ACCENT,
            font=('Fira Code', 9, 'bold')).pack(pady=(6, 0))
        tk.Label(left, text='Eight arms. Zero mercy.',
            bg=BG2, fg=TEXT3,
            font=FONT_MONO_XS).pack(pady=(2, 0))

        # Animated status dots
        self._ob_dot_lbl = tk.Label(left, text='',
            bg=BG2, fg=ACCENT, font=('Fira Code', 12))
        self._ob_dot_lbl.pack(pady=14)
        self._ob_dots = 0

        def _animate():
            if not splash.winfo_exists():
                return
            frames = ['◉ ○ ○', '◉ ◉ ○', '◉ ◉ ◉', '○ ◉ ◉', '○ ○ ◉', '○ ○ ○']
            self._ob_dot_lbl.config(text=frames[self._ob_dots % len(frames)])
            self._ob_dots += 1
            splash.after(280, _animate)

        _animate()

        # ── Right panel — info ────────────────────────────────────────────────
        right = tk.Frame(body, bg=BG)
        right.pack(side='left', fill='both', expand=True)

        # Figlet "SENTINEL" title
        try:
            import pyfiglet
            sentinel_art = pyfiglet.figlet_format('SENTINEL', font='slant')
        except Exception:
            sentinel_art = 'SENTINEL'

        tk.Label(right, text=sentinel_art,
            bg=BG, fg=ACCENT,
            font=('Fira Code', 8, 'bold'),
            justify='left').pack(anchor='w', padx=20, pady=(16, 0))

        tk.Label(right,
            text='  Autonomous Web Security Proxy  ·  Burp Suite Alternative',
            bg=BG, fg=TEXT2,
            font=('Fira Code', 9)).pack(anchor='w', padx=20)

        tk.Frame(right, bg=BORDER2, height=1).pack(fill='x', padx=20, pady=10)

        # Features
        features = [
            ('⚡', 'AI-Powered Analysis',   'SentinelNet v5.0 + Groq llama-3.3-70b'),
            ('⬡', '14 Professional Tabs',  'Proxy · Repeater · Intruder · Scanner · more'),
            ('⏸', 'Intercept & Modify',    'Hold, edit, forward or drop any request'),
            ('◈', '34,311 Payloads',       'SQLi · XSS · LFI · RCE · SSTI · XXE · more'),
            ('⚙', 'Auto-Fuzz Engine',      'AI param detection + smart payload selection'),
            ('⚿', 'Session Analyzer',      'JWT · OAuth · SAML · Cookie deep analysis'),
            ('◉', 'Active Scanner',        'CVE matching + remediation guidance'),
            ('⇌', 'Match & Replace',       'Auto-modify traffic with regex rules'),
        ]
        feat_f = tk.Frame(right, bg=BG)
        feat_f.pack(fill='x', padx=20)
        for icon, title_txt, desc in features:
            row = tk.Frame(feat_f, bg=BG)
            row.pack(fill='x', pady=2)
            tk.Label(row, text=icon, bg=BG, fg=ACCENT,
                font=('Fira Code', 10), width=3).pack(side='left')
            tk.Label(row, text=title_txt, bg=BG, fg=TEXT,
                font=('Fira Code', 9, 'bold'), width=20,
                anchor='w').pack(side='left')
            tk.Label(row, text=desc, bg=BG, fg=TEXT3,
                font=FONT_MONO_XS, anchor='w').pack(side='left')

        tk.Frame(right, bg=BORDER2, height=1).pack(fill='x', padx=20, pady=10)

        # AI status pills
        ai_ok = getattr(self.analyzer, '_sentinel', None) is not None
        gr_ok = getattr(self.analyzer, '_groq', None) is not None
        pill_f = tk.Frame(right, bg=BG)
        pill_f.pack(anchor='w', padx=20)
        for label, ok in [('SentinelNet v5.0', ai_ok), ('Groq llama-3.3-70b', gr_ok)]:
            bg_c  = ACCENT3 if ok else BG3
            fg_c  = ACCENT  if ok else TEXT3
            dot   = '◉' if ok else '◎'
            pill  = tk.Frame(pill_f, bg=bg_c, padx=10, pady=5)
            pill.pack(side='left', padx=(0, 8))
            tk.Label(pill, text=f'{dot}  {label}',
                bg=bg_c, fg=fg_c, font=FONT_MONO_XS).pack()

        # ── Bottom bar ────────────────────────────────────────────────────────
        bot = tk.Frame(inner, bg=BG3, height=54)
        bot.pack(fill='x', side='bottom')
        bot.pack_propagate(False)
        tk.Frame(bot, bg=ACCENT, height=1).pack(fill='x', side='top')

        _launched = [False]   # guard against multiple calls

        def _launch():
            if _launched[0]:
                return
            _launched[0] = True
            try:
                if splash.winfo_exists():
                    splash.destroy()
            except Exception:
                pass
            self.root.deiconify()
            self._set_window_icon(self.root)
            self._setup_styles()
            self._build_ui()
            self._load_history()

        enter_btn = tk.Button(bot,
            text='  ▶   ENTER SENTINEL PROXY  ',
            bg=ACCENT3, fg=ACCENT,
            font=('Fira Code', 11, 'bold'),
            relief='flat', cursor='hand2',
            activebackground='#005a4e',
            activeforeground=ACCENT,
            bd=0, padx=24, pady=10,
            command=_launch)
        enter_btn.pack(side='right', padx=20, pady=8)

        tk.Label(bot,
            text='  Press  ENTER  or click to launch  ·  Auto-launch in 8s',
            bg=BG3, fg=TEXT3, font=FONT_MONO_XS).pack(side='left', padx=16)

        splash.bind('<Return>', lambda e: _launch())
        splash.bind('<Escape>', lambda e: _launch())
        splash.focus_force()
        splash.after(8000, lambda: _launch() if splash.winfo_exists() else None)


    def _setup_styles(self):
        s = ttk.Style()
        s.theme_use('clam')

        s.configure('.', background=BG, foreground=TEXT,
            fieldbackground=BG4, bordercolor=BORDER,
            troughcolor=BG2, font=FONT_MONO)

        # Notebook — bottom border accent line on selected tab
        s.configure('TNotebook', background=BG, borderwidth=0,
            tabmargins=[0, 0, 0, 0])
        s.configure('TNotebook.Tab', background=BG2, foreground=TEXT3,
            padding=[20, 9], font=FONT_MONO_SM, borderwidth=0)
        s.map('TNotebook.Tab',
            background=[('selected', BG3), ('active', BG4)],
            foreground=[('selected', ACCENT), ('active', TEXT2)])

        s.configure('TFrame', background=BG)
        s.configure('TPanedwindow', background=BORDER2, sashwidth=2, sashpad=0)

        # Buttons — neon teal style
        for name, bg, fg, abg in [
            ('TButton',       BG4,      TEXT,   BG5),
            ('Cyan.TButton',  ACCENT3,  ACCENT, '#004d42'),
            ('Green.TButton', GREEN_DIM, GREEN, '#1a4d2a'),
            ('Red.TButton',   RED_DIM,  RED,    '#5c1525'),
            ('Ghost.TButton', BG2,      TEXT2,  BG3),
            ('Accent.TButton',ACCENT3,  ACCENT, '#005a4e'),
        ]:
            s.configure(name, background=bg, foreground=fg,
                bordercolor=BORDER2, relief='flat',
                padding=[12, 6], font=FONT_MONO_SM)
            s.map(name,
                background=[('active', abg), ('pressed', abg)],
                foreground=[('active', fg)])

        s.configure('TEntry', fieldbackground=BG4, foreground=TEXT,
            insertcolor=ACCENT, bordercolor=BORDER2,
            selectbackground=ACCENT3, selectforeground=ACCENT,
            padding=[8, 5])

        s.configure('TCombobox', fieldbackground=BG4, foreground=TEXT,
            selectbackground=ACCENT3, selectforeground=ACCENT,
            bordercolor=BORDER2, arrowcolor=TEXT2, padding=[6, 4])
        s.map('TCombobox',
            fieldbackground=[('readonly', BG4)],
            foreground=[('readonly', TEXT)])

        s.configure('Treeview', background=BG2, foreground=TEXT,
            fieldbackground=BG2, rowheight=26, borderwidth=0,
            font=FONT_MONO_SM)
        s.configure('Treeview.Heading', background=BG3, foreground=TEXT2,
            font=('Fira Code', 8, 'bold'), relief='flat', padding=[8, 6])
        s.map('Treeview',
            background=[('selected', ACCENT3)],
            foreground=[('selected', ACCENT)])
        s.map('Treeview.Heading',
            background=[('active', BG4)],
            foreground=[('active', ACCENT)])

        s.configure('TScrollbar', background=BG3, troughcolor=BG2,
            bordercolor=BG, arrowcolor=TEXT3, relief='flat', width=5)
        s.map('TScrollbar', background=[('active', BG5)])

        s.configure('TCheckbutton', background=BG3, foreground=TEXT2,
            font=FONT_MONO_SM, indicatorcolor=BG4,
            indicatorrelief='flat')
        s.map('TCheckbutton',
            foreground=[('active', ACCENT)],
            indicatorcolor=[('selected', ACCENT), ('active', ACCENT2)])

        s.configure('TSeparator', background=BORDER2)

    # ── Main UI ───────────────────────────────────────────────────────────────

    def _build_ui(self):
        # ── Title Bar ─────────────────────────────────────────────────────────
        title = tk.Frame(self.root, bg=BG2, height=52)
        title.pack(fill='x', side='top')
        title.pack_propagate(False)

        # Left accent stripe — neon teal
        tk.Frame(title, bg=ACCENT, width=4).pack(side='left', fill='y')

        # Logo area
        logo_f = tk.Frame(title, bg=BG2)
        logo_f.pack(side='left', padx=(12, 0))
        tk.Label(logo_f, text='⬡', bg=BG2, fg=ACCENT,
            font=('Fira Code', 18)).pack(side='left', padx=(0, 6))
        tk.Label(logo_f, text='SENTINEL', bg=BG2, fg=ACCENT,
            font=FONT_TITLE).pack(side='left')
        tk.Label(logo_f, text='PROXY', bg=BG2, fg=TEXT,
            font=FONT_TITLE).pack(side='left', padx=(4, 0))
        tk.Label(logo_f, text=' v1.0', bg=BG2, fg=TEXT3,
            font=FONT_MONO_SM).pack(side='left')

        # Separator
        tk.Frame(title, bg=BORDER2, width=1).pack(side='left', fill='y', padx=16, pady=10)
        tk.Label(title, text='Autonomous Web Security Proxy',
            bg=BG2, fg=TEXT3, font=FONT_MONO_XS).pack(side='left')

        # Right — AI status + proxy status + req count
        rc = tk.Frame(title, bg=BG2)
        rc.pack(side='right', padx=16)

        ai_ok = getattr(self.analyzer, '_sentinel', None) is not None
        gr_ok = getattr(self.analyzer, '_groq', None) is not None

        self.lbl_proxy_status = tk.Label(rc, text='◉ OFFLINE',
            bg=BG2, fg=RED, font=('Fira Code', 9, 'bold'))
        self.lbl_proxy_status.pack(side='right', padx=(12, 0))

        tk.Frame(rc, bg=BORDER2, width=1).pack(side='right', fill='y', pady=10, padx=10)

        self.lbl_req_count = tk.Label(rc, text='0 reqs',
            bg=BG2, fg=TEXT2, font=FONT_MONO_XS)
        self.lbl_req_count.pack(side='right', padx=6)

        tk.Frame(rc, bg=BORDER2, width=1).pack(side='right', fill='y', pady=10, padx=6)

        for label, ok in [('Groq', gr_ok), ('SentinelNet', ai_ok)]:
            dot   = '◉' if ok else '◎'
            color = ACCENT if ok else TEXT3
            bg_c  = ACCENT3 if ok else BG2
            lf = tk.Frame(rc, bg=bg_c, padx=6, pady=2)
            lf.pack(side='right', padx=3)
            tk.Label(lf, text=f'{dot} {label}',
                bg=bg_c, fg=color, font=FONT_MONO_XS).pack()

        # ── Control Bar ───────────────────────────────────────────────────────
        ctrl = tk.Frame(self.root, bg=BG3, height=44)
        ctrl.pack(fill='x', side='top')
        ctrl.pack_propagate(False)

        # Left accent line
        tk.Frame(ctrl, bg=BORDER2, width=1).pack(side='left', fill='y')

        lc = tk.Frame(ctrl, bg=BG3)
        lc.pack(side='left', padx=10, pady=6)

        self._proxy_btn_text = tk.StringVar(value='▶  START PROXY')
        self.btn_proxy = ttk.Button(lc,
            textvariable=self._proxy_btn_text,
            style='Green.TButton',
            command=self._toggle_proxy)
        self.btn_proxy.pack(side='left', padx=(0, 8))

        # Intercept toggle — styled label button
        self.btn_intercept = tk.Label(lc,
            text='  ⏸  INTERCEPT: OFF  ',
            bg=BG4, fg=TEXT3,
            font=('Fira Code', 8, 'bold'),
            padx=4, pady=4, cursor='hand2', relief='flat')
        self.btn_intercept.pack(side='left', padx=3)
        self.btn_intercept.bind('<Button-1>', self._toggle_intercept)

        self.btn_fwd = ttk.Button(lc, text='▶ FWD', style='Cyan.TButton',
            command=self._intercept_forward, state='disabled')
        self.btn_fwd.pack(side='left', padx=2)

        self.btn_drop = ttk.Button(lc, text='✕ DROP', style='Red.TButton',
            command=self._intercept_drop, state='disabled')
        self.btn_drop.pack(side='left', padx=2)

        tk.Frame(lc, bg=BORDER2, width=1).pack(side='left', fill='y', padx=10)

        # Filter row
        tk.Label(lc, text='HOST', bg=BG3, fg=TEXT3,
            font=FONT_MONO_XS).pack(side='left', padx=(0, 3))
        self.entry_filter = ttk.Entry(lc, textvariable=self.filter_host, width=18)
        self.entry_filter.pack(side='left', padx=(0, 4))

        self.combo_method = ttk.Combobox(lc, textvariable=self.filter_method,
            values=['ALL','GET','POST','PUT','DELETE','PATCH','OPTIONS'],
            width=7, state='readonly')
        self.combo_method.pack(side='left', padx=(0, 4))

        ttk.Button(lc, text='FILTER', style='Ghost.TButton',
            command=self._apply_filter).pack(side='left', padx=2)
        ttk.Button(lc, text='CLR', style='Ghost.TButton',
            command=self._clear_history).pack(side='left', padx=2)

        tk.Frame(lc, bg=BORDER2, width=1).pack(side='left', fill='y', padx=10)

        # Search
        tk.Label(lc, text='⌕', bg=BG3, fg=ACCENT,
            font=('Fira Code', 11)).pack(side='left', padx=(0, 3))
        self.search_var = tk.StringVar()
        self.search_var.trace_add('write', self._on_search)
        ttk.Entry(lc, textvariable=self.search_var, width=22).pack(side='left', padx=(0, 3))
        ttk.Button(lc, text='✕', style='Ghost.TButton',
            command=self._clear_search).pack(side='left', padx=1)

        # Right controls
        rc2 = tk.Frame(ctrl, bg=BG3)
        rc2.pack(side='right', padx=10, pady=6)

        ttk.Button(rc2, text='⚿  CERT', style='Cyan.TButton',
            command=self._show_cert_window).pack(side='right', padx=4)
        ttk.Button(rc2, text='↑ EXPORT', style='Ghost.TButton',
            command=self._export_requests).pack(side='right', padx=4)

        tk.Frame(rc2, bg=BORDER2, width=1).pack(side='right', fill='y', pady=8, padx=6)
        tk.Label(rc2, text='PORT', bg=BG3, fg=TEXT3,
            font=FONT_MONO_XS).pack(side='right', padx=(0, 3))
        self.entry_port = ttk.Entry(rc2, width=6)
        self.entry_port.insert(0, '8082')
        self.entry_port.pack(side='right', padx=(0, 4))

        # Notebook
        self.nb = ttk.Notebook(self.root)
        self.nb.pack(fill='both', expand=True)

        self._build_proxy_tab()
        self._build_repeater_tab()
        self._build_intruder_tab()
        self._build_scanner_tab()
        self._build_decoder_tab()
        self._build_logger_tab()
        self._build_highlight_tab()
        self._build_autofuzz_tab()
        self._build_comparer_tab()
        self._build_scope_tab()
        self._build_report_tab()
        self._build_match_replace_tab()
        self._build_active_scanner_tab()
        self._build_session_analyzer_tab()

        # New tabs
        from sentinel_proxy.ui.tabs import (
            WebSocketTab, TargetTab, OrganizerTab,
            CollaboratorTab, AIPayloadTab, CSRFTab,
            ParamMinerTab, RaceConditionTab
        )
        self._ws_tab           = WebSocketTab(self.nb, self)
        self._target_tab       = TargetTab(self.nb, self)
        self._organizer_tab    = OrganizerTab(self.nb, self)
        self._collaborator_tab = CollaboratorTab(self.nb, self)
        self._ai_payload_tab   = AIPayloadTab(self.nb, self)
        self._csrf_tab         = CSRFTab(self.nb, self)
        self._param_miner_tab  = ParamMinerTab(self.nb, self)
        self._race_tab         = RaceConditionTab(self.nb, self)

        # Start background timers now that UI is fully built
        self.root.after(3000, self._auto_refresh_logger)
        self.root.after(500,  self._check_intercept_pending)
        self.root.after(1500, self._target_tab.refresh)

        # Status bar
        sb = tk.Frame(self.root, bg=BG2, height=24)
        sb.pack(fill='x', side='bottom')
        sb.pack_propagate(False)
        tk.Frame(sb, bg=ACCENT, width=3).pack(side='left', fill='y')
        tk.Label(sb, text=' ⬡ ', bg=BG2, fg=ACCENT,
            font=('Fira Code', 9)).pack(side='left')
        self.lbl_status = tk.Label(sb,
            text='Ready  ·  Set browser proxy: 127.0.0.1:8082',
            bg=BG2, fg=TEXT2, font=FONT_MONO_XS)
        self.lbl_status.pack(side='left', padx=4)
        tk.Frame(sb, bg=BORDER2, width=1).pack(side='right', fill='y', pady=4)
        tk.Label(sb, text='@who_is_the_black_hat  ',
            bg=BG2, fg=TEXT3, font=FONT_MONO_XS).pack(side='right', padx=4)
        tk.Frame(sb, bg=BORDER2, width=1).pack(side='right', fill='y', pady=4)
        self.lbl_sb_stats = tk.Label(sb, text='',
            bg=BG2, fg=ACCENT, font=FONT_MONO_XS)
        self.lbl_sb_stats.pack(side='right', padx=8)

    # ── Tab 1: Proxy ──────────────────────────────────────────────────────────

    def _build_proxy_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ⬡ Proxy  ')

        pw = ttk.PanedWindow(frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left panel
        left = tk.Frame(pw, bg=BG)
        pw.add(left, weight=2)

        # Tree
        tf = tk.Frame(left, bg=BG)
        tf.pack(fill='both', expand=True)

        cols = ('id','method','host','path','status','risk','length','ms','time')
        self.tree = ttk.Treeview(tf, columns=cols,
            show='headings', selectmode='browse')

        widths = [40, 65, 180, 260, 55, 75, 65, 60, 65]
        heads  = ['#','Method','Host','Path','Status','Risk','Length','ms','Time']
        for col, w, h in zip(cols, widths, heads):
            self.tree.heading(col, text=h)
            self.tree.column(col, width=w, minwidth=w//2,
                anchor='center' if col in ('id','method','status','risk','length','time') else 'w')

        for sev, color in SEV_COLOR.items():
            self.tree.tag_configure(sev, foreground=color)
        self.tree.tag_configure('flagged',  background='#1a0d10', foreground=RED)
        self.tree.tag_configure('GET',      foreground=ACCENT)
        self.tree.tag_configure('POST',     foreground=GREEN)
        self.tree.tag_configure('DELETE',   foreground=RED)
        self.tree.tag_configure('PUT',      foreground=ORANGE)
        self.tree.tag_configure('PATCH',    foreground=PURPLE)
        self.tree.tag_configure('OPTIONS',  foreground=TEXT2)

        vsb = ttk.Scrollbar(tf, orient='vertical', command=self.tree.yview)
        self.tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.tree.pack(fill='both', expand=True)

        self.tree.bind('<<TreeviewSelect>>', self._on_select)
        self.tree.bind('<Double-1>', self._send_to_repeater)
        self.tree.bind('<Button-3>', self._tree_context_menu)

        # Right panel
        right = tk.Frame(pw, bg=BG)
        pw.add(right, weight=3)

        # Action bar
        ab = tk.Frame(right, bg=BG3)
        ab.pack(fill='x')

        for txt, cmd in [
            ('→ Repeater',   self._send_to_repeater),
            ('→ Intruder',   self._send_to_intruder),
            ('→ Scanner',    self._send_to_scanner),
            ('AI Deep Scan', self._deep_ai_scan),
            ('Flag',         self._flag_request),
            ('Copy URL',     self._copy_url),
            ('Copy cURL',    self._copy_curl),
            ('Organizer',    self._save_to_organizer),
        ]:
            ttk.Button(ab, text=txt, style='Ghost.TButton',
                command=cmd).pack(side='left', padx=3, pady=6)

        # Detail tabs
        dn = ttk.Notebook(right)
        dn.pack(fill='both', expand=True)

        # Request tab — Raw / Params / Hex sub-tabs
        req_frame = ttk.Frame(dn)
        dn.add(req_frame, text='  Request  ')
        req_nb = ttk.Notebook(req_frame)
        req_nb.pack(fill='both', expand=True)

        rq_raw = ttk.Frame(req_nb)
        req_nb.add(rq_raw, text=' Raw ')
        self.txt_request = self._make_text(rq_raw, fg=TEXT)

        rq_params = ttk.Frame(req_nb)
        req_nb.add(rq_params, text=' Params ')
        cols_p = ('name','value','type')
        self.req_params_tree = ttk.Treeview(rq_params, columns=cols_p, show='headings', height=12)
        for c,w,h in [('name',180,'Name'),('value',320,'Value'),('type',80,'Type')]:
            self.req_params_tree.heading(c, text=h)
            self.req_params_tree.column(c, width=w, anchor='w')
        vsb_p = ttk.Scrollbar(rq_params, orient='vertical', command=self.req_params_tree.yview)
        self.req_params_tree.configure(yscrollcommand=vsb_p.set)
        vsb_p.pack(side='right', fill='y')
        self.req_params_tree.pack(fill='both', expand=True)

        rq_hex = ttk.Frame(req_nb)
        req_nb.add(rq_hex, text=' Hex ')
        self.txt_request_hex = self._make_text(rq_hex, fg=ACCENT)

        # Response tab — Raw / Hex / Render sub-tabs
        resp_frame = ttk.Frame(dn)
        dn.add(resp_frame, text='  Response  ')
        resp_nb = ttk.Notebook(resp_frame)
        resp_nb.pack(fill='both', expand=True)

        rs_raw = ttk.Frame(resp_nb)
        resp_nb.add(rs_raw, text=' Raw ')
        self.txt_response = self._make_text(rs_raw, fg=TEXT)

        rs_hex = ttk.Frame(resp_nb)
        resp_nb.add(rs_hex, text=' Hex ')
        self.txt_response_hex = self._make_text(rs_hex, fg=ACCENT)

        rs_render = ttk.Frame(resp_nb)
        resp_nb.add(rs_render, text=' Render ')
        self.txt_response_render = self._make_text(rs_render, fg=GREEN)

        # AI Analysis tab
        ai_frame = ttk.Frame(dn)
        dn.add(ai_frame, text='  AI Analysis  ')
        self.txt_ai = self._make_text(ai_frame, fg=GREEN)

    # ── Tab 2: Repeater ───────────────────────────────────────────────────────

    def _build_repeater_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ↺ Repeater  ')

        # URL bar
        ub = tk.Frame(frame, bg=BG3)
        ub.pack(fill='x')

        self.rep_method = ttk.Combobox(ub,
            values=['GET','POST','PUT','DELETE','PATCH','OPTIONS','HEAD'],
            width=8, state='readonly')
        self.rep_method.set('GET')
        self.rep_method.pack(side='left', padx=8, pady=6)

        self.rep_url = ttk.Entry(ub, font=FONT_MONO)
        self.rep_url.pack(side='left', fill='x', expand=True, padx=4, pady=6)

        self.rep_status_lbl = tk.Label(ub, text='',
            bg=BG3, fg=GREEN, font=FONT_MONO_SM)
        self.rep_status_lbl.pack(side='right', padx=12)

        ttk.Button(ub, text='HISTORY', style='Ghost.TButton',
            command=self._repeater_show_history).pack(side='right', padx=4, pady=6)
        ttk.Button(ub, text='CLEAR', style='Ghost.TButton',
            command=self._repeater_clear).pack(side='right', padx=4, pady=6)
        ttk.Button(ub, text='SAVE', style='Ghost.TButton',
            command=self._repeater_save).pack(side='right', padx=4, pady=6)
        ttk.Button(ub, text='SEND  ▶', style='Cyan.TButton',
            command=self._repeater_send).pack(side='right', padx=4, pady=6)

        # Split pane
        pw = ttk.PanedWindow(frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Request panel — Raw / Params / Hex
        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=1)
        req_nb = ttk.Notebook(lf)
        req_nb.pack(fill='both', expand=True)

        rq_raw = ttk.Frame(req_nb)
        req_nb.add(rq_raw, text=' Raw ')
        self._section_label(rq_raw, 'REQUEST')
        self.rep_req_txt = self._make_text(rq_raw)

        rq_hex = ttk.Frame(req_nb)
        req_nb.add(rq_hex, text=' Hex ')
        self.rep_req_hex = self._make_text(rq_hex, fg=ACCENT)

        # Response panel — Raw / Hex / Render
        rf = tk.Frame(pw, bg=BG)
        pw.add(rf, weight=1)
        resp_nb = ttk.Notebook(rf)
        resp_nb.pack(fill='both', expand=True)

        rs_raw = ttk.Frame(resp_nb)
        resp_nb.add(rs_raw, text=' Raw ')
        self._section_label(rs_raw, 'RESPONSE')
        self.rep_resp_txt = self._make_text(rs_raw)

        rs_hex = ttk.Frame(resp_nb)
        resp_nb.add(rs_hex, text=' Hex ')
        self.rep_resp_hex = self._make_text(rs_hex, fg=ACCENT)

        rs_render = ttk.Frame(resp_nb)
        resp_nb.add(rs_render, text=' Render ')
        self.rep_resp_render = self._make_text(rs_render, fg=GREEN)

    # ── Tab 3: Intruder ───────────────────────────────────────────────────────

    def _build_intruder_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ⚡ Intruder  ')

        cfg = tk.Frame(frame, bg=BG3)
        cfg.pack(fill='x')

        inner = tk.Frame(cfg, bg=BG3)
        inner.pack(padx=12, pady=8, fill='x')

        # Row 1 — URL + params
        r1 = tk.Frame(inner, bg=BG3)
        r1.pack(fill='x', pady=3)
        self._cfg_label(r1, 'TARGET URL')
        self.int_url = ttk.Entry(r1, width=48, font=FONT_MONO)
        self.int_url.pack(side='left', padx=(0,12))
        self._cfg_label(r1, 'PARAM 1')
        self.int_param = ttk.Entry(r1, width=12)
        self.int_param.pack(side='left', padx=(0,12))
        self._cfg_label(r1, 'PARAM 2')
        self.int_param2 = ttk.Entry(r1, width=12)
        self.int_param2.pack(side='left', padx=(0,4))
        tk.Label(r1, text='(Pitchfork/Cluster Bomb)',
            bg=BG3, fg=TEXT3, font=FONT_MONO_XS).pack(side='left')

        # Row 2 — attack mode + type + threads
        r2 = tk.Frame(inner, bg=BG3)
        r2.pack(fill='x', pady=3)
        self._cfg_label(r2, 'ATTACK MODE')
        self.int_mode = ttk.Combobox(r2, width=16, state='readonly',
            values=['Sniper','Battering Ram','Pitchfork','Cluster Bomb'])
        self.int_mode.set('Sniper')
        self.int_mode.pack(side='left', padx=(0,12))
        self.int_mode.bind('<<ComboboxSelected>>', self._on_mode_change)

        self._cfg_label(r2, 'PAYLOAD TYPE')
        self.int_type = ttk.Combobox(r2, width=20, state='readonly',
            values=['SQLi','XSS','LFI','SSRF','SSTI','RCE','XXE',
                    'Open Redirect','LDAP','NoSQL','GraphQL','JWT',
                    'CORS','CRLF','Path Traversal','File Upload',
                    'Prototype Pollution','Request Smuggling',
                    'Cache Deception','XPATH','Custom'])
        self.int_type.set('SQLi')
        self.int_type.pack(side='left', padx=(0,12))
        self.int_type.bind('<<ComboboxSelected>>', self._load_payloads)

        self._cfg_label(r2, 'THREADS')
        self.int_threads = ttk.Entry(r2, width=5)
        self.int_threads.insert(0, '10')
        self.int_threads.pack(side='left', padx=(0,12))

        ttk.Button(r2, text='▶  START ATTACK', style='Red.TButton',
            command=self._intruder_start).pack(side='left', padx=4)
        ttk.Button(r2, text='STOP', style='Ghost.TButton',
            command=self._intruder_stop).pack(side='left', padx=4)

        self.int_progress = tk.Label(r2, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.int_progress.pack(side='left', padx=8)

        # Row 3 — grep + delay + POST toggle
        r3 = tk.Frame(inner, bg=BG3)
        r3.pack(fill='x', pady=3)
        self._cfg_label(r3, 'GREP MATCH')
        self.int_grep = ttk.Entry(r3, width=22)
        self.int_grep.pack(side='left', padx=(0,8))
        self._cfg_label(r3, 'DELAY(ms)')
        self.int_delay = ttk.Entry(r3, width=5)
        self.int_delay.insert(0, '0')
        self.int_delay.pack(side='left', padx=(0,8))
        self.int_post_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(r3, text='POST Body Fuzz',
            variable=self.int_post_var,
            command=self._int_toggle_post).pack(side='left', padx=4)

        self.int_mode_lbl = tk.Label(r3,
            text='Mode: Sniper — one param, one payload list',
            bg=BG3, fg=ACCENT, font=FONT_MONO_XS)
        self.int_mode_lbl.pack(side='right', padx=8)

        # Row 4 — POST body (hidden by default)
        self._int_post_frame = tk.Frame(inner, bg=BG3)
        self._cfg_label(self._int_post_frame, 'POST BODY')
        tk.Label(self._int_post_frame,
            text='Use §param§ as injection marker  e.g. username=§user§&password=test',
            bg=BG3, fg=TEXT3, font=FONT_MONO_XS).pack(side='left', padx=4)
        self.int_post_body = ttk.Entry(self._int_post_frame, width=55, font=FONT_MONO_XS)
        self.int_post_body.pack(side='left', padx=4, pady=3, fill='x', expand=True)

        # Split
        pw = ttk.PanedWindow(frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Payload panel — notebook for payload1 + payload2
        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=1)

        pnb = ttk.Notebook(lf)
        pnb.pack(fill='both', expand=True)

        p1f = ttk.Frame(pnb)
        pnb.add(p1f, text='  Payload 1  ')
        self._section_label(p1f, 'PAYLOAD LIST 1')
        self.int_payloads_txt = self._make_text(p1f)

        p2f = ttk.Frame(pnb)
        pnb.add(p2f, text='  Payload 2  ')
        self._section_label(p2f, 'PAYLOAD LIST 2  (Pitchfork / Cluster Bomb)')
        self.int_payloads2_txt = self._make_text(p2f)

        # Results panel
        rf = tk.Frame(pw, bg=BG)
        pw.add(rf, weight=2)

        # Results header with clear button
        rh = tk.Frame(rf, bg=BG3)
        rh.pack(fill='x')
        tk.Frame(rh, bg=ACCENT, width=3).pack(side='left', fill='y')
        tk.Label(rh, text='  RESULTS',
            bg=BG3, fg=TEXT2, font=('Fira Code', 8, 'bold')).pack(side='left', padx=4, pady=6)
        ttk.Button(rh, text='CLEAR', style='Ghost.TButton',
            command=self._intruder_clear).pack(side='right', padx=4, pady=4)
        ttk.Button(rh, text='EXPORT', style='Ghost.TButton',
            command=self._intruder_export).pack(side='right', padx=4, pady=4)
        ttk.Button(rh, text='INTERESTING ONLY', style='Ghost.TButton',
            command=self._intruder_filter_interesting).pack(side='right', padx=4, pady=4)
        ttk.Button(rh, text='SHOW ALL', style='Ghost.TButton',
            command=self._intruder_show_all).pack(side='right', padx=4, pady=4)

        cols = ('payload','payload2','status','length','diff','grep','flag')
        self.int_tree = ttk.Treeview(rf, columns=cols, show='headings')
        for col, w, h in [
            ('payload', 220,'Payload 1'), ('payload2',120,'Payload 2'),
            ('status',  60, 'Status'),   ('length',  70, 'Length'),
            ('diff',    65, 'Diff'),     ('grep',    50, 'Grep'),
            ('flag',    30, '!'),
        ]:
            self.int_tree.heading(col, text=h,
                command=lambda c=col: self._intruder_sort(c))
            self.int_tree.column(col, width=w,
                anchor='w' if col in ('payload','payload2') else 'center')
        self.int_tree.tag_configure('interesting', foreground=ORANGE, background='#1a1200')
        self.int_tree.tag_configure('critical',    foreground=RED,    background='#1a0000')
        self.int_tree.tag_configure('grep_match',  foreground=PURPLE, background='#1a0020')

        vsb = ttk.Scrollbar(rf, orient='vertical', command=self.int_tree.yview)
        self.int_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.int_tree.pack(fill='both', expand=True)
        self.int_tree.bind('<Button-3>', self._intruder_context_menu)
        self.int_tree.bind('<<TreeviewSelect>>', self._intruder_on_select)

        # Response preview
        self._section_label(rf, 'RESPONSE PREVIEW')
        self.int_resp_txt = self._make_text(rf, fg=TEXT2)
        self.int_resp_txt.configure(height=6)

        self.root.after(100, self._load_payloads)  # defer until widget exists
        self._int_all_results = []   # store all results for filtering

    # ── Tab 4: Scanner ────────────────────────────────────────────────────────

    def _build_scanner_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ⌖ Scanner  ')

        ub = tk.Frame(frame, bg=BG3)
        ub.pack(fill='x')

        self._cfg_label(ub, 'TARGET')
        self.scan_url = ttk.Entry(ub, width=50, font=FONT_MONO)
        self.scan_url.pack(side='left', padx=4, pady=8)

        ttk.Button(ub, text='▶  RUN AI SCAN', style='Cyan.TButton',
            command=self._scanner_run).pack(side='left', padx=4, pady=8)
        ttk.Button(ub, text='CLEAR', style='Ghost.TButton',
            command=lambda: self.scan_out.delete('1.0','end')).pack(side='left', padx=4, pady=8)
        ttk.Button(ub, text='EXPORT', style='Ghost.TButton',
            command=self._scanner_export).pack(side='left', padx=4, pady=8)

        self.scan_out = self._make_text(frame, fg=GREEN)

    # ── Tab 5: Decoder ────────────────────────────────────────────────────────

    def _build_decoder_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ⊞ Decoder  ')

        ub = tk.Frame(frame, bg=BG3)
        ub.pack(fill='x')

        self.dec_mode = ttk.Combobox(ub, width=18, state='readonly',
            values=['URL Encode','URL Decode','Base64 Encode','Base64 Decode',
                    'HTML Encode','HTML Decode','Hex Encode','Hex Decode',
                    'MD5 Hash','SHA1 Hash','SHA256 Hash','SHA512 Hash'])
        self.dec_mode.set('URL Decode')
        self.dec_mode.pack(side='left', padx=8, pady=6)

        ttk.Button(ub, text='CONVERT  ▶', style='Cyan.TButton',
            command=self._decode_convert).pack(side='left', padx=4, pady=6)
        ttk.Button(ub, text='⇅ SWAP', style='Ghost.TButton',
            command=self._decode_swap).pack(side='left', padx=4, pady=6)
        ttk.Button(ub, text='CLEAR', style='Ghost.TButton',
            command=self._decode_clear).pack(side='left', padx=4, pady=6)

        pw = ttk.PanedWindow(frame, orient='vertical')
        pw.pack(fill='both', expand=True)

        tf = tk.Frame(pw, bg=BG)
        pw.add(tf, weight=1)
        self._section_label(tf, 'INPUT')
        self.dec_input = self._make_text(tf)

        bf = tk.Frame(pw, bg=BG)
        pw.add(bf, weight=1)
        self._section_label(bf, 'OUTPUT')
        self.dec_output = self._make_text(bf, fg=CYAN)

    # ── Tab 6: Logger ─────────────────────────────────────────────────────────

    def _build_logger_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ≡ Logger  ')

        tb = tk.Frame(frame, bg=BG3)
        tb.pack(fill='x')

        self._cfg_label(tb, 'SEARCH')
        self.log_search_var = tk.StringVar()
        self.log_search_var.trace_add('write', self._log_search)
        ttk.Entry(tb, textvariable=self.log_search_var,
            width=28).pack(side='left', padx=(0,8), pady=6)

        self._cfg_label(tb, 'RISK')
        self.log_risk_var = tk.StringVar(value='ALL')
        ttk.Combobox(tb, textvariable=self.log_risk_var,
            values=['ALL','CRITICAL','HIGH','MEDIUM','LOW','UNKNOWN'],
            width=10, state='readonly').pack(side='left', padx=(0,8), pady=6)
        self.log_risk_var.trace_add('write', self._log_search)

        self._cfg_label(tb, 'METHOD')
        self.log_method_var = tk.StringVar(value='ALL')
        ttk.Combobox(tb, textvariable=self.log_method_var,
            values=['ALL','GET','POST','PUT','DELETE','PATCH','OPTIONS'],
            width=8, state='readonly').pack(side='left', padx=(0,8), pady=6)
        self.log_method_var.trace_add('write', self._log_search)

        ttk.Button(tb, text='FLAGGED ONLY', style='Ghost.TButton',
            command=self._log_flagged).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='REFRESH', style='Ghost.TButton',
            command=self._log_refresh).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='EXPORT JSON', style='Ghost.TButton',
            command=self._export_requests).pack(side='right', padx=8, pady=6)

        self.log_count_lbl = tk.Label(tb, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.log_count_lbl.pack(side='right', padx=8)

        pw = ttk.PanedWindow(frame, orient='vertical')
        pw.pack(fill='both', expand=True)

        top = tk.Frame(pw, bg=BG)
        pw.add(top, weight=2)

        cols = ('id','ts','method','host','path','status','risk','length','vulns')
        self.log_tree = ttk.Treeview(top, columns=cols, show='headings')
        for col, w, h in [
            ('id',40,'#'), ('ts',80,'Time'), ('method',65,'Method'),
            ('host',180,'Host'), ('path',260,'Path'),
            ('status',55,'Status'), ('risk',75,'Risk'),
            ('length',65,'Length'), ('vulns',140,'Vulns'),
        ]:
            self.log_tree.heading(col, text=h)
            self.log_tree.column(col, width=w,
                anchor='center' if col in ('id','ts','method','status','risk','length') else 'w')

        for sev, color in SEV_COLOR.items():
            self.log_tree.tag_configure(sev, foreground=color)
        self.log_tree.tag_configure('flagged', background='#1a0d10', foreground=RED)

        vsb = ttk.Scrollbar(top, orient='vertical', command=self.log_tree.yview)
        self.log_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.log_tree.pack(fill='both', expand=True)
        self.log_tree.bind('<<TreeviewSelect>>', self._log_on_select)
        self.log_tree.bind('<Button-3>', self._log_context_menu)

        bot = tk.Frame(pw, bg=BG)
        pw.add(bot, weight=1)
        self._section_label(bot, 'RAW LOG')
        self.log_detail = self._make_text(bot, fg=TEXT2)

        self._log_refresh()


    # ── Tab 7: Highlight Rules ────────────────────────────────────────────────

    def _build_highlight_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ◈ Highlight  ')

        # Info label
        tk.Label(frame,
            text='  Define rules to color-code requests in Proxy and Logger tabs.',
            bg=BG, fg=TEXT2, font=FONT_MONO_XS, anchor='w').pack(fill='x', pady=4)

        # Add rule bar
        ab = tk.Frame(frame, bg=BG3)
        ab.pack(fill='x')

        self._cfg_label(ab, 'MATCH')
        self.hl_match = ttk.Entry(ab, width=24)
        self.hl_match.pack(side='left', padx=(0,8), pady=8)

        self._cfg_label(ab, 'FIELD')
        self.hl_field = ttk.Combobox(ab, width=10, state='readonly',
            values=['URL','Host','Path','Method','Status','Body','Any'])
        self.hl_field.set('URL')
        self.hl_field.pack(side='left', padx=(0,8), pady=8)

        self._cfg_label(ab, 'COLOR')
        self.hl_color = ttk.Combobox(ab, width=10, state='readonly',
            values=['Red','Orange','Yellow','Green','Cyan','Purple','White'])
        self.hl_color.set('Orange')
        self.hl_color.pack(side='left', padx=(0,8), pady=8)

        self._cfg_label(ab, 'COMMENT')
        self.hl_comment = ttk.Entry(ab, width=20)
        self.hl_comment.pack(side='left', padx=(0,8), pady=8)

        ttk.Button(ab, text='ADD RULE', style='Cyan.TButton',
            command=self._hl_add_rule).pack(side='left', padx=4, pady=8)
        ttk.Button(ab, text='CLEAR ALL', style='Ghost.TButton',
            command=self._hl_clear_all).pack(side='left', padx=4, pady=8)
        ttk.Button(ab, text='TEST RULE', style='Ghost.TButton',
            command=self._hl_test_rule).pack(side='left', padx=4, pady=8)

        # Rules list
        cols = ('id','match','field','color','preview','comment','enabled')
        self.hl_tree = ttk.Treeview(frame, columns=cols, show='headings', height=12)
        for col, w, h in [
            ('id',35,'#'), ('match',200,'Match Pattern'),
            ('field',75,'Field'), ('color',75,'Color'),
            ('preview',60,'Preview'), ('comment',180,'Comment'), ('enabled',55,'Active'),
        ]:
            self.hl_tree.heading(col, text=h)
            self.hl_tree.column(col, width=w,
                anchor='center' if col in ('id','field','color','preview','enabled') else 'w')

        COLOR_MAP = {
            'Red': RED, 'Orange': ORANGE, 'Yellow': YELLOW,
            'Green': GREEN, 'Cyan': CYAN, 'Purple': PURPLE, 'White': TEXT,
        }
        for name, color in COLOR_MAP.items():
            self.hl_tree.tag_configure(f'hl_{name.lower()}', foreground=color)

        vsb = ttk.Scrollbar(frame, orient='vertical', command=self.hl_tree.yview)
        self.hl_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.hl_tree.pack(fill='both', expand=True, padx=0)
        self.hl_tree.bind('<Button-3>', self._hl_context_menu)
        self.hl_tree.bind('<Double-1>', self._hl_toggle)

        # Bottom info
        tk.Label(frame,
            text='  Double-click to enable/disable  ·  Right-click to delete  ·  Rules apply to new requests',
            bg=BG, fg=TEXT3, font=FONT_MONO_XS, anchor='w').pack(fill='x', pady=4)

        self._hl_rules = []   # list of dicts: {id, match, field, color, comment, enabled}
        self._hl_load()

    def _build_autofuzz_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ⚙ Auto-Fuzz  ')

        # Top bar
        tb = tk.Frame(frame, bg=BG3)
        tb.pack(fill='x')

        self._cfg_label(tb, 'TARGET URL')
        self.af_url = ttk.Entry(tb, width=45, font=FONT_MONO)
        self.af_url.pack(side='left', padx=(0,8), pady=8)

        ttk.Button(tb, text='▶  DETECT PARAMS', style='Cyan.TButton',
            command=self._af_detect).pack(side='left', padx=4, pady=8)
        ttk.Button(tb, text='▶  START FUZZ', style='Red.TButton',
            command=self._af_start).pack(side='left', padx=4, pady=8)
        ttk.Button(tb, text='STOP', style='Ghost.TButton',
            command=self._af_stop).pack(side='left', padx=4, pady=8)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=self._af_clear).pack(side='left', padx=4, pady=8)
        ttk.Button(tb, text='EXPORT', style='Ghost.TButton',
            command=self._af_export).pack(side='left', padx=4, pady=8)

        self.af_status_lbl = tk.Label(tb, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.af_status_lbl.pack(side='right', padx=12)

        # Split: left=detected params, right=results
        pw = ttk.PanedWindow(frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        # Left: detected params panel
        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=1)
        self._section_label(lf, 'DETECTED PARAMETERS')

        cols = ('param','type','source','fuzz')
        self.af_param_tree = ttk.Treeview(lf, columns=cols, show='headings', height=8)
        for col, w, h in [
            ('param',140,'Parameter'), ('type',80,'Type'),
            ('source',100,'Source'),   ('fuzz',50,'Fuzz?'),
        ]:
            self.af_param_tree.heading(col, text=h)
            self.af_param_tree.column(col, width=w,
                anchor='w' if col in ('param','source') else 'center')
        self.af_param_tree.tag_configure('selected', foreground=GREEN)
        self.af_param_tree.tag_configure('skipped',  foreground=TEXT3)
        vsb1 = ttk.Scrollbar(lf, orient='vertical', command=self.af_param_tree.yview)
        self.af_param_tree.configure(yscrollcommand=vsb1.set)
        vsb1.pack(side='right', fill='y')
        self.af_param_tree.pack(fill='both', expand=True)
        self.af_param_tree.bind('<Double-1>', self._af_toggle_param)

        # Payload type selector
        pf = tk.Frame(lf, bg=BG3)
        pf.pack(fill='x')
        self._cfg_label(pf, 'PAYLOAD TYPE')
        self.af_payload_type = ttk.Combobox(pf, width=18, state='readonly',
            values=['Auto (AI)','SQLi','XSS','LFI','SSRF','SSTI','RCE',
                    'XXE','Open Redirect','Path Traversal'])
        self.af_payload_type.set('Auto (AI)')
        self.af_payload_type.pack(side='left', padx=4, pady=4)
        self._cfg_label(pf, 'THREADS')
        self.af_threads = ttk.Entry(pf, width=4)
        self.af_threads.insert(0, '5')
        self.af_threads.pack(side='left', padx=4, pady=4)

        # Right: results
        rf = tk.Frame(pw, bg=BG)
        pw.add(rf, weight=2)
        self._section_label(rf, 'FUZZ RESULTS')

        cols2 = ('param','payload','status','length','diff','flag')
        self.af_result_tree = ttk.Treeview(rf, columns=cols2, show='headings')
        for col, w, h in [
            ('param',100,'Param'), ('payload',200,'Payload'),
            ('status',60,'Status'), ('length',70,'Length'),
            ('diff',65,'Diff'), ('flag',30,'!'),
        ]:
            self.af_result_tree.heading(col, text=h)
            self.af_result_tree.column(col, width=w,
                anchor='w' if col in ('param','payload') else 'center')
        self.af_result_tree.tag_configure('interesting', foreground=ORANGE, background='#1a1200')
        self.af_result_tree.tag_configure('critical',    foreground=RED,    background='#1a0000')
        vsb2 = ttk.Scrollbar(rf, orient='vertical', command=self.af_result_tree.yview)
        self.af_result_tree.configure(yscrollcommand=vsb2.set)
        vsb2.pack(side='right', fill='y')
        self.af_result_tree.pack(fill='both', expand=True)
        self.af_result_tree.bind('<Button-3>', self._af_result_context_menu)

        self._af_running   = False
        self._af_params    = []   # list of {param, type, source, enabled}

    # ── Tab 9: Comparer ───────────────────────────────────────────────────────

    def _build_comparer_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ⇄ Comparer  ')

        # Toolbar
        tb = tk.Frame(frame, bg=BG3)
        tb.pack(fill='x', side='top')

        ttk.Button(tb, text='COMPARE', style='Cyan.TButton',
            command=self._cmp_compare).pack(side='left', padx=6, pady=6)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=self._cmp_clear).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='← REPEATER', style='Ghost.TButton',
            command=self._cmp_from_repeater).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='SWAP A/B', style='Ghost.TButton',
            command=self._cmp_swap).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='COPY DIFF', style='Ghost.TButton',
            command=self._cmp_copy_diff).pack(side='left', padx=4, pady=6)

        self.cmp_stats_lbl = tk.Label(tb, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.cmp_stats_lbl.pack(side='right', padx=12)

        # Main vertical pane: top=inputs, bottom=diff
        main_pw = ttk.PanedWindow(frame, orient='vertical')
        main_pw.pack(fill='both', expand=True)

        # Top pane: two input panels side by side
        top_frame = tk.Frame(main_pw, bg=BG)
        main_pw.add(top_frame, weight=1)

        top_pw = ttk.PanedWindow(top_frame, orient='horizontal')
        top_pw.pack(fill='both', expand=True)

        # Left input
        lf = tk.Frame(top_pw, bg=BG)
        top_pw.add(lf, weight=1)
        lh = tk.Frame(lf, bg=BG3)
        lh.pack(fill='x')
        tk.Label(lh, text='  RESPONSE A', bg=BG3, fg=ACCENT,
            font=('Fira Code', 9, 'bold')).pack(side='left', padx=4, pady=6)
        ttk.Button(lh, text='Paste', style='Ghost.TButton',
            command=lambda: self._cmp_paste(self.cmp_left)).pack(side='right', padx=4, pady=4)
        ttk.Button(lh, text='Clear', style='Ghost.TButton',
            command=lambda: self.cmp_left.delete('1.0','end')).pack(side='right', padx=2, pady=4)
        self.cmp_left = self._make_text(lf)

        # Right input
        rf = tk.Frame(top_pw, bg=BG)
        top_pw.add(rf, weight=1)
        rh = tk.Frame(rf, bg=BG3)
        rh.pack(fill='x')
        tk.Label(rh, text='  RESPONSE B', bg=BG3, fg=PURPLE,
            font=('Fira Code', 9, 'bold')).pack(side='left', padx=4, pady=6)
        ttk.Button(rh, text='Paste', style='Ghost.TButton',
            command=lambda: self._cmp_paste(self.cmp_right)).pack(side='right', padx=4, pady=4)
        ttk.Button(rh, text='Clear', style='Ghost.TButton',
            command=lambda: self.cmp_right.delete('1.0','end')).pack(side='right', padx=2, pady=4)
        self.cmp_right = self._make_text(rf)

        # Bottom pane: diff output
        bot_frame = tk.Frame(main_pw, bg=BG)
        main_pw.add(bot_frame, weight=1)

        dh = tk.Frame(bot_frame, bg=BG3)
        dh.pack(fill='x')
        tk.Label(dh, text='  DIFF OUTPUT', bg=BG3, fg=YELLOW,
            font=('Fira Code', 9, 'bold')).pack(side='left', padx=4, pady=6)
        tk.Label(dh,
            text='  GREEN = added  ·  RED = removed  ·  GREY = unchanged',
            bg=BG3, fg=TEXT3, font=FONT_MONO_XS).pack(side='left', padx=8)

        self.cmp_diff = self._make_text(bot_frame)
        self.cmp_diff.tag_configure('added',     foreground=GREEN,  background='#0d2818')
        self.cmp_diff.tag_configure('removed',   foreground=RED,    background='#2d0a0a')
        self.cmp_diff.tag_configure('unchanged', foreground=TEXT3)
        self.cmp_diff.tag_configure('header',    foreground=YELLOW, font=('Fira Code',9,'bold'))



    # ── Tab 10: Scope Rules ───────────────────────────────────────────────────

    def _build_scope_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ◎ Scope  ')

        tk.Label(frame,
            text='  Define which hosts are in scope. Out-of-scope requests are logged but not analyzed.',
            bg=BG, fg=TEXT2, font=FONT_MONO_XS, anchor='w').pack(fill='x', pady=4)

        # Add rule bar
        ab = tk.Frame(frame, bg=BG3)
        ab.pack(fill='x')

        self._cfg_label(ab, 'PATTERN')
        self.scope_pattern = ttk.Entry(ab, width=30, font=FONT_MONO)
        self.scope_pattern.pack(side='left', padx=(0,8), pady=8)

        self._cfg_label(ab, 'TYPE')
        self.scope_type = ttk.Combobox(ab, width=10, state='readonly',
            values=['include', 'exclude'])
        self.scope_type.set('include')
        self.scope_type.pack(side='left', padx=(0,8), pady=8)

        ttk.Button(ab, text='ADD', style='Cyan.TButton',
            command=self._scope_add).pack(side='left', padx=4, pady=8)
        ttk.Button(ab, text='CLEAR ALL', style='Ghost.TButton',
            command=self._scope_clear_all).pack(side='left', padx=4, pady=8)
        ttk.Button(ab, text='IMPORT', style='Ghost.TButton',
            command=self._scope_import).pack(side='left', padx=4, pady=8)
        ttk.Button(ab, text='EXPORT', style='Ghost.TButton',
            command=self._scope_export).pack(side='left', padx=4, pady=8)

        tk.Frame(ab, bg=BORDER, width=1).pack(side='left', fill='y', padx=8)
        self._cfg_label(ab, 'QUICK:')
        ttk.Button(ab, text='Add Current Target', style='Ghost.TButton',
            command=self._scope_add_current).pack(side='left', padx=4, pady=8)

        self.scope_status_lbl = tk.Label(ab, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.scope_status_lbl.pack(side='right', padx=12)

        # Rules tree
        cols = ('id', 'pattern', 'type', 'enabled', 'matches')
        self.scope_tree = ttk.Treeview(frame, columns=cols, show='headings', height=14)
        for col, w, h in [
            ('id', 40, '#'), ('pattern', 300, 'Pattern'),
            ('type', 80, 'Type'), ('enabled', 70, 'Active'),
            ('matches', 80, 'Matches'),
        ]:
            self.scope_tree.heading(col, text=h)
            self.scope_tree.column(col, width=w,
                anchor='center' if col in ('id', 'type', 'enabled', 'matches') else 'w')

        self.scope_tree.tag_configure('include', foreground=GREEN)
        self.scope_tree.tag_configure('exclude', foreground=RED)
        self.scope_tree.tag_configure('disabled', foreground=TEXT3)

        vsb = ttk.Scrollbar(frame, orient='vertical', command=self.scope_tree.yview)
        self.scope_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.scope_tree.pack(fill='both', expand=True)
        self.scope_tree.bind('<Double-1>', self._scope_toggle)
        self.scope_tree.bind('<Button-3>', self._scope_context_menu)

        tk.Label(frame,
            text='  Double-click to enable/disable  ·  Right-click to delete  ·  Wildcards supported: *.example.com',
            bg=BG, fg=TEXT3, font=FONT_MONO_XS, anchor='w').pack(fill='x', pady=4)

        self._scope_match_counts = {}
        self._scope_load()

    # ── Tab 11: Auto Report ───────────────────────────────────────────────────

    def _build_report_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ⬒ Report  ')

        # Toolbar
        tb = tk.Frame(frame, bg=BG3)
        tb.pack(fill='x')

        ttk.Button(tb, text='▶  GENERATE REPORT', style='Cyan.TButton',
            command=self._report_generate).pack(side='left', padx=8, pady=8)
        ttk.Button(tb, text='SAVE HTML', style='Green.TButton',
            command=self._report_save_html).pack(side='left', padx=4, pady=8)
        ttk.Button(tb, text='SAVE PDF', style='Ghost.TButton',
            command=self._report_save_pdf).pack(side='left', padx=4, pady=8)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=lambda: self.report_out.delete('1.0', 'end')).pack(side='left', padx=4, pady=8)

        self.report_status_lbl = tk.Label(tb, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.report_status_lbl.pack(side='right', padx=12)

        # Options bar
        ob = tk.Frame(frame, bg=BG4)
        ob.pack(fill='x')

        self._cfg_label(ob, 'TARGET FILTER')
        self.report_host_filter = ttk.Entry(ob, width=25)
        self.report_host_filter.pack(side='left', padx=(0,12), pady=6)

        self._cfg_label(ob, 'MIN RISK')
        self.report_min_risk = ttk.Combobox(ob, width=10, state='readonly',
            values=['ALL', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'])
        self.report_min_risk.set('MEDIUM')
        self.report_min_risk.pack(side='left', padx=(0,12), pady=6)

        self.report_groq_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(ob, text='Groq Executive Summary',
            variable=self.report_groq_var).pack(side='left', padx=8, pady=6)

        self.report_flagged_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ob, text='Flagged Only',
            variable=self.report_flagged_var).pack(side='left', padx=8, pady=6)

        self.report_include_resp_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(ob, text='Include Response Bodies',
            variable=self.report_include_resp_var).pack(side='left', padx=8, pady=6)

        # Preview
        # Stats bar
        sb2 = tk.Frame(frame, bg=BG2)
        sb2.pack(fill='x')
        self.report_stats_lbl = tk.Label(sb2, text='',
            bg=BG2, fg=TEXT2, font=FONT_MONO_XS)
        self.report_stats_lbl.pack(side='left', padx=8, pady=3)

        self._section_label(frame, 'REPORT PREVIEW')
        self.report_out = self._make_text(frame, fg=TEXT)
        self._report_html = ''



    # ── Tab 12: Match & Replace ───────────────────────────────────────────────

    def _build_match_replace_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ⇌ Match & Replace  ')

        tk.Label(frame,
            text='  Auto-modify requests/responses matching rules. Applied to all intercepted traffic.',
            bg=BG, fg=TEXT2, font=FONT_MONO_XS, anchor='w').pack(fill='x', pady=4)

        # Add rule bar
        ab = tk.Frame(frame, bg=BG3)
        ab.pack(fill='x')

        self._cfg_label(ab, 'MATCH')
        self.mr_match = ttk.Entry(ab, width=22)
        self.mr_match.pack(side='left', padx=(0,6), pady=6)

        self._cfg_label(ab, 'REPLACE')
        self.mr_replace = ttk.Entry(ab, width=22)
        self.mr_replace.pack(side='left', padx=(0,6), pady=6)

        self._cfg_label(ab, 'IN')
        self.mr_target = ttk.Combobox(ab, width=12, state='readonly',
            values=['Request Header','Request Body','Response Header',
                    'Response Body','URL','Any'])
        self.mr_target.set('Request Header')
        self.mr_target.pack(side='left', padx=(0,6), pady=6)

        self._cfg_label(ab, 'TYPE')
        self.mr_type = ttk.Combobox(ab, width=8, state='readonly',
            values=['Literal','Regex'])
        self.mr_type.set('Literal')
        self.mr_type.pack(side='left', padx=(0,6), pady=6)

        ttk.Button(ab, text='ADD', style='Cyan.TButton',
            command=self._mr_add).pack(side='left', padx=4, pady=6)
        ttk.Button(ab, text='CLEAR ALL', style='Ghost.TButton',
            command=self._mr_clear_all).pack(side='left', padx=4, pady=6)

        self.mr_status_lbl = tk.Label(ab, text='0 rules',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.mr_status_lbl.pack(side='right', padx=12)

        # Rules tree
        cols = ('id','match','replace','target','type','enabled','hits')
        self.mr_tree = ttk.Treeview(frame, columns=cols, show='headings', height=10)
        for col, w, h in [
            ('id',35,'#'), ('match',200,'Match'), ('replace',200,'Replace'),
            ('target',130,'In'), ('type',65,'Type'),
            ('enabled',60,'Active'), ('hits',50,'Hits'),
        ]:
            self.mr_tree.heading(col, text=h)
            self.mr_tree.column(col, width=w,
                anchor='center' if col in ('id','type','enabled','hits') else 'w')
        self.mr_tree.tag_configure('active',   foreground=GREEN)
        self.mr_tree.tag_configure('inactive', foreground=TEXT3)
        vsb = ttk.Scrollbar(frame, orient='vertical', command=self.mr_tree.yview)
        self.mr_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.mr_tree.pack(fill='both', expand=True)
        self.mr_tree.bind('<Double-1>', self._mr_toggle)
        self.mr_tree.bind('<Button-3>', self._mr_context_menu)

        tk.Label(frame,
            text='  Double-click to enable/disable  ·  Right-click to delete  ·  Regex supported',
            bg=BG, fg=TEXT3, font=FONT_MONO_XS, anchor='w').pack(fill='x', pady=4)

        self._mr_load()

    # ── Tab 13: Active Scanner ────────────────────────────────────────────────

    def _build_active_scanner_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ◉ Active Scanner  ')

        # Toolbar
        tb = tk.Frame(frame, bg=BG3)
        tb.pack(fill='x')

        self._cfg_label(tb, 'TARGET URL')
        self.as_url = ttk.Entry(tb, width=40, font=FONT_MONO)
        self.as_url.pack(side='left', padx=(0,8), pady=8)

        self._cfg_label(tb, 'SCAN TYPE')
        self.as_scan_type = ttk.Combobox(tb, width=14, state='readonly',
            values=['Full Auto','SQLi Only','XSS Only','LFI Only',
                    'SSRF Only','SSTI Only','RCE Only','Headers Only',
                    'XXE Only','Open Redirect Only','Path Traversal Only'])
        self.as_scan_type.set('Full Auto')
        self.as_scan_type.pack(side='left', padx=(0,8), pady=8)

        self._cfg_label(tb, 'THREADS')
        self.as_threads = ttk.Entry(tb, width=4)
        self.as_threads.insert(0, '5')
        self.as_threads.pack(side='left', padx=(0,8), pady=8)

        ttk.Button(tb, text='▶  START SCAN', style='Cyan.TButton',
            command=self._as_start).pack(side='left', padx=4, pady=8)
        ttk.Button(tb, text='STOP', style='Ghost.TButton',
            command=self._as_stop).pack(side='left', padx=4, pady=8)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=self._as_clear).pack(side='left', padx=4, pady=8)
        ttk.Button(tb, text='EXPORT', style='Ghost.TButton',
            command=self._as_export).pack(side='left', padx=4, pady=8)

        self.as_status_lbl = tk.Label(tb, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.as_status_lbl.pack(side='right', padx=12)

        # Split: findings tree + detail
        pw = ttk.PanedWindow(frame, orient='vertical')
        pw.pack(fill='both', expand=True)

        top = tk.Frame(pw, bg=BG)
        pw.add(top, weight=2)

        cols = ('sev','type','param','url','evidence')
        self.as_tree = ttk.Treeview(top, columns=cols, show='headings')
        for col, w, h in [
            ('sev',80,'Severity'), ('type',120,'Vuln Type'),
            ('param',100,'Parameter'), ('url',280,'URL'),
            ('evidence',200,'Evidence'),
        ]:
            self.as_tree.heading(col, text=h)
            self.as_tree.column(col, width=w,
                anchor='center' if col == 'sev' else 'w')
        self.as_tree.tag_configure('CRITICAL', foreground=CRITICAL)
        self.as_tree.tag_configure('HIGH',     foreground=HIGH)
        self.as_tree.tag_configure('MEDIUM',   foreground=MEDIUM)
        self.as_tree.tag_configure('LOW',      foreground=LOW)
        vsb = ttk.Scrollbar(top, orient='vertical', command=self.as_tree.yview)
        self.as_tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        self.as_tree.pack(fill='both', expand=True)
        self.as_tree.bind('<<TreeviewSelect>>', self._as_on_select)
        self.as_tree.bind('<Button-3>', self._as_context_menu)

        bot = tk.Frame(pw, bg=BG)
        pw.add(bot, weight=1)
        self._section_label(bot, 'FINDING DETAIL')
        self.as_detail = self._make_text(bot, fg=GREEN)

        self._as_running = False

    # ── Tab 14: Session Analyzer ──────────────────────────────────────────────

    def _build_session_analyzer_tab(self):
        frame = ttk.Frame(self.nb)
        self.nb.add(frame, text='  ⚿ Session  ')

        # Toolbar
        tb = tk.Frame(frame, bg=BG3)
        tb.pack(fill='x')

        ttk.Button(tb, text='▶  ANALYZE', style='Cyan.TButton',
            command=self._sa_analyze).pack(side='left', padx=8, pady=6)
        ttk.Button(tb, text='SCAN HISTORY', style='Ghost.TButton',
            command=self._sa_scan_history).pack(side='left', padx=4, pady=6)
        ttk.Button(tb, text='CLEAR', style='Ghost.TButton',
            command=lambda: [self.sa_input.delete('1.0','end'),
                             self.sa_output.delete('1.0','end')]).pack(side='left', padx=4, pady=6)

        self.sa_status_lbl = tk.Label(tb, text='',
            bg=BG3, fg=TEXT2, font=FONT_MONO_XS)
        self.sa_status_lbl.pack(side='right', padx=12)

        # Split: input + output
        pw = ttk.PanedWindow(frame, orient='horizontal')
        pw.pack(fill='both', expand=True)

        lf = tk.Frame(pw, bg=BG)
        pw.add(lf, weight=1)
        lh = tk.Frame(lf, bg=BG3)
        lh.pack(fill='x')
        tk.Label(lh, text='  TOKEN INPUT  (paste JWT / OAuth / SAML / Cookie)',
            bg=BG3, fg=ACCENT, font=('Fira Code', 9, 'bold')).pack(side='left', padx=4, pady=4)
        self.sa_input = self._make_text(lf)

        rf = tk.Frame(pw, bg=BG)
        pw.add(rf, weight=1)
        rh = tk.Frame(rf, bg=BG3)
        rh.pack(fill='x')
        tk.Label(rh, text='  ANALYSIS RESULT',
            bg=BG3, fg=GREEN, font=('Fira Code', 9, 'bold')).pack(side='left', padx=4, pady=4)
        self.sa_output = self._make_text(rf, fg=GREEN)


    # ── Helpers ───────────────────────────────────────────────────────────────

    def _make_text(self, parent, fg=None):
        f = tk.Frame(parent, bg=BG, padx=0, pady=0)
        f.pack(fill='both', expand=True)
        t = tk.Text(f, bg=BG2, fg=fg or TEXT,
            insertbackground=ACCENT,
            selectbackground=ACCENT3, selectforeground=ACCENT,
            font=FONT_MONO_SM, relief='flat', borderwidth=0,
            wrap='none', padx=12, pady=10,
            spacing1=2, spacing3=2)
        vs = ttk.Scrollbar(f, orient='vertical',   command=t.yview)
        hs = ttk.Scrollbar(f, orient='horizontal', command=t.xview)
        t.configure(yscrollcommand=vs.set, xscrollcommand=hs.set)
        vs.pack(side='right',  fill='y')
        hs.pack(side='bottom', fill='x')
        t.pack(fill='both', expand=True)
        return t

    def _section_label(self, parent, text):
        hdr = tk.Frame(parent, bg=BG3)
        hdr.pack(fill='x')
        tk.Frame(hdr, bg=ACCENT, width=3).pack(side='left', fill='y')
        tk.Label(hdr, text=f'  {text}',
            bg=BG3, fg=TEXT2, font=('Fira Code', 8, 'bold'),
            anchor='w').pack(side='left', padx=4, pady=5)

    def _cfg_label(self, parent, text):
        tk.Label(parent, text=text, bg=BG3, fg=TEXT2,
            font=('Fira Code', 8, 'bold')).pack(side='left', padx=(0,5))

    def _set_status(self, msg):
        try:
            self.lbl_status.config(text=msg)
        except Exception:
            pass

    def _to_hex(self, text: str, width: int = 16) -> str:
        """Convert text to hex dump format."""
        result = []
        data   = text.encode('utf-8', errors='replace')
        for i in range(0, min(len(data), 4096), width):
            chunk   = data[i:i+width]
            hex_str = ' '.join(f'{b:02x}' for b in chunk)
            asc_str = ''.join(chr(b) if 32 <= b < 127 else '.' for b in chunk)
            result.append(f'{i:04x}  {hex_str:<{width*3}}  {asc_str}')
        return '\n'.join(result)

    def _render_body(self, body: str, content_type: str = '') -> str:
        """Render response body as readable text."""
        if not body:
            return ''
        if 'json' in content_type:
            try:
                return json.dumps(json.loads(body), indent=2)[:5000]
            except Exception:
                pass
        if 'html' in content_type or body.strip().startswith('<'):
            try:
                from bs4 import BeautifulSoup
                return BeautifulSoup(body[:20000], 'html.parser').get_text(
                    separator='\n', strip=True)[:5000]
            except Exception:
                pass
        return body[:3000]


    # ── Proxy Toggle ──────────────────────────────────────────────────────────

    def _toggle_proxy(self):
        if self.proxy_running:
            # Stop Rust core if started from UI
            if hasattr(self, '_rust_proc') and self._rust_proc:
                self._rust_proc.terminate()
                self._rust_proc = None
            if self.proxy and hasattr(self.proxy, 'stop'):
                self.proxy.stop()
            self.proxy_running = False
            self._proxy_btn_text.set('▶  START PROXY')
            self.btn_proxy.configure(style='Green.TButton')
            self.lbl_proxy_status.config(text='● OFFLINE', fg=RED)
            self._set_status('Proxy stopped')
        else:
            try:
                port = int(self.entry_port.get() or 8082)
            except ValueError:
                port = 8082

            # Use Rust bridge if already running (started from main.py)
            if self._rust_bridge and self._rust_bridge.is_running():
                self.proxy = self._rust_bridge
                self.proxy_running = True
                self._proxy_btn_text.set('■  STOP PROXY')
                self.btn_proxy.configure(style='Red.TButton')
                self.lbl_proxy_status.config(text=f'● ONLINE :{port}  [Rust]', fg=GREEN)
                self._set_status(f'Rust proxy on 127.0.0.1:{port}  ·  Set browser proxy to 127.0.0.1:{port}')
                return

            # Start Rust core + bridge from UI button
            import subprocess, threading, time, os
            from sentinel_proxy.core.rust_bridge import RustCoreBridge
            from pathlib import Path

            rust_bin = Path(__file__).parents[1] / 'rust_core' / 'target' / 'release' / 'sentinel_proxy_core'
            socket_path = '/tmp/sentinel_proxy_v2.sock'

            if not rust_bin.exists():
                messagebox.showerror('Proxy Error',
                    f'Rust binary not found:\n{rust_bin}\n\n'
                    f'Build it:\ncd sentinel_proxy/rust_core\ncargo build --release')
                return

            # Kill stale
            try:
                r = subprocess.run(['lsof', '-t', f'-i:{port}'], capture_output=True, text=True)
                for pid in r.stdout.strip().split():
                    if pid: subprocess.run(['kill', '-9', pid], capture_output=True)
                time.sleep(0.3)
            except Exception:
                pass

            proc = subprocess.Popen(
                [str(rust_bin), '127.0.0.1', str(port), socket_path],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            self._rust_proc = proc

            # Wait for port
            import socket as _sock
            ready = False
            for _ in range(20):
                try:
                    s = _sock.create_connection(('127.0.0.1', port), timeout=0.3)
                    s.close(); ready = True; break
                except Exception:
                    time.sleep(0.2)

            if not ready or proc.poll() is not None:
                messagebox.showerror('Proxy Error', f'Rust core failed to start on port {port}')
                return

            bridge = RustCoreBridge(socket_path)
            bridge.on_request   = self._on_proxy_request
            bridge.on_response  = self._on_proxy_response
            bridge.on_websocket = self._on_proxy_websocket
            bridge.start()

            self.proxy         = bridge
            self._rust_bridge  = bridge
            self.proxy_running = True
            self._proxy_btn_text.set('■  STOP PROXY')
            self.btn_proxy.configure(style='Red.TButton')
            self.lbl_proxy_status.config(text=f'● ONLINE :{port}  [Rust]', fg=GREEN)
            self._set_status(f'Rust proxy on 127.0.0.1:{port}  ·  Set browser proxy to 127.0.0.1:{port}')

    def _toggle_intercept(self, event=None):
        self.intercept_on = not self.intercept_on
        if self.intercept_on:
            self.btn_intercept.config(text='  INTERCEPT: ON   ', bg='#0d2818', fg=GREEN)
        else:
            self.btn_intercept.config(text='  INTERCEPT: OFF  ', bg=BG4, fg=TEXT3)
            if self.proxy and hasattr(self.proxy, 'forward_all'):
                self.proxy.forward_all()
        # Tell Rust core via bridge
        if self.proxy and hasattr(self.proxy, 'set_intercept'):
            self.proxy.set_intercept(self.intercept_on)

    def _intercept_forward(self):
        flow_id = getattr(self, '_current_intercept_id', '')
        if self.proxy and flow_id:
            # Parse edited request from txt_request widget
            raw     = self.txt_request.get('1.0', 'end').strip()
            headers = []
            body    = ''
            in_body = False
            for line in raw.split('\n')[1:]:
                if not line.strip():
                    in_body = True
                    continue
                if in_body:
                    body += line + '\n'
                elif ':' in line:
                    k, _, v = line.partition(':')
                    headers.append({'name': k.strip(), 'value': v.strip()})
            if hasattr(self.proxy, 'forward_modified'):
                self.proxy.forward_modified(flow_id, headers, body.strip())
            elif hasattr(self.proxy, 'forward_flow'):
                self.proxy.forward_flow(flow_id)
        self._intercept_pending    = False
        self._current_intercept_id = ''
        self.btn_fwd.config(state='disabled')
        self.btn_drop.config(state='disabled')
        self._set_status('Request forwarded')

    def _intercept_drop(self):
        flow_id = getattr(self, '_current_intercept_id', '')
        if self.proxy and flow_id:
            if hasattr(self.proxy, 'drop_flow'):
                self.proxy.drop_flow(flow_id)
            elif hasattr(self.proxy, 'intercept_drop'):
                self.proxy.intercept_drop()
        self._intercept_pending    = False
        self._current_intercept_id = ''
        self.btn_fwd.config(state='disabled')
        self.btn_drop.config(state='disabled')
        self._set_status('Request dropped')

    def _on_intercept_held(self, entry: dict):
        """Called from interceptor when a flow is held — update UI."""
        self._current_intercept_id = entry.get('id', '')
        self.root.after(0, lambda: self._show_intercept_entry(entry))

    def _show_intercept_entry(self, entry: dict):
        """Show intercepted request in proxy panel and enable FWD/DROP."""
        self._intercept_pending = True
        self.btn_fwd.config(state='normal')
        self.btn_drop.config(state='normal')
        flow   = entry
        method = flow.get('method', '')
        url    = flow.get('url', '')
        self._set_status(f'⏸ INTERCEPTED: {method} {url[:60]}')
        hdrs = flow.get('headers', {})
        rt   = f"{method} {flow.get('path','')} HTTP/1.1\nHost: {flow.get('host','')}\n"
        for k, v in hdrs.items():
            rt += f"{k}: {v}\n"
        if flow.get('body'):
            rt += '\n' + flow['body']
        try:
            self.txt_request.delete('1.0', 'end')
            self.txt_request.insert('1.0', rt)
            self.txt_ai.delete('1.0', 'end')
            self.txt_ai.insert('1.0',
                f'⏸ REQUEST INTERCEPTED\n{"="*40}\n'
                f'Method : {method}\nURL    : {url}\n'
                f'ID     : {self._current_intercept_id}\n\n'
                f'Edit request above then click ▶ FWD to forward or ✕ DROP to drop.\n')
        except Exception:
            pass

    def _on_proxy_request(self, flow):
        """Called from daemon thread — return immediately, do all work in background."""
        def _work():
            try:
                host = flow.get('host', '')
                try:
                    in_scope = self.db.check_scope(host)
                except Exception:
                    in_scope = True
                if not in_scope:
                    return
                row_id = self.db.save_request(flow)
                flow['_row_id'] = row_id

                # Pattern + SentinelNet + Groq
                if self.analyzer:
                    result = self.analyzer.analyze(flow)
                else:
                    result = {'risk': 'UNKNOWN', 'vulns': [], 'summary': ''}

                # ProxyMLEngine — 10 algorithms (merge results)
                try:
                    from sentinel_proxy.ai.proxy_ml_engine import get_engine
                    ml = get_engine().analyze_request(flow)
                    # Merge vulns from ML engine
                    ml_vulns = ml.get('vulns', [])
                    if ml_vulns:
                        existing_types = {v.get('type') for v in result.get('vulns', [])}
                        for v in ml_vulns:
                            if v.get('type') not in existing_types:
                                result['vulns'].append(v)
                    # Upgrade risk if ML found something higher
                    risk_order = {'LOW': 0, 'MEDIUM': 1, 'HIGH': 2, 'CRITICAL': 3, 'UNKNOWN': -1}
                    if risk_order.get(ml.get('risk', 'LOW'), 0) > risk_order.get(result['risk'], 0):
                        result['risk'] = ml['risk']
                    # Store ML metadata in flow for UI
                    flow['_ml_session_pattern'] = ml.get('session_pattern', 'normal')
                    flow['_ml_waf_bypass']       = ml.get('waf_bypass_prob', 0.0)
                    flow['_ml_anomaly']          = ml.get('anomaly_score', 0.0)
                    flow['_ml_attack_chain']     = ml.get('attack_chain', 'normal')
                except Exception:
                    pass

                self.db.update_ai(row_id, result['risk'], result['vulns'], result['summary'])
                self.root.after(0, self._add_to_tree, flow, row_id, result)
            except Exception:
                pass
        threading.Thread(target=_work, daemon=True, name='sp-req-work').start()

    def _on_proxy_response(self, flow):
        """Called from daemon thread — return immediately, do all work in background."""
        def _work():
            try:
                flow_id = flow.get('id', '')
                if not flow_id:
                    return
                self.db.update_response(
                    flow_id,
                    flow.get('status_code', 0),
                    flow.get('resp_headers', {}),
                    flow.get('resp_body', ''),
                    flow.get('resp_length', 0),
                    flow.get('content_type', ''),
                    flow.get('response_time', 0),
                )
                row = self.db.get_request_by_flow_id(flow_id)
                if not row:
                    return
                row_id = row['id']
                self.root.after(0, self._update_tree_row, str(row_id), flow,
                                {'risk': row.get('ai_risk', 'UNKNOWN'), 'vulns': [], 'summary': ''})
            except Exception:
                pass
        threading.Thread(target=_work, daemon=True, name='sp-resp-work').start()

    def _on_proxy_websocket(self, msg):
        """Called from daemon thread on WebSocket message."""
        try:
            if hasattr(self, '_ws_tab'):
                self.root.after(0, lambda: self._ws_tab.add_message(msg))
        except Exception:
            pass

    def _add_to_tree(self, flow, row_id, ai):
        risk   = ai.get('risk', 'UNKNOWN')
        method = flow.get('method', '')
        ts     = datetime.now().strftime('%H:%M:%S')
        self._req_counter += 1

        tags = [risk]
        if method in ('GET','POST','DELETE','PUT'):
            tags.append(method)
        if risk == 'CRITICAL':
            tags.append('flagged')
            threading.Thread(target=lambda: self.db.flag_request(row_id, True),
                             daemon=True).start()

        self.tree.insert('', 0, iid=str(row_id),
            values=(self._req_counter, method,
                    flow.get('host','')[:38],
                    flow.get('path','')[:55],
                    flow.get('status_code','') or '',
                    risk,
                    flow.get('resp_length','') or '',
                    '',
                    ts),
            tags=tuple(tags))

        self.lbl_req_count.config(text=f'{self._req_counter} reqs')
        self._hl_apply(flow, row_id)
        if hasattr(self, '_target_tab'):
            self._target_tab.on_new_request(flow, row_id)
        # Stats update in background
        def _update_stats():
            try:
                st = self.db.stats()
                self.root.after(0, lambda: self.lbl_sb_stats.config(
                    text=f"total:{st['total']}  flagged:{st['flagged']}  risky:{st['risky']}"))
            except Exception:
                pass
        threading.Thread(target=_update_stats, daemon=True).start()

    def _update_tree_row(self, iid: str, flow: dict, ai: dict):
        """Update existing tree row with response data after response arrives."""
        try:
            if not self.tree.exists(iid):
                return
            risk   = ai.get('risk', 'UNKNOWN')
            ms     = flow.get('response_time', '')
            ms_str = f"{ms:.0f}" if ms else ''
            vals   = list(self.tree.item(iid, 'values'))
            # cols: id, method, host, path, status, risk, length, ms, time
            vals[4] = flow.get('status_code', '') or ''
            vals[5] = risk
            vals[6] = flow.get('resp_length', '') or ''
            vals[7] = ms_str
            self.tree.item(iid, values=tuple(vals))
            # Update tags with new risk
            current_tags = [t for t in self.tree.item(iid, 'tags')
                            if t not in ('LOW','MEDIUM','HIGH','CRITICAL','UNKNOWN')]
            current_tags.insert(0, risk)
            if risk == 'CRITICAL' and 'flagged' not in current_tags:
                current_tags.append('flagged')
                threading.Thread(target=lambda: self.db.flag_request(int(iid), True),
                                 daemon=True).start()
            self.tree.item(iid, tags=tuple(current_tags))
        except Exception:
            pass


    # ── Selection ─────────────────────────────────────────────────────────────

    def _on_select(self, event=None):
        sel = self.tree.selection()
        if not sel:
            return
        row_id = int(sel[0])
        self.selected_req = row_id
        req = self.db.get_request(row_id)
        if not req:
            return

        # Request tab
        try:
            hdrs = json.loads(req.get('headers', '{}'))
        except (json.JSONDecodeError, TypeError):
            hdrs = {}
        rt   = f"{req.get('method','')} {req.get('path','')} HTTP/1.1\nHost: {req.get('host','')}\n"
        for k, v in hdrs.items():
            rt += f"{k}: {v}\n"
        if req.get('body'):
            rt += f"\n{req['body']}"
        self.txt_request.delete('1.0', 'end')
        self.txt_request.insert('1.0', rt)

        # Request Hex tab
        self.txt_request_hex.delete('1.0', 'end')
        self.txt_request_hex.insert('1.0', self._to_hex(rt))

        # Params tab
        for i in self.req_params_tree.get_children():
            self.req_params_tree.delete(i)
        try:
            params = json.loads(req.get('params', '{}'))
        except Exception:
            params = {}
        for k, v in params.items():
            self.req_params_tree.insert('', 'end', values=(k, v, 'query'))
        body = req.get('body', '')
        if body and '=' in body:
            for part in body.split('&'):
                if '=' in part:
                    k, _, v = part.partition('=')
                    self.req_params_tree.insert('', 'end',
                        values=(k.strip(), urllib.parse.unquote(v.strip()), 'body'))
        for k, v in hdrs.items():
            if k.lower() in ('cookie', 'authorization', 'x-api-key'):
                self.req_params_tree.insert('', 'end', values=(k, v, 'header'))

        # Response tab
        self.txt_response.delete('1.0', 'end')
        rsp = ''
        if req.get('status_code'):
            rsp = f"HTTP/1.1 {req.get('status_code','')}\n"
            try:
                rhdrs = json.loads(req.get('resp_headers', '{}')) if req.get('resp_headers') else {}
            except (json.JSONDecodeError, TypeError):
                rhdrs = {}
            for k, v in rhdrs.items():
                rsp += f"{k}: {v}\n"
            if req.get('resp_body'):
                rsp += f"\n{req['resp_body'][:8000]}"
            self.txt_response.insert('1.0', rsp)

        # Response Hex tab
        self.txt_response_hex.delete('1.0', 'end')
        if rsp:
            self.txt_response_hex.insert('1.0', self._to_hex(rsp[:2000]))

        # Response Render tab (HTML preview as plain text)
        self.txt_response_render.delete('1.0', 'end')
        resp_body = req.get('resp_body', '')
        if resp_body:
            ct = req.get('content_type', '')
            if 'html' in ct or resp_body.strip().startswith('<'):
                try:
                    from bs4 import BeautifulSoup
                    soup = BeautifulSoup(resp_body[:20000], 'html.parser')
                    rendered = soup.get_text(separator='\n', strip=True)
                    self.txt_response_render.insert('1.0', rendered[:5000])
                except Exception:
                    self.txt_response_render.insert('1.0', resp_body[:3000])
            elif 'json' in ct:
                try:
                    pretty = json.dumps(json.loads(resp_body), indent=2)
                    self.txt_response_render.insert('1.0', pretty[:5000])
                except Exception:
                    self.txt_response_render.insert('1.0', resp_body[:3000])
            else:
                self.txt_response_render.insert('1.0', resp_body[:3000])

        # AI tab
        try:
            vulns = json.loads(req.get('ai_vulns', '[]'))
        except (json.JSONDecodeError, TypeError):
            vulns = []
        risk    = req.get('ai_risk', 'UNKNOWN')
        summary = req.get('ai_summary', '')
        at = f"{'='*55}\n  RISK: {risk}\n{'='*55}\n\n"
        at += f"Summary: {summary}\n\n"
        if vulns:
            at += f"Vulnerabilities Found ({len(vulns)}):\n"
            at += '-'*40 + '\n'
            for v in vulns:
                at += f"  [{v.get('severity','?')}]  {v.get('type','?')}\n"
                at += f"         {v.get('detail','')}\n"
                if v.get('param'):
                    at += f"         Param: {v['param']}\n"
                at += '\n'
            at += "Suggested Payloads:\n" + '-'*40 + '\n'
            for v in vulns[:2]:
                at += f"\n  {v.get('type','')}:\n"
                for p in self.analyzer.suggest_payloads(v.get('type',''))[:5]:
                    at += f"    {p}\n"
        else:
            at += "No vulnerabilities detected.\n\nUse 'AI Deep Scan' for Groq LLM analysis.\n"
        self.txt_ai.delete('1.0', 'end')
        self.txt_ai.insert('1.0', at)

    def _tree_context_menu(self, event):
        item = self.tree.identify_row(event.y)
        if not item:
            return
        self.tree.selection_set(item)
        self.selected_req = int(item)
        m = tk.Menu(self.root, tearoff=0,
            bg=BG3, fg=TEXT,
            activebackground=BG4, activeforeground=ACCENT,
            font=FONT_MONO_SM, bd=0, relief='flat')
        m.add_command(label='  → Send to Repeater', command=self._send_to_repeater)
        m.add_command(label='  → Send to Intruder', command=self._send_to_intruder)
        m.add_command(label='  → Send to Scanner',  command=self._send_to_scanner)
        m.add_separator()
        m.add_command(label='  AI Deep Scan',        command=self._deep_ai_scan)
        m.add_command(label='  Flag / Unflag',        command=self._flag_request)
        m.add_command(label='  Save to Organizer',   command=self._save_to_organizer)
        m.add_command(label='  Copy URL',             command=self._copy_url)
        m.add_command(label='  Copy as cURL',         command=self._copy_curl)
        m.post(event.x_root, event.y_root)

    # ── Actions ───────────────────────────────────────────────────────────────

    def _send_to_repeater(self, event=None):
        if not self.selected_req:
            return
        req = self.db.get_request(self.selected_req)
        if not req:
            return
        self.rep_method.set(req.get('method', 'GET'))
        self.rep_url.delete(0, 'end')
        self.rep_url.insert(0, req.get('url', ''))
        try:
            hdrs = json.loads(req.get('headers', '{}'))
        except (json.JSONDecodeError, TypeError):
            hdrs = {}
        rt   = f"{req.get('method','')} {req.get('path','')} HTTP/1.1\nHost: {req.get('host','')}\n"
        for k, v in hdrs.items():
            rt += f"{k}: {v}\n"
        if req.get('body'):
            rt += f"\n{req['body']}"
        self.rep_req_txt.delete('1.0', 'end')
        self.rep_req_txt.insert('1.0', rt)
        self.nb.select(1)
        self._set_status(f'Request #{self.selected_req} sent to Repeater')

    def _send_to_intruder(self):
        if not self.selected_req:
            return
        req = self.db.get_request(self.selected_req)
        if not req:
            return
        self.int_url.delete(0, 'end')
        self.int_url.insert(0, req.get('url', ''))
        self.nb.select(2)
        self._set_status(f'Request #{self.selected_req} sent to Intruder')

    def _send_to_scanner(self):
        if not self.selected_req:
            return
        req = self.db.get_request(self.selected_req)
        if not req:
            return
        self.scan_url.delete(0, 'end')
        self.scan_url.insert(0, req.get('url', ''))
        self.nb.select(3)

    def _deep_ai_scan(self):
        if not self.selected_req:
            return
        req = self.db.get_request(self.selected_req)
        if not req:
            return
        self.txt_ai.insert('end', '\n' + '─'*50 + '\nRunning Groq deep analysis...\n')
        def cb(r):
            out  = f"\n── Groq Analysis ──\n"
            out += f"Risk   : {r.get('risk','?')}\n"
            out += f"Vulns  : {', '.join(r.get('vulns',[]))}\n"
            out += f"Detail : {r.get('detail','')}\n"
            out += f"Fix    : {r.get('fix','')}\n"
            self.root.after(0, lambda: self.txt_ai.insert('end', out))
        self.analyzer.analyze_deep(req, callback=cb)

    def _flag_request(self):
        if not self.selected_req:
            return
        req     = self.db.get_request(self.selected_req)
        flagged = not bool(req.get('flagged', 0))
        self.db.flag_request(self.selected_req, flagged)
        self._set_status(f"{'Flagged' if flagged else 'Unflagged'}: #{self.selected_req}")

    def _copy_url(self):
        if not self.selected_req:
            return
        req = self.db.get_request(self.selected_req)
        if req:
            self.root.clipboard_clear()
            self.root.clipboard_append(req.get('url', ''))
            self._set_status('URL copied to clipboard')

    def _copy_curl(self):
        if not self.selected_req:
            return
        req  = self.db.get_request(self.selected_req)
        if not req:
            return
        try:
            hdrs = json.loads(req.get('headers', '{}'))
        except (json.JSONDecodeError, TypeError):
            hdrs = {}
        url  = req.get('url', '').replace("'", "%27")
        cmd  = f"curl -X {req.get('method','GET')} '{url}'"
        for k, v in list(hdrs.items())[:5]:
            v_safe = str(v).replace("'", "'\"'\"'")
            cmd += f" -H '{k}: {v_safe}'"
        if req.get('body'):
            body_safe = req['body'][:200].replace("'", "'\"'\"'")
            cmd += f" -d '{body_safe}'"
        self.root.clipboard_clear()
        self.root.clipboard_append(cmd)
        self._set_status('cURL command copied')

    def _save_to_organizer(self):
        if not self.selected_req:
            return
        if hasattr(self, '_organizer_tab'):
            self._organizer_tab.save_request(self.selected_req)


    # ── Repeater ──────────────────────────────────────────────────────────────

    def _repeater_send(self):
        url    = self.rep_url.get().strip()
        method = self.rep_method.get()
        if not url:
            messagebox.showwarning('Repeater', 'Enter a URL')
            return
        raw     = self.rep_req_txt.get('1.0', 'end').strip()
        headers = {}
        body    = ''
        in_body = False
        for line in raw.split('\n')[1:]:
            if not line.strip():
                in_body = True
                continue
            if in_body:
                body += line + '\n'
            elif ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip()] = v.strip()

        def _go():
            try:
                self.root.after(0, lambda: self.rep_status_lbl.config(
                    text='Sending...', fg=YELLOW))
                t0 = time.time()
                r  = requests.request(method, url,
                    headers=headers,
                    data=body.encode() if body else None,
                    verify=False, timeout=15,
                    allow_redirects=False)
                elapsed = (time.time() - t0) * 1000
                sc    = GREEN if r.status_code < 400 else (ORANGE if r.status_code < 500 else RED)
                rt    = f"HTTP/1.1 {r.status_code} {r.reason}\n"
                for k, v in r.headers.items():
                    rt += f"{k}: {v}\n"
                rt += f"\n{r.text[:15000]}"
                label = f"{r.status_code} {r.reason}  ·  {len(r.content)} bytes  ·  {elapsed:.0f}ms"
                # Save to repeater history
                self.db.save_repeater_history(
                    method, url, headers, body, rt,
                    r.status_code, len(r.content), round(elapsed, 1))
                self.root.after(0, lambda: [
                    self.rep_resp_txt.delete('1.0', 'end'),
                    self.rep_resp_txt.insert('1.0', rt),
                    self.rep_status_lbl.config(text=label, fg=sc)])
                # Hex + Render tabs
                self.root.after(0, lambda rt=rt, rb=r.text: [
                    self.rep_resp_hex.delete('1.0', 'end'),
                    self.rep_resp_hex.insert('1.0', self._to_hex(rt[:2000])),
                    self.rep_resp_render.delete('1.0', 'end'),
                    self.rep_resp_render.insert('1.0', self._render_body(rb, r.headers.get('content-type','')))])
                # Request hex
                raw_req = self.rep_req_txt.get('1.0', 'end')
                self.root.after(0, lambda rq=raw_req: [
                    self.rep_req_hex.delete('1.0', 'end'),
                    self.rep_req_hex.insert('1.0', self._to_hex(rq[:2000]))])
            except Exception as e:
                self.root.after(0, lambda: self.rep_status_lbl.config(
                    text=str(e)[:60], fg=RED))
        threading.Thread(target=_go, daemon=True).start()

    def _repeater_clear(self):
        self.rep_req_txt.delete('1.0', 'end')
        self.rep_resp_txt.delete('1.0', 'end')
        self.rep_url.delete(0, 'end')
        self.rep_status_lbl.config(text='')

    def _repeater_save(self):
        url = self.rep_url.get().strip()
        if not url:
            return
        raw = self.rep_req_txt.get('1.0', 'end').strip()
        headers = {}
        body = ''
        in_body = False
        for line in raw.split('\n')[1:]:
            if not line.strip():
                in_body = True
                continue
            if in_body:
                body += line + '\n'
            elif ':' in line:
                k, _, v = line.partition(':')
                headers[k.strip()] = v.strip()
        self.db.save_to_repeater(
            f"{self.rep_method.get()} {url[:40]}",
            self.rep_method.get(), url, headers, body)
        self._set_status('Request saved to history')

    def _repeater_show_history(self):
        rows = self.db.get_repeater_history(50)
        if not rows:
            messagebox.showinfo('Repeater History', 'No history yet.')
            return
        w = tk.Toplevel(self.root)
        w.title('Repeater History')
        w.geometry('900x500')
        w.configure(bg=BG)
        w.grab_set()
        tk.Frame(w, bg=ACCENT, height=2).pack(fill='x')
        tk.Label(w, text='  REPEATER HISTORY',
            bg=BG, fg=ACCENT, font=FONT_BOLD).pack(anchor='w', padx=8, pady=6)
        cols = ('id','method','url','status','length','time')
        tree = ttk.Treeview(w, columns=cols, show='headings', height=12)
        for col, w2, h in [
            ('id',40,'#'), ('method',65,'Method'), ('url',380,'URL'),
            ('status',60,'Status'), ('length',70,'Length'), ('time',80,'Time'),
        ]:
            tree.heading(col, text=h)
            tree.column(col, width=w2, anchor='w' if col=='url' else 'center')
        vsb = ttk.Scrollbar(w, orient='vertical', command=tree.yview)
        tree.configure(yscrollcommand=vsb.set)
        vsb.pack(side='right', fill='y')
        tree.pack(fill='both', expand=True, padx=8)
        for r in rows:
            tree.insert('', 'end', iid=str(r['id']),
                values=(r['id'], r.get('method',''), r.get('url','')[:70],
                        r.get('status',''), r.get('length',''),
                        r.get('created_at','')[:16]))
        def _load(event=None):
            sel = tree.selection()
            if not sel: return
            r = next((x for x in rows if str(x['id']) == sel[0]), None)
            if not r: return
            self.rep_method.set(r.get('method','GET'))
            self.rep_url.delete(0, 'end')
            self.rep_url.insert(0, r.get('url',''))
            self.rep_req_txt.delete('1.0', 'end')
            try:
                hdrs = json.loads(r.get('headers','{}'))
            except Exception:
                hdrs = {}
            rt = f"{r.get('method','')} {r.get('url','')} HTTP/1.1\n"
            for k, v in hdrs.items():
                rt += f"{k}: {v}\n"
            if r.get('body'):
                rt += f"\n{r['body']}"
            self.rep_req_txt.insert('1.0', rt)
            self.rep_resp_txt.delete('1.0', 'end')
            if r.get('response'):
                self.rep_resp_txt.insert('1.0', r['response'])
            w.destroy()
            self.nb.select(1)
        tree.bind('<Double-1>', _load)
        ttk.Button(w, text='LOAD SELECTED', style='Cyan.TButton',
            command=_load).pack(pady=8)

    # ── Intruder ──────────────────────────────────────────────────────────────

    def _load_payloads(self, event=None):
        vuln_type = self.int_type.get()
        p = self._load_payloads_from_file(vuln_type)
        if not p:
            p = self.analyzer.suggest_payloads(vuln_type)
        self.int_payloads_txt.delete('1.0', 'end')
        self.int_payloads_txt.insert('1.0', '\n'.join(p))
        if hasattr(self, 'lbl_status'):
            self._set_status(f'Loaded {len(p)} payloads for {vuln_type}')

    def _load_payloads_from_file(self, vuln_type: str) -> list:
        FILE_MAP = {
            'SQLi': 'sqli.txt', 'XSS': 'xss.txt', 'LFI': 'lfi.txt',
            'SSRF': 'ssrf.txt', 'SSTI': 'ssti.txt', 'RCE': 'rce.txt',
            'XXE': 'xxe.txt', 'Open Redirect': 'open_redirect.txt',
            'LDAP': 'ldap.txt', 'NoSQL': 'nosql.txt', 'GraphQL': 'graphql.txt',
            'JWT': 'jwt.txt', 'CORS': 'cors.txt', 'CRLF': 'crlf.txt',
            'Path Traversal': 'path_traversal.txt', 'File Upload': 'file_upload.txt',
            'Prototype Pollution': 'prototype_pollution.txt',
            'Request Smuggling': 'smuggling.txt',
            'Cache Deception': 'cache_deception.txt',
            'XPATH': 'xpath.txt',
        }
        fname = FILE_MAP.get(vuln_type)
        if not fname:
            return []
        try:
            fpath = Path(__file__).parent.parent / 'payloads' / fname
            lines = fpath.read_text(errors='ignore').splitlines()
            return [l for l in lines if l.strip()][:2000]
        except Exception:
            return []

    def _on_mode_change(self, event=None):
        mode = self.int_mode.get()
        desc = {
            'Sniper':       'Sniper — one param, one payload list',
            'Battering Ram':'Battering Ram — same payload in all params',
            'Pitchfork':    'Pitchfork — two params, two lists (paired)',
            'Cluster Bomb': 'Cluster Bomb — two params, all combinations',
        }
        self.int_mode_lbl.config(text=f"Mode: {desc.get(mode,'')}")

    def _intruder_start(self):
        if self._intruder_running:
            return
        url    = self.int_url.get().strip()
        param  = self.int_param.get().strip()
        param2 = self.int_param2.get().strip()
        mode   = self.int_mode.get()
        grep   = self.int_grep.get().strip()

        payloads1 = [p.strip() for p in
            self.int_payloads_txt.get('1.0','end').strip().split('\n') if p.strip()]
        payloads2 = [p.strip() for p in
            self.int_payloads2_txt.get('1.0','end').strip().split('\n') if p.strip()]

        try:
            threads_n = int(self.int_threads.get() or 10)
        except ValueError:
            threads_n = 10

        if not url or not param:
            from tkinter import messagebox
            messagebox.showwarning('Intruder', 'TARGET URL and PARAM 1 are required')
            return
        if not payloads1:
            from tkinter import messagebox
            messagebox.showwarning('Intruder', 'No payloads in Payload 1')
            return

        # Try Rust fuzzer first (50x faster)
        from sentinel_proxy.core.rust_fuzzer_bridge import RustFuzzerBridge
        rust_fuzz = RustFuzzerBridge()
        if rust_fuzz.is_available():
            self._intruder_running = True
            self._rust_fuzzer      = rust_fuzz
            for i in self.int_tree.get_children():
                self.int_tree.delete(i)
            self._int_all_results = []
            total = [len(payloads1)]
            done  = [0]

            mode_map = {
                'Sniper': 'sniper', 'Battering Ram': 'battering_ram',
                'Pitchfork': 'pitchfork', 'Cluster Bomb': 'cluster_bomb',
            }

            def on_result(r):
                done[0] += 1
                p1   = r.get('payload', '')
                p2   = r.get('payload2', '')
                s    = r.get('status', 0)
                ln   = r.get('length', 0)
                d    = r.get('diff', 0)
                gh   = r.get('grep_match', False)
                intr = r.get('interesting', False)
                err  = r.get('error')
                resp = r.get('body', '')
                tag  = 'grep_match' if gh else ('interesting' if intr else '')
                self._int_all_results.append(
                    {'p1': p1, 'p2': p2, 'status': s, 'length': ln,
                     'diff': d, 'grep': gh, 'tag': tag, 'resp': resp})
                self.root.after(0, lambda p1=p1, p2=p2, s=s, ln=ln, d=d,
                    gh=gh, tg=tag, dn=done[0]: [
                    self.int_tree.insert('', 'end',
                        values=(str(p1)[:60], str(p2)[:40] if p2 else '',
                                s or 'ERR', ln,
                                f'+{d}' if d > 0 else str(d),
                                'YES' if gh else '',
                                '!!' if tg in ('grep_match',) else ('!' if tg == 'interesting' else '')),
                        tags=(tg,) if tg else ()),
                    self.int_progress.config(text=f'{dn}/{total[0]}')])

            def on_done():
                self._intruder_running = False
                interesting = sum(1 for i in self.int_tree.get_children()
                                  if self.int_tree.item(i)['tags'])
                self.root.after(0, lambda: [
                    self.int_progress.config(
                        text=f'Done [Rust]  ·  {total[0]} sent  ·  {interesting} interesting'),
                    self._set_status(
                        f'Intruder [Rust] done  ·  {total[0]} requests  ·  {interesting} flagged')])

            use_post  = self.int_post_var.get()
            post_body = self.int_post_body.get().strip() if use_post else ''
            try:
                delay = int(self.int_delay.get() or 0)
            except ValueError:
                delay = 0

            if mode == 'Cluster Bomb':
                total[0] = len(payloads1) * len(payloads2)
            elif mode == 'Pitchfork':
                total[0] = min(len(payloads1), len(payloads2))

            rust_fuzz.start(
                url=url, param=param, payloads=payloads1,
                mode=mode_map.get(mode, 'sniper'),
                param2=param2, payloads2=payloads2,
                threads=threads_n, delay_ms=delay,
                grep=grep, post_body=post_body,
                on_result=on_result, on_done=on_done,
            )
            self.int_progress.config(text=f'0/{total[0]}  [Rust engine]')
            self._set_status(f'Intruder running with Rust engine  ·  {total[0]} payloads')
            return

        if not url or not param:
            messagebox.showwarning('Intruder', 'TARGET URL and PARAM 1 are required')
            return
        if not payloads1:
            messagebox.showwarning('Intruder', 'No payloads in Payload 1')
            return
        if mode in ('Pitchfork','Cluster Bomb') and not param2:
            messagebox.showwarning('Intruder', f'{mode} requires PARAM 2')
            return

        # Build attack pairs based on mode
        if mode == 'Sniper':
            pairs = [(p, '') for p in payloads1]
        elif mode == 'Battering Ram':
            pairs = [(p, p) for p in payloads1]
        elif mode == 'Pitchfork':
            pairs = list(zip(payloads1, payloads2 or payloads1))
        else:  # Cluster Bomb
            pairs = [(p1, p2) for p1 in payloads1 for p2 in (payloads2 or [''])]

        for i in self.int_tree.get_children():
            self.int_tree.delete(i)
        self.int_resp_txt.delete('1.0', 'end')
        self._int_all_results = []

        self._intruder_running = True
        session_id = str(int(time.time()))
        base_len   = [None]
        base_lock  = threading.Lock()
        done       = [0]
        total      = len(pairs)

        use_post  = self.int_post_var.get()
        post_body = self.int_post_body.get().strip() if use_post else ''
        try:
            req_delay = int(self.int_delay.get() or 0) / 1000.0
        except ValueError:
            req_delay = 0

        def _send(pair):
            p1, p2 = pair
            if not self._intruder_running:
                return
            try:
                sep = '&' if '?' in url else '?'
                if use_post and post_body:
                    body_fuzzed = post_body.replace(f'§{param}§', urllib.parse.quote(str(p1)))
                    if param2:
                        body_fuzzed = body_fuzzed.replace(f'§{param2}§', urllib.parse.quote(str(p2)))
                    r = requests.post(url, data=body_fuzzed,
                        headers={'Content-Type': 'application/x-www-form-urlencoded'},
                        verify=False, timeout=8, allow_redirects=False)
                    target_url = url
                else:
                    if mode == 'Sniper':
                        target_url = f"{url}{sep}{param}={urllib.parse.quote(str(p1))}"
                    elif mode == 'Battering Ram':
                        target_url = (f"{url}{sep}{param}={urllib.parse.quote(str(p1))}"
                                      + (f"&{param2}={urllib.parse.quote(str(p1))}" if param2 else ''))
                    else:
                        target_url = (f"{url}{sep}{param}={urllib.parse.quote(str(p1))}"
                                      + f"&{param2}={urllib.parse.quote(str(p2))}")
                    r = requests.get(target_url, verify=False,
                                     timeout=8, allow_redirects=False)

                length = len(r.content)
                with base_lock:
                    if base_len[0] is None:
                        base_len[0] = length
                diff = length - base_len[0]

                grep_hit    = bool(grep and grep.lower() in r.text.lower())
                interesting = (r.status_code not in (200,301,302,404)
                               or abs(diff) > 50 or grep_hit)
                tag = ('grep_match' if grep_hit
                       else ('critical'    if abs(diff) > 200 and r.status_code in (200,500)
                       else ('interesting' if interesting else '')))

                self.db.save_intruder_result(
                    session_id, str(p1), r.status_code, length,
                    r.text[:500], interesting, str(p2))
                done[0] += 1
                resp_preview = r.text[:800]
                if req_delay > 0:
                    import time as _t; _t.sleep(req_delay)
                self.root.after(0, lambda p1=p1, p2=p2, s=r.status_code,
                    ln=length, d=diff, gh=grep_hit, tg=tag, rp=resp_preview: [
                    self._int_all_results.append(
                        {'p1':str(p1),'p2':str(p2),'status':s,'length':ln,
                         'diff':d,'grep':gh,'tag':tg,'resp':rp}),
                    self.int_tree.insert('', 'end',
                        values=(str(p1)[:60], str(p2)[:40] if p2 else '',
                                s, ln,
                                f"+{d}" if d > 0 else str(d),
                                'YES' if gh else '',
                                '!!' if tg in ('critical','grep_match') else ('!' if tg == 'interesting' else '')),
                        tags=(tg,) if tg else ()),
                    self.int_progress.config(text=f"{done[0]}/{total}")])
            except Exception as e:
                done[0] += 1
                err_msg = str(e)[:50]
                self.root.after(0, lambda p=str(p1), em=err_msg, d=done[0]: [
                    self._int_all_results.append(
                        {'p1':p,'p2':'','status':'ERR','length':0,
                         'diff':0,'grep':False,'tag':'','resp':f'Error: {em}'}),
                    self.int_tree.insert('', 'end',
                        values=(p[:60], '', 'ERR', 0, 0, '', ''),
                        tags=()),
                    self.int_progress.config(text=f"{d}/{total}  (errors present)")])
                logger.debug(f'Intruder _send error payload={p1!r}: {e}')

        def _run():
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=threads_n) as ex:
                ex.map(_send, pairs)
            self._intruder_running = False
            interesting_count = sum(
                1 for i in self.int_tree.get_children()
                if self.int_tree.item(i)['tags'])
            self.root.after(0, lambda: [
                self.int_progress.config(
                    text=f"Done  ·  {total} sent  ·  {interesting_count} interesting"),
                self._set_status(
                    f"Intruder [{mode}] complete  ·  {total} requests  ·  {interesting_count} flagged")])
        threading.Thread(target=_run, daemon=True).start()

    def _int_toggle_post(self):
        if self.int_post_var.get():
            self._int_post_frame.pack(fill='x', pady=2)
        else:
            self._int_post_frame.pack_forget()

    def _intruder_stop(self):
        self._intruder_running = False
        if hasattr(self, '_rust_fuzzer') and self._rust_fuzzer:
            self._rust_fuzzer.stop()
        self._set_status('Intruder stopped')

    def _intruder_clear(self):
        for i in self.int_tree.get_children():
            self.int_tree.delete(i)
        self.int_resp_txt.delete('1.0', 'end')
        self._int_all_results = []
        self.int_progress.config(text='')

    def _intruder_on_select(self, event=None):
        sel = self.int_tree.selection()
        if not sel:
            return
        idx = self.int_tree.index(sel[0])
        if idx < len(self._int_all_results):
            resp = self._int_all_results[idx].get('resp', '')
            self.int_resp_txt.delete('1.0', 'end')
            self.int_resp_txt.insert('1.0', resp)

    def _intruder_filter_interesting(self):
        for i in self.int_tree.get_children():
            tags = self.int_tree.item(i, 'tags')
            if not tags or tags == ('',):
                self.int_tree.detach(i)
        self._set_status('Showing interesting results only — click SHOW ALL to reset')

    def _intruder_show_all(self):
        """Re-attach all detached rows."""
        for r in self._int_all_results:
            iid_candidates = [str(i) for i in range(len(self._int_all_results))]
        self._intruder_clear()
        for idx, r in enumerate(self._int_all_results):
            tag = r.get('tag', '')
            d   = r.get('diff', 0)
            self.int_tree.insert('', 'end',
                values=(r['p1'][:60], r.get('p2','')[:40],
                        r['status'], r['length'],
                        f"+{d}" if d > 0 else str(d),
                        'YES' if r.get('grep') else '',
                        '!!' if tag in ('critical','grep_match') else ('!' if tag == 'interesting' else '')),
                tags=(tag,) if tag else ())
        self._set_status(f'Showing all {len(self._int_all_results)} results')

    def _intruder_sort(self, col):
        items = [(self.int_tree.set(i, col), i) for i in self.int_tree.get_children()]
        try:
            items.sort(key=lambda x: int(x[0]) if x[0].lstrip('+-').isdigit() else x[0])
        except Exception:
            items.sort()
        for idx, (_, iid) in enumerate(items):
            self.int_tree.move(iid, '', idx)

    def _intruder_export(self):
        from tkinter import filedialog
        if not self._int_all_results:
            messagebox.showwarning('Intruder', 'No results to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON','*.json'),('All','*.*')],
            initialfile=f'intruder_{int(time.time())}.json')
        if not path:
            return
        with open(path, 'w') as f:
            json.dump(self._int_all_results, f, indent=2)
        self._set_status(f'Exported {len(self._int_all_results)} results → {path}')

    def _intruder_context_menu(self, event):
        item = self.int_tree.identify_row(event.y)
        if not item:
            return
        self.int_tree.selection_set(item)
        idx  = self.int_tree.index(item)
        vals = self.int_tree.item(item, 'values')
        m = tk.Menu(self.root, tearoff=0, bg=BG3, fg=TEXT,
            activebackground=BG4, activeforeground=ACCENT, font=FONT_MONO_SM)
        m.add_command(label='  Copy Payload',
            command=lambda: [self.root.clipboard_clear(),
                             self.root.clipboard_append(vals[0] if vals else '')])
        m.add_command(label='  Send to Repeater',
            command=lambda: [self.rep_url.delete(0,'end'),
                             self.rep_url.insert(0, self.int_url.get()),
                             self.nb.select(1)])
        m.add_command(label='  Send to Scanner',
            command=lambda: [self.scan_url.delete(0,'end'),
                             self.scan_url.insert(0, self.int_url.get()),
                             self.nb.select(3)])
        m.add_separator()
        m.add_command(label='  Flag as Interesting',
            command=lambda: self.int_tree.item(item,
                tags=('interesting',)))
        m.post(event.x_root, event.y_root)

    # ── Scanner ───────────────────────────────────────────────────────────────

    def _scanner_run(self):
        url = self.scan_url.get().strip()
        if not url:
            messagebox.showwarning('Scanner', 'Enter a target URL')
            return
        if not url.startswith('http'):
            url = 'http://' + url
            self.scan_url.delete(0, 'end')
            self.scan_url.insert(0, url)

        self.scan_out.delete('1.0', 'end')
        self.scan_out.insert('end',
            f"{'='*60}\n  SentinelProxy Scanner\n  Target: {url}\n  Time  : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n{'='*60}\n\n")

        PROBES = [
            ('SQLi',          f"{url}?id=1'",                          'GET',  None),
            ('XSS',           f"{url}?q=<script>alert(1)</script>",    'GET',  None),
            ('LFI',           f"{url}?file=../../../etc/passwd",        'GET',  None),
            ('SSRF',          f"{url}?url=http://127.0.0.1/",          'GET',  None),
            ('SSTI',          f"{url}?name={{{{7*7}}}}",               'GET',  None),
            ('RCE',           f"{url}?cmd=;id",                        'GET',  None),
            ('Open Redirect', f"{url}?redirect=https://evil.com",      'GET',  None),
            ('XXE',           url, 'POST',
             '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>'),
            ('Path Traversal',f"{url}?path=....//....//etc/passwd",    'GET',  None),
        ]

        def _run():
            found = []
            for vuln, tu, method, body in PROBES:
                try:
                    hdrs = {'User-Agent': 'SentinelProxy/1.0'}
                    if body:
                        hdrs['Content-Type'] = 'application/xml'
                        r = requests.post(tu, data=body, headers=hdrs,
                            verify=False, timeout=6, allow_redirects=False)
                    else:
                        r = requests.get(tu, headers=hdrs,
                            verify=False, timeout=6, allow_redirects=False)
                    flow = {'url': tu, 'method': method, 'body': body or '',
                            'params': {}, 'resp_body': r.text[:3000],
                            'status_code': r.status_code}
                    res  = self.analyzer.analyze(flow)
                    risk = res['risk']
                    mark = {'CRITICAL':'[!!]','HIGH':'[! ]','MEDIUM':'[~ ]','LOW':'[  ]'}.get(risk,'[  ]')
                    det  = '  <- POTENTIAL VULN' if res['vulns'] else ''
                    if res['vulns']:
                        found.append(vuln)
                    line = f"{mark} {vuln:<18} {risk:<10} HTTP {r.status_code}  {len(r.content)}b{det}\n"
                    self.root.after(0, lambda l=line: self.scan_out.insert('end', l))
                except Exception as e:
                    self.root.after(0, lambda v=vuln, e=e:
                        self.scan_out.insert('end', f"[ERR] {v:<18} {str(e)[:40]}\n"))

            summary = (f"\n{'='*60}\n"
                       f"Pattern Scan Complete\n"
                       f"Potential Issues : {len(found)}\n"
                       f"Detected         : {', '.join(found) if found else 'none'}\n"
                       f"{'='*60}\n")
            self.root.after(0, lambda: self.scan_out.insert('end', summary))

            if self.analyzer._groq:
                self.root.after(0, lambda: self.scan_out.insert('end',
                    '\n[*] Running Groq LLM deep analysis...\n'))
                try:
                    out = self.analyzer._groq.ask(
                        f"Security assessment of {url}.\n"
                        f"Pattern scan found potential: {', '.join(found) or 'none'}.\n"
                        f"Give: 1) Overall risk rating  2) Top vulnerabilities to test  "
                        f"3) Specific recommendations. Concise bullet points.",
                        max_tokens=400)
                    self.root.after(0, lambda: self.scan_out.insert('end', f"\n{out}\n"))
                except Exception as e:
                    self.root.after(0, lambda: self.scan_out.insert('end', f"Groq error: {e}\n"))

            self.root.after(0, lambda: self.scan_out.insert('end', '\n[+] Scan complete.\n'))
        threading.Thread(target=_run, daemon=True).start()

    def _scanner_export(self):
        from tkinter import filedialog
        content = self.scan_out.get('1.0', 'end').strip()
        if not content:
            messagebox.showwarning('Scanner', 'No scan output to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.txt',
            filetypes=[('Text', '*.txt'), ('All', '*.*')],
            initialfile=f'scanner_{int(time.time())}.txt')
        if not path:
            return
        with open(path, 'w') as f:
            f.write(content)
        self._set_status(f'Scanner output exported → {path}')

    # ── Decoder ───────────────────────────────────────────────────────────────

    def _decode_convert(self):
        text = self.dec_input.get('1.0', 'end').strip()
        if not text:
            return
        mode = self.dec_mode.get()
        try:
            import base64, html, hashlib
            ops = {
                'URL Encode':    lambda: urllib.parse.quote(text),
                'URL Decode':    lambda: urllib.parse.unquote(text),
                'Base64 Encode': lambda: base64.b64encode(text.encode()).decode(),
                'Base64 Decode': lambda: base64.b64decode(text.encode()).decode('utf-8', 'replace'),
                'HTML Encode':   lambda: html.escape(text),
                'HTML Decode':   lambda: html.unescape(text),
                'Hex Encode':    lambda: text.encode().hex(),
                'Hex Decode':    lambda: bytes.fromhex(
                    ''.join(c for c in text if c in '0123456789abcdefABCDEF')
                ).decode('utf-8', 'replace'),
                'MD5 Hash':      lambda: hashlib.md5(text.encode()).hexdigest(),
                'SHA1 Hash':     lambda: hashlib.sha1(text.encode()).hexdigest(),
                'SHA256 Hash':   lambda: hashlib.sha256(text.encode()).hexdigest(),
                'SHA512 Hash':   lambda: hashlib.sha512(text.encode()).hexdigest(),
            }
            result = ops.get(mode, lambda: text)()
        except Exception as e:
            result = f"Error: {e}"
        self.dec_output.delete('1.0', 'end')
        self.dec_output.insert('1.0', result)

    def _decode_swap(self):
        a = self.dec_input.get('1.0', 'end').strip()
        b = self.dec_output.get('1.0', 'end').strip()
        self.dec_input.delete('1.0', 'end')
        self.dec_input.insert('1.0', b)
        self.dec_output.delete('1.0', 'end')
        self.dec_output.insert('1.0', a)

    def _decode_clear(self):
        self.dec_input.delete('1.0', 'end')
        self.dec_output.delete('1.0', 'end')


    # ── Filter / History ──────────────────────────────────────────────────────


    # ── Search ───────────────────────────────────────────────────────────────

    def _on_search(self, *args):
        kw = self.search_var.get().strip()
        if not kw:
            self._load_history()
            return
        rows = self.db.search_requests(kw, limit=500)
        for i in self.tree.get_children():
            self.tree.delete(i)
        for idx, r in enumerate(rows, 1):
            risk = r.get('ai_risk', 'UNKNOWN')
            tags = [risk]
            if r.get('method') in ('GET','POST','DELETE','PUT'):
                tags.append(r['method'])
            if r.get('flagged'):
                tags.append('flagged')
            ms_str = f"{r.get('response_time',0):.0f}" if r.get('response_time') else ''
            self.tree.insert('', 'end', iid=str(r['id']),
                values=(idx, r.get('method',''), r.get('host','')[:38],
                        r.get('path','')[:55], r.get('status_code',''),
                        risk, r.get('resp_length',''), ms_str, ''),
                tags=tuple(tags))
        self._set_status(f"Search '{kw}'  ·  {len(rows)} results")

    def _clear_search(self):
        self.search_var.set('')
        self._load_history()

    # ── Logger Methods ────────────────────────────────────────────────────────

    def _log_refresh(self):
        rows = self.db.get_requests(1000)
        self._log_populate(rows)

    def _log_flagged(self):
        rows = self.db.get_requests(1000, flagged_only=True)
        self._log_populate(rows)
        self._set_status(f'Flagged requests: {len(rows)}')

    def _log_search(self, *args):
        kw     = self.log_search_var.get().strip()
        risk   = self.log_risk_var.get()
        method = self.log_method_var.get()
        if kw:
            rows = self.db.search_requests(kw, limit=1000)
        else:
            rows = self.db.get_requests(1000,
                method_filter='' if method == 'ALL' else method)
        if risk != 'ALL':
            rows = [r for r in rows if r.get('ai_risk') == risk]
        if method != 'ALL' and not kw:
            rows = [r for r in rows if r.get('method') == method]
        self._log_populate(rows)

    def _log_populate(self, rows: list):
        for i in self.log_tree.get_children():
            self.log_tree.delete(i)
        for r in rows:
            risk  = r.get('ai_risk', 'UNKNOWN')
            vulns = []
            try:
                vulns = [v.get('type','') for v in json.loads(r.get('ai_vulns','[]'))]
            except Exception:
                pass
            ts   = r.get('timestamp','')[:19].replace('T',' ')
            tags = [risk]
            if r.get('flagged'):
                tags.append('flagged')
            self.log_tree.insert('', 'end', iid=str(r['id']),
                values=(r['id'], ts, r.get('method',''),
                        r.get('host','')[:35], r.get('path','')[:55],
                        r.get('status_code',''), risk,
                        r.get('resp_length',''),
                        ', '.join(vulns) if vulns else ''),
                tags=tuple(tags))
        self.log_count_lbl.config(text=f'{len(rows)} entries')

    def _log_on_select(self, event=None):
        sel = self.log_tree.selection()
        if not sel:
            return
        row_id = int(sel[0])
        req    = self.db.get_request(row_id)
        if not req:
            return
        import json as _json
        hdrs  = _json.loads(req.get('headers', '{}'))
        rhdrs = _json.loads(req.get('resp_headers', '{}')) if req.get('resp_headers') else {}
        vulns = _json.loads(req.get('ai_vulns', '[]'))
        out   = '='*60 + '\n'
        out  += f"ID       : {req['id']}\n"
        out  += f"Time     : {req.get('timestamp','')[:19]}\n"
        out  += f"Method   : {req.get('method','')}\n"
        out  += f"URL      : {req.get('url','')}\n"
        out  += f"Status   : {req.get('status_code','')}\n"
        out  += f"Risk     : {req.get('ai_risk','')}\n"
        out  += f"Length   : {req.get('resp_length','')}\n"
        out  += f"Flagged  : {'Yes' if req.get('flagged') else 'No'}\n"
        out  += '='*60 + '\n\nREQUEST HEADERS:\n'
        for k, v in hdrs.items():
            out += f"  {k}: {v}\n"
        if req.get('body'):
            out += f"\nREQUEST BODY:\n{req['body'][:1000]}\n"
        out += '\nRESPONSE HEADERS:\n'
        for k, v in rhdrs.items():
            out += f"  {k}: {v}\n"
        if req.get('resp_body'):
            out += f"\nRESPONSE BODY (first 2000):\n{req['resp_body'][:2000]}\n"
        if vulns:
            out += '\nVULNERABILITIES:\n'
            for v in vulns:
                out += f"  [{v.get('severity','?')}] {v.get('type','?')} — {v.get('detail','')}\n"
        self.log_detail.delete('1.0', 'end')
        self.log_detail.insert('1.0', out)

    def _log_context_menu(self, event):
        item = self.log_tree.identify_row(event.y)
        if not item:
            return
        self.log_tree.selection_set(item)
        self.selected_req = int(item)
        m = tk.Menu(self.root, tearoff=0,
            bg=BG3, fg=TEXT, activebackground=BG4,
            activeforeground=ACCENT, font=FONT_MONO_SM)
        m.add_command(label='  → Send to Repeater', command=self._send_to_repeater)
        m.add_command(label='  → Send to Intruder', command=self._send_to_intruder)
        m.add_command(label='  → Send to Scanner',  command=self._send_to_scanner)
        m.add_separator()
        m.add_command(label='  Flag / Unflag',       command=self._flag_request)
        m.add_command(label='  Copy URL',            command=self._copy_url)
        m.add_command(label='  Copy as cURL',        command=self._copy_curl)
        m.post(event.x_root, event.y_root)

    # ── Export ────────────────────────────────────────────────────────────────

    def _export_requests(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json'), ('All', '*.*')],
            initialfile=f'sentinel_proxy_{datetime.now().strftime("%Y%m%d_%H%M%S")}.json',
            title='Export Requests')
        if not path:
            return
        rows = self.db.export_requests()
        with open(path, 'w') as f:
            json.dump(rows, f, indent=2, default=str)
        self._set_status(f'Exported {len(rows)} requests → {path}')
        messagebox.showinfo('Export Done', f'Exported {len(rows)} requests to:\n{path}')


    def _apply_filter(self):
        host   = self.filter_host.get().strip()
        method = self.filter_method.get()
        if method == 'ALL':
            method = ''
        rows = self.db.get_requests(500, host, method)
        for i in self.tree.get_children():
            self.tree.delete(i)
        for idx, r in enumerate(rows, 1):
            risk = r.get('ai_risk', 'UNKNOWN')
            tags = [risk]
            if r.get('method') in ('GET','POST','DELETE','PUT'):
                tags.append(r['method'])
            if r.get('flagged'):
                tags.append('flagged')
            ms_str = f"{r.get('response_time',0):.0f}" if r.get('response_time') else ''
            self.tree.insert('', 'end', iid=str(r['id']),
                values=(idx, r.get('method',''), r.get('host','')[:38],
                        r.get('path','')[:55], r.get('status_code',''),
                        risk, r.get('resp_length',''), ms_str, ''),
                tags=tuple(tags))
        self._set_status(f"Filter applied  ·  {len(rows)} requests")

    def _load_history(self):
        # Clear first to prevent duplicates on re-call
        for i in self.tree.get_children():
            self.tree.delete(i)
        rows = self.db.get_requests(200)
        for idx, r in enumerate(rows, 1):
            risk = r.get('ai_risk', 'UNKNOWN')
            tags = [risk]
            if r.get('method') in ('GET','POST','DELETE','PUT'):
                tags.append(r['method'])
            if r.get('flagged'):
                tags.append('flagged')
            ms_str = f"{r.get('response_time',0):.0f}" if r.get('response_time') else ''
            ts     = r.get('timestamp','')[:19].replace('T',' ')[11:]  # HH:MM:SS
            self.tree.insert('', 'end', iid=str(r['id']),
                values=(idx, r.get('method',''), r.get('host','')[:38],
                        r.get('path','')[:55], r.get('status_code',''),
                        risk, r.get('resp_length',''), ms_str, ts),
                tags=tuple(tags))
        self._req_counter = len(rows)
        self.lbl_req_count.config(text=f"{self._req_counter} reqs")

    def _clear_history(self):
        if messagebox.askyesno('Clear History', 'Clear all intercepted requests?'):
            self.db.clear_history()
            for i in self.tree.get_children():
                self.tree.delete(i)
            self._req_counter = 0
            self.lbl_req_count.config(text='0 reqs')
            self._set_status('History cleared')

    # ── Cert Window ───────────────────────────────────────────────────────────

    def _show_cert_window(self):
        import subprocess
        cert = Path.home() / '.mitmproxy' / 'mitmproxy-ca-cert.pem'

        w = tk.Toplevel(self.root)
        w.title('Install CA Certificate')
        w.geometry('600x500')
        w.configure(bg=BG)
        w.resizable(False, False)
        w.grab_set()

        tk.Frame(w, bg=ACCENT, height=2).pack(fill='x')
        tk.Label(w, text='CA CERTIFICATE INSTALLER',
            bg=BG, fg=ACCENT, font=('Fira Code', 12, 'bold')).pack(pady=10)

        sf = tk.Frame(w, bg=BG3)
        sf.pack(fill='x', padx=16, pady=4)
        status_text = f"Certificate: {cert}" if cert.exists() else "Start proxy first to generate certificate"
        tk.Label(sf, text=status_text,
            bg=BG3, fg=GREEN if cert.exists() else ORANGE,
            font=FONT_MONO_XS, wraplength=560).pack(padx=10, pady=8)

        bf = tk.Frame(w, bg=BG)
        bf.pack(fill='x', padx=16, pady=4)
        ttk.Button(bf, text='Open Folder',
            command=lambda: subprocess.Popen(['xdg-open', str(cert.parent)])).pack(side='left', padx=4)
        ttk.Button(bf, text='Copy Path',
            command=lambda: [w.clipboard_clear(), w.clipboard_append(str(cert))]).pack(side='left', padx=4)
        ttk.Button(bf, text='Install System-wide', style='Green.TButton',
            command=lambda: self._install_cert_system(cert)).pack(side='left', padx=4)

        nb2 = ttk.Notebook(w)
        nb2.pack(fill='both', expand=True, padx=16, pady=8)

        def tab(title, text):
            f = ttk.Frame(nb2)
            nb2.add(f, text=title)
            t = tk.Text(f, bg=BG2, fg=TEXT, font=FONT_MONO_XS,
                relief='flat', wrap='word', padx=10, pady=8)
            t.pack(fill='both', expand=True)
            t.insert('1.0', text)
            t.config(state='disabled')

        tab(' Firefox ', (
            "1. Open Firefox → Settings → Privacy & Security\n"
            "2. Scroll to Certificates → View Certificates\n"
            "3. Authorities tab → Import\n"
            f"4. Select: {cert}\n"
            "5. Check: Trust this CA to identify websites\n"
            "6. OK → Restart Firefox\n\n"
            "Proxy: Settings → Network → Manual Proxy\n"
            "HTTP Proxy: 127.0.0.1   Port: 8082\n"
            "Also use for HTTPS: ✓"))

        tab(' Chromium ', (
            "Option 1 — Launch with flags (easiest):\n\n"
            "chromium --proxy-server=http://127.0.0.1:8082 \\\n"
            "         --ignore-certificate-errors \\\n"
            "         --user-data-dir=/tmp/sentinel-proxy\n\n"
            "Option 2 — Install cert:\n"
            "Settings → Privacy → Manage Certificates\n"
            f"Authorities → Import → {cert}"))

        try:
            import socket
            s = socket.socket()
            s.connect(('8.8.8.8', 80))
            ip = s.getsockname()[0]
            s.close()
        except Exception:
            ip = '192.168.x.x'

        tab(' Mobile ', (
            "1. Connect phone to same WiFi network\n\n"
            "2. Set WiFi proxy:\n"
            f"   Host: {ip}\n"
            "   Port: 8082\n\n"
            "3. Open browser → http://mitm.it\n"
            "4. Download & install certificate\n\n"
            "Android: Settings → Security → Install Certificate\n"
            "iOS: Settings → General → VPN & Device Management\n"
            "     → Install Profile → Trust"))

    def _install_cert_system(self, cert):
        import shutil, subprocess
        try:
            dst = Path('/usr/local/share/ca-certificates/mitmproxy-ca.crt')
            shutil.copy2(cert, dst)
            subprocess.run(['update-ca-certificates'], check=True, capture_output=True)
            messagebox.showinfo('Done', 'System CA certificate updated successfully!')
        except Exception:
            messagebox.showerror('Error',
                f"Run manually:\n"
                f"sudo cp {cert} /usr/local/share/ca-certificates/mitmproxy-ca.crt\n"
                f"sudo update-ca-certificates")

    # ── Run ───────────────────────────────────────────────────────────────────


    # ── Highlight Rules Methods ───────────────────────────────────────────────

    _HL_COLOR_MAP = {
        'Red': '#f85149', 'Orange': '#d29922', 'Yellow': '#e3b341',
        'Green': '#3fb950', 'Cyan': '#79c0ff', 'Purple': '#bc8cff', 'White': '#e6edf3',
    }

    def _hl_load(self):
        self._hl_rules = self.db.get_highlight_rules()
        for i in self.hl_tree.get_children():
            self.hl_tree.delete(i)
        for rule in self._hl_rules:
            color_name = rule['color']
            tag = f"hl_{color_name.lower()}"
            self.hl_tree.insert('', 'end', iid=str(rule['id']),
                values=(rule['id'], rule['match'], rule['field'],
                        color_name, '███', rule['comment'],
                        'ON' if rule['enabled'] else 'OFF'),
                tags=(tag,))

    def _hl_test_rule(self):
        """Highlight all existing proxy rows that match current rule inputs."""
        match   = self.hl_match.get().strip()
        field   = self.hl_field.get().lower()
        color   = self.hl_color.get()
        if not match:
            messagebox.showwarning('Highlight', 'Enter a match pattern to test')
            return
        hex_color = self._HL_COLOR_MAP.get(color, TEXT)
        count = 0
        for iid in self.tree.get_children():
            vals = self.tree.item(iid, 'values')
            # vals: id, method, host, path, status, risk, length, ms, time
            target_map = {
                'url':    f"{vals[2]}{vals[3]}",
                'host':   vals[2],
                'path':   vals[3],
                'method': vals[1],
                'status': str(vals[4]),
                'any':    ' '.join(str(v) for v in vals),
            }
            target = target_map.get(field, target_map['any']).lower()
            if match.lower() in target:
                self.tree.tag_configure(f'test_hl_{iid}', foreground=hex_color, background='#1a1a2e')
                current_tags = list(self.tree.item(iid, 'tags'))
                if f'test_hl_{iid}' not in current_tags:
                    current_tags.append(f'test_hl_{iid}')
                self.tree.item(iid, tags=tuple(current_tags))
                count += 1
        self._set_status(f'Test highlight: {count} matching rows highlighted')

    def _hl_add_rule(self):
        match   = self.hl_match.get().strip()
        field   = self.hl_field.get()
        color   = self.hl_color.get()
        comment = self.hl_comment.get().strip()
        if not match:
            messagebox.showwarning('Highlight', 'Enter a match pattern')
            return
        self.db.add_highlight_rule(match, field, color, comment)
        self._hl_load()
        self.hl_match.delete(0, 'end')
        self.hl_comment.delete(0, 'end')
        self._set_status(f'Highlight rule added: {match} → {color}')

    def _hl_toggle(self, event=None):
        sel = self.hl_tree.selection()
        if not sel:
            return
        rule_id = int(sel[0])
        rule    = next((r for r in self._hl_rules if r['id'] == rule_id), None)
        if rule:
            self.db.toggle_highlight_rule(rule_id, not bool(rule['enabled']))
        self._hl_load()

    def _hl_clear_all(self):
        if messagebox.askyesno('Highlight', 'Clear all highlight rules?'):
            for r in self._hl_rules:
                self.db.delete_highlight_rule(r['id'])
            self._hl_load()

    def _hl_context_menu(self, event):
        item = self.hl_tree.identify_row(event.y)
        if not item:
            return
        self.hl_tree.selection_set(item)
        m = tk.Menu(self.root, tearoff=0,
            bg=BG3, fg=TEXT, activebackground=BG4,
            activeforeground=ACCENT, font=FONT_MONO_SM)
        m.add_command(label='  Enable / Disable', command=self._hl_toggle)
        m.add_command(label='  Delete Rule',
            command=lambda: self._hl_delete(int(item)))
        m.post(event.x_root, event.y_root)

    def _hl_delete(self, rule_id: int):
        self.db.delete_highlight_rule(rule_id)
        self._hl_load()

    def _hl_apply(self, flow: dict, row_id: int):
        """Apply highlight rules to a proxy tree row."""
        for rule in self._hl_rules:
            if not rule['enabled']:
                continue
            field  = rule['field'].lower()
            match  = rule['match'].lower()
            target = ''
            if field == 'url'    : target = flow.get('url','').lower()
            elif field == 'host' : target = flow.get('host','').lower()
            elif field == 'path' : target = flow.get('path','').lower()
            elif field == 'method': target = flow.get('method','').lower()
            elif field == 'status': target = str(flow.get('status_code','')).lower()
            elif field == 'body' : target = flow.get('body','').lower()
            elif field == 'any'  :
                target = ' '.join([
                    flow.get('url',''), flow.get('host',''),
                    flow.get('path',''), flow.get('body',''),
                ]).lower()
            if match in target:
                color = self._HL_COLOR_MAP.get(rule['color'], '#e6edf3')
                try:
                    self.tree.tag_configure(
                        f"hl_row_{row_id}", foreground=color, background='#1a1a2e')
                    current_tags = list(self.tree.item(str(row_id), 'tags'))
                    current_tags.append(f"hl_row_{row_id}")
                    self.tree.item(str(row_id), tags=tuple(current_tags))
                except Exception:
                    pass
                break



    # ── Auto-Fuzz Methods ─────────────────────────────────────────────────────

    def _af_detect(self):
        url = self.af_url.get().strip()
        if not url:
            messagebox.showwarning('Auto-Fuzz', 'Enter a target URL')
            return
        if not url.startswith('http'):
            url = 'http://' + url
            self.af_url.delete(0, 'end')
            self.af_url.insert(0, url)

        self.af_status_lbl.config(text='Detecting parameters...', fg=YELLOW)
        for i in self.af_param_tree.get_children():
            self.af_param_tree.delete(i)
        self._af_params.clear()

        def _run():
            params = []
            try:
                import re
                from bs4 import BeautifulSoup
                from urllib.parse import urlparse, parse_qs
                r = requests.get(url, verify=False, timeout=10,
                    headers={'User-Agent': 'SentinelProxy/1.0'})

                # 1. URL query params
                parsed = urlparse(url)
                for k in parse_qs(parsed.query):
                    params.append({'param': k, 'type': 'query', 'source': 'URL', 'enabled': True})

                # 2. HTML form inputs
                soup = BeautifulSoup(r.text, 'html.parser')
                seen = {p['param'] for p in params}
                for inp in soup.find_all(['input', 'textarea', 'select']):
                    name = inp.get('name') or inp.get('id', '')
                    if name and name not in seen:
                        itype = inp.get('type', 'text')
                        params.append({'param': name, 'type': f'form:{itype}',
                                       'source': 'HTML', 'enabled': True})
                        seen.add(name)

                # 3. JS variable patterns
                js_params = re.findall(
                    r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,20})["\']:\s*["\'][^"\']{0,50}["\']',
                    r.text)
                SKIP = {'true', 'false', 'null', 'undefined', 'function', 'return',
                        'class', 'const', 'let', 'var', 'type', 'name', 'id', 'src',
                        'href', 'style', 'data', 'value', 'text'}
                for jp in js_params[:30]:
                    if jp not in seen and jp.lower() not in SKIP:
                        params.append({'param': jp, 'type': 'js_var',
                                       'source': 'JS', 'enabled': True})
                        seen.add(jp)

                # 4. Groq AI detection
                if self.analyzer._groq and len(params) < 5:
                    prompt = (
                        f"URL: {url}\nHTML: {r.text[:800]}\n\n"
                        f"List injectable HTTP parameters as JSON array only: "
                        f'[{{"param":"name","type":"query/form/header"}}]')
                    out = self.analyzer._groq.ask(prompt, max_tokens=200)
                    if out:
                        m = re.search(r'\[.*\]', out, re.DOTALL)
                        if m:
                            try:
                                ai_params = json.loads(m.group())
                                for ap in ai_params:
                                    if ap.get('param') and ap['param'] not in seen:
                                        params.append({
                                            'param': ap['param'],
                                            'type': ap.get('type', 'ai'),
                                            'source': 'AI', 'enabled': True,
                                        })
                                        seen.add(ap['param'])
                            except Exception:
                                pass

            except Exception as e:
                self.root.after(0, lambda: self.af_status_lbl.config(
                    text=f'Error: {str(e)[:50]}', fg=RED))
                return

            self._af_params = params
            self.root.after(0, lambda: self._af_show_params(params))

        threading.Thread(target=_run, daemon=True).start()

    def _af_show_params(self, params: list):
        for i in self.af_param_tree.get_children():
            self.af_param_tree.delete(i)
        for p in params:
            tag = 'selected' if p['enabled'] else 'skipped'
            self.af_param_tree.insert('', 'end',
                values=(p['param'], p['type'], p['source'],
                        'YES' if p['enabled'] else 'NO'),
                tags=(tag,))
        self.af_status_lbl.config(
            text=f'{len(params)} params detected  ·  Double-click to toggle', fg=GREEN)

    def _af_toggle_param(self, event=None):
        sel = self.af_param_tree.selection()
        if not sel:
            return
        idx = self.af_param_tree.index(sel[0])
        if idx < len(self._af_params):
            self._af_params[idx]['enabled'] = not self._af_params[idx]['enabled']
            self._af_show_params(self._af_params)

    def _af_result_context_menu(self, event):
        item = self.af_result_tree.identify_row(event.y)
        if not item:
            return
        self.af_result_tree.selection_set(item)
        vals = self.af_result_tree.item(item, 'values')
        m = tk.Menu(self.root, tearoff=0, bg=BG3, fg=TEXT,
            activebackground=BG4, activeforeground=ACCENT, font=FONT_MONO_SM)
        m.add_command(label='  Copy Payload',
            command=lambda: [self.root.clipboard_clear(),
                             self.root.clipboard_append(vals[1] if len(vals)>1 else '')])
        m.add_command(label='  Send to Intruder',
            command=lambda: [self.int_url.delete(0,'end'),
                             self.int_url.insert(0, self.af_url.get()),
                             self.nb.select(2)])
        m.add_command(label='  Send to Repeater',
            command=lambda: [self.rep_url.delete(0,'end'),
                             self.rep_url.insert(0, self.af_url.get()),
                             self.nb.select(1)])
        m.post(event.x_root, event.y_root)

    def _af_stop(self):
        self._af_running = False
        self.af_status_lbl.config(text='Stopped', fg=ORANGE)

    def _af_clear(self):
        for i in self.af_result_tree.get_children():
            self.af_result_tree.delete(i)
        for i in self.af_param_tree.get_children():
            self.af_param_tree.delete(i)
        self._af_params.clear()
        self.af_status_lbl.config(text='')

    def _af_export(self):
        from tkinter import filedialog
        results = []
        for iid in self.af_result_tree.get_children():
            vals = self.af_result_tree.item(iid, 'values')
            results.append({'param': vals[0], 'payload': vals[1],
                            'status': vals[2], 'length': vals[3],
                            'diff': vals[4], 'flag': vals[5]})
        if not results:
            messagebox.showwarning('Auto-Fuzz', 'No results to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json')],
            initialfile=f'autofuzz_{int(time.time())}.json')
        if not path:
            return
        with open(path, 'w') as f:
            json.dump(results, f, indent=2)
        self._set_status(f'Exported {len(results)} results → {path}')

    def _af_start(self):
        if self._af_running:
            return
        url = self.af_url.get().strip()
        if not url:
            messagebox.showwarning('Auto-Fuzz', 'Enter a target URL')
            return
        active = [p for p in self._af_params if p['enabled']]
        if not active:
            messagebox.showwarning('Auto-Fuzz',
                'No parameters. Run DETECT PARAMS first.')
            return

        payload_type = self.af_payload_type.get()
        try:
            threads_n = int(self.af_threads.get() or 5)
        except ValueError:
            threads_n = 5

        for i in self.af_result_tree.get_children():
            self.af_result_tree.delete(i)

        self._af_running = True
        done     = [0]
        session  = str(int(time.time()))
        base_len = {}

        def _get_payloads(param_name: str) -> list:
            if payload_type == 'Auto (AI)':
                n = param_name.lower()
                if any(x in n for x in ['id', 'num', 'page', 'limit', 'offset']):
                    ptype = 'SQLi'
                elif any(x in n for x in ['url', 'redirect', 'next', 'return', 'goto']):
                    ptype = 'SSRF'
                elif any(x in n for x in ['file', 'path', 'dir', 'include', 'load']):
                    ptype = 'LFI'
                elif any(x in n for x in ['cmd', 'exec', 'run', 'shell', 'ping']):
                    ptype = 'RCE'
                elif any(x in n for x in ['template', 'tpl', 'view', 'render']):
                    ptype = 'SSTI'
                else:
                    ptype = 'XSS'
            else:
                ptype = payload_type
            p = self._load_payloads_from_file(ptype)
            return p[:100] if p else self.analyzer.suggest_payloads(ptype)

        def _fuzz_param(param_info):
            pname    = param_info['param']
            payloads = _get_payloads(pname)
            for payload in payloads:
                if not self._af_running:
                    return
                try:
                    sep = '&' if '?' in url else '?'
                    r   = requests.get(
                        f"{url}{sep}{pname}={urllib.parse.quote(str(payload))}",
                        verify=False, timeout=6, allow_redirects=False)
                    length = len(r.content)
                    if pname not in base_len:
                        base_len[pname] = length
                    diff        = length - base_len[pname]
                    interesting = (r.status_code not in (200, 301, 302, 404)
                                   or abs(diff) > 50)
                    tag = ('critical' if abs(diff) > 200 and r.status_code in (200, 500)
                           else ('interesting' if interesting else ''))
                    done[0] += 1
                    self.db.save_intruder_result(
                        session, str(payload), r.status_code, length,
                        r.text[:300], interesting)
                    self.root.after(0, lambda pn=pname, p=payload,
                        s=r.status_code, ln=length, d=diff, tg=tag: [
                        self.af_result_tree.insert('', 'end',
                            values=(pn, str(p)[:60], s, ln,
                                    f"+{d}" if d > 0 else str(d),
                                    '!!' if tg == 'critical' else ('!' if tg == 'interesting' else '')),
                            tags=(tg,) if tg else ()),
                        self.af_status_lbl.config(
                            text=f"{done[0]} sent  ·  {len(self.af_result_tree.get_children())} results")])
                except Exception:
                    done[0] += 1

        def _run():
            from concurrent.futures import ThreadPoolExecutor
            with ThreadPoolExecutor(max_workers=threads_n) as ex:
                ex.map(_fuzz_param, active)
            self._af_running = False
            interesting = sum(1 for i in self.af_result_tree.get_children()
                              if self.af_result_tree.item(i)['tags'])
            self.root.after(0, lambda: [
                self.af_status_lbl.config(
                    text=f"Done  ·  {done[0]} requests  ·  {interesting} interesting",
                    fg=GREEN),
                self._set_status(
                    f"Auto-Fuzz done  ·  {len(active)} params  ·  {done[0]} requests")])

        threading.Thread(target=_run, daemon=True).start()

    # ── Comparer Methods ──────────────────────────────────────────────────────

    def _cmp_paste(self, widget):
        try:
            text = self.root.clipboard_get()
            widget.delete('1.0', 'end')
            widget.insert('1.0', text)
        except Exception:
            pass

    def _cmp_from_repeater(self):
        resp = self.rep_resp_txt.get('1.0', 'end').strip()
        if not resp:
            messagebox.showwarning('Comparer', 'No response in Repeater tab')
            return
        left = self.cmp_left.get('1.0', 'end').strip()
        if not left:
            self.cmp_left.delete('1.0', 'end')
            self.cmp_left.insert('1.0', resp)
            self._set_status('Response loaded into Comparer → Response A')
        else:
            self.cmp_right.delete('1.0', 'end')
            self.cmp_right.insert('1.0', resp)
            self._set_status('Response loaded into Comparer → Response B')
        # Switch to Comparer tab by name
        try:
            for i in range(self.nb.index('end')):
                if 'Comparer' in self.nb.tab(i, 'text'):
                    self.nb.select(i)
                    break
        except Exception:
            pass

    def _cmp_swap(self):
        a = self.cmp_left.get('1.0', 'end')
        b = self.cmp_right.get('1.0', 'end')
        self.cmp_left.delete('1.0', 'end')
        self.cmp_left.insert('1.0', b.strip())
        self.cmp_right.delete('1.0', 'end')
        self.cmp_right.insert('1.0', a.strip())

    def _cmp_copy_diff(self):
        diff_text = self.cmp_diff.get('1.0', 'end').strip()
        if diff_text:
            self.root.clipboard_clear()
            self.root.clipboard_append(diff_text)
            self._set_status('Diff copied to clipboard')

    def _cmp_clear(self):
        self.cmp_left.delete('1.0', 'end')
        self.cmp_right.delete('1.0', 'end')
        self.cmp_diff.delete('1.0', 'end')
        self.cmp_stats_lbl.config(text='')

    def _cmp_compare(self):
        import difflib
        a = self.cmp_left.get('1.0', 'end').splitlines()
        b = self.cmp_right.get('1.0', 'end').splitlines()
        if not any(a) or not any(b):
            messagebox.showwarning('Comparer', 'Paste responses in both panels first')
            return

        self.cmp_diff.delete('1.0', 'end')
        added = removed = unchanged = 0

        diff = list(difflib.unified_diff(
            a, b, lineterm='', fromfile='Response A', tofile='Response B'))

        if not diff:
            self.cmp_diff.insert('end', 'Responses are IDENTICAL\n', 'header')
            self.cmp_stats_lbl.config(text='Identical')
            return

        for line in diff:
            if line.startswith('+++') or line.startswith('---'):
                self.cmp_diff.insert('end', line + '\n', 'header')
            elif line.startswith('@@'):
                self.cmp_diff.insert('end', line + '\n', 'header')
            elif line.startswith('+'):
                self.cmp_diff.insert('end', line + '\n', 'added')
                added += 1
            elif line.startswith('-'):
                self.cmp_diff.insert('end', line + '\n', 'removed')
                removed += 1
            else:
                self.cmp_diff.insert('end', line + '\n', 'unchanged')
                unchanged += 1

        summary = (
            f"\n{'='*50}\n"
            f"Added   : {added} lines\n"
            f"Removed : {removed} lines\n"
            f"Same    : {unchanged} lines\n"
            f"Total A : {len(a)} lines  |  Total B : {len(b)} lines\n")
        self.cmp_diff.insert('end', summary, 'header')
        self.cmp_stats_lbl.config(text=f"+{added} / -{removed} / ={unchanged}")



    # ── Scope Methods ─────────────────────────────────────────────────────────

    def _scope_load(self):
        for i in self.scope_tree.get_children():
            self.scope_tree.delete(i)
        rules = self.db.get_scope_rules()
        for r in rules:
            tag = 'disabled' if not r['enabled'] else r['rule_type']
            matches = self._scope_match_counts.get(r['id'], 0)
            self.scope_tree.insert('', 'end', iid=str(r['id']),
                values=(r['id'], r['pattern'], r['rule_type'],
                        'ON' if r['enabled'] else 'OFF', matches),
                tags=(tag,))
        self.scope_status_lbl.config(
            text=f"{len(rules)} rules  ·  {sum(1 for r in rules if r['rule_type']=='include' and r['enabled'])} active includes")

    def _scope_add(self):
        pattern = self.scope_pattern.get().strip()
        rule_type = self.scope_type.get()
        if not pattern:
            messagebox.showwarning('Scope', 'Enter a pattern (e.g. example.com or *.example.com)')
            return
        self.db.add_scope_rule(pattern, rule_type)
        self.scope_pattern.delete(0, 'end')
        self._scope_load()
        self._set_status(f'Scope rule added: [{rule_type}] {pattern}')

    def _scope_add_current(self):
        # Add host from currently selected proxy request
        if self.selected_req:
            req = self.db.get_request(self.selected_req)
            if req and req.get('host'):
                self.scope_pattern.delete(0, 'end')
                self.scope_pattern.insert(0, req['host'])
                self.scope_type.set('include')
                self._scope_add()
                return
        # Fallback: add from scanner URL
        url = self.scan_url.get().strip()
        if url:
            from urllib.parse import urlparse
            host = urlparse(url).netloc or url
            self.scope_pattern.delete(0, 'end')
            self.scope_pattern.insert(0, host)
            self.scope_type.set('include')
            self._scope_add()

    def _scope_toggle(self, event=None):
        sel = self.scope_tree.selection()
        if not sel:
            return
        rule_id = int(sel[0])
        rules = self.db.get_scope_rules()
        for r in rules:
            if r['id'] == rule_id:
                self.db.toggle_scope_rule(rule_id, not bool(r['enabled']))
                break
        self._scope_load()

    def _scope_delete(self, rule_id: int):
        self.db.delete_scope_rule(rule_id)
        self._scope_load()

    def _scope_clear_all(self):
        if messagebox.askyesno('Scope', 'Clear all scope rules?'):
            for r in self.db.get_scope_rules():
                self.db.delete_scope_rule(r['id'])
            self._scope_load()

    def _scope_import(self):
        from tkinter import filedialog
        path = filedialog.askopenfilename(
            filetypes=[('Text/JSON', '*.txt *.json'), ('All', '*.*')],
            title='Import Scope Rules')
        if not path:
            return
        try:
            content = open(path).read()
            if path.endswith('.json'):
                rules = json.loads(content)
                for r in rules:
                    self.db.add_scope_rule(r.get('pattern',''), r.get('rule_type','include'))
            else:
                for line in content.splitlines():
                    line = line.strip()
                    if line and not line.startswith('#'):
                        self.db.add_scope_rule(line, 'include')
            self._scope_load()
            self._set_status(f'Scope rules imported from {path}')
        except Exception as e:
            messagebox.showerror('Import Error', str(e))

    def _scope_export(self):
        from tkinter import filedialog
        rules = self.db.get_scope_rules()
        if not rules:
            messagebox.showwarning('Scope', 'No rules to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json'), ('Text', '*.txt')],
            initialfile='scope_rules.json')
        if not path:
            return
        with open(path, 'w') as f:
            json.dump(rules, f, indent=2)
        self._set_status(f'Exported {len(rules)} scope rules → {path}')

    def _scope_context_menu(self, event):
        item = self.scope_tree.identify_row(event.y)
        if not item:
            return
        self.scope_tree.selection_set(item)
        m = tk.Menu(self.root, tearoff=0,
            bg=BG3, fg=TEXT, activebackground=BG4,
            activeforeground=ACCENT, font=FONT_MONO_SM)
        m.add_command(label='  Enable / Disable', command=self._scope_toggle)
        m.add_command(label='  Delete Rule',
            command=lambda: self._scope_delete(int(item)))
        m.post(event.x_root, event.y_root)

    def _scope_check(self, host: str) -> bool:
        """Delegate to cached DB scope check."""
        return self.db.check_scope(host)

    # ── Report Methods ────────────────────────────────────────────────────────

    def _report_generate(self):
        host_filter = self.report_host_filter.get().strip()
        min_risk    = self.report_min_risk.get()
        flagged_only = self.report_flagged_var.get()
        use_groq    = self.report_groq_var.get()

        RISK_ORDER = {'ALL': 0, 'LOW': 1, 'MEDIUM': 2, 'HIGH': 3, 'CRITICAL': 4}
        min_level  = RISK_ORDER.get(min_risk, 0)

        self.report_out.delete('1.0', 'end')
        self.report_out.insert('end', 'Generating report...\n')
        self.report_status_lbl.config(text='Generating...', fg=YELLOW)

        def _run():
            rows = self.db.get_requests(2000, host_filter=host_filter,
                                        flagged_only=flagged_only)
            # Filter by risk
            if min_risk != 'ALL':
                rows = [r for r in rows
                        if RISK_ORDER.get(r.get('ai_risk','LOW'), 0) >= min_level]

            # Stats
            total     = len(rows)
            by_risk   = {'CRITICAL': 0, 'HIGH': 0, 'MEDIUM': 0, 'LOW': 0, 'UNKNOWN': 0}
            all_vulns = []
            hosts     = set()
            for r in rows:
                risk = r.get('ai_risk', 'UNKNOWN')
                by_risk[risk] = by_risk.get(risk, 0) + 1
                hosts.add(r.get('host', ''))
                try:
                    vulns = json.loads(r.get('ai_vulns', '[]'))
                    all_vulns.extend(vulns)
                except Exception:
                    pass

            vuln_types = {}
            for v in all_vulns:
                t = v.get('type', 'Unknown')
                vuln_types[t] = vuln_types.get(t, 0) + 1

            # Groq executive summary
            exec_summary = ''
            if use_groq and self.analyzer._groq and rows:
                top_vulns = ', '.join(f"{k}({v})" for k, v in
                    sorted(vuln_types.items(), key=lambda x: -x[1])[:5])
                prompt = (
                    f"Security proxy scan report summary:\n"
                    f"Total requests: {total}\n"
                    f"Hosts: {', '.join(list(hosts)[:5])}\n"
                    f"Risk breakdown: CRITICAL={by_risk['CRITICAL']}, "
                    f"HIGH={by_risk['HIGH']}, MEDIUM={by_risk['MEDIUM']}\n"
                    f"Top vulnerabilities: {top_vulns}\n\n"
                    f"Write a professional 3-paragraph executive summary "
                    f"for a security report. Be concise and actionable.")
                try:
                    exec_summary = self.analyzer._groq.ask(prompt, max_tokens=400)
                except Exception:
                    exec_summary = 'Groq summary unavailable.'

            # Build HTML report
            html = self._report_build_html(
                rows, by_risk, vuln_types, hosts, exec_summary, total)
            self._report_html = html

            # Build text preview
            preview = self._report_build_preview(
                rows, by_risk, vuln_types, hosts, exec_summary, total)

            self.root.after(0, lambda: [
                self.report_out.delete('1.0', 'end'),
                self.report_out.insert('1.0', preview),
                self.report_status_lbl.config(
                    text=f'Done  ·  {total} requests  ·  {len(all_vulns)} vulns', fg=GREEN),
                self.report_stats_lbl.config(
                    text=f'CRITICAL:{by_risk.get("CRITICAL",0)}  HIGH:{by_risk.get("HIGH",0)}  MEDIUM:{by_risk.get("MEDIUM",0)}  LOW:{by_risk.get("LOW",0)}  ·  Hosts:{len(hosts)}  ·  Vulns:{len(all_vulns)}'),
                self._set_status(f'Report generated  ·  {total} requests analyzed')])

        threading.Thread(target=_run, daemon=True).start()

    def _report_build_preview(self, rows, by_risk, vuln_types, hosts,
                               exec_summary, total) -> str:
        ts  = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        out = f"{'='*60}\n  SENTINELPROXY SECURITY REPORT\n  Generated: {ts}\n{'='*60}\n\n"

        if exec_summary:
            out += "EXECUTIVE SUMMARY\n" + '-'*40 + '\n'
            out += exec_summary + '\n\n'

        out += "STATISTICS\n" + '-'*40 + '\n'
        out += f"  Total Requests : {total}\n"
        out += f"  Unique Hosts   : {len(hosts)}\n"
        out += f"  CRITICAL       : {by_risk.get('CRITICAL',0)}\n"
        out += f"  HIGH           : {by_risk.get('HIGH',0)}\n"
        out += f"  MEDIUM         : {by_risk.get('MEDIUM',0)}\n"
        out += f"  LOW            : {by_risk.get('LOW',0)}\n\n"

        if vuln_types:
            out += "VULNERABILITY TYPES\n" + '-'*40 + '\n'
            for vtype, count in sorted(vuln_types.items(), key=lambda x: -x[1]):
                out += f"  {vtype:<25} {count}\n"
            out += '\n'

        out += "HOSTS IN SCOPE\n" + '-'*40 + '\n'
        for h in sorted(hosts):
            out += f"  {h}\n"
        out += '\n'

        critical_high = [r for r in rows
                         if r.get('ai_risk') in ('CRITICAL', 'HIGH')][:20]
        if critical_high:
            out += f"TOP FINDINGS ({len(critical_high)} shown)\n" + '-'*40 + '\n'
            for r in critical_high:
                out += (f"  [{r.get('ai_risk','?')}] {r.get('method','')} "
                        f"{r.get('url','')[:70]}\n")
                out += f"         {r.get('ai_summary','')}\n\n"

        out += '='*60 + '\n  END OF REPORT\n' + '='*60 + '\n'
        return out

    def _report_build_html(self, rows, by_risk, vuln_types, hosts,
                            exec_summary, total) -> str:
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        RISK_COLOR = {
            'CRITICAL': '#f85149', 'HIGH': '#d29922',
            'MEDIUM': '#e3b341', 'LOW': '#3fb950', 'UNKNOWN': '#8b949e'
        }

        vuln_rows = ''
        for vtype, count in sorted(vuln_types.items(), key=lambda x: -x[1]):
            vuln_rows += f'<tr><td>{vtype}</td><td>{count}</td></tr>\n'

        findings_rows = ''
        for r in rows[:100]:
            risk  = r.get('ai_risk', 'UNKNOWN')
            color = RISK_COLOR.get(risk, '#8b949e')
            findings_rows += (
                f'<tr>'
                f'<td><span style="color:{color};font-weight:bold">{risk}</span></td>'
                f'<td>{r.get("method","")}</td>'
                f'<td style="word-break:break-all">{r.get("url","")[:80]}</td>'
                f'<td>{r.get("status_code","")}</td>'
                f'<td>{r.get("ai_summary","")[:80]}</td>'
                f'</tr>\n')

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<title>SentinelProxy Report — {ts}</title>
<style>
  body {{ background:#0d1117; color:#e6edf3; font-family:'Fira Code',monospace; margin:0; padding:20px; }}
  h1   {{ color:#58a6ff; border-bottom:2px solid #30363d; padding-bottom:10px; }}
  h2   {{ color:#79c0ff; margin-top:30px; }}
  .stats {{ display:flex; gap:16px; flex-wrap:wrap; margin:16px 0; }}
  .stat-box {{ background:#161b22; border:1px solid #30363d; border-radius:6px;
               padding:12px 20px; min-width:120px; text-align:center; }}
  .stat-box .num {{ font-size:2em; font-weight:bold; }}
  .critical {{ color:#f85149; }} .high {{ color:#d29922; }}
  .medium   {{ color:#e3b341; }} .low  {{ color:#3fb950; }}
  table {{ width:100%; border-collapse:collapse; margin:12px 0; }}
  th    {{ background:#161b22; color:#8b949e; padding:8px 12px;
           text-align:left; border-bottom:1px solid #30363d; font-size:0.85em; }}
  td    {{ padding:7px 12px; border-bottom:1px solid #21262d; font-size:0.85em; }}
  tr:hover td {{ background:#161b22; }}
  .exec {{ background:#161b22; border-left:3px solid #58a6ff;
           padding:16px; margin:16px 0; border-radius:0 6px 6px 0;
           white-space:pre-wrap; line-height:1.6; }}
  .footer {{ color:#484f58; font-size:0.8em; margin-top:40px; text-align:center; }}
</style>
</head>
<body>
<h1>SentinelProxy Security Report</h1>
<p style="color:#8b949e">Generated: {ts} &nbsp;·&nbsp; @who_is_the_black_hat</p>

<h2>Statistics</h2>
<div class="stats">
  <div class="stat-box"><div class="num">{total}</div>Requests</div>
  <div class="stat-box"><div class="num">{len(hosts)}</div>Hosts</div>
  <div class="stat-box"><div class="num critical">{by_risk.get('CRITICAL',0)}</div>Critical</div>
  <div class="stat-box"><div class="num high">{by_risk.get('HIGH',0)}</div>High</div>
  <div class="stat-box"><div class="num medium">{by_risk.get('MEDIUM',0)}</div>Medium</div>
  <div class="stat-box"><div class="num low">{by_risk.get('LOW',0)}</div>Low</div>
</div>

{"<h2>Executive Summary</h2><div class='exec'>" + exec_summary + "</div>" if exec_summary else ""}

<h2>Vulnerability Types</h2>
<table><tr><th>Type</th><th>Count</th></tr>{vuln_rows}</table>

<h2>Findings (top 100)</h2>
<table>
<tr><th>Risk</th><th>Method</th><th>URL</th><th>Status</th><th>Summary</th></tr>
{findings_rows}
</table>

<div class="footer">SentinelProxy v1.0 &nbsp;·&nbsp; @who_is_the_black_hat</div>
</body></html>"""
        return html

    def _report_save_html(self):
        if not self._report_html:
            messagebox.showwarning('Report', 'Generate report first')
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension='.html',
            filetypes=[('HTML', '*.html'), ('All', '*.*')],
            initialfile=f'sentinel_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.html')
        if not path:
            return
        with open(path, 'w', encoding='utf-8') as f:
            f.write(self._report_html)
        self._set_status(f'HTML report saved: {path}')
        messagebox.showinfo('Saved', f'HTML report saved:\n{path}')

    def _report_save_pdf(self):
        if not self._report_html:
            messagebox.showwarning('Report', 'Generate report first')
            return
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            defaultextension='.pdf',
            filetypes=[('PDF', '*.pdf'), ('All', '*.*')],
            initialfile=f'sentinel_report_{datetime.now().strftime("%Y%m%d_%H%M%S")}.pdf')
        if not path:
            return
        try:
            import weasyprint
            weasyprint.HTML(string=self._report_html).write_pdf(path)
            self._set_status(f'PDF report saved: {path}')
            messagebox.showinfo('Saved', f'PDF report saved:\n{path}')
        except ImportError:
            # Fallback: save HTML and open in browser to print as PDF
            html_path = path.replace('.pdf', '.html')
            with open(html_path, 'w', encoding='utf-8') as f:
                f.write(self._report_html)
            import subprocess
            subprocess.Popen(['xdg-open', html_path])
            self._set_status(f'weasyprint not found — HTML opened in browser (Print → Save as PDF)')
            messagebox.showinfo('Info',
                f'weasyprint not installed.\nHTML saved and opened in browser.\nUse Print → Save as PDF.\n\n{html_path}')



    # ── Match & Replace Methods ───────────────────────────────────────────────

    def _mr_add(self):
        match   = self.mr_match.get().strip()
        replace = self.mr_replace.get().strip()
        target  = self.mr_target.get()
        mtype   = self.mr_type.get()
        if not match:
            messagebox.showwarning('Match & Replace', 'Enter a match pattern')
            return
        self.db.add_mr_rule(match, replace, target, mtype)
        self._mr_load()
        self.mr_match.delete(0, 'end')
        self.mr_replace.delete(0, 'end')
        self._set_status(f'Match & Replace rule added: {match} → {replace}')

    def _mr_load(self):
        self._mr_rules = self.db.get_mr_rules()
        for i in self.mr_tree.get_children():
            self.mr_tree.delete(i)
        for r in self._mr_rules:
            tag = 'active' if r['enabled'] else 'inactive'
            self.mr_tree.insert('', 'end', iid=str(r['id']),
                values=(r['id'], r['match'][:40], r['replace'][:40],
                        r['target'], r['rule_type'],
                        'ON' if r['enabled'] else 'OFF', r['hits']),
                tags=(tag,))
        active = sum(1 for r in self._mr_rules if r['enabled'])
        self.mr_status_lbl.config(text=f'{len(self._mr_rules)} rules  ·  {active} active')
        # Sync rules to Rust core via IPC
        if self.proxy and hasattr(self.proxy, '_send_cmd'):
            self.proxy._send_cmd({'action': 'set_mr_rules', 'rules': [
                {'id': r['id'], 'match': r['match'], 'replace': r['replace'],
                 'target': r['target'], 'rule_type': r.get('rule_type', 'Literal'),
                 'enabled': bool(r['enabled'])}
                for r in self._mr_rules
            ]})

    def _mr_toggle(self, event=None):
        sel = self.mr_tree.selection()
        if not sel:
            return
        rid  = int(sel[0])
        rule = next((r for r in self._mr_rules if r['id'] == rid), None)
        if rule:
            self.db.toggle_mr_rule(rid, not bool(rule['enabled']))
        self._mr_load()

    def _mr_clear_all(self):
        if messagebox.askyesno('Match & Replace', 'Clear all rules?'):
            for r in self._mr_rules:
                self.db.delete_mr_rule(r['id'])
            self._mr_load()

    def _mr_delete(self, rid: int):
        self.db.delete_mr_rule(rid)
        self._mr_load()

    def _mr_context_menu(self, event):
        item = self.mr_tree.identify_row(event.y)
        if not item:
            return
        self.mr_tree.selection_set(item)
        m = tk.Menu(self.root, tearoff=0, bg=BG3, fg=TEXT,
            activebackground=BG4, activeforeground=ACCENT, font=FONT_MONO_SM)
        m.add_command(label='  Enable / Disable', command=self._mr_toggle)
        m.add_command(label='  Delete Rule',
            command=lambda: self._mr_delete(int(item)))
        m.post(event.x_root, event.y_root)

    def _mr_apply(self, flow: dict) -> dict:
        """Apply match & replace rules to a flow dict. Returns modified flow."""
        for rule in self._mr_rules:
            if not rule['enabled']:
                continue
            match_str = rule['match']
            replace   = rule['replace']
            target    = rule['target']
            mtype     = rule.get('rule_type', rule.get('type', 'Literal'))
            rule_id   = rule['id']

            def do_replace(text: str, _m=match_str, _r=replace, _t=mtype, _id=rule_id) -> str:
                if not text:
                    return text
                try:
                    if _t == 'Regex':
                        new_text = re.sub(_m, _r, text)
                    else:
                        new_text = text.replace(_m, _r)
                    if new_text != text:
                        self.db.increment_mr_hits(_id)
                    return new_text
                except Exception:
                    return text

            if target in ('Request Header', 'Any'):
                flow['headers'] = {k: do_replace(v) for k, v in flow.get('headers', {}).items()}
            if target in ('Request Body', 'Any'):
                flow['body'] = do_replace(flow.get('body', ''))
            if target in ('URL', 'Any'):
                flow['url'] = do_replace(flow.get('url', ''))
            if target in ('Response Header', 'Any'):
                flow['resp_headers'] = {k: do_replace(v) for k, v in flow.get('resp_headers', {}).items()}
            if target in ('Response Body', 'Any'):
                flow['resp_body'] = do_replace(flow.get('resp_body', ''))
        return flow

    # ── Active Scanner Methods ────────────────────────────────────────────────

    def _as_start(self):
        if self._as_running:
            return
        url = self.as_url.get().strip()
        if not url:
            messagebox.showwarning('Active Scanner', 'Enter a target URL')
            return
        if not url.startswith('http'):
            url = 'http://' + url
            self.as_url.delete(0, 'end')
            self.as_url.insert(0, url)

        scan_type = self.as_scan_type.get()
        try:
            threads_n = int(self.as_threads.get() or 5)
        except (ValueError, AttributeError):
            threads_n = 5
        self._as_running = True
        self.as_status_lbl.config(text='Scanning...', fg=YELLOW)

        # Clear previous results
        for i in self.as_tree.get_children():
            self.as_tree.delete(i)
        self.as_detail.delete('1.0', 'end')

        def _run():
            findings = []
            try:
                # Determine which vuln types to test
                if scan_type == 'Full Auto':
                    types = ['SQLi','XSS','LFI','SSRF','SSTI','RCE','XXE',
                             'Open Redirect','Path Traversal']
                elif scan_type == 'Headers Only':
                    types = ['headers']
                else:
                    types = [scan_type.replace(' Only','')]

                # Step 1: Detect params
                params = self._af_detect_params_sync(url)
                self.root.after(0, lambda: self.as_status_lbl.config(
                    text=f'Found {len(params)} params, testing...', fg=YELLOW))

                # Step 2: Test headers
                if scan_type in ('Full Auto', 'Headers Only'):
                    hdr_findings = self._as_check_headers(url)
                    findings.extend(hdr_findings)

                # Step 3: Fuzz each param with each vuln type — parallel
                SEV_MAP = {
                    'SQLi':'CRITICAL','RCE':'CRITICAL','SSTI':'CRITICAL',
                    'XXE':'CRITICAL','LFI':'HIGH','SSRF':'HIGH',
                    'XSS':'HIGH','Path Traversal':'HIGH','Open Redirect':'MEDIUM',
                }
                test_jobs = [
                    (param, vtype)
                    for param in params
                    for vtype in [t for t in types if t != 'headers']
                ]

                def _test_job(job):
                    param, vtype = job
                    if not self._as_running:
                        return
                    payloads = self._load_payloads_from_file(vtype)[:30]
                    if not payloads:
                        payloads = self.analyzer.suggest_payloads(vtype)[:10]
                    base_r = None
                    for payload in payloads:
                        if not self._as_running:
                            return
                        try:
                            sep = '&' if '?' in url else '?'
                            test_url = f"{url}{sep}{param}={urllib.parse.quote(str(payload))}"
                            r = requests.get(test_url, verify=False,
                                timeout=6, allow_redirects=False)
                            if base_r is None:
                                base_r = len(r.content)
                            resp_text = r.text[:3000]
                            vuln_detected = False
                            if vtype == 'SQLi':
                                sqli_errors = [
                                    'sql syntax','mysql_fetch','ora-','pg_query',
                                    'sqlite_','odbc_','mssql_','syntax error',
                                    'unclosed quotation','you have an error in your sql',
                                    'warning: mysql','supplied argument is not a valid mysql',
                                ]
                                vuln_detected = any(e in resp_text.lower() for e in sqli_errors)
                                if not vuln_detected and base_r and abs(len(r.content) - base_r) > 200:
                                    vuln_detected = True
                            elif vtype == 'XSS':
                                vuln_detected = str(payload)[:20] in resp_text
                            elif vtype == 'LFI':
                                lfi_indicators = ['root:x:0:0','[boot loader]','[extensions]','daemon:x:']
                                vuln_detected = any(i in resp_text for i in lfi_indicators)
                            elif vtype == 'SSRF':
                                vuln_detected = r.status_code in (200, 500) and base_r and abs(len(r.content) - base_r) > 100
                            elif vtype == 'SSTI':
                                vuln_detected = '49' in resp_text
                            elif vtype == 'RCE':
                                rce_indicators = ['uid=','gid=','root','www-data','daemon']
                                vuln_detected = any(i in resp_text for i in rce_indicators)
                            elif vtype == 'Path Traversal':
                                pt_indicators = ['root:x:0:0','[boot loader]','daemon:x:']
                                vuln_detected = any(i in resp_text for i in pt_indicators)
                            else:
                                vuln_detected = base_r and abs(len(r.content) - base_r) > 150

                            if vuln_detected:
                                sev = SEV_MAP.get(vtype, 'MEDIUM')
                                finding = {
                                    'sev': sev, 'type': vtype,
                                    'param': param, 'url': test_url,
                                    'payload': payload,
                                    'status': r.status_code,
                                    'evidence': f"Payload: {str(payload)[:60]}",
                                    'response': r.text[:500],
                                }
                                findings.append(finding)
                                self.root.after(0, lambda f=finding: self._as_add_finding(f))
                                return  # one confirmed finding per param/type
                        except Exception:
                            pass

                from concurrent.futures import ThreadPoolExecutor
                with ThreadPoolExecutor(max_workers=threads_n) as ex:
                    ex.map(_test_job, test_jobs)

            except Exception as e:
                self.root.after(0, lambda: self.as_status_lbl.config(
                    text=f'Error: {str(e)[:50]}', fg=RED))
                return

            self._as_running = False
            self.root.after(0, lambda: self.as_status_lbl.config(
                text=f'Done  ·  {len(findings)} findings', fg=GREEN if findings else TEXT2))
            self._set_status(f'Active Scanner done  ·  {len(findings)} vulnerabilities found')

        threading.Thread(target=_run, daemon=True).start()

    def _af_detect_params_sync(self, url: str) -> list:
        """Sync param detection — URL query + HTML forms + JSON body + JS vars."""
        params = []
        try:
            from bs4 import BeautifulSoup
            from urllib.parse import urlparse, parse_qs
            r = requests.get(url, verify=False, timeout=8,
                headers={'User-Agent': 'SentinelProxy/1.0'})
            # 1. URL query params
            parsed = urlparse(url)
            for k in parse_qs(parsed.query):
                if k not in params:
                    params.append(k)
            # 2. HTML form inputs (GET and POST)
            soup = BeautifulSoup(r.text, 'html.parser')
            for inp in soup.find_all(['input', 'textarea', 'select']):
                name = inp.get('name') or inp.get('id', '')
                if name and name not in params:
                    params.append(name)
            # 3. JSON body keys from API responses
            ct = r.headers.get('content-type', '')
            if 'json' in ct:
                try:
                    import json as _j
                    data = _j.loads(r.text)
                    if isinstance(data, dict):
                        for k in list(data.keys())[:20]:
                            if k not in params:
                                params.append(k)
                except Exception:
                    pass
            # 4. JS variable patterns
            js_params = re.findall(
                r'["\']([a-zA-Z_][a-zA-Z0-9_]{1,20})["\']\s*:\s*["\'][^"\']{0,50}["\']',
                r.text)
            SKIP = {'true','false','null','undefined','function','return',
                    'class','const','let','var','type','name','id','src',
                    'href','style','data','value','text','content'}
            for jp in js_params[:20]:
                if jp not in params and jp.lower() not in SKIP:
                    params.append(jp)
        except Exception:
            pass
        return params or ['id', 'q', 'search', 'page', 'url', 'file', 'name', 'user']

    def _as_check_headers(self, url: str) -> list:
        """Check security headers."""
        findings = []
        try:
            r = requests.get(url, verify=False, timeout=8)
            hdrs = {k.lower(): v for k, v in r.headers.items()}
            checks = [
                ('content-security-policy',  'Missing CSP Header',           'MEDIUM'),
                ('x-frame-options',          'Missing X-Frame-Options',       'MEDIUM'),
                ('x-content-type-options',   'Missing X-Content-Type-Options','LOW'),
                ('strict-transport-security','Missing HSTS Header',           'MEDIUM'),
                ('x-xss-protection',         'Missing X-XSS-Protection',      'LOW'),
                ('referrer-policy',          'Missing Referrer-Policy',        'LOW'),
            ]
            for header, desc, sev in checks:
                if header not in hdrs:
                    findings.append({
                        'sev': sev, 'type': 'Missing Header',
                        'param': header, 'url': url,
                        'payload': '', 'status': r.status_code,
                        'evidence': desc,
                        'response': '',
                    })
        except Exception:
            pass
        return findings

    def _as_add_finding(self, f: dict):
        self.as_tree.insert('', 'end',
            values=(f['sev'], f['type'], f['param'],
                    f['url'][:70], f['evidence'][:60]),
            tags=(f['sev'],))

    def _as_stop(self):
        self._as_running = False
        self.as_status_lbl.config(text='Stopped', fg=ORANGE)

    def _as_clear(self):
        for i in self.as_tree.get_children():
            self.as_tree.delete(i)
        self.as_detail.delete('1.0', 'end')
        self.as_status_lbl.config(text='')

    def _as_export(self):
        from tkinter import filedialog
        findings = []
        for iid in self.as_tree.get_children():
            vals = self.as_tree.item(iid, 'values')
            findings.append({'severity': vals[0], 'type': vals[1],
                             'param': vals[2], 'url': vals[3], 'evidence': vals[4]})
        if not findings:
            messagebox.showwarning('Active Scanner', 'No findings to export')
            return
        path = filedialog.asksaveasfilename(
            defaultextension='.json',
            filetypes=[('JSON', '*.json')],
            initialfile=f'active_scan_{int(time.time())}.json')
        if not path:
            return
        with open(path, 'w') as f:
            json.dump(findings, f, indent=2)
        self._set_status(f'Exported {len(findings)} findings → {path}')

    def _as_context_menu(self, event):
        item = self.as_tree.identify_row(event.y)
        if not item:
            return
        self.as_tree.selection_set(item)
        vals = self.as_tree.item(item, 'values')
        m = tk.Menu(self.root, tearoff=0, bg=BG3, fg=TEXT,
            activebackground=BG4, activeforeground=ACCENT, font=FONT_MONO_SM)
        m.add_command(label='  Copy URL',
            command=lambda: [self.root.clipboard_clear(),
                             self.root.clipboard_append(vals[3] if len(vals) > 3 else '')])
        m.add_command(label='  Copy Payload/Evidence',
            command=lambda: [self.root.clipboard_clear(),
                             self.root.clipboard_append(vals[4] if len(vals) > 4 else '')])
        m.add_command(label='  → Send to Repeater',
            command=lambda: [self.rep_url.delete(0, 'end'),
                             self.rep_url.insert(0, vals[3] if len(vals) > 3 else ''),
                             self.nb.select(1)])
        m.add_command(label='  → Send to Intruder',
            command=lambda: [self.int_url.delete(0, 'end'),
                             self.int_url.insert(0, vals[3] if len(vals) > 3 else ''),
                             self.nb.select(2)])
        m.post(event.x_root, event.y_root)

    # ── Session Analyzer Methods ──────────────────────────────────────────────

    def _sa_analyze(self):
        token = self.sa_input.get('1.0', 'end').strip()
        if not token:
            messagebox.showwarning('Session Analyzer', 'Paste a token first')
            return
        self.sa_output.delete('1.0', 'end')
        self.sa_status_lbl.config(text='Analyzing...', fg=YELLOW)

        def _run():
            result = self._sa_detect_and_analyze(token)
            self.root.after(0, lambda: [
                self.sa_output.delete('1.0', 'end'),
                self.sa_output.insert('1.0', result),
                self.sa_status_lbl.config(text='Done', fg=GREEN)])

        threading.Thread(target=_run, daemon=True).start()

    def _sa_detect_and_analyze(self, token: str) -> str:
        import base64, json as _json, re as _re, time as _time

        out = '=' * 55 + '\n  SESSION TOKEN ANALYZER\n' + '=' * 55 + '\n\n'

        # Detect token type
        token = token.strip().strip('"\'')

        # JWT detection
        if _re.match(r'^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]*$', token):
            out += '[TOKEN TYPE] JWT (JSON Web Token)\n\n'
            parts = token.split('.')
            try:
                def b64d(s):
                    s += '=' * (4 - len(s) % 4)
                    return _json.loads(base64.urlsafe_b64decode(s))

                header  = b64d(parts[0])
                payload = b64d(parts[1])

                out += '── HEADER ──\n'
                for k, v in header.items():
                    out += f'  {k:<15} : {v}\n'

                out += '\n── PAYLOAD ──\n'
                for k, v in payload.items():
                    out += f'  {k:<15} : {v}\n'

                # Security checks
                out += '\n── SECURITY ANALYSIS ──\n'
                alg = header.get('alg', '').upper()
                if alg == 'NONE':
                    out += '  [CRITICAL] Algorithm is "none" — signature bypass possible!\n'
                elif alg in ('HS256','HS384','HS512'):
                    out += f'  [INFO]     Algorithm: {alg} (HMAC — shared secret)\n'
                elif alg in ('RS256','RS384','RS512'):
                    out += f'  [INFO]     Algorithm: {alg} (RSA — asymmetric)\n'
                    out += '  [CHECK]    Try algorithm confusion: RS256 → HS256\n'
                else:
                    out += f'  [INFO]     Algorithm: {alg}\n'

                # Expiry check
                exp = payload.get('exp')
                iat = payload.get('iat')
                nbf = payload.get('nbf')
                now = _time.time()
                if exp:
                    import datetime
                    exp_dt = datetime.datetime.fromtimestamp(exp)
                    if exp < now:
                        out += f'  [HIGH]     Token EXPIRED at {exp_dt}\n'
                    else:
                        remaining = exp - now
                        out += f'  [INFO]     Expires: {exp_dt} ({remaining/3600:.1f}h remaining)\n'
                else:
                    out += '  [MEDIUM]   No expiry (exp) claim — token never expires!\n'

                if iat:
                    import datetime
                    out += f'  [INFO]     Issued at: {datetime.datetime.fromtimestamp(iat)}\n'

                # Sensitive data check
                sensitive = ['password','passwd','secret','key','token','ssn',
                             'credit','card','cvv','pin','private']
                for k, v in payload.items():
                    if any(s in k.lower() for s in sensitive):
                        out += f'  [HIGH]     Sensitive field in payload: {k}\n'

                # Common attacks
                out += '\n── ATTACK VECTORS ──\n'
                out += '  1. Algorithm confusion (alg:none)\n'
                out += '  2. Weak secret brute-force (if HMAC)\n'
                out += '  3. Key confusion RS256→HS256\n'
                out += '  4. Claim manipulation (change role/admin)\n'
                if not exp:
                    out += '  5. Token replay (no expiry)\n'

            except Exception as e:
                out += f'  Parse error: {e}\n'

        # OAuth Bearer token
        elif token.lower().startswith('bearer ') or len(token) in range(20, 200):
            out += '[TOKEN TYPE] OAuth Bearer / API Token\n\n'
            out += f'  Length    : {len(token)} chars\n'
            out += f'  Entropy   : {"High" if len(set(token)) > 20 else "Low — possibly weak"}\n\n'
            out += '── SECURITY ANALYSIS ──\n'
            if len(token) < 32:
                out += '  [HIGH]   Token too short — brute-force risk\n'
            if token.isalnum() and len(set(token)) < 15:
                out += '  [MEDIUM] Low entropy — predictable token\n'
            out += '\n── ATTACK VECTORS ──\n'
            out += '  1. Token leakage in logs/referrer\n'
            out += '  2. Brute-force if short/low entropy\n'
            out += '  3. Token fixation\n'
            out += '  4. Replay attack\n'

        # Cookie / Session ID
        elif '=' in token or len(token) < 100:
            out += '[TOKEN TYPE] Cookie / Session Token\n\n'
            # Parse cookie
            cookies = {}
            for part in token.split(';'):
                part = part.strip()
                if '=' in part:
                    k, _, v = part.partition('=')
                    cookies[k.strip()] = v.strip()
            out += '── COOKIES ──\n'
            for k, v in cookies.items():
                out += f'  {k:<20} : {v[:60]}\n'
            out += '\n── SECURITY ANALYSIS ──\n'
            for k, v in cookies.items():
                if 'session' in k.lower() or 'sess' in k.lower():
                    if len(v) < 32:
                        out += f'  [HIGH]   Session ID too short: {k}\n'
                    if v.isdigit():
                        out += f'  [CRITICAL] Numeric session ID — predictable: {k}\n'
            out += '\n── ATTACK VECTORS ──\n'
            out += '  1. Session fixation\n'
            out += '  2. Session hijacking\n'
            out += '  3. CSRF (if no SameSite)\n'
            out += '  4. XSS cookie theft\n'

        # SAML
        elif '<saml' in token.lower() or 'samlp' in token.lower():
            out += '[TOKEN TYPE] SAML Assertion\n\n'
            out += '── SECURITY ANALYSIS ──\n'
            out += '  [CHECK] XML Signature Wrapping (XSW)\n'
            out += '  [CHECK] XXE in SAML assertion\n'
            out += '  [CHECK] Signature validation bypass\n'
            out += '\n── ATTACK VECTORS ──\n'
            out += '  1. XML Signature Wrapping\n'
            out += '  2. XXE injection\n'
            out += '  3. Replay attack\n'
        else:
            out += '[TOKEN TYPE] Unknown / Raw Token\n\n'
            out += f'  Length : {len(token)}\n'
            out += f'  Value  : {token[:100]}\n'

        # Groq deep analysis
        if self.analyzer._groq:
            out += '\n── GROQ AI ANALYSIS ──\n'
            try:
                prompt = (
                    f"Analyze this security token for vulnerabilities:\n{token[:300]}\n\n"
                    f"Give: 1) Token type 2) Security issues 3) Attack vectors. "
                    f"Be concise, bullet points.")
                groq_out = self.analyzer._groq.ask(prompt, max_tokens=300)
                out += groq_out + '\n'
            except Exception:
                out += '  Groq analysis unavailable\n'

        out += '\n' + '=' * 55 + '\n'
        return out

    def _sa_scan_history(self):
        """Scan proxy history for tokens."""
        rows = self.db.get_requests(500)
        tokens_found = []
        import re as _re
        jwt_pattern = _re.compile(
            r'[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*')
        bearer_pattern = _re.compile(r'Bearer\s+([A-Za-z0-9_\-\.]+)', _re.IGNORECASE)

        for r in rows:
            text = ' '.join([
                r.get('url',''), r.get('body',''),
                r.get('resp_body','')[:500],
                str(r.get('headers',''))
            ])
            for m in jwt_pattern.finditer(text):
                tokens_found.append(('JWT', m.group(), r.get('url','')))
            for m in bearer_pattern.finditer(text):
                tokens_found.append(('Bearer', m.group(1), r.get('url','')))

        if not tokens_found:
            self.sa_output.delete('1.0', 'end')
            self.sa_output.insert('1.0', 'No tokens found in proxy history.\n')
            return

        self.sa_input.delete('1.0', 'end')
        self.sa_output.delete('1.0', 'end')
        out = f'Found {len(tokens_found)} tokens in proxy history:\n\n'
        for ttype, tval, turl in tokens_found[:20]:
            out += f'[{ttype}] {tval[:80]}\n  URL: {turl[:60]}\n\n'
        self.sa_output.insert('1.0', out)
        # Load first token for analysis
        if tokens_found:
            self.sa_input.insert('1.0', tokens_found[0][1])
        self.sa_status_lbl.config(
            text=f'{len(tokens_found)} tokens found in history', fg=YELLOW)



    # ── CVE Auto-Match ────────────────────────────────────────────────────────

    def _cve_lookup(self, vuln_type: str, tech: str = '') -> list:
        """Look up CVEs for a vuln type. Returns list of {cve_id, score, desc}."""
        import sys
        sys.path.insert(0, '/home/kali/osints')
        try:
            from modules.bugbounty.cve_lookup import CVELookup
            cve = CVELookup()
            query = f"{vuln_type} {tech}".strip()
            results = cve.search(query, limit=5)
            return results if results else []
        except Exception:
            pass
        # Fallback: static common CVEs per vuln type
        STATIC = {
            'SQLi':          [{'cve_id':'CVE-2023-23752','score':7.5,'desc':'SQL Injection in Joomla'},
                              {'cve_id':'CVE-2022-21661','score':7.5,'desc':'WordPress SQL Injection'}],
            'XSS':           [{'cve_id':'CVE-2023-2745', 'score':6.1,'desc':'WordPress XSS'},
                              {'cve_id':'CVE-2022-3590', 'score':6.1,'desc':'WordPress XSS via pingback'}],
            'LFI':           [{'cve_id':'CVE-2022-1329', 'score':9.8,'desc':'Elementor LFI'},
                              {'cve_id':'CVE-2021-25003','score':8.8,'desc':'WPCargo LFI'}],
            'SSRF':          [{'cve_id':'CVE-2021-26855','score':9.8,'desc':'Exchange SSRF (ProxyLogon)'},
                              {'cve_id':'CVE-2022-22954','score':9.8,'desc':'VMware SSRF'}],
            'RCE':           [{'cve_id':'CVE-2021-44228','score':10.0,'desc':'Log4Shell RCE'},
                              {'cve_id':'CVE-2022-22965','score':9.8,'desc':'Spring4Shell RCE'}],
            'SSTI':          [{'cve_id':'CVE-2022-22947','score':10.0,'desc':'Spring Cloud Gateway SSTI'},
                              {'cve_id':'CVE-2021-25770','score':9.8,'desc':'Smarty SSTI'}],
            'XXE':           [{'cve_id':'CVE-2021-40438','score':9.0,'desc':'Apache mod_proxy XXE'},
                              {'cve_id':'CVE-2022-42889','score':9.8,'desc':'Apache Commons Text'}],
            'Missing Header':[{'cve_id':'CWE-693',       'score':5.0,'desc':'Protection Mechanism Failure'},
                              {'cve_id':'CWE-1021',      'score':4.3,'desc':'Improper Frame Restriction'}],
        }
        return STATIC.get(vuln_type, [])

    def _as_on_select(self, event=None):
        sel = self.as_tree.selection()
        if not sel:
            return
        vals = self.as_tree.item(sel[0], 'values')
        sev, vtype, param, url, evidence = vals

        self.as_detail.delete('1.0', 'end')
        out = (f"{'='*50}\n"
               f"Severity  : {sev}\n"
               f"Vuln Type : {vtype}\n"
               f"Parameter : {param}\n"
               f"URL       : {url}\n"
               f"Evidence  : {evidence}\n\n")

        # CVE Auto-Match
        out += '── CVE MATCHES ──\n'
        cves = self._cve_lookup(vtype)
        if cves:
            for c in cves:
                score = c.get('score', c.get('cvss_score', '?'))
                cid   = c.get('cve_id', c.get('id', '?'))
                desc  = c.get('desc', c.get('description', ''))[:80]
                out += f"  {cid:<20} CVSS: {score:<5} {desc}\n"
        else:
            out += '  No CVE matches found\n'

        out += '\n── REMEDIATION ──\n'
        FIXES = {
            'SQLi':          'Use parameterized queries / prepared statements',
            'XSS':           'Encode output, implement CSP header',
            'LFI':           'Validate file paths, use whitelist',
            'SSRF':          'Whitelist allowed URLs, block internal ranges',
            'SSTI':          'Use safe template engines, sandbox templates',
            'RCE':           'Patch immediately, disable dangerous functions',
            'XXE':           'Disable external entity processing in XML parser',
            'Open Redirect': 'Validate redirect URLs against whitelist',
            'Path Traversal':'Normalize paths, use chroot/jail',
            'Missing Header':'Add security headers in server config',
        }
        out += f"  {FIXES.get(vtype, 'Review OWASP guidelines for ' + vtype)}\n"
        self.as_detail.insert('1.0', out)


    def _auto_refresh_logger(self):
        """Auto-refresh logger tab every 3 seconds when proxy is running."""
        try:
            current_tab = self.nb.index(self.nb.select())
            logger_tab  = next((i for i in range(self.nb.index('end'))
                                if 'Logger' in self.nb.tab(i, 'text')), -1)
            if current_tab == logger_tab and self.proxy_running:
                self._log_refresh()
        except Exception:
            pass
        self.root.after(3000, self._auto_refresh_logger)

    def _check_intercept_pending(self):
        """Poll for pending count — only if proxy supports intercept."""
        if self.proxy and hasattr(self.proxy, 'intercept') and self.proxy.intercept:
            if hasattr(self.proxy, 'pending_count'):
                count = self.proxy.pending_count()
                if count > 0:
                    self._set_status(f'⏸ {count} request(s) intercepted · FWD or DROP')
        self.root.after(500, self._check_intercept_pending)

    def _show_intercepted(self, flow: dict):
        """Legacy — kept for compatibility."""
        pass

    def _on_proxy_websocket(self, msg: dict):
        """Called from proxy thread for WS messages."""
        if hasattr(self, '_ws_tab'):
            self.root.after(0, self._ws_tab.add_message, msg)

    def run(self):
        # _auto_refresh and _check_intercept start after UI is built via _build_ui
        self.root.mainloop()


def main():
    app = SentinelProxyApp()
    app.run()


if __name__ == '__main__':
    main()
