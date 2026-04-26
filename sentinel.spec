# -*- mode: python ; coding: utf-8 -*-
#
# The Sentinel Pro v3.0 — PyInstaller Build Spec
#
# Build:
#   pip install pyinstaller
#   pyinstaller sentinel.spec
#
# Output: dist/sentinel/  (folder with binary + all assets)

import sys
import os
from pathlib import Path

BASE       = Path(SPECPATH)
NLTK_DATA  = Path.home() / 'nltk_data'

# ── Hidden imports ────────────────────────────────────────────────────────────
HIDDEN_IMPORTS = [
    # ML / AI
    'torch', 'torch.nn', 'torch.optim', 'torch.utils.data',
    'torch.nn.functional',
    'sklearn', 'sklearn.ensemble', 'sklearn.linear_model',
    'sklearn.feature_extraction.text', 'sklearn.cluster',
    'sklearn.metrics.pairwise', 'sklearn.preprocessing',
    'sklearn.model_selection',
    'lightgbm', 'joblib', 'numpy', 'scipy', 'scipy.sparse',
    'networkx',
    # NLP
    'nltk', 'nltk.tokenize', 'nltk.corpus', 'nltk.tag',
    'nltk.chunk', 'nltk.stem', 'nltk.sentiment',
    'spacy', 'spacy.lang.en', 'langdetect',
    # Groq
    'groq', 'tokenizers', 'tokenizers.implementations',
    # HTTP
    'requests', 'requests.adapters', 'requests.auth',
    'httpx', 'httpx._transports',
    'urllib3', 'urllib3.util',
    'aiohttp', 'aiohttp.connector',
    'PySocks', 'socks',
    # HTML / DNS
    'bs4', 'bs4.builder',
    'lxml', 'lxml.etree', 'lxml.html',
    'dns', 'dns.resolver', 'dns.rdatatype',
    'whois',
    # Crypto / Security
    'cryptography', 'cryptography.fernet',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.kdf.pbkdf2',
    'cryptography.hazmat.backends',
    'OpenSSL', 'OpenSSL.SSL',
    # Image
    'PIL', 'PIL.Image', 'PIL.ExifTags',
    'cv2', 'mmh3',
    # Reporting
    'weasyprint', 'weasyprint.fonts',
    'matplotlib', 'matplotlib.pyplot', 'matplotlib.backends',
    'matplotlib.backends.backend_agg',
    'seaborn',
    # CLI / UI
    'rich', 'rich.console', 'rich.table', 'rich.panel',
    'rich.progress', 'rich.live', 'rich.markup',
    'pyfiglet', 'colorama', 'tqdm',
    # System
    'psutil', 'keyring', 'stem', 'stem.control',
    # Misc
    'dotenv', 'magic', 'shodan',
    'ddgs', 'fake_useragent',
    'websocket', 'websocket._core',
    'ratelimit',
    # Sentinel core modules
    'config',
    'modules.wordlist_manager',
    'modules.database',
    'modules.notifications',
    'modules.cli_interface',
    'modules.utils',
    'modules.evidence_manager',
    'modules.pdf_export',
    'modules.reporting_engine',
    'modules.bugbounty.payload_loader',
    'modules.bugbounty.vuln_scanner',
    'modules.bugbounty.ssl_checker',
    'modules.bugbounty.headers_checker',
    'modules.bugbounty.port_scanner',
    'modules.bugbounty.endpoint_scanner',
    'modules.bugbounty.js_analyzer',
    'modules.bugbounty.shodan_scanner',
    'modules.bugbounty.cve_lookup',
    'modules.bugbounty.cors_scanner',
    'modules.bugbounty.nuclei_bridge',
    'modules.bugbounty.dirbuster_bridge',
    'modules.bugbounty.fuzzer_bridge',
    'modules.bugbounty.smuggler_bridge',
    'modules.bugbounty.rust_analyzer_bridge',
    'modules.recon.whois_lookup',
    'modules.recon.subdomain_enum',
    'modules.recon.go_scraper_bridge',
    'modules.recon.wayback',
    'modules.recon.email_osint',
    'modules.recon.phone_osint',
    'modules.recon.person_osint',
    'modules.recon.image_osint',
    'modules.recon.relation_mapper',
    'modules.breach.breach_checker',
    'modules.ml_engine.sentinel_net',
    'modules.ml_engine.trainer',
    'modules.ml_engine.groq_llm',
    'modules.ml_engine.decision_engine',
    'modules.ml_engine.autonomous_loop',
    'modules.ml_engine.nlp_analyzer',
    'modules.ml_engine.entity_matcher',
    'modules.ml_engine.identity_scorer',
    'modules.ml_engine.username_clusterer',
    'modules.ml_engine.writing_fingerprinter',
    'modules.ml_engine.timeline_analyzer',
    'modules.ml_engine.sentinel_lm',
    'sentinel_brain.brain',
    'sentinel_brain.kali_controller',
    'sentinel_brain.rl_agent',
    'sentinel_brain.advanced_ml',
    'sentinel_brain.memory',
    'sentinel_brain.monitor',
    'sentinel_brain.agents.recon_agent',
    'sentinel_brain.agents.exploit_agent',
    'sentinel_brain.agents.osint_agent',
    'sentinel_brain.agents.breach_agent',
    'sentinel_brain.agents.report_agent',
    'sentinel_brain.agents.threat_intel_agent',
    'sentinel_brain.agents.attack_chain_agent',
    'sentinel_brain.agents.monitor_agent',
    'sentinel_brain.agents.darkweb_agent',
    'sentinel_brain.agents.browser_agent',
    'sentinel_brain.agents.terminal_agent',
    'sentinel_brain.agents.system_monitor_agent',
    'sentinel_brain.agents.filesystem_agent',
    'sentinel_brain.agents.notification_agent',
    'sentinel_brain.agents.credential_agent',
    'sentinel_brain.agents.scheduler_agent',
    'sentinel_brain.agents.correlation_agent',
    'sentinel_brain.agents.network_agent',
]

# ── Data files to embed ───────────────────────────────────────────────────────
DATAS = [
    # ML Models
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_threat_net.pt'),   'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_vocab.json'),       'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_seq2seq.pt'),       'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_seq2seq_vocab.json'),'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_proxy_net.pt'),     'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_proxy_vocab.json'), 'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'rl_qtable.json'),            'models/ml_engine'),
    # SentinelLM (137MB — comment out to reduce size)
    (str(BASE / 'models' / 'ml_engine' / 'sentinellm_v1.pt'),          'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinellm_vocab.json'),     'models/ml_engine'),
    # Payloads (34K — 2.7MB)
    (str(BASE / 'sentinel_proxy' / 'payloads'),  'sentinel_proxy/payloads'),
    # sentinel_proxy main.py — proxy start command ke liye
    (str(BASE / 'sentinel_proxy' / 'main.py'),   'sentinel_proxy'),
    # SentinelProxy icons
    (str(BASE / 'sentinel_proxy' / 'sentinel_proxy_icon.png'),     'sentinel_proxy'),
    (str(BASE / 'sentinel_proxy' / 'sentinel_proxy_icon.ico'),     'sentinel_proxy'),
    (str(BASE / 'sentinel_proxy' / 'sentinel_proxy_icon_16.png'),  'sentinel_proxy'),
    (str(BASE / 'sentinel_proxy' / 'sentinel_proxy_icon_32.png'),  'sentinel_proxy'),
    (str(BASE / 'sentinel_proxy' / 'sentinel_proxy_icon_64.png'),  'sentinel_proxy'),
    (str(BASE / 'sentinel_proxy' / 'sentinel_proxy_icon_128.png'), 'sentinel_proxy'),
    (str(BASE / 'sentinel_proxy' / 'sentinel_proxy_icon_256.png'), 'sentinel_proxy'),
    # Config files
    (str(BASE / '.env.example'),          '.'),
    (str(BASE / 'config_profiles.json'),  '.'),
    (str(BASE / 'output_formats.json'),   '.'),
    # NLTK data (tokenizers + corpora + taggers + chunkers)
    (str(NLTK_DATA / 'tokenizers'), 'nltk_data/tokenizers'),
    (str(NLTK_DATA / 'corpora'),    'nltk_data/corpora'),
    (str(NLTK_DATA / 'taggers'),    'nltk_data/taggers'),
    (str(NLTK_DATA / 'chunkers'),   'nltk_data/chunkers'),
]

# ── Runtime hook — NLTK data path set karo ───────────────────────────────────
# Yeh file PyInstaller runtime pe chalti hai
RUNTIME_HOOKS = []

# ── Excludes ──────────────────────────────────────────────────────────────────
EXCLUDES = [
    'tkinter',
]

# ── Additional hidden imports for sklearn ─────────────────────────────────────
ADDITIONAL = [
    'inspect', 'dis', 'pydoc', 'doctest', 'difflib',
    'sklearn.utils._chunking',
    'sklearn.utils._param_validation',
    'sklearn.utils._tags',
    'sklearn.utils.multiclass',
    'sklearn.utils.validation',
    'sklearn.utils._encode',
    'sklearn.utils.fixes',
]

# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(
    [str(BASE / 'main.py')],
    pathex=[str(BASE)],
    binaries=[],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS + ADDITIONAL,
    hookspath=[str(BASE / 'hooks')],
    hooksconfig={},
    runtime_hooks=RUNTIME_HOOKS,
    excludes=EXCLUDES,
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='sentinel',
    debug=False,
    bootloader_ignore_signals=False,
    strip=True,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=True,
    upx=True,
    upx_exclude=[],
    name='sentinel',
)
