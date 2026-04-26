# -*- mode: python ; coding: utf-8 -*-
#
# The Sentinel Pro v3.0 — PyInstaller Build Spec
#
# Build:
#   pip install pyinstaller
#   pyinstaller sentinel.spec
#
# Output: dist/sentinel/  (folder with binary + all assets)
#
# Then package:
#   cd dist && zip -r sentinel_v3.0_linux.zip sentinel/

import sys
import os
from pathlib import Path

BASE = Path(SPECPATH)  # osints/ directory

# ── Hidden imports — lazy loaded modules ──────────────────────────────────────
HIDDEN_IMPORTS = [
    # ML / AI
    'torch', 'torch.nn', 'torch.optim', 'torch.utils.data',
    'sklearn', 'sklearn.ensemble', 'sklearn.linear_model',
    'sklearn.feature_extraction.text', 'sklearn.cluster',
    'sklearn.metrics.pairwise', 'sklearn.preprocessing',
    'lightgbm', 'joblib', 'numpy', 'scipy', 'networkx',
    # NLP
    'nltk', 'nltk.tokenize', 'nltk.corpus', 'nltk.tag',
    'nltk.chunk', 'spacy', 'langdetect',
    # Groq
    'groq', 'tokenizers',
    # HTTP
    'requests', 'requests.adapters', 'httpx',
    'urllib3', 'aiohttp', 'PySocks',
    # HTML / DNS
    'bs4', 'lxml', 'lxml.etree', 'dnspython', 'dns.resolver',
    'whois',
    # Crypto / Security
    'cryptography', 'cryptography.fernet',
    'cryptography.hazmat.primitives',
    'cryptography.hazmat.primitives.kdf.pbkdf2',
    'OpenSSL',
    # Image
    'PIL', 'PIL.Image', 'cv2', 'mmh3',
    # Reporting
    'weasyprint', 'matplotlib', 'matplotlib.pyplot', 'seaborn',
    # CLI
    'rich', 'rich.console', 'rich.table', 'rich.panel',
    'rich.progress', 'rich.live',
    'pyfiglet', 'colorama',
    # System
    'psutil', 'keyring', 'stem',
    # Misc
    'dotenv', 'magic', 'shodan',
    'ddgs', 'fake_useragent',
    'websocket',
    # Sentinel modules
    'config',
    'modules.database',
    'modules.notifications',
    'modules.cli_interface',
    'modules.bugbounty.payload_loader',
    'modules.ml_engine.sentinel_net',
    'modules.ml_engine.trainer',
    'modules.ml_engine.groq_llm',
    'modules.ml_engine.decision_engine',
    'modules.ml_engine.autonomous_loop',
    'sentinel_brain.brain',
    'sentinel_brain.kali_controller',
    'sentinel_brain.rl_agent',
    'sentinel_brain.advanced_ml',
    'sentinel_brain.memory',
    'sentinel_brain.monitor',
]

# ── Data files to embed ───────────────────────────────────────────────────────
DATAS = [
    # ML Models (required)
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_threat_net.pt'),
     'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_vocab.json'),
     'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_seq2seq.pt'),
     'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_seq2seq_vocab.json'),
     'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_proxy_net.pt'),
     'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinel_proxy_vocab.json'),
     'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'rl_qtable.json'),
     'models/ml_engine'),
    # SentinelLM (optional — comment out to reduce size by 137MB)
    (str(BASE / 'models' / 'ml_engine' / 'sentinellm_v1.pt'),
     'models/ml_engine'),
    (str(BASE / 'models' / 'ml_engine' / 'sentinellm_vocab.json'),
     'models/ml_engine'),
    # Payloads (34K payloads — 2.7MB)
    (str(BASE / 'sentinel_proxy' / 'payloads'),
     'sentinel_proxy/payloads'),
    # Config files
    (str(BASE / '.env.example'), '.'),
    (str(BASE / 'config_profiles.json'), '.'),
]

# ── Exclude large unused packages ─────────────────────────────────────────────
EXCLUDES = [
    'tkinter',        # SentinelProxy has its own UI — exclude from main binary
    'test',
    'unittest',
    'email',
    'xml.etree',
    'pydoc',
    'doctest',
    'difflib',
    'pickle',
    'multiprocessing',
]

# ── Analysis ──────────────────────────────────────────────────────────────────
a = Analysis(
    [str(BASE / 'main.py')],
    pathex=[str(BASE)],
    binaries=[],
    datas=DATAS,
    hiddenimports=HIDDEN_IMPORTS,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=EXCLUDES,
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

# ── One-folder build (not onefile — faster startup, easier to update) ─────────
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
