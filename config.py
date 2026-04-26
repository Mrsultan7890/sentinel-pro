"""
Configuration Management Module
Centralized configuration with environment variable support
"""

import os
import sys
from pathlib import Path
from dotenv import load_dotenv

# ── Base directory — binary aur source dono ke liye sahi ───────────────────────────
def _get_base_dir() -> Path:
    """
    PyInstaller binary mein: executable ke saath wali directory
    Normal Python mein: config.py wali directory
    """
    if getattr(sys, 'frozen', False):
        # PyInstaller — user ne jahan binary rakhi hai woh folder
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent

BASE_DIR = _get_base_dir()

# Load .env from BASE_DIR
load_dotenv(BASE_DIR / '.env')

def get_base_dir() -> Path:
    """Har module se BASE_DIR lene ka safe tarika."""
    return BASE_DIR

# Directory structure
INVESTIGATIONS_DIR = BASE_DIR / "investigations"
REPORTS_DIR = BASE_DIR / "reports"
MODELS_DIR = BASE_DIR / "models"
EVIDENCE_DIR = BASE_DIR / "evidence"
LOGS_DIR = BASE_DIR / "logs"

# Create directories if they don't exist
for directory in [INVESTIGATIONS_DIR, REPORTS_DIR, MODELS_DIR, EVIDENCE_DIR, LOGS_DIR]:
    directory.mkdir(exist_ok=True)

# Binary paths
SCRAPER_BIN        = BASE_DIR / "scraper" / "scraper"
PREDICTOR_BIN      = BASE_DIR / "predictor" / "predictor"
ANALYZER_BIN       = BASE_DIR / "analyzer" / "target" / "release" / "analyzer"
NETWORK_MAPPER_BIN = BASE_DIR / "network_mapper" / "network_mapper"
STEALTH_PROXY_BIN  = BASE_DIR / "stealth_proxy" / "stealth_proxy"
MEDIA_ANALYZER_BIN = BASE_DIR / "media_analyzer" / "target" / "release" / "media_analyzer"

# Screenshots directory
SCREENSHOTS_DIR = BASE_DIR / "screenshots"
SCREENSHOTS_DIR.mkdir(exist_ok=True)

# Telegram Alerts
TELEGRAM_BOT_TOKEN = os.getenv('TELEGRAM_BOT_TOKEN', '')
TELEGRAM_CHAT_ID   = os.getenv('TELEGRAM_CHAT_ID', '')

# Breach API Keys
HIBP_API_KEY       = os.getenv('HIBP_API_KEY', '')
DEHASHED_EMAIL     = os.getenv('DEHASHED_EMAIL', '')
DEHASHED_API_KEY   = os.getenv('DEHASHED_API_KEY', '')

# Phone OSINT API Keys
NUMVERIFY_API_KEY      = os.getenv('NUMVERIFY_API_KEY', '')
ABSTRACTAPI_PHONE_KEY  = os.getenv('ABSTRACTAPI_PHONE_KEY', '')

# Groq LLM API
GROQ_API_KEY = os.getenv('GROQ_API_KEY', '')

# API Keys - read from environment variables
SHODAN_API_KEY         = os.getenv('SHODAN_API_KEY', '')
GITHUB_TOKEN           = os.getenv('GITHUB_TOKEN', '')
SERPAPI_KEY            = os.getenv('SERPAPI_KEY', '')
SECURITYTRAILS_API_KEY = os.getenv('SECURITYTRAILS_API_KEY', '')
NVD_API_KEY            = os.getenv('NVD_API_KEY', '')

# Rate limiting configuration
RATE_LIMIT_REQUESTS = int(os.getenv('OSINT_RATE_LIMIT', '10'))
RATE_LIMIT_PERIOD = int(os.getenv('OSINT_RATE_PERIOD', '60'))

# OSINT scanning configuration (for profile switching)
OSINT_MIN_DELAY = float(os.getenv('OSINT_MIN_DELAY', '2.0'))
OSINT_MAX_DELAY = float(os.getenv('OSINT_MAX_DELAY', '5.0'))
OSINT_RATE_LIMIT = int(os.getenv('OSINT_RATE_LIMIT', '10'))
OSINT_RATE_PERIOD = int(os.getenv('OSINT_RATE_PERIOD', '60'))
OSINT_SSL_VERIFY = os.getenv('OSINT_SSL_VERIFY', 'true').lower() == 'true'

# ML Engine Configuration
ML_CONFIDENCE_THRESHOLD = float(os.getenv('ML_CONFIDENCE_THRESHOLD', '0.50'))
ML_CLUSTER_EPS          = float(os.getenv('ML_CLUSTER_EPS', '0.35'))
ML_CLUSTER_MIN_SAMPLES  = int(os.getenv('ML_CLUSTER_MIN_SAMPLES', '2'))
ML_NLP_MAX_TEXT_LENGTH  = int(os.getenv('ML_NLP_MAX_TEXT_LENGTH', '5000'))
ML_TIMELINE_MIN_POSTS   = int(os.getenv('ML_TIMELINE_MIN_POSTS', '3'))
ML_FINGERPRINT_MIN_WORDS = int(os.getenv('ML_FINGERPRINT_MIN_WORDS', '10'))

# ML models directory
ML_MODELS_DIR = MODELS_DIR / 'ml_engine'
ML_MODELS_DIR.mkdir(exist_ok=True)

# Request timeouts
REQUEST_TIMEOUT = int(os.getenv('OSINT_TIMEOUT', '10'))
LONG_REQUEST_TIMEOUT = int(os.getenv('OSINT_LONG_TIMEOUT', '30'))

# Stealth configuration
STEALTH_MIN_DELAY = float(os.getenv('OSINT_MIN_DELAY', '2.0'))
STEALTH_MAX_DELAY = float(os.getenv('OSINT_MAX_DELAY', '5.0'))

# Tor configuration
TOR_PROXY = os.getenv('TOR_PROXY', 'socks5h://127.0.0.1:9050')
TOR_CONTROL_PORT = int(os.getenv('TOR_CONTROL_PORT', '9051'))
TOR_PASSWORD = os.getenv('TOR_PASSWORD', '')
TOR_ENABLED = os.getenv('TOR_ENABLED', 'false').lower() == 'true'

# Runtime toggle — changed via 'tor on/off' command without restart
_tor_active = False

def tor_on():
    global _tor_active
    _tor_active = True

def tor_off():
    global _tor_active
    _tor_active = False

def is_tor_active() -> bool:
    return _tor_active or TOR_ENABLED

def get_proxies() -> dict:
    """Return proxy dict for requests if Tor is active, else empty."""
    if is_tor_active():
        return {'http': TOR_PROXY, 'https': TOR_PROXY}
    return {}

# Logging configuration
LOG_LEVEL = os.getenv('OSINT_LOG_LEVEL', 'INFO')
LOG_FILE = LOGS_DIR / "sentinel.log"

# Legal compliance
EVIDENCE_STANDARDS = ['ISO 27037', 'NIST SP 800-86', 'RFC 3227']
LEGAL_JURISDICTION = os.getenv('OSINT_JURISDICTION', 'international')

# Security
SSL_VERIFY = os.getenv('OSINT_SSL_VERIFY', 'true').lower() == 'true'
MAX_RETRIES = int(os.getenv('OSINT_MAX_RETRIES', '3'))

# User agents pool
USER_AGENTS = [
    'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36',
    'Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0',
    'Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0'
]

def validate_binaries():
    """Validate that required binaries exist"""
    binaries = {
        'scraper': SCRAPER_BIN,
        'predictor': PREDICTOR_BIN,
        'network_mapper': NETWORK_MAPPER_BIN
    }
    missing = []
    for name, path in binaries.items():
        if not path.exists():
            missing.append(f"{name} ({path})")
    return missing

def validate_ml_engine() -> dict:
    """ML engine dependencies check karo"""
    status = {}
    ml_packages = {
        'sklearn':  'scikit-learn',
        'numpy':    'numpy',
        'nltk':     'nltk',
        'scipy':    'scipy',
    }
    for imp, pkg in ml_packages.items():
        try:
            __import__(imp)
            status[pkg] = 'ok'
        except ImportError:
            status[pkg] = 'missing'

    # NLTK data check
    try:
        import nltk
        nltk_path_map = {
            'punkt_tab':                        'tokenizers/punkt_tab',
            'stopwords':                        'corpora/stopwords',
            'averaged_perceptron_tagger_eng':   'taggers/averaged_perceptron_tagger_eng',
            'maxent_ne_chunker_tab':            'chunkers/maxent_ne_chunker_tab',
            'words':                            'corpora/words',
        }
        for pkg, path in nltk_path_map.items():
            try:
                nltk.data.find(path)
                status[f'nltk_{pkg}'] = 'ok'
            except LookupError:
                status[f'nltk_{pkg}'] = 'missing'
    except ImportError:
        pass

    return status

def get_config():
    """Get complete configuration dictionary"""
    return {
        'base_dir': str(BASE_DIR),
        'investigations_dir': str(INVESTIGATIONS_DIR),
        'reports_dir': str(REPORTS_DIR),
        'models_dir': str(MODELS_DIR),
        'evidence_dir': str(EVIDENCE_DIR),
        'logs_dir': str(LOGS_DIR),
        'rate_limit': {
            'requests': RATE_LIMIT_REQUESTS,
            'period': RATE_LIMIT_PERIOD
        },
        'timeouts': {
            'default': REQUEST_TIMEOUT,
            'long': LONG_REQUEST_TIMEOUT
        },
        'stealth': {
            'min_delay': STEALTH_MIN_DELAY,
            'max_delay': STEALTH_MAX_DELAY
        },
        'tor': {
            'proxy': TOR_PROXY,
            'control_port': TOR_CONTROL_PORT
        },
        'security': {
            'ssl_verify': SSL_VERIFY,
            'max_retries': MAX_RETRIES
        }
    }
