"""
Credential Agent — API Keys & Secrets Management
=================================================
- .env file manage karo
- API keys validate karo
- Expired/weak keys detect karo
- Secrets vault (encrypted)
- SSH keys manage karo

Author: @who_is_the_black_hat
"""

import hashlib
import json
import logging
import os
import re
import subprocess
from pathlib import Path

import config

logger = logging.getLogger(__name__)

ENV_FILE    = config.BASE_DIR / '.env'
VAULT_FILE  = config.BASE_DIR / 'data' / 'secrets_vault.json'

# Known API key patterns
KEY_PATTERNS = {
    # Core Services
    'GROQ_API_KEY':              r'^gsk_[a-zA-Z0-9]{50,}$',
    'TELEGRAM_BOT_TOKEN':        r'^\d+:[a-zA-Z0-9_-]{35}$',
    'TELEGRAM_CHAT_ID':          r'^\d+$',
    
    # Security & Vulnerability
    'SHODAN_API_KEY':            r'^[a-zA-Z0-9]{32}$',
    'NVD_API_KEY':               r'^[a-zA-Z0-9-]{36}$',
    'VIRUSTOTAL_API_KEY':        r'^[a-zA-Z0-9]{64}$',
    'VULNDB_API_KEY':            r'^[a-zA-Z0-9-]{36,}$',
    'VULNERS_API_KEY':           r'^[a-zA-Z0-9]{40,}$',
    
    # Breach & Leaks
    'HIBP_API_KEY':              r'^[a-zA-Z0-9-]{30,}$',
    'DEHASHED_API_KEY':          r'^[a-zA-Z0-9]{32,}$',
    'DEHASHED_EMAIL':            r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$',
    'INTELX_API_KEY':            r'^[a-zA-Z0-9-]{36,}$',
    'LEAKCHECK_API_KEY':         r'^[a-zA-Z0-9]{32,}$',
    'SNUSBASE_API_KEY':          r'^[a-zA-Z0-9]{32,}$',
    
    # OSINT & Intelligence
    'HUNTER_API_KEY':            r'^[a-zA-Z0-9]{40}$',
    'PIPL_API_KEY':              r'^[a-zA-Z0-9-]{36,}$',
    'FULLCONTACT_API_KEY':       r'^[a-zA-Z0-9]{32,}$',
    'CLEARBIT_API_KEY':          r'^sk_[a-zA-Z0-9]{32}$',
    
    # Network & Infrastructure
    'SECURITYTRAILS_API_KEY':    r'^[a-zA-Z0-9]{32,}$',
    'CENSYS_API_ID':             r'^[a-zA-Z0-9-]{36}$',
    'CENSYS_API_SECRET':         r'^[a-zA-Z0-9]{32,}$',
    'URLSCAN_API_KEY':           r'^[a-zA-Z0-9-]{36}$',
    'BUILTWITH_API_KEY':         r'^[a-zA-Z0-9]{32,}$',
    
    # Threat Intelligence
    'ABUSEIPDB_API_KEY':         r'^[a-zA-Z0-9]{80}$',
    'GREYNOISE_API_KEY':         r'^[a-zA-Z0-9]{32,}$',
    'PHISHTANK_API_KEY':         r'^[a-zA-Z0-9]{64}$',
    'CHECKPHISH_API_KEY':        r'^[a-zA-Z0-9-]{36,}$',
    
    # Malware Analysis
    'MALSHARE_API_KEY':          r'^[a-zA-Z0-9]{64}$',
    'HYBRIDANALYSIS_API_KEY':    r'^[a-zA-Z0-9]{64}$',
    
    # Development & Search
    'GITHUB_TOKEN':              r'^gh[ps]_[a-zA-Z0-9]{36,}$',
    'SERPAPI_KEY':               r'^[a-zA-Z0-9]{64}$',
    
    # Phone Validation
    'NUMVERIFY_API_KEY':         r'^[a-zA-Z0-9]{32}$',
    'ABSTRACTAPI_PHONE_KEY':     r'^[a-zA-Z0-9]{32}$',
    
    # Blockchain & Crypto
    'ETHERSCAN_API_KEY':         r'^[A-Z0-9]{34}$',
    'WHALE_ALERT_API_KEY':       r'^[a-zA-Z0-9]{32,}$',
    
    # Business Intelligence
    'CRUNCHBASE_API_KEY':        r'^[a-zA-Z0-9]{32,}$',
    'COMPANIES_HOUSE_API_KEY':   r'^[a-zA-Z0-9_-]{32,}$',
}


class CredentialAgent:
    NAME = 'credential_agent'

    def __init__(self):
        self._vault = self._load_vault()

    def _load_vault(self) -> dict:
        if VAULT_FILE.exists():
            try:
                return json.loads(VAULT_FILE.read_text())
            except Exception:
                pass
        return {}

    def _save_vault(self):
        VAULT_FILE.parent.mkdir(parents=True, exist_ok=True)
        VAULT_FILE.write_text(json.dumps(self._vault, indent=2))

    # ── .env Management ───────────────────────────────────────────────────────

    def read_env(self) -> dict:
        """Current .env file read karo."""
        env = {}
        if not ENV_FILE.exists():
            return env
        for line in ENV_FILE.read_text().splitlines():
            line = line.strip()
            if line and not line.startswith('#') and '=' in line:
                k, _, v = line.partition('=')
                env[k.strip()] = v.strip()
        return env

    def set_key(self, key: str, value: str) -> bool:
        """API key .env mein set karo."""
        env = self.read_env()
        env[key] = value

        lines = []
        if ENV_FILE.exists():
            for line in ENV_FILE.read_text().splitlines():
                if line.strip().startswith(f'{key}=') or line.strip().startswith(f'{key} ='):
                    continue
                lines.append(line)
        lines.append(f'{key}={value}')

        ENV_FILE.write_text('\n'.join(lines) + '\n')
        os.environ[key] = value
        logger.info(f"[CredentialAgent] Key set: {key}")
        return True

    def remove_key(self, key: str) -> bool:
        """Key .env se remove karo."""
        if not ENV_FILE.exists():
            return False
        lines = [
            l for l in ENV_FILE.read_text().splitlines()
            if not l.strip().startswith(f'{key}=')
        ]
        ENV_FILE.write_text('\n'.join(lines) + '\n')
        os.environ.pop(key, None)
        return True

    # ── Validation ────────────────────────────────────────────────────────────

    def validate_all(self) -> dict:
        """Sab API keys validate karo."""
        env     = self.read_env()
        results = {}

        for key, pattern in KEY_PATTERNS.items():
            value = env.get(key, '')
            if not value or value in ('your_key_here', 'your_groq_api_key_here', ''):
                results[key] = {'status': 'MISSING', 'valid': False}
            elif re.match(pattern, value):
                results[key] = {'status': 'OK', 'valid': True,
                                'preview': value[:8] + '...'}
            else:
                results[key] = {'status': 'INVALID_FORMAT', 'valid': False,
                                'preview': value[:8] + '...'}

        # Live validation
        results.update(self._live_validate(env))
        return results

    def _live_validate(self, env: dict) -> dict:
        """API keys ko actually test karo."""
        results = {}

        # Groq
        groq_key = env.get('GROQ_API_KEY', '')
        if groq_key and not groq_key.startswith('your_'):
            try:
                from groq import Groq
                Groq(api_key=groq_key).models.list()
                results['GROQ_API_KEY'] = {'status': 'ACTIVE', 'valid': True}
            except Exception as e:
                results['GROQ_API_KEY'] = {'status': f'ERROR: {str(e)[:50]}', 'valid': False}

        # Telegram
        tg_token = env.get('TELEGRAM_BOT_TOKEN', '')
        tg_chat  = env.get('TELEGRAM_CHAT_ID', '')
        if tg_token and tg_chat:
            try:
                import requests
                r = requests.get(
                    f'https://api.telegram.org/bot{tg_token}/getMe',
                    timeout=5
                )
                if r.json().get('ok'):
                    results['TELEGRAM_BOT_TOKEN'] = {'status': 'ACTIVE', 'valid': True}
                else:
                    results['TELEGRAM_BOT_TOKEN'] = {'status': 'INVALID', 'valid': False}
            except Exception:
                pass

        return results

    # ── Secrets Vault ─────────────────────────────────────────────────────────

    def vault_store(self, name: str, secret: str, note: str = '') -> bool:
        """Secret vault mein store karo (hashed)."""
        self._vault[name] = {
            'hash':    hashlib.sha256(secret.encode()).hexdigest()[:16],
            'note':    note,
            'stored':  __import__('time').strftime('%Y-%m-%d %H:%M'),
            'length':  len(secret),
        }
        self._save_vault()
        logger.info(f"[CredentialAgent] Vault stored: {name}")
        return True

    def vault_list(self) -> list:
        """Vault mein stored secrets list karo."""
        return [
            {'name': k, **{kk: vv for kk, vv in v.items() if kk != 'hash'}}
            for k, v in self._vault.items()
        ]

    # ── SSH Keys ──────────────────────────────────────────────────────────────

    def list_ssh_keys(self) -> list:
        """SSH keys list karo."""
        ssh_dir = Path.home() / '.ssh'
        keys = []
        if ssh_dir.exists():
            for f in ssh_dir.glob('id_*'):
                if not f.name.endswith('.pub'):
                    pub = f.with_suffix('.pub')
                    keys.append({
                        'private': str(f),
                        'public':  str(pub) if pub.exists() else None,
                        'exists':  f.exists(),
                    })
        return keys

    def generate_ssh_key(self, name: str = 'sentinel_key',
                         key_type: str = 'ed25519') -> dict:
        """Naya SSH key generate karo."""
        key_path = Path.home() / '.ssh' / name
        r = subprocess.run(
            f'ssh-keygen -t {key_type} -f {key_path} -N "" -C "sentinel-pro"',
            shell=True, capture_output=True, text=True
        )
        if r.returncode == 0:
            pub = key_path.with_suffix('.pub')
            return {
                'success':    True,
                'private':    str(key_path),
                'public':     str(pub),
                'public_key': pub.read_text().strip() if pub.exists() else '',
            }
        return {'success': False, 'error': r.stderr[:200]}

    # ── Status ────────────────────────────────────────────────────────────────

    def status(self) -> dict:
        validation = self.validate_all()
        active  = sum(1 for v in validation.values() if v.get('valid'))
        missing = sum(1 for v in validation.values() if v.get('status') == 'MISSING')
        return {
            'total_keys':  len(KEY_PATTERNS),
            'active':      active,
            'missing':     missing,
            'vault_items': len(self._vault),
            'details':     validation,
        }
