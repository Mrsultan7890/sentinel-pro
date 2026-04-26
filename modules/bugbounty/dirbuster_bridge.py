"""
Directory Brute-Force Bridge
Calls the Go dirbuster binary with a wordlist and returns findings.
Supports SCAN_DEPTH: fast / normal / deep
"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

import config as _config
DIRBUSTER_BIN = _config.get_base_dir() / 'dirbuster' / 'dirbuster'

# Wordlist priority per depth
# FAST   — small curated list (~200 paths, ~10 sec)
# NORMAL — common.txt (~4700 paths, ~1-2 min)   [DEFAULT]
# DEEP   — big.txt (~20K paths, ~10+ min)
WORDLISTS = {
    'FAST': [
        # We generate a small curated list inline — no file needed
        None,
    ],
    'NORMAL': [
        '/usr/share/seclists/Discovery/Web-Content/common.txt',
        '/usr/share/wordlists/dirb/common.txt',
    ],
    'DEEP': [
        '/usr/share/seclists/Discovery/Web-Content/big.txt',
        '/usr/share/seclists/Discovery/Web-Content/raft-large-directories.txt',
        '/usr/share/wordlists/dirb/big.txt',
    ],
}

# Fast mode — top sensitive paths only (no wordlist file needed)
FAST_PATHS = [
    'admin', 'login', 'dashboard', 'api', 'config', 'backup',
    '.env', '.git', 'wp-admin', 'phpmyadmin', 'upload', 'uploads',
    'static', 'assets', 'js', 'css', 'images', 'img',
    'test', 'dev', 'staging', 'debug', 'console', 'panel',
    'user', 'users', 'account', 'accounts', 'profile',
    'register', 'signup', 'logout', 'auth', 'oauth',
    'api/v1', 'api/v2', 'api/users', 'api/admin',
    'robots.txt', 'sitemap.xml', '.htaccess', 'web.config',
    'server-status', 'server-info', 'phpinfo.php',
    'wp-config.php', 'wp-login.php', 'xmlrpc.php',
    'swagger', 'swagger-ui', 'swagger.json', 'openapi.json',
    'graphql', 'graphiql', 'actuator', 'health', 'metrics',
    'shell.php', 'cmd.php', 'eval.php', 'info.php',
]


def _get_depth() -> str:
    """Get current scan depth from payload_loader."""
    try:
        from modules.bugbounty.payload_loader import SCAN_DEPTH
        return SCAN_DEPTH
    except Exception:
        return 'NORMAL'


def _find_wordlist(depth: str) -> str | None:
    """Find best available wordlist for given depth."""
    for wl in WORDLISTS.get(depth, WORDLISTS['NORMAL']):
        if wl and Path(wl).exists():
            return wl
    # Fallback to any available
    for wl in WORDLISTS['NORMAL']:
        if wl and Path(wl).exists():
            return wl
    return None


def _write_fast_wordlist() -> Path:
    """Write fast wordlist to temp file."""
    import tempfile
    tmp = Path(tempfile.mktemp(suffix='.txt', prefix='sentinel_fast_'))
    tmp.write_text('\n'.join(FAST_PATHS))
    return tmp


class DirBusterBridge:

    TIMEOUT_MAP = {'FAST': 30, 'NORMAL': 120, 'DEEP': 600}

    def run(self, domain: str, wordlist: str = None,
            threads: int = 50, extensions: str = 'php,html,js,txt') -> dict:

        depth = _get_depth()
        timeout = self.TIMEOUT_MAP.get(depth, 120)

        result = {
            'domain':     domain,
            'results':    [],
            'total':      0,
            'scanned':    0,
            'critical':   0,
            'high':       0,
            'risk_level': 'LOW',
            'wordlist':   None,
            'depth':      depth,
            'error':      None,
        }

        if not DIRBUSTER_BIN.exists():
            result['error'] = 'dirbuster binary not found — run: cd dirbuster && go build -o dirbuster main.go'
            return result

        tmp_file = None
        if wordlist:
            wl = wordlist
        elif depth == 'FAST':
            tmp_file = _write_fast_wordlist()
            wl = str(tmp_file)
        else:
            wl = _find_wordlist(depth)

        if not wl:
            result['error'] = 'No wordlist found. Install seclists: apt install seclists'
            return result

        result['wordlist'] = wl
        logger.info(f'[DirBuster] depth={depth} wordlist={wl} timeout={timeout}s')

        try:
            proc = subprocess.run(
                [str(DIRBUSTER_BIN), domain, wl, str(threads), extensions],
                capture_output=True, text=True, timeout=timeout
            )
            data = json.loads(proc.stdout)
            result['results'] = data.get('results', [])
            result['total']   = data.get('total', 0)
            result['scanned'] = data.get('scanned', 0)
            if data.get('error'):
                result['error'] = data['error']
        except subprocess.TimeoutExpired:
            result['error'] = f'Dirbuster timed out after {timeout}s (depth={depth})'
        except json.JSONDecodeError as e:
            result['error'] = f'Invalid JSON from dirbuster: {e}'
        except Exception as e:
            result['error'] = str(e)
        finally:
            if tmp_file and tmp_file.exists():
                tmp_file.unlink()

        result['critical'] = sum(1 for r in result['results'] if r.get('risk') == 'CRITICAL')
        result['high']     = sum(1 for r in result['results'] if r.get('risk') == 'HIGH')

        if result['critical'] > 0:
            result['risk_level'] = 'CRITICAL'
        elif result['high'] > 0:
            result['risk_level'] = 'HIGH'
        elif result['total'] > 0:
            result['risk_level'] = 'MEDIUM'

        return result
