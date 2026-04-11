"""
Directory Brute-Force Bridge
Calls the Go dirbuster binary with a wordlist and returns findings.
"""

import json
import logging
import subprocess
from pathlib import Path

logger = logging.getLogger(__name__)

DIRBUSTER_BIN = Path(__file__).resolve().parents[2] / 'dirbuster' / 'dirbuster'

# Wordlist priority: use best available on Kali
WORDLIST_CANDIDATES = [
    '/usr/share/seclists/Discovery/Web-Content/common.txt',
    '/usr/share/wordlists/dirb/common.txt',
    '/usr/share/wordlists/dirb/big.txt',
]


class DirBusterBridge:

    TIMEOUT = 60   # 1 min max

    def run(self, domain: str, wordlist: str = None,
            threads: int = 50, extensions: str = 'php,html,js,txt') -> dict:
        result = {
            'domain':   domain,
            'results':  [],
            'total':    0,
            'scanned':  0,
            'critical': 0,
            'high':     0,
            'risk_level': 'LOW',
            'wordlist': None,
            'error':    None
        }

        if not DIRBUSTER_BIN.exists():
            result['error'] = 'dirbuster binary not found — run: cd dirbuster && go build -o dirbuster main.go'
            return result

        wl = wordlist or self._find_wordlist()
        if not wl:
            result['error'] = 'No wordlist found. Install seclists: apt install seclists'
            return result

        result['wordlist'] = wl

        try:
            proc = subprocess.run(
                [str(DIRBUSTER_BIN), domain, wl, str(threads), extensions],
                capture_output=True, text=True, timeout=self.TIMEOUT
            )
            data = json.loads(proc.stdout)
            result['results'] = data.get('results', [])
            result['total']   = data.get('total', 0)
            result['scanned'] = data.get('scanned', 0)
            if data.get('error'):
                result['error'] = data['error']
        except subprocess.TimeoutExpired:
            result['error'] = f'Dirbuster timed out after {self.TIMEOUT}s'
        except json.JSONDecodeError as e:
            result['error'] = f'Invalid JSON from dirbuster: {e}'
        except Exception as e:
            result['error'] = str(e)

        result['critical'] = sum(1 for r in result['results'] if r.get('risk') == 'CRITICAL')
        result['high']     = sum(1 for r in result['results'] if r.get('risk') == 'HIGH')

        if result['critical'] > 0:
            result['risk_level'] = 'CRITICAL'
        elif result['high'] > 0:
            result['risk_level'] = 'HIGH'
        elif result['total'] > 0:
            result['risk_level'] = 'MEDIUM'

        return result

    def _find_wordlist(self) -> str | None:
        for wl in WORDLIST_CANDIDATES:
            if Path(wl).exists():
                return wl
        return None
